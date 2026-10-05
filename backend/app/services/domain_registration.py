"""Domain registration expiry via RDAP (the successor of WHOIS).

The RDAP server for a TLD comes from the IANA bootstrap file, so nothing is hard-coded and no
third-party aggregator sees the queries. Results are cached (RDAP servers rate-limit).

Not every registry publishes an expiry date (for example .de and several other ccTLDs); the
result then says so instead of guessing.
"""
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urljoin

from app.utils.net_safety import UnsafeTargetError, safe_get

BOOTSTRAP_URL = os.environ.get('RDAP_BOOTSTRAP_URL', 'https://data.iana.org/rdap/dns.json')
RDAP_CACHE_SECONDS = int(os.environ.get('RDAP_CACHE_SECONDS', '21600'))  # 6 hours; 0 disables
_BOOTSTRAP_TTL = 86400
_NAME_RE = re.compile(r'^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$')
_lock = threading.Lock()
_bootstrap: Dict = {'at': 0.0, 'map': {}}
_cache: Dict = {}


class RDAPError(Exception):
    pass


def normalize(name: Optional[str]) -> str:
    name = (name or '').strip().lower().rstrip('.')
    if name.startswith('*.'):
        name = name[2:]
    if '://' in name:
        raise ValueError('Enter a domain name, not a URL')
    try:
        name = name.encode('idna').decode('ascii')
    except UnicodeError:
        raise ValueError('Invalid domain name')
    if not _NAME_RE.match(name):
        raise ValueError('A valid domain name is required')
    return name


def _bootstrap_map() -> Dict[str, str]:
    with _lock:
        if _bootstrap['map'] and time.time() - _bootstrap['at'] < _BOOTSTRAP_TTL:
            return _bootstrap['map']
    resp = safe_get(BOOTSTRAP_URL, timeout=15, headers={'User-Agent': 'ssl-toolkit-rdap/1.0'})
    if resp.status_code != 200:
        raise RDAPError(f'Could not load the RDAP bootstrap list (HTTP {resp.status_code})')
    try:
        services = resp.json()['services']
    except (ValueError, KeyError, TypeError):
        raise RDAPError('The RDAP bootstrap list is malformed')
    mapping: Dict[str, str] = {}
    for tlds, urls in services:
        https = [u for u in urls if u.startswith('https://')] or urls
        if https:
            for tld in tlds:
                mapping[tld.lower()] = https[0]
    with _lock:
        _bootstrap.update(at=time.time(), map=mapping)
    return mapping


def _get_json(url: str):
    """GET with up to two validated redirect hops (RDAP servers often redirect to the registrar)."""
    for _ in range(3):
        resp = safe_get(url, timeout=15, headers={'Accept': 'application/rdap+json, application/json',
                                                  'User-Agent': 'ssl-toolkit-rdap/1.0'})
        if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get('Location'):
            url = urljoin(url, resp.headers['Location'])
            continue
        return resp
    raise RDAPError('Too many redirects from the RDAP server')


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _registrar(data: Dict) -> Optional[str]:
    for entity in data.get('entities', []) or []:
        if 'registrar' in (entity.get('roles') or []):
            for item in (entity.get('vcardArray') or [None, []])[1]:
                if item and item[0] == 'fn':
                    return item[3]
    return None


def parse_rdap(data: Dict, queried: str, now: Optional[datetime] = None) -> Dict:
    now = now or datetime.now(timezone.utc)
    events = {}
    for e in data.get('events', []) or []:
        action, when = (e.get('eventAction') or '').lower(), _parse_time(e.get('eventDate'))
        if action and when and action not in events:
            events[action] = when
    expires = events.get('expiration')
    status = [s for s in (data.get('status') or []) if isinstance(s, str)]
    name = (data.get('ldhName') or queried).lower()
    result = {
        'domain': name,
        'registrar': _registrar(data),
        'status': status,
        'registered': events.get('registration').isoformat() if events.get('registration') else None,
        'last_changed': events.get('last changed').isoformat() if events.get('last changed') else None,
        'expires': expires.isoformat() if expires else None,
        'days_until_expiry': (expires - now).days if expires else None,
        'nameservers': sorted({(n.get('ldhName') or '').lower() for n in data.get('nameservers', []) or [] if n.get('ldhName')}),
        'dnssec': bool((data.get('secureDNS') or {}).get('delegationSigned')),
        'findings': [],
    }
    f: List[Dict] = result['findings']
    if expires is None:
        f.append({'severity': 'info', 'message': 'This registry does not publish an expiry date over RDAP '
                                                 '(common for some country-code TLDs); the registrar can tell you'})
    elif result['days_until_expiry'] < 0:
        f.append({'severity': 'critical', 'message': f"The registration expired {-result['days_until_expiry']} day(s) ago"})
    elif result['days_until_expiry'] <= 30:
        f.append({'severity': 'warning', 'message': f"The registration expires in {result['days_until_expiry']} day(s)"})
    lowered = [s.lower() for s in status]
    for flag, text in (('redemption', 'The domain is in the redemption period (expired, recoverable at a fee)'),
                       ('pending delete', 'The domain is pending deletion'),
                       ('client hold', 'The registrar has put the domain on hold (it does not resolve)'),
                       ('server hold', 'The registry has put the domain on hold (it does not resolve)')):
        if any(flag in s for s in lowered):
            f.append({'severity': 'critical', 'message': text})
    if not any('transfer prohibited' in s for s in lowered) and expires is not None:
        f.append({'severity': 'info', 'message': 'No transfer lock (clientTransferProhibited) is set'})
    return result


def lookup(domain: str) -> Dict:
    """RDAP lookup of the registered domain that covers `domain` (sub-domains are stripped)."""
    name = normalize(domain)
    cached = _cache.get(name)
    if cached and cached[0] > time.time():
        return cached[1]
    tld = name.rsplit('.', 1)[1]
    base = _bootstrap_map().get(tld)
    if not base:
        raise RDAPError(f'No RDAP service is published for .{tld}')
    labels = name.split('.')
    last = None
    for i in range(0, max(1, min(len(labels) - 1, 4))):  # a.b.example.co.uk -> b.example.co.uk -> example.co.uk
        candidate = '.'.join(labels[i:])
        if candidate.count('.') < 1:
            break
        try:
            resp = _get_json(base.rstrip('/') + '/domain/' + candidate)
        except UnsafeTargetError:
            raise
        except RDAPError:
            raise
        except Exception as e:
            raise RDAPError(f'The RDAP server could not be reached ({type(e).__name__})')
        last = resp.status_code
        if resp.status_code == 200:
            try:
                result = parse_rdap(resp.json(), candidate)
            except ValueError:
                raise RDAPError('The RDAP server returned an invalid response')
            result['queried'] = name
            if RDAP_CACHE_SECONDS > 0:
                if len(_cache) > 500:
                    _cache.clear()
                _cache[name] = (time.time() + RDAP_CACHE_SECONDS, result)
            return result
        if resp.status_code == 429:
            raise RDAPError('The RDAP server is rate-limiting this server (HTTP 429); try again in a few minutes')
        if resp.status_code != 404:
            raise RDAPError(f'The RDAP server answered HTTP {resp.status_code}')
    raise RDAPError('The domain is not registered' if last == 404 else 'The domain could not be looked up')
