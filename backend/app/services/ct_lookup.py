"""Certificate Transparency lookup (crt.sh): every certificate ever logged for a domain.

Privacy: the queried domain name is sent to the CT search service (crt.sh by default,
override with CT_API_URL). Everything it returns is public by design.
"""
import json
import os
import re
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.utils.net_safety import safe_get

CT_API_URL = os.environ.get('CT_API_URL', 'https://crt.sh/')
MAX_RAW_ENTRIES = 20000
MAX_CERTS_RETURNED = 200
CT_TIMEOUT = 40  # crt.sh is slow for large domains
CT_CACHE_SECONDS = int(os.environ.get('CT_CACHE_SECONDS', '900'))  # 0 disables the cache
_CACHE_MAX = 200
_cache: Dict = {}  # (query) -> (expires_at, entries); repeat searches must not count against the CT service's rate limit
_HOSTNAME_RE = re.compile(r'^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$')


class CTLookupError(Exception):
    pass


def normalize_domain(domain: Optional[str]) -> str:
    d = (domain or '').strip().lower().rstrip('.')
    if d.startswith('*.'):
        d = d[2:]
    if not _HOSTNAME_RE.match(d):
        raise ValueError('A valid domain name is required')
    return d


def _parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _retry_after(resp) -> Optional[int]:
    value = (getattr(resp, 'headers', None) or {}).get('Retry-After', '')
    return int(value) if str(value).isdigit() else None


def fetch_entries(domain: str, include_subdomains: bool = True) -> List[Dict]:
    query = f'%.{domain}' if include_subdomains else domain
    cached = _cache.get(query)
    if cached and cached[0] > time.time():
        return cached[1]
    last_error = None
    for attempt in range(2):  # crt.sh regularly answers 502/504 under load
        try:
            resp = safe_get(CT_API_URL, params={'q': query, 'output': 'json'}, timeout=CT_TIMEOUT,
                            headers={'User-Agent': 'ssl-toolkit-ct/1.0'})
        except Exception as e:
            last_error = f'{type(e).__name__}: {str(e)[:120]}'
        else:
            if resp.status_code == 200:
                try:
                    data = json.loads(resp.text or '[]')
                except ValueError:
                    raise CTLookupError('The CT service returned an invalid response')
                if not isinstance(data, list):
                    raise CTLookupError('The CT service returned an unexpected response')
                data = data[:MAX_RAW_ENTRIES]
                if CT_CACHE_SECONDS > 0:
                    if len(_cache) >= _CACHE_MAX:
                        _cache.clear()
                    _cache[query] = (time.time() + CT_CACHE_SECONDS, data)
                return data
            if resp.status_code == 429:  # retrying immediately only prolongs the block
                wait = _retry_after(resp)
                hint = f' Try again in about {max(1, round(wait / 60))} minute(s).' if wait else ' Try again in a few minutes.'
                raise CTLookupError('The CT search service is rate-limiting this server (HTTP 429).' + hint)
            last_error = f'HTTP {resp.status_code}'
        time.sleep(1)
    raise CTLookupError(f'The CT search service is unavailable ({last_error}); try again shortly')


def _names_in(entry: Dict, domain: str) -> List[str]:
    names = set()
    for raw in (entry.get('name_value') or '').split('\n') + [entry.get('common_name') or '']:
        n = raw.strip().lower().rstrip('.')
        if n and (n == domain or n.endswith('.' + domain)):  # also matches *.domain
            names.add(n)
    return sorted(names)


def analyze(entries: List[Dict], domain: str, include_expired: bool = True,
            expected_issuers: Optional[List[str]] = None, now: Optional[datetime] = None) -> Dict:
    now = now or datetime.now(timezone.utc)
    expected = [e.lower() for e in (expected_issuers or []) if e and e.strip()]
    certs: Dict[str, Dict] = {}
    for e in entries:
        # CT logs contain a precertificate and a final certificate per issuance; they share a serial.
        key = e.get('serial_number') or str(e.get('id'))
        not_before, not_after = _parse_time(e.get('not_before')), _parse_time(e.get('not_after'))
        cert = {
            'id': e.get('id'), 'serial_number': e.get('serial_number'),
            'issuer': e.get('issuer_name'), 'common_name': e.get('common_name'),
            'names': _names_in(e, domain),
            'not_before': e.get('not_before'), 'not_after': e.get('not_after'),
            'logged_at': e.get('entry_timestamp'),
            'expired': bool(not_after and not_after < now),
            'link': f"https://crt.sh/?id={e.get('id')}" if e.get('id') else None,
        }
        if key not in certs or (not_before and not_before < (_parse_time(certs[key]['not_before']) or now)):
            certs[key] = cert
    all_certs = list(certs.values())
    if not include_expired:
        all_certs = [c for c in all_certs if not c['expired']]
    all_certs.sort(key=lambda c: c['not_before'] or '', reverse=True)

    subdomains: Dict[str, Dict] = {}
    for c in all_certs:
        for name in c['names']:
            if name.startswith('*.'):
                continue
            info = subdomains.setdefault(name, {'name': name, 'certificates': 0, 'first_seen': c['not_before'],
                                                'last_seen': c['not_before'], 'active': False})
            info['certificates'] += 1
            if c['not_before'] and (not info['first_seen'] or c['not_before'] < info['first_seen']):
                info['first_seen'] = c['not_before']
            if c['not_before'] and (not info['last_seen'] or c['not_before'] > info['last_seen']):
                info['last_seen'] = c['not_before']
            if not c['expired']:
                info['active'] = True
    issuers = Counter(c['issuer'] or 'unknown' for c in all_certs)
    findings: List[Dict] = []
    if expected:
        unexpected = [i for i in issuers if not any(x in i.lower() for x in expected)]
        for i in unexpected:
            findings.append({'severity': 'warning', 'message': f'{issuers[i]} certificate(s) issued by an unexpected CA: {i}'})
    wildcards = sorted({n for c in all_certs for n in c['names'] if n.startswith('*.')})
    if wildcards:
        findings.append({'severity': 'info', 'message': 'Wildcard certificates exist: ' + ', '.join(wildcards[:5])})
    active = [c for c in all_certs if not c['expired']]
    return {
        'domain': domain,
        'total_certificates': len(all_certs),
        'active_certificates': len(active),
        'subdomains': sorted(subdomains.values(), key=lambda s: s['name']),
        'issuers': [{'issuer': i, 'count': n} for i, n in issuers.most_common()],
        'findings': findings,
        'certificates': all_certs[:MAX_CERTS_RETURNED],
        'truncated': len(all_certs) > MAX_CERTS_RETURNED,
    }


def lookup(domain: str, include_expired: bool = True, expected_issuers: Optional[List[str]] = None) -> Dict:
    domain = normalize_domain(domain)
    entries = fetch_entries(domain)
    result = analyze(entries, domain, include_expired, expected_issuers)
    result['source'] = CT_API_URL
    return result
