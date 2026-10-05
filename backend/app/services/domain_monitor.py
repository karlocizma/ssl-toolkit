"""Live-domain monitoring: scheduled re-checks, expiry history and change detection."""
import fcntl
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.services.ssl_checker import _fetch_single_certificate
from app.utils.net_safety import UnsafeTargetError, resolve_public, validate_port

DOMAIN_DATA_FILE = os.environ.get('DOMAIN_MONITOR_FILE', '/app/data/monitored_domains.json')
HISTORY_LIMIT = 90
_HOSTNAME_RE = re.compile(r'^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')


def _lock_path() -> str:
    return DOMAIN_DATA_FILE + '.lock'


def _load() -> Dict:
    os.makedirs(os.path.dirname(DOMAIN_DATA_FILE), exist_ok=True)
    with open(_lock_path(), 'w') as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_SH)
        try:
            with open(DOMAIN_DATA_FILE) as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return {'domains': []}
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)


def _save(data: Dict) -> None:
    os.makedirs(os.path.dirname(DOMAIN_DATA_FILE), exist_ok=True)
    with open(_lock_path(), 'w') as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            tmp = DOMAIN_DATA_FILE + '.tmp'
            with open(tmp, 'w') as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, DOMAIN_DATA_FILE)
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _public_view(entry: Dict, include_history: bool = False) -> Dict:
    view = {k: v for k, v in entry.items() if k not in ('history', 'notified', 'registration_notified')}
    if include_history:
        view['history'] = entry.get('history', [])
    return view


def _new_entry(hostname: str, port: int, label: Optional[str] = None, tags: Optional[List[str]] = None) -> Dict:
    return {
        'id': f'dom_{uuid.uuid4().hex[:12]}',
        'hostname': hostname,
        'port': port,
        'label': label or hostname,
        'tags': tags or [],
        'added_at': _now(),
        'last_check': None,
        'status': 'pending',
        'last_error': None,
        'not_after': None,
        'days_until_expiry': None,
        'issuer': None,
        'serial_number': None,
        'fingerprint_sha256': None,
        'changes': [],
        'history': [],
        'notified': [],
        'registration': None,
        'registration_notified': [],
        'public': False,
        'public_id': None,
        'public_name': None,
    }


MAX_BULK = 50
MAX_BULK_ENTRIES = 100  # CSV import


def _validate_host(hostname: str, port: int) -> Optional[str]:
    """Return an error message, or None when the host may be monitored."""
    if not _HOSTNAME_RE.match(hostname):
        return 'Invalid hostname'
    try:
        resolve_public(hostname, port)
    except UnsafeTargetError as e:
        return str(e)
    except OSError as e:
        return f'DNS resolution error: {e}'
    return None


def add_domain_entries(entries: List[Dict]) -> Dict:
    """Add many hosts at once; each entry is {hostname, port?, label?, tags?}.
    Checks run in parallel and are saved together."""
    from concurrent.futures import ThreadPoolExecutor
    cleaned, seen = [], set()
    for e in entries or []:
        host = str(e.get('hostname', '')).strip().lower().rstrip('.')
        port = validate_port(e.get('port', 443))
        if host and (host, port) not in seen:
            seen.add((host, port))
            cleaned.append({'hostname': host, 'port': port, 'label': e.get('label'), 'tags': e.get('tags') or []})
    if not cleaned:
        raise ValueError('hostnames must be a non-empty list')
    if len(cleaned) > MAX_BULK_ENTRIES:
        raise ValueError(f'At most {MAX_BULK_ENTRIES} hosts can be added at once')

    with ThreadPoolExecutor(max_workers=8) as pool:
        errors = list(pool.map(lambda e: _validate_host(e['hostname'], e['port']), cleaned))
    data = _load()
    existing = {(d['hostname'], d['port']) for d in data['domains']}
    results, new_entries = [], []
    for e, err in zip(cleaned, errors):
        if err:
            results.append({'hostname': e['hostname'], 'status': 'invalid', 'message': err})
        elif (e['hostname'], e['port']) in existing:
            results.append({'hostname': e['hostname'], 'status': 'exists', 'message': 'Already being monitored'})
        else:
            entry = _new_entry(e['hostname'], e['port'], e['label'], e['tags'])
            new_entries.append(entry)
            results.append({'hostname': e['hostname'], 'status': 'added', 'domain_id': entry['id']})
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_check_entry, new_entries))
    if new_entries:
        # Re-read before saving so concurrent adds/removes made during the checks are kept.
        data = _load()
        data['domains'].extend(new_entries)
        _save(data)
    return {'success': True, 'added': len(new_entries), 'results': results}


def add_domains(hostnames: List[str], port=443, tags: Optional[List[str]] = None) -> Dict:
    """Add many hosts on one port (e.g. from a CT lookup)."""
    hostnames = list(hostnames or [])
    if len(hostnames) > MAX_BULK:
        raise ValueError(f'At most {MAX_BULK} hosts can be added at once')
    return add_domain_entries([{'hostname': h, 'port': port, 'tags': tags} for h in hostnames])


def add_domain(hostname: str, port=443, label: Optional[str] = None, tags: Optional[List[str]] = None) -> Dict:
    hostname = (hostname or '').strip().lower().rstrip('.')
    if not _HOSTNAME_RE.match(hostname):
        return {'success': False, 'message': 'Invalid hostname'}
    try:
        port = validate_port(port)
        resolve_public(hostname, port)  # reject internal targets up front
    except UnsafeTargetError as e:
        return {'success': False, 'message': str(e)}
    except OSError as e:
        return {'success': False, 'message': f'DNS resolution error: {e}'}

    data = _load()
    for existing in data['domains']:
        if existing['hostname'] == hostname and existing['port'] == port:
            return {'success': False, 'message': 'Domain already being monitored', 'domain_id': existing['id']}

    entry = _new_entry(hostname, port, label, tags)
    data['domains'].append(entry)
    _save(data)
    check_domain(entry['id'])
    return {'success': True, 'message': 'Domain added to monitoring', 'domain_id': entry['id']}


def set_public(domain_id: str, public: bool, name: Optional[str] = None) -> Dict:
    """Show or hide a host on the public status page. The public id stays the same across toggles, so badge URLs keep working."""
    import secrets
    data = _load()
    for entry in data['domains']:
        if entry['id'] == domain_id:
            entry['public'] = bool(public)
            if public and not entry.get('public_id'):
                entry['public_id'] = 'pub_' + secrets.token_urlsafe(9)
            if name is not None:
                entry['public_name'] = str(name).strip()[:100] or None
            _save(data)
            return {'success': True, 'domain': _public_view(entry)}
    return {'success': False, 'message': 'Domain not found'}


def remove_domain(domain_id: str) -> Dict:
    data = _load()
    remaining = [d for d in data['domains'] if d['id'] != domain_id]
    if len(remaining) == len(data['domains']):
        return {'success': False, 'message': 'Domain not found'}
    data['domains'] = remaining
    _save(data)
    return {'success': True, 'message': 'Domain removed from monitoring'}


def list_domains() -> Dict:
    domains = [_public_view(d) for d in _load()['domains']]
    return {'success': True, 'count': len(domains), 'domains': domains}


def get_domain(domain_id: str) -> Dict:
    for d in _load()['domains']:
        if d['id'] == domain_id:
            return {'success': True, 'domain': _public_view(d, include_history=True)}
    return {'success': False, 'message': 'Domain not found'}


def apply_check_result(entry: Dict, cert_info: Optional[Dict], error: Optional[str]) -> List[Dict]:
    """Update an entry in place from a check result; returns change events."""
    events = []
    entry['last_check'] = _now()

    if cert_info is None:
        if entry['status'] != 'error':
            events.append({'kind': 'unreachable', 'domain_id': entry['id'],
                           'hostname': entry['hostname'], 'detail': error or 'Unable to fetch certificate'})
        entry['status'] = 'error'
        entry['last_error'] = error or 'Unable to fetch certificate'
        return events

    validity = cert_info['validity']
    issuer = cert_info['issuer'].get('common_name') or cert_info['issuer'].get('organization')
    serial = cert_info['serial_number']
    fingerprint = cert_info['fingerprints']['sha256']

    if entry['status'] == 'error':
        events.append({'kind': 'recovered', 'domain_id': entry['id'],
                       'hostname': entry['hostname'], 'detail': 'Domain is reachable again'})

    previous_serial = entry.get('serial_number')
    if previous_serial and previous_serial != serial:
        change = {
            'detected_at': entry['last_check'],
            'old_serial': previous_serial, 'new_serial': serial,
            'old_issuer': entry.get('issuer'), 'new_issuer': issuer,
            'issuer_changed': entry.get('issuer') != issuer,
        }
        entry['changes'] = (entry.get('changes', []) + [change])[-20:]
        entry['notified'] = []  # fresh certificate: re-arm expiry alerts
        detail = 'Certificate replaced (renewed)'
        if change['issuer_changed']:
            detail = f"Certificate replaced and issuer changed: {change['old_issuer']} -> {issuer}"
        events.append({'kind': 'changed', 'domain_id': entry['id'],
                       'hostname': entry['hostname'], 'detail': detail})

    entry.update({
        'status': 'ok',
        'last_error': None,
        'not_after': validity['not_after'],
        'days_until_expiry': validity['days_until_expiry'],
        'issuer': issuer,
        'serial_number': serial,
        'fingerprint_sha256': fingerprint,
    })
    history = entry.setdefault('history', [])
    history.append({'checked_at': entry['last_check'], 'days_until_expiry': validity['days_until_expiry'],
                    'serial_number': serial, 'issuer': issuer})
    entry['history'] = history[-HISTORY_LIMIT:]
    return events


def check_domain(domain_id: str) -> Dict:
    """Re-check one domain now and persist the outcome."""
    data = _load()
    for entry in data['domains']:
        if entry['id'] == domain_id:
            events = _check_entry(entry, force_registration=True)
            _save(data)
            return {'success': True, 'domain': _public_view(entry), 'events': events}
    return {'success': False, 'message': 'Domain not found'}


REGISTRATION_REFRESH_HOURS = 20  # registration dates change rarely and RDAP servers rate-limit


def refresh_registration(entry: Dict, force: bool = False) -> None:
    """Update entry['registration'] from RDAP (at most about once a day unless forced)."""
    from app.services import domain_registration as dr
    reg = entry.get('registration') or {}
    checked = reg.get('checked_at')
    if not force and checked:
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(checked)).total_seconds() / 3600
        if age < REGISTRATION_REFRESH_HOURS:
            return
    try:
        info = dr.lookup(entry['hostname'])
    except ValueError:
        entry['registration'] = None  # an IP address or a name RDAP cannot cover
        return
    except Exception as e:  # never let RDAP trouble break a certificate check; keep the last known data
        reg['checked_at'] = _now()
        reg['error'] = str(e)[:200]
        entry['registration'] = reg
        return
    entry['registration'] = {
        'domain': info['domain'], 'registrar': info['registrar'], 'expires': info['expires'],
        'days_until_expiry': info['days_until_expiry'], 'status': info['status'],
        'checked_at': _now(), 'error': None,
    }


def _check_entry(entry: Dict, force_registration: bool = False) -> List[Dict]:
    try:
        cert_info = _fetch_single_certificate(entry['hostname'], entry['port'], 10)
        error = None if cert_info else 'Unable to retrieve certificate'
    except Exception as e:  # defensive: never let one domain break a scheduled run
        cert_info, error = None, str(e)
    events = apply_check_result(entry, cert_info, error)
    refresh_registration(entry, force=force_registration)
    return events


def check_all_domains() -> List[Dict]:
    """Re-check every monitored domain; returns change events (not expiry alerts)."""
    events = []
    checked = {}
    for entry in _load()['domains']:
        events.extend(_check_entry(entry))
        checked[entry['id']] = entry
    # Re-read before saving so domains added/removed during the (slow) run are not clobbered.
    data = _load()
    data['domains'] = [checked.get(d['id'], d) for d in data['domains']]
    _save(data)
    return events


def all_entries() -> List[Dict]:
    return _load()['domains']


def mark_registration_notified(domain_id: str, thresholds: List[int]) -> None:
    data = _load()
    for entry in data['domains']:
        if entry['id'] == domain_id:
            entry['registration_notified'] = sorted(set(entry.get('registration_notified', [])) | set(thresholds))
    _save(data)


def mark_notified(domain_id: str, thresholds: List[int]) -> None:
    data = _load()
    for entry in data['domains']:
        if entry['id'] == domain_id:
            entry['notified'] = sorted(set(entry.get('notified', [])) | set(thresholds))
    _save(data)
