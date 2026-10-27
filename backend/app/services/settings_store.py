"""Settings that can be changed from the UI without editing .env or restarting.

Values saved here live in a JSON file on the data volume and win over the environment variable of the
same name; `.env` stays the fallback (and the place for secrets such as ADMIN_TOKEN, which are never
editable here). Every worker reads the file (cached by mtime), so a change applies everywhere at once.
Secret values are write-only: they are never returned by `view()`.
"""
import fcntl
import json
import os
import threading
from typing import Any, Dict, List, Optional, Tuple

SETTINGS_FILE = os.environ.get('SETTINGS_FILE', '/app/data/settings.json')
_LOCK_FILE = SETTINGS_FILE + '.lock'

# name -> spec. type: str | int | float | bool | csv_ints | csv_ips | csv_hosts | url | https_url | emails
SCHEMA: Dict[str, Dict[str, Any]] = {
    # --- alerts
    'ALERT_THRESHOLDS': {'group': 'alerts', 'type': 'csv_ints', 'default': '30,14,7,1', 'min': 0, 'max': 3650},
    'ALERT_CHECK_INTERVAL_HOURS': {'group': 'alerts', 'type': 'float', 'default': '12', 'min': 0, 'max': 720},
    'ALERT_WEBHOOK_URL': {'group': 'alerts', 'type': 'url', 'secret': True},
    'ALERT_TEAMS_WEBHOOK_URL': {'group': 'alerts', 'type': 'https_url', 'secret': True},
    'APP_URL': {'group': 'alerts', 'type': 'url'},
    # --- email
    'SMTP_HOST': {'group': 'email', 'type': 'str', 'max_len': 255},
    'SMTP_PORT': {'group': 'email', 'type': 'int', 'default': '587', 'min': 1, 'max': 65535},
    'SMTP_USER': {'group': 'email', 'type': 'str', 'max_len': 255},
    'SMTP_PASSWORD': {'group': 'email', 'type': 'str', 'secret': True, 'max_len': 512},
    'SMTP_STARTTLS': {'group': 'email', 'type': 'bool', 'default': 'true'},
    'ALERT_EMAIL_FROM': {'group': 'email', 'type': 'str', 'max_len': 255},
    'ALERT_EMAIL_TO': {'group': 'email', 'type': 'emails'},
    # --- access
    'MONITOR_PUBLIC': {'group': 'access', 'type': 'bool', 'default': 'false'},
    'ALLOW_PRIVATE_TARGETS': {'group': 'access', 'type': 'bool', 'default': 'false'},
    # --- status page
    'STATUS_PAGE_ENABLED': {'group': 'status', 'type': 'bool', 'default': 'true'},
    'STATUS_PAGE_TITLE': {'group': 'status', 'type': 'str', 'max_len': 100},
    # --- lookups
    'RBL_RESOLVERS': {'group': 'lookups', 'type': 'csv_ips'},
    'RBL_LISTS': {'group': 'lookups', 'type': 'csv_hosts'},
    'ACME_DNS_RESOLVERS': {'group': 'lookups', 'type': 'csv_ips', 'default': '1.1.1.1,8.8.8.8'},
    'CT_CACHE_SECONDS': {'group': 'lookups', 'type': 'int', 'default': '900', 'min': 0, 'max': 86400},
    'RDAP_CACHE_SECONDS': {'group': 'lookups', 'type': 'int', 'default': '21600', 'min': 0, 'max': 604800},
    # --- audit log
    'AUDIT_LOG_MAX_BYTES': {'group': 'audit', 'type': 'int', 'default': str(5 * 1024 * 1024), 'min': 10000, 'max': 1024 ** 3},
    'AUDIT_LOG_KEEP': {'group': 'audit', 'type': 'int', 'default': '5', 'min': 0, 'max': 50},
}
GROUP_ORDER = ['alerts', 'email', 'access', 'status', 'lookups', 'audit']

_cache: Tuple[Optional[Tuple[float, int]], Dict[str, str]] = (None, {})
_cache_lock = threading.Lock()


class SettingsError(ValueError):
    """Raised with a {field: message} dict when submitted values are invalid."""

    def __init__(self, errors: Dict[str, str]):
        super().__init__('; '.join(f'{k}: {v}' for k, v in errors.items()))
        self.errors = errors


def _load() -> Dict[str, str]:
    """Saved overrides, re-read only when the file changed."""
    global _cache
    try:
        st = os.stat(SETTINGS_FILE)
    except OSError:
        return {}
    stamp = (st.st_mtime, st.st_size)
    with _cache_lock:
        if _cache[0] == stamp:
            return _cache[1]
        try:
            with open(SETTINGS_FILE) as fh:
                raw = json.load(fh)
        except (OSError, ValueError):
            return {}
        data = {k: str(v) for k, v in raw.items() if k in SCHEMA and isinstance(v, (str, int, float, bool))} \
            if isinstance(raw, dict) else {}
        _cache = (stamp, data)
        return data


def get(name: str, default: Optional[str] = None) -> Optional[str]:
    """Saved value if there is one (even an empty one, which switches a .env value off), else the environment."""
    saved = _load()
    if name in saved:
        return saved[name]
    return os.environ.get(name, default)


def get_bool(name: str, default: bool = False) -> bool:
    value = get(name)
    if value is None or value == '':
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


# --------------------------------------------------------------------------- validation
def _normalise(name: str, spec: Dict[str, Any], value: Any) -> str:
    kind = spec['type']
    if kind == 'bool':
        if isinstance(value, bool):
            return 'true' if value else 'false'
        if str(value).strip().lower() in ('true', 'false'):
            return str(value).strip().lower()
        raise ValueError('must be on or off')
    text = '' if value is None else str(value).strip()
    if text == '':
        return ''  # empty = cleared / switched off
    if kind in ('int', 'float'):
        try:
            number = int(text) if kind == 'int' else float(text)
        except ValueError:
            raise ValueError('must be a number')
        if number < spec.get('min', number) or number > spec.get('max', number):
            raise ValueError(f"must be between {spec['min']} and {spec['max']}")
        return str(number)
    if kind in ('url', 'https_url'):
        needed = ('https://',) if kind == 'https_url' else ('http://', 'https://')
        if not text.lower().startswith(needed) or len(text) > 2048 or any(c.isspace() for c in text):
            raise ValueError('must be an https:// URL' if kind == 'https_url' else 'must be an http:// or https:// URL')
        return text
    if kind == 'csv_ints':
        parts = [p.strip() for p in text.split(',') if p.strip()]
        if not parts or not all(p.isdigit() for p in parts):
            raise ValueError('must be comma-separated whole numbers, e.g. 30,14,7,1')
        values = sorted({int(p) for p in parts}, reverse=True)
        if values[0] > spec['max']:
            raise ValueError(f"must not exceed {spec['max']}")
        return ','.join(str(v) for v in values)
    if kind == 'csv_ips':
        import ipaddress
        parts = [p.strip() for p in text.split(',') if p.strip()]
        for p in parts:
            try:
                ipaddress.ip_address(p)
            except ValueError:
                raise ValueError(f'{p[:40]!r} is not an IP address')
        return ','.join(parts)
    if kind == 'csv_hosts':
        import re
        parts = [p.strip() for p in text.split(',') if p.strip()]
        for p in parts:
            if not re.fullmatch(r'[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', p) or '.' not in p:
                raise ValueError(f'{p[:40]!r} is not a DNS zone name')
        return ','.join(parts)
    if kind == 'emails':
        parts = [p.strip() for p in text.split(',') if p.strip()]
        for p in parts:
            if p.count('@') != 1 or any(c.isspace() for c in p) or '.' not in p.split('@')[1] or p.startswith('@'):
                raise ValueError(f'{p[:40]!r} is not an email address')
        return ','.join(parts)
    if len(text) > spec.get('max_len', 255) or '\n' in text or '\r' in text:
        raise ValueError(f"must be at most {spec.get('max_len', 255)} characters on one line")
    return text


def validate(values: Dict[str, Any]) -> Dict[str, str]:
    errors, clean = {}, {}
    for name, value in values.items():
        spec = SCHEMA.get(name)
        if spec is None:
            errors[name] = 'unknown setting'
            continue
        try:
            clean[name] = _normalise(name, spec, value)
        except ValueError as e:
            errors[name] = str(e)
    if errors:
        raise SettingsError(errors)
    return clean


# --------------------------------------------------------------------------- persistence
def _read_raw() -> Dict[str, str]:
    try:
        with open(SETTINGS_FILE) as fh:
            raw = json.load(fh)
        return {k: v for k, v in raw.items() if k in SCHEMA} if isinstance(raw, dict) else {}
    except (OSError, ValueError):
        return {}


def save(values: Optional[Dict[str, Any]] = None, reset: Optional[List[str]] = None) -> List[str]:
    """Validate and store `values`; names in `reset` go back to the .env value. Returns the changed names."""
    values, reset = values or {}, list(reset or [])
    unknown = {n: 'unknown setting' for n in reset if n not in SCHEMA}
    if unknown:
        raise SettingsError(unknown)
    clean = validate(values)
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(_LOCK_FILE, 'w') as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            data = _read_raw()
            data.update(clean)
            for name in reset:
                data.pop(name, None)
            tmp = SETTINGS_FILE + '.tmp'
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
            os.replace(tmp, SETTINGS_FILE)
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)
    return sorted(set(clean) | set(reset))


def view() -> List[Dict[str, Any]]:
    """Every setting with its effective value and where it comes from. Secrets only report whether they are set."""
    saved = _load()
    out = []
    for name, spec in SCHEMA.items():
        if name in saved:
            source, value = 'ui', saved[name]
        elif os.environ.get(name):
            source, value = 'env', os.environ[name]
        else:
            source, value = 'default', spec.get('default', '')
        secret = bool(spec.get('secret'))
        out.append({'name': name, 'group': spec['group'], 'type': spec['type'], 'secret': secret,
                    'is_set': bool(value), 'source': source, 'default': spec.get('default', ''),
                    'value': None if secret else value})
    order = {g: i for i, g in enumerate(GROUP_ORDER)}
    return sorted(out, key=lambda s: order[s['group']])
