"""Expiring share links for tool results.

A result can be shared as a read-only snapshot at /shared/<token>. Rules that keep this safe:
  * only results of read-only check tools (SHAREABLE_TOOLS); generators and issuers, whose output can
    hold private keys, are not on the list, and anything that contains key material is refused anyway;
  * the link token is random (192 bits) and only its SHA-256 is stored, so the data file cannot be
    used to rebuild links; the creator sees the token once;
  * snapshots expire (1 hour to 30 days, default 24 hours), can be revoked, and are purged when expired;
  * size limits: 256 KB per snapshot, 200 active snapshots.

Configuration: SHARE_FILE (default /app/data/shares.json).
"""
import fcntl
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

SHAREABLE_TOOLS = {
    'ssl-checker', 'tls-scanner', 'mail-tls', 'security-headers', 'domain-expiry', 'ct-lookup', 'chain-builder',
    'email-deliverability', 'mta-sts',
}
MAX_BYTES = 256 * 1024
MAX_ACTIVE = 200
MIN_TTL_HOURS, MAX_TTL_HOURS, DEFAULT_TTL_HOURS = 1, 24 * 30, 24
_KEY_MATERIAL = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----|"private_key"|"api_key"|"admin_token"', re.I)


def _path() -> str:
    return os.environ.get('SHARE_FILE', '/app/data/shares.json')


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


class _Locked:
    def __init__(self, exclusive: bool):
        self.exclusive = exclusive

    def __enter__(self):
        os.makedirs(os.path.dirname(_path()), exist_ok=True)
        self.lock = open(_path() + '.lock', 'w')
        fcntl.flock(self.lock, fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH)
        try:
            with open(_path()) as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {'shares': []}
        return self

    def save(self):
        tmp = _path() + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(self.data, f)
        os.replace(tmp, _path())

    def __exit__(self, *exc):
        fcntl.flock(self.lock, fcntl.LOCK_UN)
        self.lock.close()


def _purge(data: Dict, now: datetime) -> bool:
    before = len(data['shares'])
    data['shares'] = [s for s in data['shares'] if datetime.fromisoformat(s['expires_at']) > now]
    return len(data['shares']) != before


def _summary(s: Dict) -> Dict:
    return {k: s[k] for k in ('id', 'title', 'tool', 'created_at', 'expires_at', 'views', 'created_by', 'size')}


def create(title: str, tool: str, result, ttl_hours=DEFAULT_TTL_HOURS, created_by: Optional[Dict] = None) -> Dict:
    if tool not in SHAREABLE_TOOLS:
        raise ValueError(f'Results of "{tool}" cannot be shared')
    title = str(title or '').strip()[:120]
    if not title:
        raise ValueError('A title is required')
    if not isinstance(result, (dict, list)):
        raise ValueError('result must be a JSON object or array')
    try:
        ttl = float(ttl_hours)
    except (TypeError, ValueError):
        raise ValueError('ttl_hours must be a number')
    if not MIN_TTL_HOURS <= ttl <= MAX_TTL_HOURS:
        raise ValueError(f'ttl_hours must be between {MIN_TTL_HOURS} and {MAX_TTL_HOURS}')
    try:
        body = json.dumps(result, separators=(',', ':'))
    except (TypeError, ValueError):
        raise ValueError('result is not valid JSON data')
    if len(body.encode()) > MAX_BYTES:
        raise ValueError(f'The result is too large to share ({MAX_BYTES // 1024} KB limit)')
    if _KEY_MATERIAL.search(body):
        raise ValueError('The result contains key material or credentials and cannot be shared')
    now = _now()
    token = secrets.token_urlsafe(24)
    entry = {'id': _hash(token)[:12], 'hash': _hash(token), 'title': title, 'tool': tool, 'created_at': now.isoformat(),
             'expires_at': (now + timedelta(hours=ttl)).isoformat(), 'views': 0, 'size': len(body),
             'created_by': created_by or {'type': 'unknown'}, 'result': result}
    with _Locked(True) as store:
        _purge(store.data, now)
        if len(store.data['shares']) >= MAX_ACTIVE:
            raise ValueError(f'There are already {MAX_ACTIVE} active shared results; revoke some first')
        store.data['shares'].append(entry)
        store.save()
    return {'token': token, **_summary(entry)}


def get(token: str) -> Optional[Dict]:
    """Snapshot for a token (counts a view), or None if unknown or expired."""
    digest, now = _hash(str(token)), _now()
    with _Locked(True) as store:
        changed = _purge(store.data, now)
        found = next((s for s in store.data['shares'] if s['hash'] == digest), None)
        if found:
            found['views'] += 1
            changed = True
        if changed:
            store.save()
    if not found:
        return None
    return {'title': found['title'], 'tool': found['tool'], 'created_at': found['created_at'],
            'expires_at': found['expires_at'], 'result': found['result']}


def list_shares() -> List[Dict]:
    with _Locked(True) as store:
        if _purge(store.data, _now()):
            store.save()
        return [_summary(s) for s in reversed(store.data['shares'])]


def revoke(share_id: str) -> bool:
    with _Locked(True) as store:
        before = len(store.data['shares'])
        store.data['shares'] = [s for s in store.data['shares'] if s['id'] != share_id]
        if len(store.data['shares']) != before:
            store.save()
            return True
    return False
