"""Audit log: who changed what, and who was refused.

An append-only JSON Lines file on the data volume. Every entry carries the hash of the previous entry
and its own hash, so deleting or editing a line in the middle is detected by `verify()`. (That is
tamper-evidence, not tamper-proofing: someone who can rewrite the whole file and recompute the chain
can still hide their traces. Ship the file to a log server if that matters.)

Secrets never enter the log: no tokens, API keys, certificates or private keys, only identifiers and a few
allow-listed fields.

Configuration:
  AUDIT_LOG_FILE        default /app/data/audit.log
  AUDIT_LOG_MAX_BYTES   rotate when the file is larger (default 5 MB)
  AUDIT_LOG_KEEP        rotated files to keep (default 5)
"""
import csv
import fcntl
import hashlib
import io
import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)
GENESIS = '0' * 64
MAX_FIELD = 200


def _path() -> str:
    return os.environ.get('AUDIT_LOG_FILE', '/app/data/audit.log')


def _max_bytes() -> int:
    try:
        return max(10_000, int(os.environ.get('AUDIT_LOG_MAX_BYTES', str(5 * 1024 * 1024))))
    except ValueError:
        return 5 * 1024 * 1024


def _keep() -> int:
    try:
        return max(0, min(int(os.environ.get('AUDIT_LOG_KEEP', '5')), 50))
    except ValueError:
        return 5


def _canonical(entry: Dict) -> str:
    return json.dumps({k: v for k, v in entry.items() if k != 'hash'}, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _hash(prev: str, entry: Dict) -> str:
    return hashlib.sha256((prev + _canonical(entry)).encode()).hexdigest()


def _clean(value, depth: int = 0):
    """Bound the size of logged values so a request cannot flood the log."""
    if isinstance(value, str):
        return value[:MAX_FIELD]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)) and depth < 2:
        return [_clean(v, depth + 1) for v in value[:20]]
    if isinstance(value, dict) and depth < 2:
        return {str(k)[:60]: _clean(v, depth + 1) for k, v in list(value.items())[:20]}
    return str(value)[:MAX_FIELD]


def _last_hash(fh) -> str:
    """Hash of the last entry in an open file (reads only the tail)."""
    fh.seek(0, os.SEEK_END)
    size = fh.tell()
    if size == 0:
        return ''
    fh.seek(max(0, size - 8192))
    lines = fh.read().decode('utf-8', 'replace').splitlines()
    for line in reversed(lines):
        try:
            return json.loads(line).get('hash', '')
        except ValueError:
            continue
    return ''


def _rotate(base: str) -> None:
    keep = _keep()
    for i in range(keep, 0, -1):
        src = base if i == 1 else f'{base}.{i - 1}'
        if os.path.exists(src):
            if i == keep and os.path.exists(f'{base}.{i}'):
                os.remove(f'{base}.{i}')
            os.replace(src, f'{base}.{i}')
    if keep == 0 and os.path.exists(base):
        os.remove(base)


def record(action: str, actor: Optional[Dict] = None, ip: Optional[str] = None, target: Optional[str] = None,
           detail: Optional[Dict] = None, result: str = 'success', status: Optional[int] = None) -> Optional[Dict]:
    """Append an entry. Never raises: a broken audit log must not break the request it describes."""
    base = _path()
    try:
        os.makedirs(os.path.dirname(base), exist_ok=True)
        with open(base + '.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                with open(base, 'ab+') as fh:
                    prev = _last_hash(fh)
                    if not prev:  # first entry, or the file was just rotated: continue the chain from the rotated file
                        prev = _chain_tip(base) or GENESIS
                    entry = {
                        'ts': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
                        'action': action, 'result': result, 'status': status,
                        'actor': _clean(actor or {'type': 'anonymous'}), 'ip': _clean(ip),
                        'target': _clean(target), 'detail': _clean(detail or {}), 'prev': prev,
                    }
                    entry['hash'] = _hash(prev, entry)
                    fh.write((json.dumps(entry, sort_keys=True) + '\n').encode())
                    size = fh.tell()
                if size > _max_bytes():
                    _rotate(base)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
        return entry
    except Exception:
        logger.exception('Audit log write failed for %s', action)
        return None


def _chain_tip(base: str) -> str:
    """Hash of the newest entry in the rotated files (used when the current file is empty)."""
    for i in range(1, _keep() + 1):
        rotated = f'{base}.{i}'
        if os.path.exists(rotated):
            with open(rotated, 'rb') as fh:
                return _last_hash(fh)
    return ''


def _files_oldest_first(base: str) -> List[str]:
    rotated = [f'{base}.{i}' for i in range(_keep(), 0, -1) if os.path.exists(f'{base}.{i}')]
    return rotated + ([base] if os.path.exists(base) else [])


def _iter_entries(path: str) -> Iterator[Dict]:
    with open(path, encoding='utf-8', errors='replace') as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except ValueError:
                    yield {'_corrupt': line[:80]}


def query(action: Optional[str] = None, actor: Optional[str] = None, result: Optional[str] = None,
          since: Optional[str] = None, until: Optional[str] = None, search: Optional[str] = None,
          limit: int = 100, offset: int = 0) -> Dict:
    """Newest first. `action` matches by prefix (e.g. "monitor." or "apikey.generate")."""
    limit = max(1, min(int(limit), 500))
    offset = max(0, int(offset))
    matches: List[Dict] = []
    needle = (search or '').lower()
    for path in reversed(_files_oldest_first(_path())):
        for e in reversed(list(_iter_entries(path))):
            if '_corrupt' in e:
                continue
            if action and not str(e.get('action', '')).startswith(action):
                continue
            if result and e.get('result') != result:
                continue
            if actor and actor.lower() not in json.dumps(e.get('actor', {})).lower():
                continue
            if since and e.get('ts', '') < since:
                continue
            if until and e.get('ts', '') > until:
                continue
            if needle and needle not in json.dumps(e).lower():
                continue
            matches.append(e)
    return {'total': len(matches), 'offset': offset, 'limit': limit, 'entries': matches[offset:offset + limit]}


def verify() -> Dict:
    """Check the hash chain across all files. Reports the first break, if any."""
    count, prev = 0, None
    for path in _files_oldest_first(_path()):
        for n, e in enumerate(_iter_entries(path), 1):
            where = {'file': os.path.basename(path), 'line': n}
            if '_corrupt' in e:
                return {'valid': False, 'entries': count, 'problem': {**where, 'reason': 'unreadable line'}}
            if prev is not None and e.get('prev') != prev:
                return {'valid': False, 'entries': count, 'problem': {**where, 'reason': 'chain broken: an entry before this one was removed or changed'}}
            if e.get('hash') != _hash(e.get('prev', ''), e):
                return {'valid': False, 'entries': count, 'problem': {**where, 'reason': 'entry was modified'}}
            prev = e['hash']
            count += 1
    return {'valid': True, 'entries': count, 'problem': None}


def export(fmt: str = 'json', **filters) -> str:
    entries = query(limit=500, **filters)['entries']
    if fmt == 'csv':
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['time', 'action', 'result', 'status', 'actor', 'ip', 'target', 'detail'])
        for e in entries:
            actor = e['actor']
            writer.writerow([_csv_safe(v) for v in (e['ts'], e['action'], e['result'], e.get('status') or '',
                             f"{actor.get('type')}:{actor.get('id', '')}".rstrip(':'), e.get('ip') or '', e.get('target') or '',
                             json.dumps(e.get('detail') or {}, sort_keys=True))])
        return buf.getvalue()
    return json.dumps(entries, indent=2)


def _csv_safe(value) -> str:
    """Stop spreadsheet programs from running log text as a formula."""
    text = str(value)
    return "'" + text if text[:1] in ('=', '+', '-', '@') else text
