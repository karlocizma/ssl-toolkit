"""Public status page for monitored certificates.

Only hosts that someone explicitly published are shown, and only what a visitor of the site could see
anyway: a display name, the certificate's expiry and a coarse status. Serials, fingerprints, issuer
changes, tags, internal ids and error details stay private. The page is built from the data the monitor
already collected; a public request never triggers a connection to any host.

Configuration: STATUS_PAGE_ENABLED (default true), STATUS_PAGE_TITLE (default "Certificate status").
"""
import html
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.services import domain_monitor

EXPIRING_DAYS = 30
CRITICAL_DAYS = 7
_RANK = {'ok': 0, 'pending': 0, 'expiring': 1, 'critical': 2, 'expired': 3, 'unreachable': 3}
_OVERALL = {0: 'ok', 1: 'attention', 2: 'problem', 3: 'problem'}
_COLORS = {'ok': '#2e7d32', 'pending': '#757575', 'expiring': '#ed6c02', 'critical': '#d32f2f',
           'expired': '#b71c1c', 'unreachable': '#b71c1c'}


def enabled() -> bool:
    return os.environ.get('STATUS_PAGE_ENABLED', 'true').lower() not in ('0', 'false', 'no')


def title() -> str:
    return (os.environ.get('STATUS_PAGE_TITLE') or 'Certificate status')[:100]


def _days(iso: Optional[str], now: datetime) -> Optional[int]:
    if not iso:
        return None
    try:
        when = datetime.fromisoformat(iso.replace('Z', '+00:00'))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (when - now).days


def classify(entry: Dict, now: datetime) -> Dict:
    days = _days(entry.get('not_after'), now)
    if entry.get('status') == 'error':
        status = 'unreachable'
    elif days is None:
        status = 'pending'
    elif days < 0:
        status = 'expired'
    elif days <= CRITICAL_DAYS:
        status = 'critical'
    elif days <= EXPIRING_DAYS:
        status = 'expiring'
    else:
        status = 'ok'
    return {'status': status, 'days': days}


def _host(entry: Dict, now: datetime) -> Dict:
    c = classify(entry, now)
    reg = entry.get('registration') or {}
    reg_days = _days(reg.get('expires'), now)
    return {
        'id': entry['public_id'],
        'name': (entry.get('public_name') or entry.get('label') or entry['hostname'])[:100],
        'status': c['status'],
        'days_until_expiry': c['days'],
        'not_after': entry.get('not_after'),
        'last_check': entry.get('last_check'),
        'domain_expires': reg.get('expires') if reg_days is not None else None,
        'domain_days_until_expiry': reg_days,
    }


def build(now: Optional[datetime] = None) -> Dict:
    now = now or datetime.now(timezone.utc)
    hosts: List[Dict] = [_host(e, now) for e in domain_monitor.all_entries() if e.get('public') and e.get('public_id')]
    hosts.sort(key=lambda h: (-_RANK[h['status']], h['days_until_expiry'] if h['days_until_expiry'] is not None else 10 ** 9, h['name'].lower()))
    worst = max((_RANK[h['status']] for h in hosts), default=0)
    counts = {s: sum(1 for h in hosts if h['status'] == s) for s in _RANK}
    return {'title': title(), 'overall': _OVERALL[worst], 'generated_at': now.isoformat(), 'counts': counts, 'hosts': hosts}


def badge_svg(public_id: str, now: Optional[datetime] = None) -> Optional[str]:
    now = now or datetime.now(timezone.utc)
    entry = next((e for e in domain_monitor.all_entries() if e.get('public') and e.get('public_id') == public_id), None)
    if not entry:
        return None
    host = _host(entry, now)
    days = host['days_until_expiry']
    text = {'unreachable': 'unreachable', 'pending': 'pending', 'expired': 'expired'}.get(host['status'], f'{days} days')
    left, right = 'certificate', text
    lw, rw = 7 * len(left) + 12, 7 * len(right) + 12
    color = _COLORS[host['status']]
    label = html.escape(f"{left}: {right}", quote=True)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + rw}" height="20" role="img" aria-label="{label}">'
            f'<title>{label}</title><rect width="{lw}" height="20" fill="#555"/><rect x="{lw}" width="{rw}" height="20" fill="{color}"/>'
            f'<g fill="#fff" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">'
            f'<text x="{lw / 2}" y="14">{html.escape(left)}</text><text x="{lw + rw / 2}" y="14">{html.escape(right)}</text></g></svg>')
