"""Expiry alerting and the background scheduler.

Configuration (environment):
  ALERT_THRESHOLDS              days before expiry to alert at (default "30,14,7,1")
  ALERT_CHECK_INTERVAL_HOURS    scheduler period (default 12; 0 disables the scheduler)
  ALERT_WEBHOOK_URL             Slack or any generic JSON webhook (receives {"text", "events"})
  ALERT_TEAMS_WEBHOOK_URL       Microsoft Teams: a Workflows "When a Teams webhook request is received"
                                URL or a legacy Incoming Webhook URL (receives an Adaptive Card)
  APP_URL                       public URL of this app; adds an "Open Domain Monitor" button to Teams cards
  SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_STARTTLS (default true),
  ALERT_EMAIL_FROM, ALERT_EMAIL_TO (comma separated)
"""
import fcntl
import json
import logging
import os
import smtplib
import threading
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Dict, List, Optional

import requests

from app.services import cert_monitor, domain_monitor

logger = logging.getLogger(__name__)
_SCHEDULER_LOCK = os.environ.get('SCHEDULER_LOCK_FILE', '/app/data/scheduler.lock')
_scheduler_lock_fh = None  # held for the life of the process by the elected worker


def get_thresholds() -> List[int]:
    raw = os.environ.get('ALERT_THRESHOLDS', '30,14,7,1')
    values = {int(t) for t in raw.split(',') if t.strip().isdigit()}
    return sorted(values, reverse=True) or [30, 14, 7, 1]


def get_config() -> Dict:
    """Redacted view of the alerting configuration."""
    return {
        'thresholds': get_thresholds(),
        'interval_hours': _interval_hours(),
        'email_configured': bool(os.environ.get('SMTP_HOST') and os.environ.get('ALERT_EMAIL_TO')),
        'email_recipients': [r.strip() for r in os.environ.get('ALERT_EMAIL_TO', '').split(',') if r.strip()],
        'webhook_configured': bool(os.environ.get('ALERT_WEBHOOK_URL')),
        'teams_configured': bool(os.environ.get('ALERT_TEAMS_WEBHOOK_URL')),
    }


def applicable_threshold(days_left: int, thresholds: List[int]) -> Optional[int]:
    """Smallest threshold that days_left has reached; 0 means already expired."""
    if days_left < 0:
        return 0
    reached = [t for t in thresholds if days_left <= t]
    return min(reached) if reached else None


def _days_left(not_after_iso: str) -> int:
    not_after = datetime.fromisoformat(not_after_iso.replace('Z', '+00:00'))
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    return (not_after - datetime.now(timezone.utc)).days


def collect_expiry_events() -> List[Dict]:
    """Find expiry alerts that have not been sent yet and mark them as notified."""
    thresholds = get_thresholds()
    events = []

    for entry in domain_monitor.all_entries():
        if entry.get('status') != 'ok' or not entry.get('not_after'):
            continue
        days = _days_left(entry['not_after'])
        threshold = applicable_threshold(days, thresholds)
        if threshold is None or threshold in entry.get('notified', []):
            continue
        events.append({'kind': 'expired' if days < 0 else 'expiring', 'source': 'domain',
                       'domain_id': entry['id'], 'hostname': entry['hostname'],
                       'days_left': days, 'not_after': entry['not_after'],
                       'detail': _expiry_detail(entry['hostname'], days)})
        domain_monitor.mark_notified(entry['id'], [t for t in thresholds + [0] if t >= threshold])

    events.extend(_collect_registration_events(thresholds))

    cert_data = cert_monitor._load_monitored_certificates()
    dirty = False
    for cert in cert_data['certificates']:
        days = _days_left(cert['not_after'])
        threshold = applicable_threshold(days, thresholds)
        if threshold is None or threshold in cert.get('notified', []):
            continue
        name = cert.get('label') or cert.get('common_name')
        events.append({'kind': 'expired' if days < 0 else 'expiring', 'source': 'certificate',
                       'certificate_id': cert['id'], 'hostname': name,
                       'days_left': days, 'not_after': cert['not_after'],
                       'detail': _expiry_detail(name, days)})
        cert['notified'] = sorted(set(cert.get('notified', [])) | {t for t in thresholds + [0] if t >= threshold})
        dirty = True
    if dirty:
        cert_monitor._save_monitored_certificates(cert_data)
    return events


def _collect_registration_events(thresholds: List[int]) -> List[Dict]:
    """Domain registration (RDAP) expiry; one alert per registered domain even if many hosts share it."""
    events, emitted = [], set()
    for entry in domain_monitor.all_entries():
        reg = entry.get('registration') or {}
        if not reg.get('expires'):
            continue
        days = _days_left(reg['expires'])
        threshold = applicable_threshold(days, thresholds)
        if threshold is None or threshold in entry.get('registration_notified', []):
            continue
        if reg['domain'] not in emitted:
            emitted.add(reg['domain'])
            detail = (f"{reg['domain']}: domain registration EXPIRED {-days} day(s) ago" if days < 0
                      else f"{reg['domain']}: domain registration expires in {days} day(s)"
                      + (f" (registrar {reg['registrar']})" if reg.get('registrar') else ''))
            events.append({'kind': 'expired' if days < 0 else 'expiring', 'source': 'registration',
                           'domain_id': entry['id'], 'hostname': reg['domain'], 'days_left': days,
                           'not_after': reg['expires'], 'detail': detail})
        domain_monitor.mark_registration_notified(entry['id'], [t for t in thresholds + [0] if t >= threshold])
    return events


def _expiry_detail(name: str, days: int) -> str:
    if days < 0:
        return f'{name}: certificate EXPIRED {-days} day(s) ago'
    return f'{name}: certificate expires in {days} day(s)'


def format_message(events: List[Dict]) -> str:
    lines = ['SSL Toolkit alerts:', '']
    lines += [f"- [{e['kind']}] {e['detail']}" for e in events]
    return '\n'.join(lines)


def send_email(subject: str, body: str) -> Dict:
    host, to = os.environ.get('SMTP_HOST'), os.environ.get('ALERT_EMAIL_TO')
    if not host or not to:
        return {'channel': 'email', 'sent': False, 'reason': 'not configured'}
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = os.environ.get('ALERT_EMAIL_FROM', os.environ.get('SMTP_USER', 'ssl-toolkit@localhost'))
    msg['To'] = to
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, int(os.environ.get('SMTP_PORT', '587')), timeout=15) as smtp:
            if os.environ.get('SMTP_STARTTLS', 'true').lower() != 'false':
                smtp.starttls()
            if os.environ.get('SMTP_USER'):
                smtp.login(os.environ['SMTP_USER'], os.environ.get('SMTP_PASSWORD', ''))
            smtp.send_message(msg)
        return {'channel': 'email', 'sent': True}
    except Exception as e:
        logger.error('Alert email failed: %s', e)
        return {'channel': 'email', 'sent': False, 'reason': str(e)}


def send_webhook(text: str, events: List[Dict]) -> Dict:
    url = os.environ.get('ALERT_WEBHOOK_URL')
    if not url:
        return {'channel': 'webhook', 'sent': False, 'reason': 'not configured'}
    try:
        # URL comes from trusted operator config, not user input.
        resp = requests.post(url, json={'text': text, 'events': events}, timeout=10)
        resp.raise_for_status()
        return {'channel': 'webhook', 'sent': True}
    except Exception as e:
        logger.error('Alert webhook failed: %s', e)
        return {'channel': 'webhook', 'sent': False, 'reason': str(e)}


_TEAMS_COLORS = {'expired': 'Attention', 'unreachable': 'Attention', 'expiring': 'Warning',
                 'changed': 'Accent', 'recovered': 'Good', 'test': 'Default'}
TEAMS_MAX_EVENTS = 20  # keeps the card well below Teams' payload limit


def build_teams_card(events: List[Dict], title: str = 'SSL Toolkit alerts') -> Dict:
    """Teams message with an Adaptive Card (works with Workflows webhooks and legacy connectors)."""
    body: List[Dict] = [{'type': 'TextBlock', 'text': title, 'weight': 'Bolder', 'size': 'Medium', 'wrap': True}]
    for e in events[:TEAMS_MAX_EVENTS]:
        body.append({'type': 'TextBlock', 'wrap': True, 'spacing': 'Small',
                     'color': _TEAMS_COLORS.get(e.get('kind'), 'Default'),
                     'text': f"**{str(e.get('kind', 'alert')).upper()}** {e.get('detail', '')}"})
    if len(events) > TEAMS_MAX_EVENTS:
        body.append({'type': 'TextBlock', 'wrap': True, 'isSubtle': True,
                     'text': f'… and {len(events) - TEAMS_MAX_EVENTS} more'})
    content: Dict = {'$schema': 'http://adaptivecards.io/schemas/adaptive-card.json', 'type': 'AdaptiveCard',
                     'version': '1.4', 'body': body, 'msteams': {'width': 'Full'}}
    app_url = os.environ.get('APP_URL', '').strip().rstrip('/')
    if app_url.startswith(('http://', 'https://')):
        content['actions'] = [{'type': 'Action.OpenUrl', 'title': 'Open Domain Monitor', 'url': app_url + '/domain-monitor'}]
    return {'type': 'message', 'attachments': [{'contentType': 'application/vnd.microsoft.card.adaptive',
                                                'contentUrl': None, 'content': content}]}


def send_teams(events: List[Dict], title: str = 'SSL Toolkit alerts') -> Dict:
    url = os.environ.get('ALERT_TEAMS_WEBHOOK_URL')
    if not url:
        return {'channel': 'teams', 'sent': False, 'reason': 'not configured'}
    if not url.startswith('https://'):
        return {'channel': 'teams', 'sent': False, 'reason': 'ALERT_TEAMS_WEBHOOK_URL must be an https URL'}
    try:
        # URL comes from trusted operator config, not user input.
        resp = requests.post(url, json=build_teams_card(events, title), timeout=10)
        resp.raise_for_status()
        return {'channel': 'teams', 'sent': True}
    except Exception as e:
        logger.error('Teams alert failed: %s', type(e).__name__)
        return {'channel': 'teams', 'sent': False, 'reason': f'{type(e).__name__}: {str(e)[:150]}'.replace(url, '<webhook>')}


def dispatch(events: List[Dict], subject: str = 'SSL Toolkit: expiry alerts') -> List[Dict]:
    if not events:
        return []
    text = format_message(events)
    return [send_email(subject, text), send_webhook(text, events), send_teams(events, subject.replace('SSL Toolkit: ', 'SSL Toolkit '))]


def run_checks() -> Dict:
    """One full scheduler cycle: re-check domains, collect events, notify."""
    change_events = domain_monitor.check_all_domains()
    expiry_events = collect_expiry_events()
    events = change_events + expiry_events
    deliveries = dispatch(events)
    return {'checked_at': datetime.now(timezone.utc).isoformat(),
            'event_count': len(events), 'events': events, 'deliveries': deliveries}


def _interval_hours() -> float:
    try:
        return float(os.environ.get('ALERT_CHECK_INTERVAL_HOURS', '12'))
    except ValueError:
        return 12.0


def start_scheduler() -> bool:
    """Start the background loop in exactly one process (file-lock election)."""
    global _scheduler_lock_fh
    interval = _interval_hours()
    if interval <= 0:
        return False
    try:
        os.makedirs(os.path.dirname(_SCHEDULER_LOCK), exist_ok=True)
        fh = open(_SCHEDULER_LOCK, 'w')
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False  # another worker owns the scheduler (or the data dir is unavailable)
    _scheduler_lock_fh = fh
    stop = threading.Event()

    def loop():
        stop.wait(60)  # let the app finish booting
        while not stop.is_set():
            try:
                result = run_checks()
                logger.info('Scheduled check done: %d event(s)', result['event_count'])
            except Exception:
                logger.exception('Scheduled check failed')
            stop.wait(interval * 3600)

    threading.Thread(target=loop, name='ssl-toolkit-scheduler', daemon=True).start()
    return True
