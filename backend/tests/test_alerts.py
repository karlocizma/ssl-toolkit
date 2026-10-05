import pytest

from app.services import alerts, cert_monitor, domain_monitor
from app.utils.net_safety import UnsafeTargetError


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(domain_monitor, 'DOMAIN_DATA_FILE', str(tmp_path / 'domains.json'))
    monkeypatch.setattr(cert_monitor, 'MONITOR_DATA_FILE', str(tmp_path / 'certs.json'))
    monkeypatch.setattr(cert_monitor, 'MONITOR_LOCK_FILE', str(tmp_path / 'certs.json.lock'))
    for var in ('SMTP_HOST', 'ALERT_EMAIL_TO', 'ALERT_WEBHOOK_URL', 'ALERT_THRESHOLDS'):
        monkeypatch.delenv(var, raising=False)


def cert_info(serial='1', issuer='LE', days=40):
    return {'validity': {'not_after': '2099-01-01T00:00:00+00:00', 'days_until_expiry': days},
            'issuer': {'common_name': issuer}, 'serial_number': serial,
            'fingerprints': {'sha256': 'ff:' + serial}}


def new_entry():
    return {'id': 'dom_1', 'hostname': 'example.com', 'port': 443, 'status': 'pending',
            'notified': [], 'history': [], 'changes': []}


@pytest.mark.parametrize('days,expected', [(45, None), (30, 30), (20, 30), (14, 14), (3, 7), (1, 1), (0, 1), (-1, 0)])
def test_applicable_threshold(days, expected):
    assert alerts.applicable_threshold(days, [30, 14, 7, 1]) == expected


def test_thresholds_from_env(monkeypatch):
    monkeypatch.setenv('ALERT_THRESHOLDS', '5, 60,abc')
    assert alerts.get_thresholds() == [60, 5]


def test_apply_check_ok_records_history():
    entry = new_entry()
    events = domain_monitor.apply_check_result(entry, cert_info(), None)
    assert events == [] and entry['status'] == 'ok' and len(entry['history']) == 1


def test_renewal_detected_and_rearms_alerts():
    entry = new_entry()
    domain_monitor.apply_check_result(entry, cert_info('1'), None)
    entry['notified'] = [30, 14]
    events = domain_monitor.apply_check_result(entry, cert_info('2', issuer='Other CA'), None)
    assert events[0]['kind'] == 'changed' and 'issuer changed' in events[0]['detail']
    assert entry['notified'] == [] and entry['changes'][0]['issuer_changed']


def test_unreachable_alerts_once_then_recovers():
    entry = new_entry()
    assert domain_monitor.apply_check_result(entry, None, 'timeout')[0]['kind'] == 'unreachable'
    assert domain_monitor.apply_check_result(entry, None, 'timeout') == []
    assert domain_monitor.apply_check_result(entry, cert_info(), None)[0]['kind'] == 'recovered'


def test_add_domain_rejects_internal_and_invalid(monkeypatch):
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    assert not domain_monitor.add_domain('127.0.0.1')['success']
    assert not domain_monitor.add_domain('not a host!')['success']


def test_expiry_events_fire_once_per_threshold():
    domain_monitor._save({'domains': [dict(new_entry(), status='ok', not_after='2000-01-01T00:00:00+00:00')]})
    first = alerts.collect_expiry_events()
    assert [e['kind'] for e in first] == ['expired']
    assert alerts.collect_expiry_events() == []


def test_certificate_expiry_events(sample_cert_pem):
    cert_monitor.add_monitored_certificate(sample_cert_pem)
    data = cert_monitor._load_monitored_certificates()
    data['certificates'][0]['not_after'] = '2099-01-01T00:00:00+00:00'
    cert_monitor._save_monitored_certificates(data)
    assert alerts.collect_expiry_events() == []
    data['certificates'][0]['not_after'] = alerts.datetime.now(alerts.timezone.utc).isoformat()
    cert_monitor._save_monitored_certificates(data)
    assert len(alerts.collect_expiry_events()) == 1
    assert alerts.collect_expiry_events() == []


def test_dispatch_with_nothing_configured():
    out = alerts.dispatch([{'kind': 'test', 'detail': 'x'}])
    assert all(not d['sent'] for d in out)


def test_webhook_called(monkeypatch):
    sent = {}
    monkeypatch.setenv('ALERT_WEBHOOK_URL', 'https://hooks.example/x')

    class R:
        def raise_for_status(self): pass
    monkeypatch.setattr(alerts.requests, 'post', lambda url, json, timeout: sent.update(url=url, json=json) or R())
    assert alerts.send_webhook('hi', [])['sent']
    assert sent['json']['text'] == 'hi'


def test_alert_endpoints_require_admin(client):
    assert client.get('/api/monitor/alerts/config').status_code == 403
    assert client.post('/api/monitor/alerts/run').status_code == 403


def test_domain_routes(client, monkeypatch):
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    monkeypatch.setenv('MONITOR_PUBLIC', 'true')
    assert client.post('/api/monitor/domain/add', json={}).status_code == 400
    assert client.post('/api/monitor/domain/add', json={'hostname': '10.0.0.1'}).status_code == 400
    assert client.get('/api/monitor/domain/list').get_json()['count'] == 0
    assert client.get('/api/monitor/domain/nope').status_code == 404


def test_teams_card_structure_colors_and_truncation(monkeypatch):
    monkeypatch.setenv('APP_URL', 'https://tools.example.com/')
    events = [{'kind': 'expired', 'detail': 'a.example: certificate EXPIRED 2 day(s) ago'},
              {'kind': 'expiring', 'detail': 'b.example: certificate expires in 7 day(s)'}] + \
             [{'kind': 'recovered', 'detail': f'h{i}'} for i in range(25)]
    card = alerts.build_teams_card(events)
    content = card['attachments'][0]['content']
    assert card['type'] == 'message' and content['type'] == 'AdaptiveCard'
    assert content['body'][1]['color'] == 'Attention' and content['body'][2]['color'] == 'Warning'
    assert content['body'][-1]['text'] == '… and 7 more' and len(content['body']) == 1 + 20 + 1
    assert content['actions'][0]['url'] == 'https://tools.example.com/domain-monitor'
    monkeypatch.setenv('APP_URL', 'javascript:alert(1)')
    assert 'actions' not in alerts.build_teams_card(events)['attachments'][0]['content']


def test_send_teams(monkeypatch):
    assert alerts.send_teams([{'kind': 'test', 'detail': 'x'}])['reason'] == 'not configured'
    monkeypatch.setenv('ALERT_TEAMS_WEBHOOK_URL', 'http://insecure.example/hook')
    assert 'https' in alerts.send_teams([])['reason']
    url = 'https://prod-1.westeurope.logic.azure.com/workflows/secret-token'
    monkeypatch.setenv('ALERT_TEAMS_WEBHOOK_URL', url)
    posted = []

    class R:
        def __init__(self, ok): self.ok = ok
        def raise_for_status(self):
            if not self.ok:
                raise alerts.requests.HTTPError(f'400 Client Error for url: {url}')
    monkeypatch.setattr(alerts.requests, 'post', lambda u, json=None, timeout=None: posted.append((u, json)) or R(True))
    assert alerts.send_teams([{'kind': 'test', 'detail': 'x'}]) == {'channel': 'teams', 'sent': True}
    assert posted[0][0] == url and posted[0][1]['attachments'][0]['contentType'].endswith('adaptive')
    monkeypatch.setattr(alerts.requests, 'post', lambda u, json=None, timeout=None: R(False))
    failed = alerts.send_teams([{'kind': 'test', 'detail': 'x'}])
    assert failed['sent'] is False and 'secret-token' not in failed['reason']


def test_dispatch_includes_teams_and_config(monkeypatch):
    assert alerts.get_config()['teams_configured'] is False
    monkeypatch.setenv('ALERT_TEAMS_WEBHOOK_URL', 'https://x.example/hook')
    assert alerts.get_config()['teams_configured'] is True
    monkeypatch.setattr(alerts, 'send_teams', lambda events, title='': {'channel': 'teams', 'sent': True})
    deliveries = alerts.dispatch([{'kind': 'test', 'detail': 'x'}])
    assert [d['channel'] for d in deliveries] == ['email', 'webhook', 'teams']
