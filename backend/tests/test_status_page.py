from datetime import datetime, timedelta, timezone

import pytest

from app.services import audit_log, domain_monitor, status_page

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
ADMIN = {'Authorization': 'Bearer admin-secret'}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(domain_monitor, 'DOMAIN_DATA_FILE', str(tmp_path / 'domains.json'))
    monkeypatch.setenv('AUDIT_LOG_FILE', str(tmp_path / 'audit.log'))
    monkeypatch.setenv('ADMIN_TOKEN', 'admin-secret')
    monkeypatch.delenv('MONITOR_PUBLIC', raising=False)
    monkeypatch.delenv('STATUS_PAGE_ENABLED', raising=False)
    monkeypatch.delenv('STATUS_PAGE_TITLE', raising=False)


def entry(host, days, public=True, status='ok', **extra):
    e = domain_monitor._new_entry(host, 443, label=extra.pop('label', None))
    e.update(status=status, public=public, public_id=f'pub_{host}' if public else None, last_check=NOW.isoformat(),
             not_after=None if days is None else (NOW + timedelta(days=days, hours=1)).isoformat(),
             serial_number='SECRET-SERIAL', fingerprint_sha256='SECRET-FP', last_error='connect to 10.0.0.5 failed',
             tags=['internal'], issuer='Internal CA', **extra)
    return e


@pytest.mark.parametrize('days,status', [(90, 'ok'), (31, 'ok'), (30, 'expiring'), (8, 'expiring'), (7, 'critical'), (0, 'critical'), (-1, 'expired')])
def test_status_thresholds(days, status):
    assert status_page.classify(entry('a.example', days), NOW)['status'] == status


def test_unreachable_and_pending():
    assert status_page.classify(entry('a.example', 90, status='error'), NOW)['status'] == 'unreachable'
    assert status_page.classify(entry('a.example', None, status='pending'), NOW)['status'] == 'pending'


def test_only_published_hosts_with_safe_fields_worst_first(monkeypatch):
    domain_monitor._save({'domains': [
        entry('ok.example', 90, label='Shop'), entry('soon.example', 10), entry('private.example', 5, public=False),
        entry('down.example', 90, status='error'),
        entry('named.example', 200, public_name='Customer portal', registration={'expires': (NOW + timedelta(days=400)).isoformat(), 'domain': 'named.example'})]})
    page = status_page.build(NOW)
    assert [h['name'] for h in page['hosts']] == ['down.example', 'soon.example', 'Shop', 'Customer portal']
    assert page['overall'] == 'problem' and page['counts']['unreachable'] == 1 and page['counts']['expiring'] == 1
    assert 'private.example' not in str(page)
    leaked = str(page)
    for secret in ('SECRET-SERIAL', 'SECRET-FP', '10.0.0.5', 'internal', 'Internal CA', 'dom_'):
        assert secret not in leaked
    portal = next(h for h in page['hosts'] if h['name'] == 'Customer portal')
    assert portal['domain_days_until_expiry'] == 400 and portal['id'] == 'pub_named.example'
    assert set(portal) == {'id', 'name', 'status', 'days_until_expiry', 'not_after', 'last_check', 'domain_expires', 'domain_days_until_expiry'}


def test_overall_levels_and_empty_page():
    assert status_page.build(NOW)['overall'] == 'ok' and status_page.build(NOW)['hosts'] == []
    domain_monitor._save({'domains': [entry('a.example', 20)]})
    assert status_page.build(NOW)['overall'] == 'attention'
    domain_monitor._save({'domains': [entry('a.example', 20), entry('b.example', 3)]})
    assert status_page.build(NOW)['overall'] == 'problem'


def test_set_public_keeps_the_public_id_stable():
    e = domain_monitor._new_entry('a.example', 443)
    domain_monitor._save({'domains': [e]})
    first = domain_monitor.set_public(e['id'], True, 'My site')['domain']
    assert first['public'] and first['public_id'].startswith('pub_') and first['public_name'] == 'My site'
    off = domain_monitor.set_public(e['id'], False)['domain']
    again = domain_monitor.set_public(e['id'], True)['domain']
    assert not off['public'] and again['public_id'] == first['public_id'] and again['public_name'] == 'My site'
    assert domain_monitor.set_public(e['id'], True, '')['domain']['public_name'] is None
    assert domain_monitor.set_public('nope', True)['success'] is False


def test_badge_svg_and_escaping():
    domain_monitor._save({'domains': [entry('a.example', 74), entry('x.example', -3, public=True), entry('hidden.example', 5, public=False)]})
    svg = status_page.badge_svg('pub_a.example', NOW)
    assert svg.startswith('<svg') and '74 days' in svg and '#2e7d32' in svg
    assert 'expired' in status_page.badge_svg('pub_x.example', NOW)
    assert status_page.badge_svg('pub_hidden.example', NOW) is None and status_page.badge_svg('nope', NOW) is None


def test_public_endpoints_need_no_login(client):
    domain_monitor._save({'domains': [entry('a.example', 74)]})
    r = client.get('/api/status')
    body = r.get_json()
    assert r.status_code == 200 and body['hosts'][0]['name'] == 'a.example' and body['title'] == 'Certificate status'
    assert r.headers['Cache-Control'] == 'public, max-age=60'
    badge = client.get('/api/status/badge/pub_a.example.svg')
    assert badge.status_code == 200 and badge.mimetype == 'image/svg+xml' and b'days' in badge.data
    assert "default-src 'none'" in badge.headers['Content-Security-Policy']
    assert client.get('/api/status/badge/unknown.svg').status_code == 404


def test_kill_switch_and_title(client, monkeypatch):
    domain_monitor._save({'domains': [entry('a.example', 74)]})
    monkeypatch.setenv('STATUS_PAGE_TITLE', 'Acme certificates')
    assert client.get('/api/status').get_json()['title'] == 'Acme certificates'
    monkeypatch.setenv('STATUS_PAGE_ENABLED', 'false')
    assert client.get('/api/status').status_code == 404
    assert client.get('/api/status/badge/pub_a.example.svg').status_code == 404


def test_publishing_needs_monitor_access_and_is_audited(client):
    e = domain_monitor._new_entry('a.example', 443)
    domain_monitor._save({'domains': [e]})
    url = f"/api/monitor/domain/{e['id']}/public"
    assert client.patch(url, json={'public': True}).status_code == 401
    assert client.patch(url, json={'public': 'yes'}, headers=ADMIN).status_code == 400
    assert client.patch('/api/monitor/domain/missing/public', json={'public': True}, headers=ADMIN).status_code == 404
    r = client.patch(url, json={'public': True, 'name': 'Shop'}, headers=ADMIN)
    assert r.status_code == 200 and r.get_json()['domain']['public_id'].startswith('pub_')
    assert client.get('/api/status').get_json()['hosts'][0]['name'] == 'Shop'
    last = audit_log.query(action='monitor.domain.publish')['entries'][0]
    assert last['target'] == e['id'] and last['detail'] == {'public': True, 'name': 'Shop'}
