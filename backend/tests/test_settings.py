import json
import os
import stat

import pytest

from app.services import alerts, audit_log, domain_monitor, settings_store, status_page

ADMIN = {'Authorization': 'Bearer admin-secret'}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_store, 'SETTINGS_FILE', str(tmp_path / 'settings.json'))
    monkeypatch.setattr(settings_store, '_LOCK_FILE', str(tmp_path / 'settings.json.lock'))
    monkeypatch.setattr(settings_store, '_cache', (None, {}))
    monkeypatch.setenv('AUDIT_LOG_FILE', str(tmp_path / 'audit.log'))
    monkeypatch.setenv('ADMIN_TOKEN', 'admin-secret')
    monkeypatch.setattr(domain_monitor, 'DOMAIN_DATA_FILE', str(tmp_path / 'domains.json'))
    for name in settings_store.SCHEMA:
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def by_name(settings):
    return {s['name']: s for s in settings}


def test_saved_value_beats_env_and_reset_restores_env(monkeypatch):
    monkeypatch.setenv('STATUS_PAGE_TITLE', 'From env')
    assert settings_store.get('STATUS_PAGE_TITLE') == 'From env'
    settings_store.save({'STATUS_PAGE_TITLE': 'From UI'})
    assert settings_store.get('STATUS_PAGE_TITLE') == 'From UI'
    assert by_name(settings_store.view())['STATUS_PAGE_TITLE']['source'] == 'ui'
    settings_store.save(reset=['STATUS_PAGE_TITLE'])
    assert settings_store.get('STATUS_PAGE_TITLE') == 'From env'
    assert by_name(settings_store.view())['STATUS_PAGE_TITLE']['source'] == 'env'


def test_empty_saved_value_switches_an_env_value_off(monkeypatch):
    monkeypatch.setenv('ALERT_WEBHOOK_URL', 'https://hooks.example.com/x')
    settings_store.save({'ALERT_WEBHOOK_URL': ''})
    assert alerts.get_config()['webhook_configured'] is False


def test_secrets_are_never_returned(client):
    client.put('/api/admin/settings', headers=ADMIN, json={'values': {
        'SMTP_PASSWORD': 'hunter2-very-secret', 'ALERT_TEAMS_WEBHOOK_URL': 'https://teams.example.com/hook-secret'}})
    resp = client.get('/api/admin/settings', headers=ADMIN)
    assert 'hunter2-very-secret' not in resp.get_data(as_text=True)
    assert 'hook-secret' not in resp.get_data(as_text=True)
    settings = by_name(resp.get_json()['settings'])
    assert settings['SMTP_PASSWORD']['is_set'] is True and settings['SMTP_PASSWORD']['value'] is None
    assert settings['ALERT_WEBHOOK_URL']['is_set'] is False


def test_file_is_private_and_atomic(isolated):
    settings_store.save({'APP_URL': 'https://tools.example.com'})
    path = isolated / 'settings.json'
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert json.loads(path.read_text()) == {'APP_URL': 'https://tools.example.com'}
    assert not (isolated / 'settings.json.tmp').exists()


@pytest.mark.parametrize('name,value', [
    ('SMTP_PORT', 'abc'), ('SMTP_PORT', '70000'), ('ALERT_THRESHOLDS', '30,x'), ('ALERT_TEAMS_WEBHOOK_URL', 'http://insecure'),
    ('ALERT_WEBHOOK_URL', 'ftp://x'), ('ALERT_EMAIL_TO', 'not-an-email'), ('RBL_RESOLVERS', 'dns.example.com'),
    ('RBL_LISTS', 'bad zone'), ('ALERT_CHECK_INTERVAL_HOURS', '-1'), ('STATUS_PAGE_TITLE', 'a\nb'), ('MONITOR_PUBLIC', 'maybe'),
    ('ADMIN_TOKEN', 'x'), ('SECRET_KEY', 'x'),
])
def test_invalid_values_are_rejected(client, name, value, isolated):
    resp = client.put('/api/admin/settings', headers=ADMIN, json={'values': {name: value}})
    assert resp.status_code == 400 and name in resp.get_json()['errors']
    assert not (isolated / 'settings.json').exists()


def test_one_bad_field_saves_nothing(client, isolated):
    resp = client.put('/api/admin/settings', headers=ADMIN, json={'values': {'APP_URL': 'https://ok.example.com', 'SMTP_PORT': 'x'}})
    assert resp.status_code == 400 and not (isolated / 'settings.json').exists()


def test_values_are_normalised():
    settings_store.save({'ALERT_THRESHOLDS': ' 7, 30,14,7 ', 'ALERT_EMAIL_TO': 'a@x.org, b@y.org', 'SMTP_STARTTLS': False})
    assert settings_store.get('ALERT_THRESHOLDS') == '30,14,7'
    assert settings_store.get('ALERT_EMAIL_TO') == 'a@x.org,b@y.org'
    assert settings_store.get('SMTP_STARTTLS') == 'false'


def test_settings_apply_to_the_code_that_reads_them():
    settings_store.save({'ALERT_THRESHOLDS': '10,2', 'ALERT_CHECK_INTERVAL_HOURS': '6', 'STATUS_PAGE_ENABLED': False,
                         'STATUS_PAGE_TITLE': 'Our certs', 'AUDIT_LOG_KEEP': 2})
    assert alerts.get_thresholds() == [10, 2]
    assert alerts._interval_hours() == 6
    assert status_page.enabled() is False and status_page.title() == 'Our certs'
    assert audit_log._keep() == 2


def test_monitor_public_can_be_switched_from_settings(client):
    assert client.get('/api/monitor/domain/list').status_code == 401
    settings_store.save({'MONITOR_PUBLIC': True})
    assert client.get('/api/monitor/domain/list').status_code != 401


def test_endpoints_need_the_admin_token(client, monkeypatch):
    assert client.get('/api/admin/settings').status_code == 401
    assert client.put('/api/admin/settings', headers={'Authorization': 'Bearer nope'}, json={'values': {}}).status_code == 401
    monkeypatch.delenv('ADMIN_TOKEN')
    assert client.get('/api/admin/settings', headers=ADMIN).status_code == 403


def test_malformed_body(client):
    assert client.put('/api/admin/settings', headers=ADMIN, json=['x']).status_code == 400
    assert client.put('/api/admin/settings', headers=ADMIN, json={'reset': ['NOPE']}).status_code == 400


def test_changes_are_audited_by_name_only(client):
    client.put('/api/admin/settings', headers=ADMIN, json={'values': {'SMTP_PASSWORD': 'hunter2-very-secret', 'SMTP_HOST': 'mail.example.com'}})
    entry = audit_log.query(limit=5, action='settings')['entries'][0]
    assert entry['action'] == 'settings.update' and entry['result'] == 'success'
    assert entry['detail']['changed'] == ['SMTP_HOST', 'SMTP_PASSWORD']
    assert 'hunter2' not in json.dumps(entry) and 'mail.example.com' not in json.dumps(entry)


def test_corrupt_file_falls_back_to_env(isolated, monkeypatch):
    (isolated / 'settings.json').write_text('{not json')
    monkeypatch.setenv('APP_URL', 'https://env.example.com')
    assert settings_store.get('APP_URL') == 'https://env.example.com'
