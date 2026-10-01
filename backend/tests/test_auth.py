import pytest

from app.services import api_key_manager as akm, cert_monitor, domain_monitor

MONITOR_ROUTES = [
    ('get', '/api/monitor/certificate/list'), ('get', '/api/monitor/expiring'),
    ('post', '/api/monitor/certificate/add'), ('get', '/api/monitor/certificate/x'),
    ('delete', '/api/monitor/certificate/remove/x'), ('patch', '/api/monitor/certificate/x'),
    ('get', '/api/monitor/domain/list'), ('post', '/api/monitor/domain/add'),
    ('get', '/api/monitor/domain/x'), ('delete', '/api/monitor/domain/x'),
    ('post', '/api/monitor/domain/x/check'),
]


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(domain_monitor, 'DOMAIN_DATA_FILE', str(tmp_path / 'd.json'))
    monkeypatch.setattr(cert_monitor, 'MONITOR_DATA_FILE', str(tmp_path / 'c.json'))
    monkeypatch.setattr(cert_monitor, 'MONITOR_LOCK_FILE', str(tmp_path / 'c.lock'))
    monkeypatch.setattr(akm, 'API_KEYS_FILE', str(tmp_path / 'k.json'))
    monkeypatch.setattr(akm, '_LOCK_FILE', str(tmp_path / 'k.lock'))
    monkeypatch.delenv('MONITOR_PUBLIC', raising=False)
    monkeypatch.setenv('ADMIN_TOKEN', 'admin-secret')


@pytest.mark.parametrize('method,path', MONITOR_ROUTES)
def test_monitor_routes_require_auth(client, method, path):
    assert getattr(client, method)(path, json={}).status_code == 401


def test_admin_bearer_and_access_token_accepted(client):
    assert client.get('/api/monitor/domain/list',
                      headers={'Authorization': 'Bearer admin-secret'}).status_code == 200
    assert client.get('/api/monitor/domain/list', headers={'X-Access-Token': 'admin-secret'}).status_code == 200


def test_api_key_accepted_and_revoked_key_rejected(client):
    key = akm.generate_api_key('ci')['api_key']
    assert client.get('/api/monitor/domain/list', headers={'X-Access-Token': key}).status_code == 200
    akm.revoke_api_key(key)
    assert client.get('/api/monitor/domain/list', headers={'X-Access-Token': key}).status_code == 401


def test_wrong_tokens_rejected(client):
    for headers in ({'X-Access-Token': 'nope'}, {'Authorization': 'Bearer nope'},
                    {'Authorization': 'admin-secret'}):
        assert client.get('/api/monitor/domain/list', headers=headers).status_code == 401


def test_locked_down_when_no_admin_token_and_no_keys(client, monkeypatch):
    monkeypatch.delenv('ADMIN_TOKEN')
    assert client.get('/api/monitor/domain/list', headers={'X-Access-Token': 'admin-secret'}).status_code == 401


def test_monitor_public_opt_out(client, monkeypatch):
    monkeypatch.setenv('MONITOR_PUBLIC', 'true')
    assert client.get('/api/monitor/domain/list').status_code == 200


def test_openapi_marks_monitor_secured(client):
    spec = client.get('/api/openapi.json').get_json()
    assert spec['paths']['/monitor/domain/list']['get']['security'] == [{'accessToken': []}]


def test_cors_disabled_by_default(client):
    resp = client.get('/api/health', headers={'Origin': 'https://evil.example'})
    assert 'Access-Control-Allow-Origin' not in resp.headers


def test_cors_allows_only_listed_origins(monkeypatch):
    monkeypatch.setenv('CORS_ORIGINS', 'https://tools.example.com')
    from app import create_app
    c = create_app().test_client()
    ok = c.get('/api/health', headers={'Origin': 'https://tools.example.com'})
    bad = c.get('/api/health', headers={'Origin': 'https://evil.example'})
    assert ok.headers.get('Access-Control-Allow-Origin') == 'https://tools.example.com'
    assert 'Access-Control-Allow-Origin' not in bad.headers
