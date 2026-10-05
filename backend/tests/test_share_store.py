import json
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app
from app.services import audit_log, share_store

ADMIN = {'Authorization': 'Bearer admin-secret'}
RESULT = {'grade': 'A', 'findings': [{'severity': 'info', 'message': 'ok'}]}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv('SHARE_FILE', str(tmp_path / 'shares.json'))
    monkeypatch.setenv('AUDIT_LOG_FILE', str(tmp_path / 'audit.log'))
    monkeypatch.setenv('ADMIN_TOKEN', 'admin-secret')
    monkeypatch.delenv('MONITOR_PUBLIC', raising=False)
    return tmp_path


@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    return app.test_client()


def test_create_and_get_counts_views():
    s = share_store.create('Report', 'ssl-checker', RESULT)
    assert len(s['token']) >= 30 and s['views'] == 0
    got = share_store.get(s['token'])
    assert got['result'] == RESULT and got['tool'] == 'ssl-checker'
    share_store.get(s['token'])
    assert share_store.list_shares()[0]['views'] == 2


def test_only_hash_is_stored(isolated):
    s = share_store.create('Report', 'ssl-checker', RESULT)
    raw = (isolated / 'shares.json').read_text()
    assert s['token'] not in raw
    assert 'token' not in json.loads(raw)['shares'][0]


def test_unknown_tool_and_bad_input():
    for tool in ('csr-generator', 'key-generator', 'nope'):
        with pytest.raises(ValueError):
            share_store.create('x', tool, RESULT)
    with pytest.raises(ValueError):
        share_store.create('', 'ssl-checker', RESULT)
    with pytest.raises(ValueError):
        share_store.create('x', 'ssl-checker', 'text')
    with pytest.raises(ValueError):
        share_store.create('x', 'ssl-checker', RESULT, ttl_hours='abc')


def test_ttl_limits():
    for ttl in (0, 0.5, 24 * 30 + 1):
        with pytest.raises(ValueError):
            share_store.create('x', 'ssl-checker', RESULT, ttl_hours=ttl)
    assert share_store.create('x', 'ssl-checker', RESULT, ttl_hours=1)


def test_key_material_refused():
    for bad in ({'k': '-----BEGIN RSA PRIVATE KEY-----\nabc'}, {'private_key': 'x'}, {'api_key': 'x'}):
        with pytest.raises(ValueError, match='key material'):
            share_store.create('x', 'ssl-checker', bad)


def test_size_and_active_limits(monkeypatch):
    with pytest.raises(ValueError, match='too large'):
        share_store.create('x', 'ssl-checker', {'blob': 'a' * share_store.MAX_BYTES})
    monkeypatch.setattr(share_store, 'MAX_ACTIVE', 2)
    share_store.create('a', 'ssl-checker', RESULT)
    share_store.create('b', 'ssl-checker', RESULT)
    with pytest.raises(ValueError, match='already'):
        share_store.create('c', 'ssl-checker', RESULT)


def test_expired_shares_are_purged(monkeypatch):
    s = share_store.create('x', 'ssl-checker', RESULT, ttl_hours=1)
    later = datetime.now(timezone.utc) + timedelta(hours=2)
    monkeypatch.setattr(share_store, '_now', lambda: later)
    assert share_store.get(s['token']) is None
    assert share_store.list_shares() == []


def test_revoke():
    s = share_store.create('x', 'ssl-checker', RESULT)
    assert share_store.revoke(s['id']) is True
    assert share_store.revoke(s['id']) is False
    assert share_store.get(s['token']) is None


def test_routes_require_auth(client):
    assert client.post('/api/share', json={'title': 't', 'tool': 'ssl-checker', 'result': RESULT}).status_code == 401
    assert client.get('/api/share').status_code == 401
    assert client.delete('/api/share/abc').status_code == 401


def test_route_flow_and_public_headers(client):
    r = client.post('/api/share', json={'title': 'Site', 'tool': 'ssl-checker', 'result': RESULT, 'ttl_hours': 2}, headers=ADMIN)
    assert r.status_code == 201
    share = r.get_json()['share']
    pub = client.get(f"/api/share/{share['token']}")  # no credentials
    assert pub.status_code == 200 and pub.get_json()['result'] == RESULT
    assert pub.headers['Cache-Control'] == 'no-store'
    assert 'noindex' in pub.headers['X-Robots-Tag']
    assert pub.headers['Referrer-Policy'] == 'no-referrer'
    listing = client.get('/api/share', headers=ADMIN).get_json()['shares']
    assert listing[0]['id'] == share['id'] and 'token' not in listing[0]
    assert client.delete(f"/api/share/{share['id']}", headers=ADMIN).status_code == 200
    assert client.get(f"/api/share/{share['token']}").status_code == 404
    assert client.delete(f"/api/share/{share['id']}", headers=ADMIN).status_code == 404


def test_route_validation(client):
    r = client.post('/api/share', json={'title': 'x', 'tool': 'csr-generator', 'result': RESULT}, headers=ADMIN)
    assert r.status_code == 400
    assert client.get('/api/share/not-a-real-token').status_code == 404


def test_audit_never_contains_token(client):
    r = client.post('/api/share', json={'title': 'Site', 'tool': 'ssl-checker', 'result': RESULT}, headers=ADMIN)
    share = r.get_json()['share']
    client.get(f"/api/share/{share['token']}")
    client.delete(f"/api/share/{share['id']}", headers=ADMIN)
    es = audit_log.query(limit=50)['entries']
    actions = {e['action'] for e in es}
    assert {'share.create', 'share.revoke'} <= actions
    assert share['token'] not in json.dumps(es)
    assert audit_log.verify()['valid']
