import pytest

from app.utils import env as env_utils
from app.utils.features import acme_enabled

DISABLED = 'ACME is disabled on this server (set ENABLE_ACME=true to enable it)'


@pytest.fixture(autouse=True)
def _flag_unset(monkeypatch):
    monkeypatch.delenv('ENABLE_ACME', raising=False)


def test_acme_off_by_default(client):
    resp = client.post('/api/acme/order', json={})
    assert resp.status_code == 404 and resp.get_json() == {'error': DISABLED}


@pytest.mark.parametrize('path', ['/api/acme/order', '/api/acme/complete', '/api/acme/issue', '/api/acme/renewal-info'])
def test_every_acme_endpoint_is_gated(client, path):
    assert client.post(path, json={}).status_code == 404


def test_acme_on_reaches_service(client, monkeypatch):
    monkeypatch.setenv('ENABLE_ACME', 'true')
    resp = client.post('/api/acme/order', json={})
    assert resp.status_code != 404


def test_features_reflects_flag(client, monkeypatch):
    assert client.get('/api/features').get_json() == {'acme': False}
    monkeypatch.setenv('ENABLE_ACME', 'on')
    assert client.get('/api/features').get_json() == {'acme': True}


@pytest.mark.parametrize('value', ['1', 'true', 'YES', 'On'])
def test_truthy_values(monkeypatch, value):
    monkeypatch.setenv('ENABLE_ACME', value)
    assert acme_enabled() is True


@pytest.mark.parametrize('value', ['0', 'false', '', 'no', 'maybe'])
def test_falsy_values(monkeypatch, value):
    monkeypatch.setenv('ENABLE_ACME', value)
    assert acme_enabled() is False


def test_env_comment_tolerated():
    environ = {'ENABLE_ACME': 'false  # keep off'}
    assert env_utils.sanitize_env(environ) == ['ENABLE_ACME'] and environ['ENABLE_ACME'] == 'false'
