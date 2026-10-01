import json

import pytest

from app.services import api_key_manager as akm


@pytest.fixture(autouse=True)
def key_file(tmp_path, monkeypatch):
    path = str(tmp_path / 'api_keys.json')
    monkeypatch.setattr(akm, 'API_KEYS_FILE', path)
    monkeypatch.setattr(akm, '_LOCK_FILE', path + '.lock')
    return path


def test_keys_are_stored_hashed(key_file):
    key = akm.generate_api_key('svc')['api_key']
    raw = open(key_file).read()
    assert key not in raw
    assert akm.validate_api_key(key)['valid'] is True


def test_validate_revoke_delete(key_file):
    key = akm.generate_api_key('svc')['api_key']
    assert akm.revoke_api_key(key)['success']
    assert akm.validate_api_key(key)['valid'] is False
    assert akm.delete_api_key(key)['success']
    assert akm.validate_api_key(key)['message'] == 'Invalid API key'


def test_list_never_exposes_key(key_file):
    key = akm.generate_api_key('svc')['api_key']
    listing = akm.list_api_keys()['keys'][0]
    assert 'key' not in listing and key not in json.dumps(listing)


def test_legacy_plaintext_keys_migrated(key_file):
    with open(key_file, 'w') as f:
        json.dump({'keys': [{'key': 'sslkit_legacy_key_value_0123456789', 'name': 'old', 'rate_limit': '1/s',
                             'created_at': 'x', 'active': True}]}, f)
    assert akm.validate_api_key('sslkit_legacy_key_value_0123456789')['valid'] is True
    assert 'legacy_key_value_0123456789' not in open(key_file).read()
