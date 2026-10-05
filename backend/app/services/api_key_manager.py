import fcntl
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime
from typing import Dict, Optional

# Persisted on the same volume as the certificate monitor data.
API_KEYS_FILE = os.environ.get('API_KEYS_FILE', '/app/data/api_keys.json')
_LOCK_FILE = API_KEYS_FILE + '.lock'


def _hash_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


def _migrate(data: Dict) -> Dict:
    """Replace legacy plaintext keys with hashes so keys are never stored in the clear."""
    for entry in data.get('keys', []):
        if 'key' in entry:
            plain = entry.pop('key')
            entry['key_hash'] = _hash_key(plain)
            entry['key_preview'] = plain[:15] + '...'
    return data


def _ensure_data_file():
    os.makedirs(os.path.dirname(API_KEYS_FILE), exist_ok=True)
    if not os.path.exists(API_KEYS_FILE):
        with open(API_KEYS_FILE, 'w') as f:
            json.dump({'keys': []}, f)
        os.chmod(API_KEYS_FILE, 0o600)


def _load_api_keys() -> Dict:
    _ensure_data_file()
    with open(_LOCK_FILE, 'w') as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_SH)
        try:
            with open(API_KEYS_FILE, 'r') as f:
                return _migrate(json.load(f))
        except (json.JSONDecodeError, OSError):
            return {'keys': []}
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)


def _save_api_keys(data: Dict):
    _ensure_data_file()
    with open(_LOCK_FILE, 'w') as lock_fh:
        fcntl.flock(lock_fh, fcntl.LOCK_EX)
        try:
            tmp_path = API_KEYS_FILE + '.tmp'
            with open(tmp_path, 'w') as f:
                json.dump(data, f, indent=2)
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, API_KEYS_FILE)
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)


def _find(data: Dict, api_key: str):
    digest = _hash_key(api_key)
    for entry in data['keys']:
        if hmac.compare_digest(entry.get('key_hash', ''), digest):
            return entry
    return None


def generate_api_key(name: str, rate_limit: str = "200 per hour", description: str = None) -> Dict:
    try:
        data = _load_api_keys()
        
        api_key = f"sslkit_{secrets.token_urlsafe(32)}"
        
        key_entry = {
            'key_hash': _hash_key(api_key),
            'key_preview': api_key[:15] + '...',
            'name': name,
            'description': description or '',
            'rate_limit': rate_limit,
            'created_at': datetime.utcnow().isoformat(),
            'last_used': None,
            'usage_count': 0,
            'active': True
        }
        
        data['keys'].append(key_entry)
        _save_api_keys(data)
        
        return {
            'success': True,
            'message': 'API key generated successfully',
            'api_key': api_key,
            'name': name,
            'rate_limit': rate_limit
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to generate API key: {str(e)}'
        }


def identify_api_key(api_key: str) -> Optional[str]:
    """Name of an active key, without touching its usage counters (used to label audit entries)."""
    try:
        entry = _find(_load_api_keys(), api_key)
    except Exception:
        return None
    return entry['name'] if entry and entry.get('active') else None


def key_preview(api_key: str) -> str:
    """The same short prefix that is stored for display; never the whole key."""
    return str(api_key)[:15] + '...'


def validate_api_key(api_key: str) -> Dict:
    try:
        data = _load_api_keys()
        
        key_entry = _find(data, api_key)
        if key_entry:
            if not key_entry['active']:
                return {
                    'valid': False,
                    'message': 'API key is inactive'
                }

            key_entry['last_used'] = datetime.utcnow().isoformat()
            key_entry['usage_count'] = key_entry.get('usage_count', 0) + 1
            _save_api_keys(data)

            return {
                'valid': True,
                'name': key_entry['name'],
                'rate_limit': key_entry['rate_limit']
            }

        return {
            'valid': False,
            'message': 'Invalid API key'
        }
        
    except Exception:
        return {
            'valid': False,
            'message': 'Error validating API key'
        }


def list_api_keys() -> Dict:
    try:
        data = _load_api_keys()
        
        keys_list = []
        for key_entry in data['keys']:
            key_info = {
                'name': key_entry['name'],
                'description': key_entry.get('description', ''),
                'rate_limit': key_entry['rate_limit'],
                'created_at': key_entry['created_at'],
                'last_used': key_entry.get('last_used'),
                'usage_count': key_entry.get('usage_count', 0),
                'active': key_entry.get('active', True)
            }
            # Keys are stored hashed, so only a preview can be shown.
            key_info['key_preview'] = key_entry.get('key_preview')
            keys_list.append(key_info)
        
        return {
            'success': True,
            'count': len(keys_list),
            'keys': keys_list
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to list API keys: {str(e)}'
        }


def revoke_api_key(api_key: str) -> Dict:
    try:
        data = _load_api_keys()
        
        key_entry = _find(data, api_key)
        if key_entry:
            key_entry['active'] = False
            _save_api_keys(data)

            return {
                'success': True,
                'message': 'API key revoked successfully'
            }

        return {
            'success': False,
            'message': 'API key not found'
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to revoke API key: {str(e)}'
        }


def delete_api_key(api_key: str) -> Dict:
    try:
        data = _load_api_keys()
        
        digest = _hash_key(api_key)
        original_count = len(data['keys'])
        data['keys'] = [k for k in data['keys'] if k.get('key_hash') != digest]

        if len(data['keys']) == original_count:
            return {
                'success': False,
                'message': 'API key not found'
            }
        
        _save_api_keys(data)
        
        return {
            'success': True,
            'message': 'API key deleted successfully'
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to delete API key: {str(e)}'
        }
