import json
import os
import secrets
from datetime import datetime
from typing import Dict, List, Optional

API_KEYS_FILE = '/tmp/ssl-toolkit/api_keys.json'


def _ensure_data_file():
    os.makedirs(os.path.dirname(API_KEYS_FILE), exist_ok=True)
    if not os.path.exists(API_KEYS_FILE):
        with open(API_KEYS_FILE, 'w') as f:
            json.dump({'keys': []}, f)


def _load_api_keys() -> Dict:
    _ensure_data_file()
    try:
        with open(API_KEYS_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {'keys': []}


def _save_api_keys(data: Dict):
    _ensure_data_file()
    with open(API_KEYS_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def generate_api_key(name: str, rate_limit: str = "200 per hour", description: str = None) -> Dict:
    try:
        data = _load_api_keys()
        
        api_key = f"sslkit_{secrets.token_urlsafe(32)}"
        
        key_entry = {
            'key': api_key,
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


def validate_api_key(api_key: str) -> Dict:
    try:
        data = _load_api_keys()
        
        for key_entry in data['keys']:
            if key_entry['key'] == api_key:
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


def list_api_keys(include_keys: bool = False) -> Dict:
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
            
            if include_keys:
                key_info['key'] = key_entry['key']
            else:
                key_info['key_preview'] = key_entry['key'][:15] + '...' if key_entry['key'] else None
            
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
        
        for key_entry in data['keys']:
            if key_entry['key'] == api_key:
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
        
        original_count = len(data['keys'])
        data['keys'] = [k for k in data['keys'] if k['key'] != api_key]
        
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
