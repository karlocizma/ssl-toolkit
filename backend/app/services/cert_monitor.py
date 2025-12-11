import json
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from cryptography import x509
from cryptography.hazmat.backends import default_backend

MONITOR_DATA_FILE = '/tmp/ssl-toolkit/monitored_certificates.json'


def _ensure_data_file():
    os.makedirs(os.path.dirname(MONITOR_DATA_FILE), exist_ok=True)
    if not os.path.exists(MONITOR_DATA_FILE):
        with open(MONITOR_DATA_FILE, 'w') as f:
            json.dump({'certificates': []}, f)


def _load_monitored_certificates() -> Dict:
    _ensure_data_file()
    try:
        with open(MONITOR_DATA_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {'certificates': []}


def _save_monitored_certificates(data: Dict):
    _ensure_data_file()
    with open(MONITOR_DATA_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def add_monitored_certificate(certificate_pem: str, label: str = None, tags: List[str] = None) -> Dict:
    try:
        cert = x509.load_pem_x509_certificate(
            certificate_pem.encode() if isinstance(certificate_pem, str) else certificate_pem,
            default_backend()
        )
        
        common_name = None
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                common_name = attr.value
                break
        
        serial_number = format(cert.serial_number, 'x')
        not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before
        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
        
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = [str(name.value) for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass
        
        data = _load_monitored_certificates()
        
        for existing_cert in data['certificates']:
            if existing_cert['serial_number'] == serial_number:
                return {
                    'success': False,
                    'message': 'Certificate already being monitored',
                    'certificate_id': existing_cert['id']
                }
        
        cert_id = f"cert_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{serial_number[:8]}"
        
        monitored_cert = {
            'id': cert_id,
            'label': label or common_name or 'Unnamed Certificate',
            'common_name': common_name,
            'serial_number': serial_number,
            'not_before': not_before.isoformat(),
            'not_after': not_after.isoformat(),
            'subject_alternative_names': san_list,
            'tags': tags or [],
            'added_at': datetime.utcnow().isoformat(),
            'certificate_pem': certificate_pem if isinstance(certificate_pem, str) else certificate_pem.decode()
        }
        
        data['certificates'].append(monitored_cert)
        _save_monitored_certificates(data)
        
        return {
            'success': True,
            'message': 'Certificate added to monitoring',
            'certificate_id': cert_id,
            'certificate': monitored_cert
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to add certificate: {str(e)}'
        }


def remove_monitored_certificate(certificate_id: str) -> Dict:
    try:
        data = _load_monitored_certificates()
        
        original_count = len(data['certificates'])
        data['certificates'] = [cert for cert in data['certificates'] if cert['id'] != certificate_id]
        
        if len(data['certificates']) == original_count:
            return {
                'success': False,
                'message': 'Certificate not found'
            }
        
        _save_monitored_certificates(data)
        
        return {
            'success': True,
            'message': 'Certificate removed from monitoring'
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to remove certificate: {str(e)}'
        }


def list_monitored_certificates(include_certificate_pem: bool = False) -> Dict:
    try:
        data = _load_monitored_certificates()
        
        certificates = []
        for cert in data['certificates']:
            cert_copy = cert.copy()
            
            not_after = datetime.fromisoformat(cert['not_after'].replace('Z', '+00:00'))
            now = datetime.utcnow().replace(tzinfo=not_after.tzinfo) if not_after.tzinfo else datetime.utcnow()
            days_until_expiry = (not_after - now).days
            
            cert_copy['days_until_expiry'] = days_until_expiry
            cert_copy['is_expired'] = days_until_expiry < 0
            cert_copy['expires_soon'] = 0 <= days_until_expiry <= 30
            
            if not include_certificate_pem:
                cert_copy.pop('certificate_pem', None)
            
            certificates.append(cert_copy)
        
        return {
            'success': True,
            'count': len(certificates),
            'certificates': certificates
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to list certificates: {str(e)}'
        }


def get_monitored_certificate(certificate_id: str) -> Dict:
    try:
        data = _load_monitored_certificates()
        
        for cert in data['certificates']:
            if cert['id'] == certificate_id:
                not_after = datetime.fromisoformat(cert['not_after'].replace('Z', '+00:00'))
                now = datetime.utcnow().replace(tzinfo=not_after.tzinfo) if not_after.tzinfo else datetime.utcnow()
                days_until_expiry = (not_after - now).days
                
                cert['days_until_expiry'] = days_until_expiry
                cert['is_expired'] = days_until_expiry < 0
                cert['expires_soon'] = 0 <= days_until_expiry <= 30
                
                return {
                    'success': True,
                    'certificate': cert
                }
        
        return {
            'success': False,
            'message': 'Certificate not found'
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to get certificate: {str(e)}'
        }


def get_expiring_certificates(days_threshold: int = 30) -> Dict:
    try:
        data = _load_monitored_certificates()
        
        expiring_certs = []
        now = datetime.utcnow()
        
        for cert in data['certificates']:
            not_after = datetime.fromisoformat(cert['not_after'].replace('Z', '+00:00'))
            now_tz = now.replace(tzinfo=not_after.tzinfo) if not_after.tzinfo else now
            days_until_expiry = (not_after - now_tz).days
            
            if 0 <= days_until_expiry <= days_threshold:
                cert_copy = cert.copy()
                cert_copy.pop('certificate_pem', None)
                cert_copy['days_until_expiry'] = days_until_expiry
                expiring_certs.append(cert_copy)
        
        expiring_certs.sort(key=lambda x: x['days_until_expiry'])
        
        return {
            'success': True,
            'count': len(expiring_certs),
            'days_threshold': days_threshold,
            'certificates': expiring_certs
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to get expiring certificates: {str(e)}'
        }


def update_monitored_certificate(certificate_id: str, label: str = None, tags: List[str] = None) -> Dict:
    try:
        data = _load_monitored_certificates()
        
        for cert in data['certificates']:
            if cert['id'] == certificate_id:
                if label is not None:
                    cert['label'] = label
                if tags is not None:
                    cert['tags'] = tags
                
                _save_monitored_certificates(data)
                
                return {
                    'success': True,
                    'message': 'Certificate updated',
                    'certificate': cert
                }
        
        return {
            'success': False,
            'message': 'Certificate not found'
        }
        
    except Exception as e:
        return {
            'success': False,
            'message': f'Failed to update certificate: {str(e)}'
        }
