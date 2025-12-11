from flask import Blueprint, request, jsonify, send_file, current_app
from werkzeug.utils import secure_filename
import os
import tempfile
import base64
from cryptography.hazmat.primitives import serialization
from functools import wraps

from app.utils.ssl_utils import (
    get_certificate_info, get_csr_info, generate_private_key, 
    generate_csr, convert_certificate_format, validate_private_key,
    check_key_certificate_match, clean_pem_data
)
from app.services.ssl_checker import (
    check_ssl_certificate, check_certificate_chain, 
    check_ssl_labs_rating, check_ocsp_status, check_crl_status
)
from app.services.sysadmin_tools import (
    generate_dmarc_record, validate_dmarc_record,
    generate_spf_record, validate_spf_record,
    analyze_email_headers, generate_password_bundle,
    lookup_dns_records
)

ssl_bp = Blueprint('ssl', __name__)

def rate_limit(limit_string):
    """Decorator to apply custom rate limiting to specific routes"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        
        if hasattr(current_app, 'limiter'):
            decorated_function = current_app.limiter.limit(limit_string)(decorated_function)
        
        return decorated_function
    return decorator

@ssl_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'SSL Toolkit API'})

# Certificate Analysis Routes
@ssl_bp.route('/certificate/decode', methods=['POST'])
def decode_certificate():
    """Decode and analyze an SSL certificate"""
    try:
        data = request.get_json()
        
        if 'certificate' not in data:
            return jsonify({'error': 'Certificate data is required'}), 400
        
        cert_data = data['certificate']
        
        # Basic validation
        if not cert_data or not cert_data.strip():
            return jsonify({'error': 'Certificate data cannot be empty'}), 400
        
        # Check for basic PEM structure
        cert_data_str = cert_data.strip()
        if not (cert_data_str.startswith('-----BEGIN CERTIFICATE-----') and 
                cert_data_str.endswith('-----END CERTIFICATE-----')):
            return jsonify({
                'error': 'Invalid certificate format. Certificate must be in PEM format with proper BEGIN/END markers.'
            }), 400
        
        cert_info = get_certificate_info(cert_data)
        
        return jsonify({
            'success': True,
            'certificate_info': cert_info
        })
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500

@ssl_bp.route('/certificate/fingerprint', methods=['POST'])
def get_certificate_fingerprint():
    """Get certificate fingerprints"""
    try:
        data = request.get_json()
        
        if 'certificate' not in data:
            return jsonify({'error': 'Certificate data is required'}), 400
        
        cert_data = data['certificate']
        cert_info = get_certificate_info(cert_data)
        
        return jsonify({
            'success': True,
            'fingerprints': cert_info['fingerprints']
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# CSR Routes
@ssl_bp.route('/csr/generate', methods=['POST'])
def generate_certificate_request():
    """Generate a Certificate Signing Request"""
    try:
        data = request.get_json()
        
        # Validate required fields
        if 'subject' not in data:
            return jsonify({'error': 'Subject information is required'}), 400
        
        subject_data = data['subject']
        key_type = data.get('key_type', 'RSA')
        key_size = data.get('key_size', 2048)
        curve_name = data.get('curve_name', 'secp256r1')
        san_list = data.get('subject_alternative_names', [])
        
        # Generate private key
        private_key = generate_private_key(key_type, key_size, curve_name)
        
        # Generate CSR
        csr = generate_csr(subject_data, private_key, san_list)
        
        # Convert to PEM format
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        return jsonify({
            'success': True,
            'csr': csr_pem,
            'private_key': private_key_pem,
            'subject_info': subject_data
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@ssl_bp.route('/csr/decode', methods=['POST'])
def decode_csr():
    """Decode and analyze a Certificate Signing Request"""
    try:
        data = request.get_json()
        
        if 'csr' not in data:
            return jsonify({'error': 'CSR data is required'}), 400
        
        csr_data = data['csr']
        csr_info = get_csr_info(csr_data)
        
        return jsonify({
            'success': True,
            'csr_info': csr_info
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Key Management Routes
@ssl_bp.route('/key/generate', methods=['POST'])
def generate_key():
    """Generate a private key"""
    try:
        data = request.get_json()
        
        key_type = data.get('key_type', 'RSA')
        key_size = data.get('key_size', 2048)
        curve_name = data.get('curve_name', 'secp256r1')
        
        # Generate private key
        private_key = generate_private_key(key_type, key_size, curve_name)
        
        # Convert to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        return jsonify({
            'success': True,
            'private_key': private_key_pem,
            'key_type': key_type,
            'key_size': key_size if key_type == 'RSA' else None,
            'curve': curve_name if key_type == 'EC' else None
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@ssl_bp.route('/key/validate', methods=['POST'])
def validate_key():
    """Validate a private key"""
    try:
        data = request.get_json()
        
        if 'private_key' not in data:
            return jsonify({'error': 'Private key data is required'}), 400
        
        key_data = data['private_key']
        password = data.get('password')
        
        key_info = validate_private_key(key_data, password)
        
        return jsonify({
            'success': True,
            'key_info': key_info
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@ssl_bp.route('/key/match-certificate', methods=['POST'])
def match_key_certificate():
    """Check if a private key matches a certificate"""
    try:
        data = request.get_json()
        
        if 'private_key' not in data or 'certificate' not in data:
            return jsonify({'error': 'Both private key and certificate are required'}), 400
        
        private_key_data = data['private_key']
        certificate_data = data['certificate']
        key_password = data.get('key_password')
        
        matches = check_key_certificate_match(private_key_data, certificate_data, key_password)
        
        return jsonify({
            'success': True,
            'matches': matches
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Conversion Routes
@ssl_bp.route('/convert', methods=['POST'])
def convert_certificate():
    """Convert certificate between different formats"""
    try:
        data = request.get_json()
        
        if 'certificate_data' not in data:
            return jsonify({'error': 'Certificate data is required'}), 400
        
        cert_data = data['certificate_data']
        input_format = data.get('input_format', 'PEM')
        output_format = data.get('output_format', 'DER')
        password = data.get('password')
        private_key_data = data.get('private_key_data')  # For PEM to PFX conversion
        
        # Handle base64 encoded data
        if data.get('is_base64', False):
            cert_data = base64.b64decode(cert_data)
        elif isinstance(cert_data, str):
            cert_data = cert_data.encode('utf-8')
        
        converted_data = convert_certificate_format(
            cert_data, input_format, output_format, password, private_key_data
        )
        
        # Convert to base64 for JSON response if binary
        if output_format.upper() in ['DER', 'PFX']:
            converted_data = base64.b64encode(converted_data).decode('utf-8')
            is_base64 = True
        else:
            converted_data = converted_data.decode('utf-8') if isinstance(converted_data, bytes) else converted_data
            is_base64 = False
        
        return jsonify({
            'success': True,
            'converted_data': converted_data,
            'input_format': input_format,
            'output_format': output_format,
            'is_base64': is_base64
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# SSL Checker Routes
@ssl_bp.route('/check/domain', methods=['POST'])
def check_domain_ssl():
    """Check SSL certificate for a domain"""
    try:
        data = request.get_json()
        
        if 'hostname' not in data:
            return jsonify({'error': 'Hostname is required'}), 400
        
        hostname = data['hostname']
        port = data.get('port', 443)
        timeout = data.get('timeout', 10)
        
        result = check_ssl_certificate(hostname, port, timeout)
        
        return jsonify({
            'success': True,
            'result': result
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@ssl_bp.route('/check/chain', methods=['POST'])
def check_domain_chain():
    """Check SSL certificate chain for a domain"""
    try:
        data = request.get_json()
        
        if 'hostname' not in data:
            return jsonify({'error': 'Hostname is required'}), 400
        
        hostname = data['hostname']
        port = data.get('port', 443)
        timeout = data.get('timeout', 10)
        
        result = check_certificate_chain(hostname, port, timeout)
        
        return jsonify({
            'success': True,
            'result': result
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@ssl_bp.route('/check/ssl-labs', methods=['POST'])
def check_ssl_labs():
    """Get SSL Labs rating for a domain"""
    try:
        data = request.get_json()
        
        if 'hostname' not in data:
            return jsonify({'error': 'Hostname is required'}), 400
        
        hostname = data['hostname']
        result = check_ssl_labs_rating(hostname)
        
        return jsonify({
            'success': True,
            'result': result
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@ssl_bp.route('/check/ocsp', methods=['POST'])
def check_ocsp():
    """Check OCSP status of a certificate"""
    try:
        data = request.get_json()
        
        if 'certificate' not in data:
            return jsonify({'error': 'Certificate data is required'}), 400
        
        certificate = data['certificate']
        result = check_ocsp_status(certificate)
        
        return jsonify({
            'success': True,
            'result': result
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@ssl_bp.route('/check/crl', methods=['POST'])
def check_crl():
    """Check CRL status of a certificate"""
    try:
        data = request.get_json()
        
        if 'certificate' not in data:
            return jsonify({'error': 'Certificate data is required'}), 400
        
        certificate = data['certificate']
        result = check_crl_status(certificate)
        
        return jsonify({
            'success': True,
            'result': result
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# File Upload Routes
@ssl_bp.route('/upload/certificate', methods=['POST'])
def upload_certificate():
    """Upload and analyze a certificate file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file content
        file_content = file.read().decode('utf-8')
        
        # Analyze certificate
        cert_info = get_certificate_info(file_content)
        
        return jsonify({
            'success': True,
            'filename': secure_filename(file.filename),
            'certificate_info': cert_info
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@ssl_bp.route('/upload/csr', methods=['POST'])
def upload_csr():
    """Upload and analyze a CSR file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file content
        file_content = file.read().decode('utf-8')
        
        # Analyze CSR
        csr_info = get_csr_info(file_content)
        
        return jsonify({
            'success': True,
            'filename': secure_filename(file.filename),
            'csr_info': csr_info
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


# DMARC and SPF Routes
@ssl_bp.route('/dmarc/generate', methods=['POST'])
def dmarc_generate():
    """Generate a DMARC record recommendation"""
    try:
        data = request.get_json() or {}
        result = generate_dmarc_record(data)
        return jsonify({'success': True, 'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500


@ssl_bp.route('/dmarc/validate', methods=['POST'])
def dmarc_validate():
    """Validate an existing DMARC record"""
    try:
        data = request.get_json() or {}
        result = validate_dmarc_record(data)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/spf/generate', methods=['POST'])
def spf_generate():
    """Generate an SPF record"""
    try:
        data = request.get_json() or {}
        result = generate_spf_record(data)
        return jsonify({'success': True, 'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500


@ssl_bp.route('/spf/validate', methods=['POST'])
def spf_validate():
    """Validate an SPF record"""
    try:
        data = request.get_json() or {}
        result = validate_spf_record(data)
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# Email Header Analysis
@ssl_bp.route('/email/header/analyze', methods=['POST'])
def analyze_headers():
    """Analyze raw email headers"""
    try:
        data = request.get_json() or {}
        result = analyze_email_headers(data)
        return jsonify({'success': True, 'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500


# Password utility
@ssl_bp.route('/security/password/generate', methods=['POST'])
def password_generate():
    """Generate a password with hashing/encryption details"""
    try:
        data = request.get_json() or {}
        result = generate_password_bundle(data)
        return jsonify({'success': True, 'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500


# DNS diagnostics
@ssl_bp.route('/dns/lookup', methods=['POST'])
def dns_lookup():
    """Lookup DNS records for a domain"""
    try:
        data = request.get_json() or {}
        result = lookup_dns_records(data)
        return jsonify({'success': True, 'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500


# Certificate Monitoring Routes
@ssl_bp.route('/monitor/certificate/add', methods=['POST'])
def add_certificate_to_monitor():
    """Add a certificate to monitoring"""
    try:
        from app.services.cert_monitor import add_monitored_certificate
        
        data = request.get_json()
        
        if 'certificate' not in data:
            return jsonify({'error': 'Certificate data is required'}), 400
        
        certificate = data['certificate']
        label = data.get('label')
        tags = data.get('tags', [])
        
        result = add_monitored_certificate(certificate, label, tags)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/monitor/certificate/remove/<certificate_id>', methods=['DELETE'])
def remove_certificate_from_monitor(certificate_id):
    """Remove a certificate from monitoring"""
    try:
        from app.services.cert_monitor import remove_monitored_certificate
        
        result = remove_monitored_certificate(certificate_id)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/monitor/certificate/list', methods=['GET'])
def list_monitored_certificates():
    """List all monitored certificates"""
    try:
        from app.services.cert_monitor import list_monitored_certificates
        
        include_pem = request.args.get('include_pem', 'false').lower() == 'true'
        
        result = list_monitored_certificates(include_certificate_pem=include_pem)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/monitor/certificate/<certificate_id>', methods=['GET'])
def get_monitored_certificate_details(certificate_id):
    """Get details of a monitored certificate"""
    try:
        from app.services.cert_monitor import get_monitored_certificate
        
        result = get_monitored_certificate(certificate_id)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/monitor/certificate/<certificate_id>', methods=['PATCH'])
def update_monitored_certificate_info(certificate_id):
    """Update monitored certificate metadata"""
    try:
        from app.services.cert_monitor import update_monitored_certificate
        
        data = request.get_json()
        label = data.get('label')
        tags = data.get('tags')
        
        result = update_monitored_certificate(certificate_id, label, tags)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/monitor/expiring', methods=['GET'])
def get_expiring_certificates():
    """Get certificates expiring soon"""
    try:
        from app.services.cert_monitor import get_expiring_certificates
        
        days_threshold = int(request.args.get('days', 30))
        
        result = get_expiring_certificates(days_threshold)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# Batch Processing Routes
@ssl_bp.route('/batch/certificates/decode', methods=['POST'])
def batch_decode_certificates():
    """Decode multiple certificates at once"""
    try:
        from app.services.batch_processor import process_certificates_batch
        
        data = request.get_json()
        
        if 'certificates' not in data:
            return jsonify({'error': 'Certificates array is required'}), 400
        
        certificates = data['certificates']
        
        if not isinstance(certificates, list):
            return jsonify({'error': 'Certificates must be an array'}), 400
        
        if len(certificates) > 50:
            return jsonify({'error': 'Maximum 50 certificates allowed per batch'}), 400
        
        operations = data.get('operations', ['decode'])
        
        result = process_certificates_batch(certificates, operations)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/batch/domains/check', methods=['POST'])
def batch_check_domains():
    """Check SSL for multiple domains at once"""
    try:
        from app.services.batch_processor import check_domains_batch
        
        data = request.get_json()
        
        if 'domains' not in data:
            return jsonify({'error': 'Domains array is required'}), 400
        
        domains = data['domains']
        
        if not isinstance(domains, list):
            return jsonify({'error': 'Domains must be an array'}), 400
        
        if len(domains) > 20:
            return jsonify({'error': 'Maximum 20 domains allowed per batch'}), 400
        
        max_workers = min(int(data.get('max_workers', 5)), 10)
        timeout = min(int(data.get('timeout', 10)), 30)
        
        result = check_domains_batch(domains, max_workers, timeout)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/batch/ocsp/check', methods=['POST'])
def batch_check_ocsp():
    """Check OCSP status for multiple certificates"""
    try:
        from app.services.batch_processor import batch_ocsp_check
        
        data = request.get_json()
        
        if 'certificates' not in data:
            return jsonify({'error': 'Certificates array is required'}), 400
        
        certificates = data['certificates']
        
        if not isinstance(certificates, list):
            return jsonify({'error': 'Certificates must be an array'}), 400
        
        if len(certificates) > 30:
            return jsonify({'error': 'Maximum 30 certificates allowed per batch'}), 400
        
        max_workers = min(int(data.get('max_workers', 5)), 10)
        
        result = batch_ocsp_check(certificates, max_workers)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/batch/crl/check', methods=['POST'])
def batch_check_crl():
    """Check CRL status for multiple certificates"""
    try:
        from app.services.batch_processor import batch_crl_check
        
        data = request.get_json()
        
        if 'certificates' not in data:
            return jsonify({'error': 'Certificates array is required'}), 400
        
        certificates = data['certificates']
        
        if not isinstance(certificates, list):
            return jsonify({'error': 'Certificates must be an array'}), 400
        
        if len(certificates) > 20:
            return jsonify({'error': 'Maximum 20 certificates allowed per batch'}), 400
        
        max_workers = min(int(data.get('max_workers', 3)), 5)
        
        result = batch_crl_check(certificates, max_workers)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


# API Key Management Routes
@ssl_bp.route('/admin/apikey/generate', methods=['POST'])
def generate_new_api_key():
    """Generate a new API key"""
    try:
        from app.services.api_key_manager import generate_api_key
        
        data = request.get_json()
        
        if 'name' not in data:
            return jsonify({'error': 'API key name is required'}), 400
        
        name = data['name']
        rate_limit = data.get('rate_limit', '200 per hour')
        description = data.get('description')
        
        result = generate_api_key(name, rate_limit, description)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/admin/apikey/list', methods=['GET'])
def list_all_api_keys():
    """List all API keys"""
    try:
        from app.services.api_key_manager import list_api_keys
        
        include_keys = request.args.get('include_keys', 'false').lower() == 'true'
        
        result = list_api_keys(include_keys=include_keys)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 400
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/admin/apikey/revoke', methods=['POST'])
def revoke_existing_api_key():
    """Revoke an API key"""
    try:
        from app.services.api_key_manager import revoke_api_key
        
        data = request.get_json()
        
        if 'api_key' not in data:
            return jsonify({'error': 'API key is required'}), 400
        
        api_key = data['api_key']
        
        result = revoke_api_key(api_key)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/admin/apikey/delete', methods=['DELETE'])
def delete_existing_api_key():
    """Delete an API key"""
    try:
        from app.services.api_key_manager import delete_api_key
        
        data = request.get_json()
        
        if 'api_key' not in data:
            return jsonify({'error': 'API key is required'}), 400
        
        api_key = data['api_key']
        
        result = delete_api_key(api_key)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@ssl_bp.route('/admin/apikey/validate', methods=['POST'])
def validate_existing_api_key():
    """Validate an API key"""
    try:
        from app.services.api_key_manager import validate_api_key
        
        data = request.get_json()
        
        if 'api_key' not in data:
            return jsonify({'error': 'API key is required'}), 400
        
        api_key = data['api_key']
        
        result = validate_api_key(api_key)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 400

