from flask import Blueprint, request, jsonify, send_file
from werkzeug.utils import secure_filename
import os
import tempfile
import base64
from cryptography.hazmat.primitives import serialization

from app.utils.ssl_utils import (
    get_certificate_info, get_csr_info, generate_private_key, 
    generate_csr, convert_certificate_format, validate_private_key,
    check_key_certificate_match, clean_pem_data
)
from app.services.ssl_checker import (
    check_ssl_certificate, check_certificate_chain, 
    check_ssl_labs_rating, check_ocsp_status, check_crl_status
)

ssl_bp = Blueprint('ssl', __name__)

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

