import socket
import ssl
import requests
from datetime import datetime
from urllib.parse import urlparse
import dns.resolver
from app.utils.ssl_utils import get_certificate_info

def check_ssl_certificate(hostname, port=443, timeout=10):
    """Check SSL certificate for a given hostname and port"""
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect to the server
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate
                cert_der = ssock.getpeercert(binary_form=True)
                cert_info = ssock.getpeercert()
                
                # Convert DER to PEM
                import base64
                cert_pem = '-----BEGIN CERTIFICATE-----\n'
                cert_pem += base64.b64encode(cert_der).decode('utf-8')
                # Add line breaks every 64 characters
                cert_pem = '\n'.join([cert_pem[i:i+64] for i in range(25, len(cert_pem), 64)])
                cert_pem += '\n-----END CERTIFICATE-----'
                
                # Get detailed certificate info
                detailed_info = get_certificate_info(cert_pem)
                
                # Check if certificate is valid for the hostname
                valid_for_hostname = check_hostname_validity(hostname, detailed_info)
                
                # Get SSL/TLS version and cipher
                ssl_version = ssock.version()
                cipher = ssock.cipher()
                
                return {
                    'hostname': hostname,
                    'port': port,
                    'certificate': detailed_info,
                    'ssl_version': ssl_version,
                    'cipher': {
                        'name': cipher[0] if cipher else None,
                        'version': cipher[1] if cipher else None,
                        'bits': cipher[2] if cipher else None
                    },
                    'valid_for_hostname': valid_for_hostname,
                    'connection_secure': True,
                    'errors': []
                }
    
    except ssl.SSLError as e:
        return {
            'hostname': hostname,
            'port': port,
            'connection_secure': False,
            'errors': [f'SSL Error: {str(e)}']
        }
    except socket.timeout:
        return {
            'hostname': hostname,
            'port': port,
            'connection_secure': False,
            'errors': ['Connection timeout']
        }
    except Exception as e:
        return {
            'hostname': hostname,
            'port': port,
            'connection_secure': False,
            'errors': [f'Error: {str(e)}']
        }

def check_hostname_validity(hostname, cert_info):
    """Check if certificate is valid for the given hostname"""
    # Check common name
    common_name = cert_info.get('subject', {}).get('common_name')
    if common_name and (common_name == hostname or common_name == f'*.{hostname.split(".", 1)[-1]}'):
        return True
    
    # Check Subject Alternative Names
    san_list = cert_info.get('subject_alternative_names', [])
    for san in san_list:
        if san == hostname:
            return True
        # Check wildcard
        if san.startswith('*.'):
            domain_part = san[2:]
            if hostname.endswith(domain_part) and hostname.count('.') == domain_part.count('.') + 1:
                return True
    
    return False

def check_certificate_chain(hostname, port=443, timeout=10):
    """Check the complete certificate chain"""
    try:
        import OpenSSL
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        
        # Create OpenSSL context and connection
        openssl_context = OpenSSL.SSL.Context(OpenSSL.SSL.TLS_METHOD)
        openssl_context.set_verify(OpenSSL.SSL.VERIFY_NONE, lambda conn, cert, errno, depth, ok: True)
        
        # Connect and get certificate chain
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            # Create OpenSSL connection
            openssl_sock = OpenSSL.SSL.Connection(openssl_context, sock)
            openssl_sock.set_connect_state()
            openssl_sock.set_tlsext_host_name(hostname.encode())
            openssl_sock.do_handshake()
            
            # Get the certificate chain
            cert_chain = openssl_sock.get_peer_cert_chain()
            
            chain_info = []
            
            if cert_chain:
                for i, openssl_cert in enumerate(cert_chain):
                    try:
                        # Convert OpenSSL cert to PEM directly
                        cert_pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, openssl_cert).decode('utf-8')
                        
                        # Get certificate info
                        cert_info = get_certificate_info(cert_pem)
                        cert_info['position'] = i
                        cert_info['is_root'] = i == len(cert_chain) - 1
                        cert_info['is_intermediate'] = 0 < i < len(cert_chain) - 1
                        cert_info['is_leaf'] = i == 0
                        
                        chain_info.append(cert_info)
                    except Exception as cert_error:
                        # Skip problematic certificates but continue with others
                        continue
            else:
                # Fallback: get single certificate using standard SSL
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, port), timeout=timeout) as fallback_sock:
                    with context.wrap_socket(fallback_sock, server_hostname=hostname) as ssock:
                        cert_der = ssock.getpeercert(binary_form=True)
                        crypto_cert = x509.load_der_x509_certificate(cert_der)
                        cert_pem = crypto_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
                        
                        cert_info = get_certificate_info(cert_pem)
                        cert_info['position'] = 0
                        cert_info['is_root'] = True
                        cert_info['is_intermediate'] = False
                        cert_info['is_leaf'] = True
                        
                        chain_info = [cert_info]
            
            openssl_sock.close()
            
            return {
                'hostname': hostname,
                'port': port,
                'chain_length': len(chain_info),
                'certificates': chain_info,
                'chain_valid': len(chain_info) > 0
            }
    
    except Exception as e:
        return {
            'hostname': hostname,
            'port': port,
            'chain_valid': False,
            'error': str(e)
        }

def check_ssl_labs_rating(hostname):
    """Get SSL Labs rating for a domain (requires SSL Labs API)"""
    try:
        # This is a simplified version - in production, you'd use the full SSL Labs API
        # For now, we'll return a placeholder
        return {
            'hostname': hostname,
            'rating': 'API not implemented',
            'note': 'SSL Labs API integration would be implemented here'
        }
    except Exception as e:
        return {
            'hostname': hostname,
            'error': str(e)
        }

def check_ocsp_status(certificate_pem):
    """Check OCSP status of a certificate"""
    try:
        # This is a placeholder for OCSP checking
        # In production, you'd implement actual OCSP checking
        return {
            'status': 'Not implemented',
            'note': 'OCSP checking would be implemented here'
        }
    except Exception as e:
        return {
            'error': str(e)
        }

def check_crl_status(certificate_pem):
    """Check CRL status of a certificate"""
    try:
        # This is a placeholder for CRL checking
        # In production, you'd implement actual CRL checking
        return {
            'status': 'Not implemented',
            'note': 'CRL checking would be implemented here'
        }
    except Exception as e:
        return {
            'error': str(e)
        }

