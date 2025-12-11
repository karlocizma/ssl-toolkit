import socket
import ssl
from typing import List, Optional, Tuple

import OpenSSL
from OpenSSL import SSL, crypto

from app.utils.ssl_utils import get_certificate_info


def check_ssl_certificate(hostname, port=443, timeout=10):
    """Check SSL certificate for a given hostname and port"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    raise ValueError('Unable to retrieve certificate from remote host')

                cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                detailed_info = get_certificate_info(cert_pem)

                valid_for_hostname = check_hostname_validity(hostname, detailed_info)
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

    except ssl.CertificateError as e:
        return {
            'hostname': hostname,
            'port': port,
            'connection_secure': False,
            'errors': [f'Certificate verification failed: {str(e)}']
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
    except socket.gaierror as e:
        return {
            'hostname': hostname,
            'port': port,
            'connection_secure': False,
            'errors': [f'DNS resolution error: {str(e)}']
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
    common_name = cert_info.get('subject', {}).get('common_name')
    wildcard_domain = '*.' + hostname.split('.', 1)[-1] if '.' in hostname else ''
    if common_name and (common_name == hostname or common_name == wildcard_domain):
        return True

    san_list = cert_info.get('subject_alternative_names', [])
    for san in san_list:
        if san == hostname:
            return True
        if san.startswith('*.'):
            domain_part = san[2:]
            if hostname.endswith(domain_part) and hostname.count('.') == domain_part.count('.') + 1:
                return True

    return False


def check_certificate_chain(hostname, port=443, timeout=10):
    """Check the complete certificate chain"""
    try:
        context = SSL.Context(SSL.TLS_CLIENT_METHOD)
        context.set_verify(SSL.VERIFY_NONE, lambda *args: True)

        sock = socket.create_connection((hostname, port), timeout=timeout)
        ssl_conn = SSL.Connection(context, sock)

        try:
            ssl_conn.set_connect_state()
            ssl_conn.set_tlsext_host_name(hostname.encode())
            ssl_conn.do_handshake()

            cert_chain = ssl_conn.get_peer_cert_chain() or []
            chain_info = _serialize_certificate_chain(cert_chain)

            if not chain_info:
                fallback = _fetch_single_certificate(hostname, port, timeout)
                chain_info = [fallback] if fallback else []

            chain_valid, verification_error = _verify_chain(cert_chain)

        finally:
            try:
                ssl_conn.shutdown()
            except Exception:
                pass
            ssl_conn.close()
            sock.close()

        return {
            'hostname': hostname,
            'port': port,
            'chain_length': len(chain_info),
            'certificates': chain_info,
            'chain_valid': chain_valid,
            'verification_error': verification_error
        }

    except (socket.timeout, socket.gaierror) as e:
        return {
            'hostname': hostname,
            'port': port,
            'chain_valid': False,
            'error': str(e)
        }
    except OpenSSL.SSL.Error as e:
        return {
            'hostname': hostname,
            'port': port,
            'chain_valid': False,
            'error': f'OpenSSL error: {str(e)}'
        }
    except Exception as e:
        return {
            'hostname': hostname,
            'port': port,
            'chain_valid': False,
            'error': str(e)
        }


def _serialize_certificate_chain(cert_chain: List[crypto.X509]):
    chain_info = []
    total = len(cert_chain)

    for index, openssl_cert in enumerate(cert_chain):
        try:
            cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, openssl_cert).decode('utf-8')
            cert_info = get_certificate_info(cert_pem)
            cert_info['position'] = index
            cert_info['is_leaf'] = index == 0
            cert_info['is_root'] = _is_self_signed(openssl_cert) or index == total - 1
            cert_info['is_intermediate'] = not cert_info['is_leaf'] and not cert_info['is_root']
            chain_info.append(cert_info)
        except Exception:
            continue

    return chain_info


def _is_self_signed(cert: crypto.X509) -> bool:
    try:
        return cert.get_subject() == cert.get_issuer()
    except Exception:
        return False


def _verify_chain(cert_chain: List[crypto.X509]) -> Tuple[bool, Optional[str]]:
    if not cert_chain:
        return False, 'No certificates were returned by the remote service'

    store = crypto.X509Store()
    default_paths = ssl.get_default_verify_paths()

    cafile = getattr(default_paths, 'cafile', None)
    capath = getattr(default_paths, 'capath', None)

    try:
        if cafile or capath:
            store.load_locations(cafile=cafile or None, capath=capath or None)
    except Exception:
        # Continue even if default CA load fails
        pass

    for cert in cert_chain[1:]:
        try:
            store.add_cert(cert)
        except Exception:
            continue

    try:
        crypto.X509StoreContext(store, cert_chain[0]).verify_certificate()
        return True, None
    except crypto.X509StoreContextError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, str(exc)


def _fetch_single_certificate(hostname: str, port: int, timeout: int):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    return None
                cert_pem = ssl.DER_cert_to_PEM_cert(cert_der)
                cert_info = get_certificate_info(cert_pem)
                cert_info['position'] = 0
                cert_info['is_leaf'] = True
                cert_info['is_intermediate'] = False
                cert_info['is_root'] = True
                return cert_info
    except Exception:
        return None


def check_ssl_labs_rating(hostname):
    """Get SSL Labs rating for a domain (requires SSL Labs API)"""
    try:
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
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509 import ocsp as ocsp_module
        import requests
        
        cert = x509.load_pem_x509_certificate(certificate_pem.encode() if isinstance(certificate_pem, str) else certificate_pem, default_backend())
        
        ocsp_urls = []
        try:
            aia_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for desc in aia_ext.value:
                if desc.access_method == x509.OID_OCSP:
                    ocsp_urls.append(desc.access_location.value)
        except x509.ExtensionNotFound:
            return {
                'status': 'unavailable',
                'message': 'No OCSP URL found in certificate',
                'checked': False
            }
        
        if not ocsp_urls:
            return {
                'status': 'unavailable',
                'message': 'No OCSP responder URL found',
                'checked': False
            }
        
        ocsp_url = ocsp_urls[0]
        
        try:
            issuer_cert = _get_issuer_certificate(cert)
            if not issuer_cert:
                return {
                    'status': 'unknown',
                    'message': 'Could not obtain issuer certificate for OCSP request',
                    'ocsp_url': ocsp_url,
                    'checked': False
                }
            
            builder = ocsp_module.OCSPRequestBuilder()
            builder = builder.add_certificate(cert, issuer_cert, hashes.SHA256())
            ocsp_request = builder.build()
            
            ocsp_request_data = ocsp_request.public_bytes(serialization.Encoding.DER)
            
            response = requests.post(
                ocsp_url,
                data=ocsp_request_data,
                headers={'Content-Type': 'application/ocsp-request'},
                timeout=10
            )
            
            if response.status_code != 200:
                return {
                    'status': 'error',
                    'message': f'OCSP responder returned status code {response.status_code}',
                    'ocsp_url': ocsp_url,
                    'checked': False
                }
            
            ocsp_response = ocsp_module.load_der_ocsp_response(response.content)
            
            if ocsp_response.response_status != ocsp_module.OCSPResponseStatus.SUCCESSFUL:
                return {
                    'status': 'error',
                    'message': f'OCSP response status: {ocsp_response.response_status}',
                    'ocsp_url': ocsp_url,
                    'checked': False
                }
            
            cert_status = ocsp_response.certificate_status
            
            if cert_status == ocsp_module.OCSPCertStatus.GOOD:
                status_str = 'good'
                message = 'Certificate is not revoked'
            elif cert_status == ocsp_module.OCSPCertStatus.REVOKED:
                status_str = 'revoked'
                message = 'Certificate has been revoked'
                revocation_time = ocsp_response.revocation_time
                revocation_reason = ocsp_response.revocation_reason
                return {
                    'status': status_str,
                    'message': message,
                    'ocsp_url': ocsp_url,
                    'checked': True,
                    'revocation_time': revocation_time.isoformat() if revocation_time else None,
                    'revocation_reason': str(revocation_reason) if revocation_reason else None
                }
            else:
                status_str = 'unknown'
                message = 'Certificate status is unknown'
            
            return {
                'status': status_str,
                'message': message,
                'ocsp_url': ocsp_url,
                'checked': True,
                'produced_at': ocsp_response.produced_at.isoformat() if hasattr(ocsp_response, 'produced_at') and ocsp_response.produced_at else None,
                'this_update': ocsp_response.this_update.isoformat() if hasattr(ocsp_response, 'this_update') and ocsp_response.this_update else None,
                'next_update': ocsp_response.next_update.isoformat() if hasattr(ocsp_response, 'next_update') and ocsp_response.next_update else None
            }
            
        except requests.RequestException as e:
            return {
                'status': 'error',
                'message': f'Failed to connect to OCSP responder: {str(e)}',
                'ocsp_url': ocsp_url,
                'checked': False
            }
            
    except Exception as e:
        return {
            'status': 'error',
            'message': f'OCSP check failed: {str(e)}',
            'checked': False
        }


def _get_issuer_certificate(cert):
    """Attempt to retrieve issuer certificate from AIA extension"""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        import requests
        
        try:
            aia_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for desc in aia_ext.value:
                if desc.access_method == x509.OID_CA_ISSUERS:
                    issuer_url = desc.access_location.value
                    response = requests.get(issuer_url, timeout=10)
                    if response.status_code == 200:
                        try:
                            issuer_cert = x509.load_der_x509_certificate(response.content, default_backend())
                            return issuer_cert
                        except Exception:
                            issuer_cert = x509.load_pem_x509_certificate(response.content, default_backend())
                            return issuer_cert
        except x509.ExtensionNotFound:
            pass
        
        return None
        
    except Exception:
        return None


def check_crl_status(certificate_pem):
    """Check CRL status of a certificate"""
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        import requests
        
        cert = x509.load_pem_x509_certificate(certificate_pem.encode() if isinstance(certificate_pem, str) else certificate_pem, default_backend())
        
        crl_urls = []
        try:
            crl_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for dist_point in crl_ext.value:
                if dist_point.full_name:
                    for general_name in dist_point.full_name:
                        if isinstance(general_name, x509.UniformResourceIdentifier):
                            crl_urls.append(general_name.value)
        except x509.ExtensionNotFound:
            return {
                'status': 'unavailable',
                'message': 'No CRL distribution points found in certificate',
                'checked': False
            }
        
        if not crl_urls:
            return {
                'status': 'unavailable',
                'message': 'No CRL URLs found',
                'checked': False
            }
        
        cert_serial = cert.serial_number
        
        for crl_url in crl_urls[:3]:
            try:
                response = requests.get(crl_url, timeout=15)
                if response.status_code != 200:
                    continue
                
                try:
                    crl = x509.load_der_x509_crl(response.content, default_backend())
                except Exception:
                    crl = x509.load_pem_x509_crl(response.content, default_backend())
                
                for revoked_cert in crl:
                    if revoked_cert.serial_number == cert_serial:
                        return {
                            'status': 'revoked',
                            'message': 'Certificate has been revoked',
                            'crl_url': crl_url,
                            'checked': True,
                            'revocation_date': revoked_cert.revocation_date.isoformat(),
                            'revocation_reason': str(revoked_cert.extensions.get_extension_for_class(x509.CRLReason).value.reason) if revoked_cert.extensions else None
                        }
                
                return {
                    'status': 'good',
                    'message': 'Certificate is not in the revocation list',
                    'crl_url': crl_url,
                    'checked': True,
                    'last_update': crl.last_update.isoformat() if hasattr(crl, 'last_update') and crl.last_update else None,
                    'next_update': crl.next_update.isoformat() if hasattr(crl, 'next_update') and crl.next_update else None
                }
                
            except requests.RequestException:
                continue
            except Exception:
                continue
        
        return {
            'status': 'error',
            'message': 'Failed to retrieve or parse CRL from all distribution points',
            'crl_urls': crl_urls,
            'checked': False
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': f'CRL check failed: {str(e)}',
            'checked': False
        }
