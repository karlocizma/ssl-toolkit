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
    if common_name and (common_name == hostname or common_name == f'*.{hostname.split('.', 1)[-1]}'):
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
        return {
            'status': 'Not implemented',
            'note': 'CRL checking would be implemented here'
        }
    except Exception as e:
        return {
            'error': str(e)
        }
