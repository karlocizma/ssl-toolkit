"""Stateless mini private CA: create a root CA and issue server/client certificates.

Nothing is stored server-side. The caller keeps the CA key and sends it with each
issue request, matching how the other generators in this toolkit return keys.
"""
import base64
import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.utils.ssl_utils import generate_private_key, get_certificate_info

MAX_CA_DAYS = 7300     # 20 years
MAX_LEAF_DAYS = 825    # longest validity macOS/iOS still accept for TLS server certs
MAX_SANS = 100
BACKDATE = timedelta(minutes=5)  # tolerate small clock skew on clients


def _name(params: Dict, common_name: str) -> x509.Name:
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    for key, oid in (('country', NameOID.COUNTRY_NAME), ('state', NameOID.STATE_OR_PROVINCE_NAME),
                     ('locality', NameOID.LOCALITY_NAME), ('organization', NameOID.ORGANIZATION_NAME),
                     ('organizational_unit', NameOID.ORGANIZATIONAL_UNIT_NAME)):
        if params.get(key):
            attrs.append(x509.NameAttribute(oid, params[key]))
    return x509.Name(attrs)


def _int_in_range(params: Dict, key: str, default: int, low: int, high: int) -> int:
    try:
        value = int(params.get(key, default))
    except (TypeError, ValueError):
        raise ValueError(f'{key} must be an integer')
    if not low <= value <= high:
        raise ValueError(f'{key} must be between {low} and {high}')
    return value


def _pem_key(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _pem_cert(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _validity(cert: x509.Certificate):
    # *_utc accessors only exist in cryptography >= 42
    before = getattr(cert, 'not_valid_before_utc', None) or cert.not_valid_before.replace(tzinfo=timezone.utc)
    after = getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    return before, after


def _sign_hash(key):
    return hashes.SHA384() if isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.key_size > 256 else hashes.SHA256()


def create_ca(params: Dict) -> Dict:
    params = params or {}
    common_name = (params.get('common_name') or '').strip()
    if not common_name:
        raise ValueError('common_name is required')
    days = _int_in_range(params, 'validity_days', 3650, 1, MAX_CA_DAYS)

    key = generate_private_key(params.get('key_type', 'RSA'), params.get('key_size', 4096),
                               params.get('curve_name', 'secp384r1'))
    name = _name(params, common_name)
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - BACKDATE)
        .not_valid_after(now + timedelta(days=days))
        # path_length=0: this CA signs end-entity certificates only
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                     content_commitment=False, key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, _sign_hash(key))
    )
    pem = _pem_cert(cert)
    return {'success': True, 'ca_certificate_pem': pem, 'ca_private_key_pem': _pem_key(key),
            'certificate_info': get_certificate_info(pem),
            'warning': 'Store the CA private key offline. It is not kept on this server.'}


def _load_ca(cert_pem: str, key_pem: str, password: Optional[str]):
    try:
        ca_cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception:
        raise ValueError('ca_certificate is not a valid PEM certificate')
    try:
        ca_key = serialization.load_pem_private_key(key_pem.encode(), password.encode() if password else None)
    except Exception:
        raise ValueError('ca_private_key is invalid or the password is wrong')

    try:
        bc = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        bc = None
    if not bc or not bc.ca:
        raise ValueError('Supplied certificate is not a CA certificate')
    pub = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)  # noqa: E731
    if pub(ca_key.public_key()) != pub(ca_cert.public_key()):
        raise ValueError('CA private key does not match the CA certificate')
    before, after = _validity(ca_cert)
    if after < datetime.now(timezone.utc):
        raise ValueError('CA certificate has expired')
    return ca_cert, ca_key, after


def _parse_sans(sans: Optional[List[str]], common_name: str) -> List[x509.GeneralName]:
    entries = [s.strip() for s in (sans or []) if isinstance(s, str) and s.strip()]
    if len(entries) > MAX_SANS:
        raise ValueError(f'At most {MAX_SANS} SANs are allowed')
    if common_name and common_name not in entries:
        entries.insert(0, common_name)  # modern clients ignore the CN; always mirror it into the SANs
    names = []
    for entry in entries:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            names.append(x509.DNSName(entry))
    return names


def issue_certificate(params: Dict) -> Dict:
    params = params or {}
    for field in ('ca_certificate', 'ca_private_key'):
        if not params.get(field):
            raise ValueError(f'{field} is required')
    ca_cert, ca_key, ca_expiry = _load_ca(params['ca_certificate'], params['ca_private_key'],
                                          params.get('ca_key_password'))

    usage = params.get('usage', 'server')
    if usage not in ('server', 'client', 'both'):
        raise ValueError("usage must be 'server', 'client' or 'both'")
    days = _int_in_range(params, 'validity_days', 365, 1, MAX_LEAF_DAYS)
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=days)
    if not_after > ca_expiry:
        raise ValueError('Requested validity extends beyond the CA certificate expiry')

    generated_key = None
    if params.get('csr'):
        try:
            csr = x509.load_pem_x509_csr(params['csr'].encode())
        except Exception:
            raise ValueError('csr is not a valid PEM certificate request')
        if not csr.is_signature_valid:
            raise ValueError('CSR signature is invalid')
        leaf_public = csr.public_key()
        common_name = params.get('common_name') or next(
            (a.value for a in csr.subject if a.oid == NameOID.COMMON_NAME), '')
        subject = csr.subject if not params.get('common_name') else _name(params, common_name)
        csr_sans = []
        try:
            csr_sans = [n.value for n in csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value]
        except x509.ExtensionNotFound:
            pass
        sans = params.get('sans') or [str(v) for v in csr_sans]
    else:
        common_name = (params.get('common_name') or '').strip()
        if not common_name:
            raise ValueError('common_name (or a csr) is required')
        generated_key = generate_private_key(params.get('key_type', 'RSA'), params.get('key_size', 2048),
                                             params.get('curve_name', 'secp256r1'))
        leaf_public = generated_key.public_key()
        subject = _name(params, common_name)
        sans = params.get('sans')

    ekus = []
    if usage in ('server', 'both'):
        ekus.append(ExtendedKeyUsageOID.SERVER_AUTH)
    if usage in ('client', 'both'):
        ekus.append(ExtendedKeyUsageOID.CLIENT_AUTH)

    is_rsa = isinstance(leaf_public, rsa.RSAPublicKey)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(ca_cert.subject)
        .public_key(leaf_public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - BACKDATE)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=is_rsa, content_commitment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage(ekus), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_public), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
    )
    san_names = _parse_sans(sans, common_name if usage in ('server', 'both') else '')
    if san_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_names), critical=False)
    cert = builder.sign(ca_key, _sign_hash(ca_key))

    cert_pem, ca_pem = _pem_cert(cert), _pem_cert(ca_cert)
    result = {'success': True, 'certificate_pem': cert_pem, 'ca_certificate_pem': ca_pem,
              'fullchain_pem': cert_pem + ca_pem, 'certificate_info': get_certificate_info(cert_pem)}
    if generated_key is not None:
        result['private_key_pem'] = _pem_key(generated_key)
        password = params.get('pkcs12_password')
        if password:
            bundle = pkcs12.serialize_key_and_certificates(
                (common_name or 'certificate').encode(), generated_key, cert, [ca_cert],
                serialization.BestAvailableEncryption(password.encode()))
            result['pkcs12_base64'] = base64.b64encode(bundle).decode()
    return result
