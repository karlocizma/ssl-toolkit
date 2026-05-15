import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta

from app import create_app
from app.utils.ssl_utils import generate_csr


@pytest.fixture(scope='session')
def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope='session')
def sample_key_pem(_rsa_key):
    return _rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('utf-8')


@pytest.fixture(scope='session')
def sample_cert_pem(_rsa_key):
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Org'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(_rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName('test.example.com'),
                x509.DNSName('www.test.example.com'),
            ]),
            critical=False,
        )
        .sign(_rsa_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')


@pytest.fixture(scope='session')
def sample_csr_pem(_rsa_key):
    subject_data = {
        'common_name': 'test.example.com',
        'country': 'US',
        'organization': 'Test Org',
    }
    csr = generate_csr(subject_data, _rsa_key, ['test.example.com', 'www.test.example.com'])
    return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')


@pytest.fixture
def app():
    flask_app = create_app()
    flask_app.config.update({'TESTING': True})
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()
