import base64

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID
from OpenSSL import crypto

from app.services import private_ca as ca


@pytest.fixture(scope='module')
def root():
    return ca.create_ca({'common_name': 'Test Root CA', 'organization': 'Test', 'key_size': 2048})


def issue(root, **kw):
    return ca.issue_certificate({'ca_certificate': root['ca_certificate_pem'],
                                 'ca_private_key': root['ca_private_key_pem'], **kw})


def load(pem):
    return x509.load_pem_x509_certificate(pem.encode())


def verify_chain(leaf_pem, ca_pem):
    store = crypto.X509Store()
    store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, ca_pem))
    crypto.X509StoreContext(store, crypto.load_certificate(crypto.FILETYPE_PEM, leaf_pem)).verify_certificate()


def test_create_ca_is_constrained_ca(root):
    cert = load(root['ca_certificate_pem'])
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca and bc.value.path_length == 0
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign and ku.crl_sign


def test_issued_server_cert_chains_to_ca(root):
    r = issue(root, common_name='app.internal', sans=['www.internal', '10.1.2.3'])
    verify_chain(r['certificate_pem'], root['ca_certificate_pem'])
    cert = load(r['certificate_pem'])
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert 'app.internal' in sans.get_values_for_type(x509.DNSName)  # CN mirrored
    assert [str(i) for i in sans.get_values_for_type(x509.IPAddress)] == ['10.1.2.3']
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert r['fullchain_pem'].count('BEGIN CERTIFICATE') == 2 and 'PRIVATE KEY' in r['private_key_pem']


def test_client_cert_has_no_dns_san(root):
    cert = load(issue(root, common_name='alice', usage='client')['certificate_pem'])
    assert list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [
        ExtendedKeyUsageOID.CLIENT_AUTH]
    with pytest.raises(x509.ExtensionNotFound):
        cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)


def test_issue_from_csr_keeps_customer_key(root, sample_csr_pem):
    r = issue(root, csr=sample_csr_pem)
    assert 'private_key_pem' not in r
    verify_chain(r['certificate_pem'], root['ca_certificate_pem'])
    sans = load(r['certificate_pem']).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert 'www.test.example.com' in sans.get_values_for_type(x509.DNSName)


def test_pkcs12_export(root):
    r = issue(root, common_name='p12.internal', pkcs12_password='s3cret')
    key, cert, extra = pkcs12.load_key_and_certificates(base64.b64decode(r['pkcs12_base64']), b's3cret')
    assert key is not None and cert.subject == load(r['certificate_pem']).subject and len(extra) == 1


def test_ec_ca_and_leaf():
    ec_root = ca.create_ca({'common_name': 'EC Root', 'key_type': 'EC'})
    r = ca.issue_certificate({'ca_certificate': ec_root['ca_certificate_pem'],
                              'ca_private_key': ec_root['ca_private_key_pem'],
                              'common_name': 'ec.internal', 'key_type': 'EC'})
    verify_chain(r['certificate_pem'], ec_root['ca_certificate_pem'])


@pytest.mark.parametrize('kw,msg', [
    ({'validity_days': 5000}, 'validity_days'),
    ({'usage': 'weird', 'common_name': 'x'}, 'usage'),
    ({}, 'common_name'),
])
def test_validation(root, kw, msg):
    with pytest.raises(ValueError, match=msg):
        issue(root, **kw)


def test_leaf_cannot_outlive_ca():
    short = ca.create_ca({'common_name': 'Short', 'validity_days': 30, 'key_size': 2048})
    with pytest.raises(ValueError, match='beyond the CA'):
        ca.issue_certificate({'ca_certificate': short['ca_certificate_pem'],
                              'ca_private_key': short['ca_private_key_pem'],
                              'common_name': 'x.internal', 'validity_days': 365})


def test_rejects_non_ca_and_mismatched_key(root, sample_cert_pem, sample_key_pem):
    with pytest.raises(ValueError, match='not a CA'):
        ca.issue_certificate({'ca_certificate': sample_cert_pem, 'ca_private_key': sample_key_pem,
                              'common_name': 'x'})
    with pytest.raises(ValueError, match='does not match'):
        ca.issue_certificate({'ca_certificate': root['ca_certificate_pem'],
                              'ca_private_key': sample_key_pem, 'common_name': 'x'})
    with pytest.raises(ValueError, match='invalid'):
        ca.issue_certificate({'ca_certificate': root['ca_certificate_pem'],
                              'ca_private_key': 'garbage', 'common_name': 'x'})


def test_routes(client):
    r = client.post('/api/ca/create', json={'common_name': 'Route CA', 'key_size': 2048}).get_json()['result']
    resp = client.post('/api/ca/issue', json={'ca_certificate': r['ca_certificate_pem'],
                                              'ca_private_key': r['ca_private_key_pem'],
                                              'common_name': 'r.internal'})
    assert resp.status_code == 200 and resp.get_json()['result']['fullchain_pem']
    assert client.post('/api/ca/create', json={}).status_code == 400
    assert client.post('/api/ca/issue', json={}).status_code == 400
