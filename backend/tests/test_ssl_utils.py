import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization

from app.utils.ssl_utils import (
    get_certificate_info, get_csr_info, generate_private_key,
    validate_private_key, check_key_certificate_match, clean_pem_data,
)


class TestGetCertificateInfo:
    def test_valid_cert_fields(self, sample_cert_pem):
        info = get_certificate_info(sample_cert_pem)
        assert info['subject']['common_name'] == 'test.example.com'
        assert info['subject']['country'] == 'US'
        assert info['subject']['organization'] == 'Test Org'
        assert 'test.example.com' in info['subject_alternative_names']
        assert 'www.test.example.com' in info['subject_alternative_names']
        assert info['validity']['is_expired'] is False
        assert info['validity']['days_until_expiry'] > 0
        assert len(info['fingerprints']['sha1']) > 0
        assert len(info['fingerprints']['sha256']) > 0

    def test_invalid_pem_raises(self):
        with pytest.raises(ValueError):
            get_certificate_info('not a certificate')

    def test_empty_string_raises(self):
        with pytest.raises(ValueError):
            get_certificate_info('')

    def test_wrong_pem_type_raises(self):
        with pytest.raises(ValueError):
            get_certificate_info(
                '-----BEGIN PRIVATE KEY-----\ngarbage\n-----END PRIVATE KEY-----'
            )

    def test_accepts_bytes(self, sample_cert_pem):
        info = get_certificate_info(sample_cert_pem.encode('utf-8'))
        assert info['subject']['common_name'] == 'test.example.com'


class TestGetCsrInfo:
    def test_valid_csr_fields(self, sample_csr_pem):
        info = get_csr_info(sample_csr_pem)
        assert info['subject']['common_name'] == 'test.example.com'
        assert 'test.example.com' in info['subject_alternative_names']

    def test_invalid_csr_raises(self):
        with pytest.raises(ValueError):
            get_csr_info('not a csr')

    def test_public_key_present(self, sample_csr_pem):
        info = get_csr_info(sample_csr_pem)
        assert info['public_key']['key_size'] == 2048


class TestGeneratePrivateKey:
    def test_rsa_2048(self):
        key = generate_private_key('RSA', 2048)
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    def test_rsa_4096(self):
        key = generate_private_key('RSA', 4096)
        assert key.key_size == 4096

    def test_ec_secp256r1(self):
        key = generate_private_key('EC', curve_name='secp256r1')
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == 'secp256r1'

    def test_ec_secp384r1(self):
        key = generate_private_key('EC', curve_name='secp384r1')
        assert key.curve.name == 'secp384r1'

    def test_ec_secp521r1(self):
        key = generate_private_key('EC', curve_name='secp521r1')
        assert key.curve.name == 'secp521r1'

    def test_unsupported_type_raises(self):
        with pytest.raises(ValueError, match='Unsupported key type'):
            generate_private_key('DSA')


class TestValidatePrivateKey:
    def test_valid_key_returns_info(self, sample_key_pem):
        info = validate_private_key(sample_key_pem)
        assert info['key_size'] == 2048

    def test_wrong_password_raises(self, sample_key_pem):
        with pytest.raises(Exception):
            validate_private_key(sample_key_pem, password='wrongpass')

    def test_invalid_key_raises(self):
        with pytest.raises(Exception):
            validate_private_key('not a key')


class TestCheckKeyCertificateMatch:
    def test_matching_pair_returns_true(self, sample_key_pem, sample_cert_pem):
        assert check_key_certificate_match(sample_key_pem, sample_cert_pem) is True

    def test_mismatched_pair_returns_false(self, sample_cert_pem):
        other_key = generate_private_key('RSA', 2048)
        other_pem = other_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode('utf-8')
        assert check_key_certificate_match(other_pem, sample_cert_pem) is False


class TestCleanPemData:
    def test_strips_per_line_whitespace(self):
        pem = '  -----BEGIN CERTIFICATE-----  \n  abc  \n  -----END CERTIFICATE-----  '
        cleaned = clean_pem_data(pem)
        assert not any(line.startswith('  ') for line in cleaned.splitlines())

    def test_adds_trailing_newline(self):
        pem = '-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----'
        assert clean_pem_data(pem).endswith('\n')

    def test_accepts_bytes_returns_str(self):
        pem = b'-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----'
        result = clean_pem_data(pem)
        assert isinstance(result, str)


class TestCsrSubjectAlternativeNames:
    """generate_csr must keep every valid SAN and reject (not silently drop) invalid ones."""

    @staticmethod
    def _sans(sans):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from app.utils.ssl_utils import generate_csr
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = generate_csr({'common_name': 'x.example.com'}, key, sans)
        ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        return ext

    def test_dns_wildcard_ip_email_and_underscore_names(self):
        ext = self._sans(['a.example.com', '*.example.com', '10.0.0.5', '2001:db8::1',
                          'ops@example.com', 'my_host.example.com', 'localhost'])
        assert ext.get_values_for_type(x509.DNSName) == [
            'a.example.com', '*.example.com', 'my_host.example.com', 'localhost']
        assert [str(i) for i in ext.get_values_for_type(x509.IPAddress)] == ['10.0.0.5', '2001:db8::1']
        assert ext.get_values_for_type(x509.RFC822Name) == ['ops@example.com']

    def test_blank_entries_ignored_and_whitespace_trimmed(self):
        ext = self._sans(['  a.example.com ', '', '   '])
        assert ext.get_values_for_type(x509.DNSName) == ['a.example.com']

    @pytest.mark.parametrize('bad', ['not a name!', 'exa mple.com', '-bad.example.com', 'a..example.com',
                                     '*.*.example.com', 'bad@@example.com', 'http://example.com'])
    def test_invalid_san_raises(self, bad):
        with pytest.raises(ValueError, match='Invalid subject alternative name'):
            self._sans(['ok.example.com', bad])


class TestIpAddressSans:
    """Regression: an IP SAN's .value is an ipaddress object, which crashed hostname validation and made
    the certificate decoder's JSON response fail."""

    @staticmethod
    def _cert(sans):
        from datetime import datetime, timedelta, timezone
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'host.internal')])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=30))
                .add_extension(x509.SubjectAlternativeName(sans), critical=False).sign(key, hashes.SHA256()))
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def test_all_san_types_become_text(self):
        import ipaddress
        from app.utils.ssl_utils import get_certificate_info
        pem = self._cert([x509.DNSName('host.internal'), x509.IPAddress(ipaddress.ip_address('10.1.2.3')),
                          x509.IPAddress(ipaddress.ip_address('2001:db8::1')), x509.RFC822Name('ops@example.com'),
                          x509.UniformResourceIdentifier('https://host.internal/')])
        sans = get_certificate_info(pem)['subject_alternative_names']
        assert sans == ['host.internal', '10.1.2.3', '2001:db8::1', 'ops@example.com', 'https://host.internal/']
        assert all(isinstance(s, str) for s in sans)

    def test_decode_route_returns_json_for_ip_sans(self, client):
        import ipaddress
        pem = self._cert([x509.IPAddress(ipaddress.ip_address('192.0.2.7'))])
        resp = client.post('/api/certificate/decode', json={'certificate': pem})
        assert resp.status_code == 200
        assert resp.get_json()['certificate_info']['subject_alternative_names'] == ['192.0.2.7']

    def test_csr_with_ip_san_decodes(self):
        from app.utils.ssl_utils import generate_csr, get_csr_info
        key = ec.generate_private_key(ec.SECP256R1())
        csr = generate_csr({'common_name': 'x.internal'}, key, ['x.internal', '10.0.0.9'])
        pem = csr.public_bytes(serialization.Encoding.PEM).decode()
        assert get_csr_info(pem)['subject_alternative_names'] == ['x.internal', '10.0.0.9']

    @pytest.mark.parametrize('host,sans,expected', [
        ('10.1.2.3', ['10.1.2.3'], True),
        ('10.1.2.4', ['10.1.2.3'], False),
        ('::1', ['0:0:0:0:0:0:0:1'], True),       # same address, different spelling
        ('10.1.2.3', ['*.example.com'], False),   # wildcards never match an IP
        ('www.example.com', ['*.example.com'], True),
        ('example.com', ['10.1.2.3'], False),
    ])
    def test_hostname_validity(self, host, sans, expected):
        from app.services.ssl_checker import check_hostname_validity
        assert check_hostname_validity(host, {'subject': {}, 'subject_alternative_names': sans}) is expected
