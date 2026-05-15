import pytest
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
