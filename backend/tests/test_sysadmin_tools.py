import pytest
from unittest.mock import patch

from app.services.sysadmin_tools import (
    generate_dmarc_record, validate_dmarc_record,
    generate_spf_record, validate_spf_record,
    generate_password_bundle, analyze_email_headers,
)


class TestGenerateDmarcRecord:
    def test_basic_reject_record(self):
        result = generate_dmarc_record({'domain': 'example.com', 'policy': 'reject'})
        assert result['domain'] == 'example.com'
        assert result['dns_host'] == '_dmarc.example.com'
        assert 'v=DMARC1' in result['record']
        assert 'p=reject' in result['record']

    def test_missing_domain_raises(self):
        with pytest.raises(ValueError, match='Domain is required'):
            generate_dmarc_record({})

    def test_invalid_policy_raises(self):
        with pytest.raises(ValueError):
            generate_dmarc_record({'domain': 'example.com', 'policy': 'invalid'})

    def test_rua_mailto_prefix_added(self):
        result = generate_dmarc_record({
            'domain': 'example.com', 'policy': 'none',
            'rua': 'dmarc@example.com',
        })
        assert 'rua=mailto:dmarc@example.com' in result['record']

    def test_none_policy_triggers_recommendation(self):
        result = generate_dmarc_record({'domain': 'example.com', 'policy': 'none'})
        assert any('none' in r for r in result['recommendations'])

    def test_missing_rua_triggers_recommendation(self):
        result = generate_dmarc_record({'domain': 'example.com', 'policy': 'reject'})
        assert any('rua' in r.lower() for r in result['recommendations'])

    def test_pct_clamped_to_100(self):
        result = generate_dmarc_record({'domain': 'example.com', 'policy': 'reject', 'pct': 200})
        assert 'pct=100' in result['record']

    def test_subdomain_policy_included(self):
        result = generate_dmarc_record({
            'domain': 'example.com', 'policy': 'reject', 'subdomain_policy': 'none',
        })
        assert 'sp=none' in result['record']


class TestValidateDmarcRecord:
    def test_valid_record(self):
        result = validate_dmarc_record({'record': 'v=DMARC1; p=reject; rua=mailto:d@e.com'})
        assert result['valid'] is True
        assert result['errors'] == []

    def test_missing_policy_is_invalid(self):
        result = validate_dmarc_record({'record': 'v=DMARC1'})
        assert result['valid'] is False
        assert len(result['errors']) > 0

    def test_no_input_returns_not_present(self):
        result = validate_dmarc_record({})
        assert result['valid'] is False
        assert result['record_present'] is False

    def test_missing_rua_adds_warning(self):
        result = validate_dmarc_record({'record': 'v=DMARC1; p=reject'})
        assert any('rua' in w.lower() for w in result['warnings'])

    @patch('app.services.sysadmin_tools._resolve_txt_records')
    def test_dns_lookup_used_when_domain_given(self, mock_resolve):
        mock_resolve.return_value = (['v=DMARC1; p=quarantine'], None)
        result = validate_dmarc_record({'domain': 'example.com'})
        mock_resolve.assert_called_once_with('_dmarc.example.com', 5)
        assert result['record_source'] == 'dns'
        assert result['valid'] is True


class TestGenerateSpfRecord:
    def test_basic_mx_record(self):
        result = generate_spf_record({'domain': 'example.com', 'include_mx': True})
        assert result['record'].startswith('v=spf1')
        assert 'mx' in result['record']

    def test_missing_domain_raises(self):
        with pytest.raises(ValueError):
            generate_spf_record({})

    def test_ipv4_included(self):
        result = generate_spf_record({'domain': 'example.com', 'ipv4': '192.0.2.1'})
        assert 'ip4:192.0.2.1' in result['record']

    def test_invalid_ipv4_skipped(self):
        result = generate_spf_record({'domain': 'example.com', 'ipv4': 'not-an-ip'})
        assert 'ip4:not-an-ip' not in result['record']

    def test_include_domain_added(self):
        result = generate_spf_record({'domain': 'example.com', 'include': 'sendgrid.net'})
        assert 'include:sendgrid.net' in result['record']

    def test_ends_with_all_mechanism(self):
        result = generate_spf_record({'domain': 'example.com'})
        assert result['record'].endswith('all')


class TestValidateSpfRecord:
    def test_valid_record(self):
        result = validate_spf_record({'record': 'v=spf1 mx -all'})
        assert result['valid'] is True
        assert result['errors'] == []

    def test_missing_all_warns(self):
        result = validate_spf_record({'record': 'v=spf1 mx'})
        assert len(result['warnings']) > 0

    def test_wrong_version_invalid(self):
        result = validate_spf_record({'record': 'v=spf2 mx ~all'})
        assert result['valid'] is False

    def test_no_input_returns_not_present(self):
        result = validate_spf_record({})
        assert result['record_present'] is False
        assert result['valid'] is False


class TestGeneratePasswordBundle:
    def test_default_length_16(self):
        result = generate_password_bundle({})
        assert len(result['password']) == 16

    def test_custom_length(self):
        result = generate_password_bundle({'length': 32})
        assert len(result['password']) == 32

    def test_hashes_present(self):
        result = generate_password_bundle({})
        assert 'sha256' in result['hashes']
        assert 'sha512' in result['hashes']

    def test_entropy_positive(self):
        result = generate_password_bundle({})
        assert result['entropy_bits'] > 0

    def test_all_charsets_disabled_raises(self):
        with pytest.raises(ValueError):
            generate_password_bundle({
                'character_sets': {
                    'upper': False, 'lower': False,
                    'digits': False, 'symbols': False,
                }
            })

    def test_short_password_warns(self):
        result = generate_password_bundle({'length': 8})
        assert any('12' in w for w in result['warnings'])

    def test_unique_passwords_each_call(self):
        r1 = generate_password_bundle({})
        r2 = generate_password_bundle({})
        assert r1['password'] != r2['password']


class TestAnalyzeEmailHeaders:
    SAMPLE = (
        'From: sender@example.com\r\n'
        'To: recipient@example.com\r\n'
        'Subject: Test\r\n'
        'Received: from mail.example.com by mx.example.com with SMTP; '
        'Mon, 01 Jan 2024 12:00:00 +0000\r\n'
        'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=example.com\r\n'
    )

    def test_parses_metadata(self):
        result = analyze_email_headers({'headers': self.SAMPLE})
        assert result['metadata']['from'] == 'sender@example.com'
        assert result['metadata']['subject'] == 'Test'

    def test_spf_result_extracted(self):
        result = analyze_email_headers({'headers': self.SAMPLE})
        assert result['authentication']['spf'] is not None

    def test_hop_count(self):
        result = analyze_email_headers({'headers': self.SAMPLE})
        assert result['hop_summary']['hop_count'] == 1

    def test_empty_headers_raises(self):
        with pytest.raises(ValueError):
            analyze_email_headers({'headers': ''})

    def test_missing_key_raises(self):
        with pytest.raises(ValueError):
            analyze_email_headers({})

    def test_spf_fail_adds_warning(self):
        headers = self.SAMPLE.replace('spf=pass', 'spf=fail')
        result = analyze_email_headers({'headers': headers})
        assert any('SPF' in w for w in result['warnings'])
