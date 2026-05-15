import pytest
from app.services import cert_monitor


@pytest.fixture(autouse=True)
def isolated_data_file(tmp_path, monkeypatch):
    """Give each test its own isolated JSON file so tests never share state."""
    data_file = str(tmp_path / 'certs.json')
    monkeypatch.setattr(cert_monitor, 'MONITOR_DATA_FILE', data_file)
    monkeypatch.setattr(cert_monitor, 'MONITOR_LOCK_FILE', data_file + '.lock')


class TestAddMonitoredCertificate:
    def test_add_valid_certificate(self, sample_cert_pem):
        result = cert_monitor.add_monitored_certificate(sample_cert_pem, label='test cert')
        assert result['success'] is True
        assert 'certificate_id' in result

    def test_label_stored(self, sample_cert_pem):
        result = cert_monitor.add_monitored_certificate(sample_cert_pem, label='my cert')
        assert result['certificate']['label'] == 'my cert'

    def test_tags_stored(self, sample_cert_pem):
        result = cert_monitor.add_monitored_certificate(sample_cert_pem, tags=['prod', 'api'])
        assert result['certificate']['tags'] == ['prod', 'api']

    def test_duplicate_fails(self, sample_cert_pem):
        cert_monitor.add_monitored_certificate(sample_cert_pem)
        result = cert_monitor.add_monitored_certificate(sample_cert_pem)
        assert result['success'] is False
        assert 'already' in result['message'].lower()

    def test_invalid_pem_fails(self):
        result = cert_monitor.add_monitored_certificate('not a cert')
        assert result['success'] is False


class TestRemoveMonitoredCertificate:
    def test_remove_existing(self, sample_cert_pem):
        cert_id = cert_monitor.add_monitored_certificate(sample_cert_pem)['certificate_id']
        assert cert_monitor.remove_monitored_certificate(cert_id)['success'] is True
        assert cert_monitor.list_monitored_certificates()['count'] == 0

    def test_remove_nonexistent_fails(self):
        result = cert_monitor.remove_monitored_certificate('cert_nonexistent')
        assert result['success'] is False


class TestListMonitoredCertificates:
    def test_empty_initially(self):
        result = cert_monitor.list_monitored_certificates()
        assert result['success'] is True
        assert result['count'] == 0

    def test_count_after_add(self, sample_cert_pem):
        cert_monitor.add_monitored_certificate(sample_cert_pem)
        assert cert_monitor.list_monitored_certificates()['count'] == 1

    def test_enriches_expiry_fields(self, sample_cert_pem):
        cert_monitor.add_monitored_certificate(sample_cert_pem)
        cert = cert_monitor.list_monitored_certificates()['certificates'][0]
        assert 'days_until_expiry' in cert
        assert 'is_expired' in cert
        assert 'expires_soon' in cert

    def test_pem_excluded_by_default(self, sample_cert_pem):
        cert_monitor.add_monitored_certificate(sample_cert_pem)
        cert = cert_monitor.list_monitored_certificates()['certificates'][0]
        assert 'certificate_pem' not in cert

    def test_pem_included_when_requested(self, sample_cert_pem):
        cert_monitor.add_monitored_certificate(sample_cert_pem)
        cert = cert_monitor.list_monitored_certificates(
            include_certificate_pem=True
        )['certificates'][0]
        assert 'certificate_pem' in cert


class TestGetExpiringCertificates:
    def test_no_expiring_within_30_days(self, sample_cert_pem):
        # Test cert is valid for 365 days, so nothing expires in 30 days
        cert_monitor.add_monitored_certificate(sample_cert_pem)
        result = cert_monitor.get_expiring_certificates(days_threshold=30)
        assert result['success'] is True
        assert result['count'] == 0

    def test_found_with_large_threshold(self, sample_cert_pem):
        cert_monitor.add_monitored_certificate(sample_cert_pem)
        result = cert_monitor.get_expiring_certificates(days_threshold=400)
        assert result['count'] == 1

    def test_sorted_ascending_by_days(self, sample_cert_pem):
        cert_monitor.add_monitored_certificate(sample_cert_pem)
        result = cert_monitor.get_expiring_certificates(days_threshold=400)
        days = [c['days_until_expiry'] for c in result['certificates']]
        assert days == sorted(days)


class TestUpdateMonitoredCertificate:
    def test_update_label(self, sample_cert_pem):
        cert_id = cert_monitor.add_monitored_certificate(sample_cert_pem)['certificate_id']
        result = cert_monitor.update_monitored_certificate(cert_id, label='new label')
        assert result['success'] is True
        assert result['certificate']['label'] == 'new label'

    def test_update_tags(self, sample_cert_pem):
        cert_id = cert_monitor.add_monitored_certificate(sample_cert_pem)['certificate_id']
        result = cert_monitor.update_monitored_certificate(cert_id, tags=['staging'])
        assert result['certificate']['tags'] == ['staging']

    def test_update_nonexistent_fails(self):
        result = cert_monitor.update_monitored_certificate('cert_nonexistent', label='x')
        assert result['success'] is False
