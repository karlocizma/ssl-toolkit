import pytest


class TestHealthCheck:
    def test_returns_healthy(self, client):
        resp = client.get('/api/health')
        assert resp.status_code == 200
        assert resp.get_json()['status'] == 'healthy'


class TestCertificateDecodeRoute:
    def test_valid_certificate(self, client, sample_cert_pem):
        resp = client.post('/api/certificate/decode', json={'certificate': sample_cert_pem})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert data['certificate_info']['subject']['common_name'] == 'test.example.com'

    def test_missing_field_returns_400(self, client):
        resp = client.post('/api/certificate/decode', json={})
        assert resp.status_code == 400

    def test_invalid_pem_returns_400(self, client):
        resp = client.post('/api/certificate/decode', json={
            'certificate': '-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----'
        })
        assert resp.status_code == 400

    def test_oversized_input_returns_400(self, client):
        oversized = '-----BEGIN CERTIFICATE-----\n' + 'A' * 70_000 + '\n-----END CERTIFICATE-----'
        resp = client.post('/api/certificate/decode', json={'certificate': oversized})
        assert resp.status_code == 400
        assert '64 KB' in resp.get_json()['error']


class TestFingerprintRoute:
    def test_returns_sha1_and_sha256(self, client, sample_cert_pem):
        resp = client.post('/api/certificate/fingerprint', json={'certificate': sample_cert_pem})
        assert resp.status_code == 200
        fps = resp.get_json()['fingerprints']
        assert ':' in fps['sha1']
        assert ':' in fps['sha256']


class TestKeyRoutes:
    def test_generate_rsa_2048(self, client):
        resp = client.post('/api/key/generate', json={'key_type': 'RSA', 'key_size': 2048})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['success'] is True
        assert '-----BEGIN PRIVATE KEY-----' in data['private_key']
        assert data['key_type'] == 'RSA'

    def test_generate_ec_key(self, client):
        resp = client.post('/api/key/generate', json={'key_type': 'EC', 'curve_name': 'secp256r1'})
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True

    def test_validate_key(self, client, sample_key_pem):
        resp = client.post('/api/key/validate', json={'private_key': sample_key_pem})
        assert resp.status_code == 200
        assert resp.get_json()['success'] is True

    def test_validate_missing_field_returns_400(self, client):
        resp = client.post('/api/key/validate', json={})
        assert resp.status_code == 400

    def test_key_cert_match_true(self, client, sample_key_pem, sample_cert_pem):
        resp = client.post('/api/key/match-certificate', json={
            'private_key': sample_key_pem,
            'certificate': sample_cert_pem,
        })
        assert resp.status_code == 200
        assert resp.get_json()['matches'] is True

    def test_key_cert_match_missing_fields_returns_400(self, client):
        resp = client.post('/api/key/match-certificate', json={'private_key': 'only-key'})
        assert resp.status_code == 400


class TestCSRRoutes:
    def test_generate_csr(self, client):
        resp = client.post('/api/csr/generate', json={
            'subject': {'common_name': 'test.example.com', 'country': 'US'},
            'key_type': 'RSA',
            'key_size': 2048,
        })
        assert resp.status_code == 200
        data = resp.get_json()
        assert '-----BEGIN CERTIFICATE REQUEST-----' in data['csr']
        assert '-----BEGIN PRIVATE KEY-----' in data['private_key']

    def test_decode_csr(self, client, sample_csr_pem):
        resp = client.post('/api/csr/decode', json={'csr': sample_csr_pem})
        assert resp.status_code == 200
        assert resp.get_json()['csr_info']['subject']['common_name'] == 'test.example.com'

    def test_decode_missing_field_returns_400(self, client):
        resp = client.post('/api/csr/decode', json={})
        assert resp.status_code == 400


class TestAdminRoutes:
    def test_no_token_returns_403(self, client):
        resp = client.post('/api/admin/apikey/generate', json={'name': 'test'})
        assert resp.status_code == 403

    def test_list_no_token_returns_403(self, client):
        resp = client.get('/api/admin/apikey/list')
        assert resp.status_code == 403

    def test_revoke_no_token_returns_403(self, client):
        resp = client.post('/api/admin/apikey/revoke', json={'api_key': 'x'})
        assert resp.status_code == 403

    def test_wrong_token_returns_401(self, client, monkeypatch):
        monkeypatch.setenv('ADMIN_TOKEN', 'correct-token')
        resp = client.post(
            '/api/admin/apikey/generate',
            json={'name': 'test'},
            headers={'Authorization': 'Bearer wrong-token'},
        )
        assert resp.status_code == 401

    def test_correct_token_reaches_handler(self, client, monkeypatch):
        monkeypatch.setenv('ADMIN_TOKEN', 'correct-token')
        resp = client.post(
            '/api/admin/apikey/generate',
            json={'name': 'test'},
            headers={'Authorization': 'Bearer correct-token'},
        )
        # 401/403 would mean auth failed; anything else means the handler was reached
        assert resp.status_code not in (401, 403)
