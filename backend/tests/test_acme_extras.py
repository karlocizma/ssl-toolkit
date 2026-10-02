import base64
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.services import acme_client as ac
from app.services import acme_dns, acme_service
from tests.test_acme import (CHALL, DIRECTORY, PEBBLE, ChallTestSrvProvider, needs_pebble, pebble,  # noqa: F401
                             publish_dns, wait_ports_free)

EAB_DIRECTORY = 'https://127.0.0.1:14001/dir'
EAB_KID = 'kid-1'
EAB_KEY = 'zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W'


# ------------------------------------------------------------------ ARI certificate id (RFC 9773 appendix A)
def test_certificate_id_matches_rfc_9773_vector():
    key = ec.generate_private_key(ec.SECP256R1())
    aki = bytes.fromhex('69885B6B87464041E1B37B847BA0AE2CDE01C8D4')
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'x')]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ca')]))
            .public_key(key.public_key()).serial_number(0x87654321)
            .not_valid_before(__import__('datetime').datetime(2026, 1, 1)).not_valid_after(__import__('datetime').datetime(2027, 1, 1))
            .add_extension(x509.AuthorityKeyIdentifier(aki, None, None), critical=False)
            .sign(key, hashes.SHA256()))
    assert ac.certificate_id(cert) == 'aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE'


def test_certificate_id_requires_aki(sample_cert_pem):
    with pytest.raises(ac.AcmeError, match='Authority Key Identifier'):
        ac.certificate_id(x509.load_pem_x509_certificate(sample_cert_pem.encode()))


def test_renewal_info_validates_input():
    with pytest.raises(ValueError, match='certificate is required'):
        acme_service.renewal_info({})
    with pytest.raises(ValueError, match='not a valid PEM'):
        acme_service.renewal_info({'certificate': 'nope', 'directory': 'https://acme.example/dir'})


def test_eab_argument_validation():
    client = ac.AcmeClient('https://acme.example/dir', ac.new_account_key())
    client._directory = {'newAccount': 'https://acme.example/new'}
    with pytest.raises(ac.AcmeError, match='Both eab_kid and eab_hmac_key'):
        client.register(None, 'kid', None)
    with pytest.raises(ac.AcmeError, match='base64url'):
        client._external_account_binding('kid', '***')


def test_eab_binding_is_a_valid_hs256_jws():
    import hashlib
    import hmac
    client = ac.AcmeClient('https://acme.example/dir', ac.new_account_key())
    client._directory = {'newAccount': 'https://acme.example/new'}
    b = client._external_account_binding('kid-9', EAB_KEY)
    header = json.loads(base64.urlsafe_b64decode(b['protected'] + '=='))
    assert header == {'alg': 'HS256', 'kid': 'kid-9', 'url': 'https://acme.example/new'}
    assert json.loads(base64.urlsafe_b64decode(b['payload'] + '==')) == ac._jwk(client.key)
    mac = hmac.new(base64.urlsafe_b64decode(EAB_KEY + '=='), f"{b['protected']}.{b['payload']}".encode(), hashlib.sha256).digest()
    assert b['signature'] == ac.b64u(mac)


# ------------------------------------------------------------------ acme-dns provider (fake server)
class FakeAcmeDns(BaseHTTPRequestHandler):
    seen = []

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        FakeAcmeDns.seen.append((self.path, dict(self.headers), body))
        ok = self.headers.get('X-Api-Key') == 'secret'
        self.send_response(200 if ok else 401)
        self.end_headers()
        self.wfile.write(b'{}')

    def log_message(self, *a):
        pass


@pytest.fixture
def acme_dns_server(monkeypatch):
    srv = HTTPServer(('127.0.0.1', 0), FakeAcmeDns)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    FakeAcmeDns.seen = []
    monkeypatch.setenv('ALLOW_PRIVATE_TARGETS', 'true')
    yield f'http://127.0.0.1:{srv.server_port}'
    srv.shutdown()


def test_acme_dns_provider_posts_update(acme_dns_server):
    p = acme_dns.build_provider({'type': 'acme-dns', 'server_url': acme_dns_server + '/', 'username': 'u',
                                 'password': 'secret', 'subdomain': 'abc-123'})
    handle = p.add_txt('_acme-challenge.example.com', 'tokenvalue')
    p.remove_txt(handle)  # no-op by design
    path, headers, body = FakeAcmeDns.seen[0]
    assert path == '/update' and body == {'subdomain': 'abc-123', 'txt': 'tokenvalue'}
    assert headers['X-Api-User'] == 'u' and headers['X-Api-Key'] == 'secret'


def test_acme_dns_rejected_credentials_and_validation(acme_dns_server):
    bad = acme_dns.AcmeDnsProvider(acme_dns_server, 'u', 'wrong', 'abc')
    with pytest.raises(acme_dns.DnsProviderError, match='HTTP 401'):
        bad.add_txt('x', 'y')
    for cfg in ({'type': 'acme-dns'}, {'type': 'acme-dns', 'server_url': 'ftp://x', 'username': 'u', 'password': 'p', 'subdomain': 's'}):
        with pytest.raises(acme_dns.DnsProviderError):
            acme_dns.build_provider(cfg)


def test_acme_dns_blocks_internal_server(monkeypatch):
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    p = acme_dns.AcmeDnsProvider('http://127.0.0.1:9', 'u', 'p', 's')
    with pytest.raises(acme_dns.DnsProviderError, match='non-public'):
        p.add_txt('x', 'y')


# ------------------------------------------------------------------ Pebble: EAB and ARI
@pytest.fixture(scope='module')
def pebble_eab(pebble, tmp_path_factory):  # noqa: F811  (reuses the DNS/challenge helper started by `pebble`)
    d = tmp_path_factory.mktemp('pebble_eab')
    cert, key = pebble / 'c.pem', pebble / 'k.pem'
    (d / 'cfg.json').write_text(json.dumps({'pebble': {
        'listenAddress': '127.0.0.1:14001', 'managementListenAddress': '127.0.0.1:15001',
        'certificate': str(cert), 'privateKey': str(key), 'httpPort': 5002, 'tlsPort': 5001,
        'ocspResponderURL': '', 'externalAccountBindingRequired': True,
        'externalAccountMacKeys': {EAB_KID: EAB_KEY}}}))
    wait_ports_free(14001, 15001)
    proc = subprocess.Popen([PEBBLE, '-config', str(d / 'cfg.json'), '-dnsserver', '127.0.0.1:8053'],
                            env=dict(os.environ, PEBBLE_VA_NOSLEEP='1'),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            requests.get(EAB_DIRECTORY, verify=str(cert), timeout=1)
            break
        except requests.RequestException:
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail('EAB pebble did not start')
    assert proc.poll() is None, 'EAB pebble exited right after start'
    yield
    proc.kill()
    proc.wait()


@needs_pebble
def test_ca_requiring_eab_without_credentials_explains_it(pebble_eab):
    with pytest.raises(ValueError, match='requires external account binding'):
        acme_service.start_order({'domains': ['eab.example.test'], 'directory': EAB_DIRECTORY})


@needs_pebble
def test_eab_flow_issues_a_certificate(pebble_eab):
    start = acme_service.start_order({'domains': ['eab.example.test'], 'directory': EAB_DIRECTORY,
                                      'eab_kid': EAB_KID, 'eab_hmac_key': EAB_KEY})
    publish_dns(start['challenges'])
    result = acme_service.complete_order({'directory': EAB_DIRECTORY, 'account_key_pem': start['account_key_pem'],
                                         'order_url': start['order_url'], 'csr_pem': start['csr_pem']})
    assert 'BEGIN CERTIFICATE' in result['certificate_pem']


@needs_pebble
def test_wrong_eab_key_is_rejected_by_the_ca(pebble_eab):
    wrong = ac.b64u(b'x' * 48)
    with pytest.raises(ValueError, match='ACME server error'):
        acme_service.start_order({'domains': ['eab2.example.test'], 'directory': EAB_DIRECTORY,
                                  'eab_kid': EAB_KID, 'eab_hmac_key': wrong})
    with pytest.raises(ValueError, match='ACME server error'):
        acme_service.start_order({'domains': ['eab3.example.test'], 'directory': EAB_DIRECTORY,
                                  'eab_kid': 'unknown-kid', 'eab_hmac_key': EAB_KEY})


@needs_pebble
def test_renewal_info_for_a_freshly_issued_certificate(pebble):
    start = acme_service.start_order({'domains': ['ari.example.test'], 'directory': DIRECTORY})
    publish_dns(start['challenges'])
    issued = acme_service.complete_order({'directory': DIRECTORY, 'account_key_pem': start['account_key_pem'],
                                          'order_url': start['order_url'], 'csr_pem': start['csr_pem']})
    info = acme_service.renewal_info({'directory': DIRECTORY, 'certificate': issued['certificate_pem']})
    assert info['suggested_window_start'] and info['suggested_window_end']
    assert info['status'] in ('wait', 'renew_now') and info['days_until_window'] is not None
    assert info['suggested_window_start'] < info['suggested_window_end']


@needs_pebble
def test_renewal_info_unknown_certificate_and_route(pebble, client, sample_cert_pem):
    # a certificate this CA never issued (and which has no AKI) is explained, not a crash
    resp = client.post('/api/acme/renewal-info', json={'directory': DIRECTORY, 'certificate': sample_cert_pem})
    assert resp.status_code == 400 and 'Authority Key Identifier' in resp.get_json()['error']
    assert client.post('/api/acme/renewal-info', json={}).status_code == 400
