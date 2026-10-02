import base64
import socket
import json
import os
import shutil
import subprocess
import time

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.services import acme_client as ac
from app.services import acme_dns, acme_service

# --------------------------------------------------------------------------
# Unit tests (no network)
# --------------------------------------------------------------------------


def test_thumbprint_matches_rfc7638_vector():
    n = ('0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjB'
         'ZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8'
         'KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_'
         'xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw')
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    n_int = int.from_bytes(base64.urlsafe_b64decode(n + '=='), 'big')

    class Key:  # only public_key().public_numbers() is needed by _jwk
        def public_key(self):
            return self

        def public_numbers(self):
            return RSAPublicNumbers(65537, n_int)

    jwk = ac._jwk(Key())
    assert jwk['e'] == 'AQAB'
    # Patch isinstance check by building the canonical JSON directly
    digest = __import__('hashlib').sha256(
        json.dumps(jwk, sort_keys=True, separators=(',', ':')).encode()).digest()
    assert ac.b64u(digest) == 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs'


def test_dns_names_and_values():
    assert ac.challenge_dns_name('example.com') == '_acme-challenge.example.com'
    assert ac.challenge_dns_name('*.example.com') == '_acme-challenge.example.com'
    key = ac.new_account_key()
    value = ac.dns_txt_value('tok', key)
    assert len(value) == 43 and '=' not in value


@pytest.mark.parametrize('bad', ['', 'a', 'exa_mple.com', '-x.com', 'http://x.com', '*.*.x.com', 'x.com/path'])
def test_domain_validation_rejects(bad):
    with pytest.raises(ValueError):
        acme_service.normalize_domains([bad])


def test_domain_normalisation_and_limits():
    assert acme_service.normalize_domains(['Example.COM.', 'example.com', '*.example.com']) == [
        'example.com', '*.example.com']
    with pytest.raises(ValueError):
        acme_service.normalize_domains([f'a{i}.example.com' for i in range(25)])


def test_wildcard_needs_dns01():
    with pytest.raises(ValueError, match='dns-01'):
        acme_service._challenge_type({'challenge_type': 'http-01'}, ['*.example.com'])


def test_directory_is_ssrf_guarded(client, monkeypatch):
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    resp = client.post('/api/acme/order', json={'domains': ['example.com'],
                                                'directory': 'https://127.0.0.1:14000/dir'})
    assert resp.status_code == 400 and 'non-public' in resp.get_json()['error']


def test_order_url_must_match_directory_host():
    client = ac.AcmeClient('https://acme.example/dir', ac.new_account_key())
    with pytest.raises(ValueError):
        acme_service._check_order_url(client, 'https://evil.example/order/1')


def test_invalid_account_key():
    with pytest.raises(ac.AcmeError):
        ac.load_account_key('not a key')


def test_complete_requires_fields(client):
    assert client.post('/api/acme/complete', json={}).status_code == 400
    assert client.post('/api/acme/issue', json={'domains': ['example.com'],
                                                'dns_provider': {'type': 'nope'}}).status_code == 400


class FakeSession:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))

        class R:
            text = ''

            def json(_):
                if method == 'GET':
                    result = [{'id': 'zone1'}] if kw['params']['name'] == 'example.com' else []
                    return {'success': True, 'result': result}
                return {'success': True, 'result': {'id': 'rec1'}}
        return R()


def test_cloudflare_provider_finds_zone_and_cleans_up():
    p = acme_dns.CloudflareProvider('tok')
    p.session = FakeSession()
    handle = p.add_txt('_acme-challenge.sub.example.com', 'val')
    assert handle == {'zone': 'zone1', 'id': 'rec1'}
    method, url, kw = p.session.calls[-1]
    assert method == 'POST' and url.endswith('/zones/zone1/dns_records')
    assert kw['json']['content'] == 'val' and kw['json']['type'] == 'TXT'
    p.remove_txt(handle)
    assert p.session.calls[-1][0] == 'DELETE'


def test_cloudflare_error_surfaces():
    p = acme_dns.CloudflareProvider('tok', zone_id='z')

    class Bad:
        def request(self, *a, **k):
            class R:
                text = ''

                def json(_):
                    return {'success': False, 'errors': [{'message': 'Invalid token'}]}
            return R()
    p.session = Bad()
    with pytest.raises(acme_dns.DnsProviderError, match='Invalid token'):
        p.add_txt('x.example.com', 'v')


def test_rfc2136_builds_signed_update(monkeypatch):
    sent = []

    class Resp:
        def rcode(self):
            return 0
    monkeypatch.setattr(acme_dns, 'resolve_public', lambda host, port: [(2, 1, 6, '', ('9.9.9.9', port))])
    monkeypatch.setattr(acme_dns.dns.query, 'tcp', lambda msg, addr, port, timeout: sent.append((msg, addr)) or Resp())
    secret = base64.b64encode(b'k' * 32).decode()
    p = acme_dns.Rfc2136Provider('ns.example.com', 'example.com', 'key1', secret)
    handle = p.add_txt('_acme-challenge.example.com', 'abc')
    p.remove_txt(handle)
    add_msg, addr = sent[0]
    assert addr == '9.9.9.9' and add_msg.keyname is not None  # TSIG-signed
    assert '_acme-challenge.example.com' in add_msg.to_text() and 'abc' in add_msg.to_text()
    assert 'ANY' in sent[1][0].to_text() or 'NONE' in sent[1][0].to_text()  # delete = class NONE
    assert len(sent) == 2


def test_rfc2136_rejects_bad_secret_and_internal_server(monkeypatch):
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    with pytest.raises(acme_dns.DnsProviderError, match='base64'):
        acme_dns.Rfc2136Provider('ns.example.com', 'example.com', 'k', '***')
    with pytest.raises(acme_dns.DnsProviderError, match='non-public'):
        acme_dns.Rfc2136Provider('127.0.0.1', 'example.com', 'k', base64.b64encode(b'x').decode())


# --------------------------------------------------------------------------
# Integration tests against a real ACME server (Pebble)
# --------------------------------------------------------------------------
PEBBLE_DIR = os.environ.get('PEBBLE_BIN_DIR', '/tmp/gopath/bin')
PEBBLE = shutil.which('pebble') or os.path.join(PEBBLE_DIR, 'pebble')
CHALL = shutil.which('pebble-challtestsrv') or os.path.join(PEBBLE_DIR, 'pebble-challtestsrv')
DIRECTORY = 'https://127.0.0.1:14000/dir'
MGMT = 'http://127.0.0.1:8055'

def wait_ports_free(*ports, timeout=10):
    """A previous test run's Pebble may still be shutting down; starting on top of it makes the readiness
    probe pass against the dying process."""
    deadline = time.time() + timeout
    for port in ports:
        while time.time() < deadline:
            with socket.socket() as s:
                s.settimeout(0.2)
                if s.connect_ex(('127.0.0.1', port)) != 0:
                    break
            time.sleep(0.2)


needs_pebble = pytest.mark.skipif(not (os.path.exists(PEBBLE) and os.path.exists(CHALL)),
                                  reason='pebble / pebble-challtestsrv not installed')


@pytest.fixture(scope='module')
def pebble(tmp_path_factory):
    d = tmp_path_factory.mktemp('pebble')
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(d / 'k.pem'),
                    '-out', str(d / 'c.pem'), '-days', '2', '-subj', '/CN=pebble',
                    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True, capture_output=True)
    (d / 'cfg.json').write_text(json.dumps({'pebble': {
        'listenAddress': '127.0.0.1:14000', 'managementListenAddress': '127.0.0.1:15000',
        'certificate': str(d / 'c.pem'), 'privateKey': str(d / 'k.pem'), 'httpPort': 5002, 'tlsPort': 5001,
        'ocspResponderURL': '', 'externalAccountBindingRequired': False}}))
    env = dict(os.environ, PEBBLE_VA_NOSLEEP='1', PEBBLE_WFE_NONCEREJECT='0')
    wait_ports_free(14000, 15000, 8055, 5002)
    chall = subprocess.Popen([CHALL, '-dnsserver', '127.0.0.1:8053', '-management', '127.0.0.1:8055',
                              '-defaultIPv6', '', '-http01', '127.0.0.1:5002', '-https01', '', '-tlsalpn01', '', '-doh', ''],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    peb = subprocess.Popen([PEBBLE, '-config', str(d / 'cfg.json'), '-dnsserver', '127.0.0.1:8053'],
                           env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            requests.get(DIRECTORY, verify=str(d / 'c.pem'), timeout=1)
            break
        except requests.RequestException:
            time.sleep(0.2)
    else:
        peb.kill(); chall.kill()
        pytest.fail('pebble did not start')
    assert peb.poll() is None and chall.poll() is None, 'pebble exited right after start (port still in use?)'
    mp = pytest.MonkeyPatch()
    mp.setenv('ACME_CA_BUNDLE', str(d / 'c.pem'))
    mp.setenv('ALLOW_PRIVATE_TARGETS', 'true')
    mp.setenv('ACME_DNS_RESOLVERS', '127.0.0.1:8053')
    yield d
    mp.undo()
    peb.kill(); chall.kill()
    peb.wait(); chall.wait()


class ChallTestSrvProvider:
    """Test DNS provider backed by pebble-challtestsrv's management API."""

    def __init__(self):
        self.removed = []

    def add_txt(self, name, value):
        requests.post(f'{MGMT}/set-txt', json={'host': name + '.', 'value': value}).raise_for_status()
        return name

    def remove_txt(self, handle):
        self.removed.append(handle)
        requests.post(f'{MGMT}/clear-txt', json={'host': handle + '.'}).raise_for_status()


def publish_dns(challenges):
    for ch in challenges:
        ChallTestSrvProvider().add_txt(ch['dns_name'], ch['dns_value'])


def assert_valid_cert(result, domains, key_pem):
    cert = x509.load_pem_x509_certificate(result['certificate_pem'].encode())
    sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(sans.get_values_for_type(x509.DNSName)) == set(domains)
    key = serialization.load_pem_private_key(key_pem.encode(), None)
    pub = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)  # noqa
    assert pub(key.public_key()) == pub(cert.public_key())
    assert result['fullchain_pem'].count('BEGIN CERTIFICATE') >= 2


@needs_pebble
def test_manual_dns01_flow(pebble):
    start = acme_service.start_order({'domains': ['manual.example.test', 'www.manual.example.test'],
                                      'directory': DIRECTORY, 'email': 'ops@example.test'})
    assert start['account_key_pem'] and start['private_key_pem'] and start['order_url'].startswith('https://127.0.0.1')
    assert {c['dns_name'] for c in start['challenges']} == {
        '_acme-challenge.manual.example.test', '_acme-challenge.www.manual.example.test'}
    publish_dns(start['challenges'])
    result = acme_service.complete_order({
        'directory': DIRECTORY, 'account_key_pem': start['account_key_pem'],
        'order_url': start['order_url'], 'csr_pem': start['csr_pem']})
    assert_valid_cert(result, ['manual.example.test', 'www.manual.example.test'], start['private_key_pem'])


@needs_pebble
def test_manual_flow_with_customer_csr_and_existing_account(pebble, sample_key_pem):
    from app.utils.ssl_utils import generate_csr
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = generate_csr({'common_name': 'csr.example.test'}, key, ['csr.example.test'])
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    acct = ac.key_to_pem(ac.new_account_key())
    start = acme_service.start_order({'csr': csr_pem, 'directory': DIRECTORY, 'account_key_pem': acct})
    assert 'private_key_pem' not in start and start['account_key_pem'] is None  # caller's keys are never echoed
    publish_dns(start['challenges'])
    result = acme_service.complete_order({'directory': DIRECTORY, 'account_key_pem': acct,
                                         'order_url': start['order_url'], 'csr_pem': csr_pem})
    assert 'csr.example.test' in result['certificate_info']['subject_alternative_names'][0]


@needs_pebble
def test_manual_http01_flow(pebble):
    start = acme_service.start_order({'domains': ['web.example.test'], 'directory': DIRECTORY,
                                      'challenge_type': 'http-01'})
    ch = start['challenges'][0]
    assert ch['http_url'].endswith('/.well-known/acme-challenge/' + ch['token'])
    requests.post(f'{MGMT}/add-http01', json={'token': ch['token'], 'content': ch['http_content']}).raise_for_status()
    result = acme_service.complete_order({
        'directory': DIRECTORY, 'account_key_pem': start['account_key_pem'], 'challenge_type': 'http-01',
        'order_url': start['order_url'], 'csr_pem': start['csr_pem']})
    assert_valid_cert(result, ['web.example.test'], start['private_key_pem'])


@needs_pebble
def test_complete_fails_clearly_when_challenge_not_published(pebble):
    start = acme_service.start_order({'domains': ['missing.example.test'], 'directory': DIRECTORY})
    with pytest.raises(ValueError, match='Validation of missing.example.test failed'):
        acme_service.complete_order({'directory': DIRECTORY, 'account_key_pem': start['account_key_pem'],
                                     'order_url': start['order_url'], 'csr_pem': start['csr_pem']})


@needs_pebble
def test_automatic_flow_with_wildcard_and_cleanup(pebble, monkeypatch):
    provider = ChallTestSrvProvider()
    monkeypatch.setattr(acme_dns, 'build_provider', lambda cfg: provider)
    result = acme_service.issue_automatic({
        'domains': ['auto.example.test', '*.auto.example.test'], 'directory': DIRECTORY,
        'dns_provider': {'type': 'cloudflare', 'api_token': 'x'}, 'propagation_timeout': 30})
    assert_valid_cert(result, ['auto.example.test', '*.auto.example.test'], result['private_key_pem'])
    assert result['account_key_pem']
    assert provider.removed  # TXT records were cleaned up


@needs_pebble
def test_automatic_flow_cleans_up_on_failure(pebble, monkeypatch):
    provider = ChallTestSrvProvider()
    monkeypatch.setattr(acme_dns, 'build_provider', lambda cfg: provider)
    monkeypatch.setattr(acme_dns, 'wait_for_txt', lambda *a, **k: (_ for _ in ()).throw(
        acme_dns.DnsProviderError('never visible')))
    with pytest.raises(ValueError, match='never visible'):
        acme_service.issue_automatic({'domains': ['fail.example.test'], 'directory': DIRECTORY,
                                      'dns_provider': {'type': 'cloudflare', 'api_token': 'x'}})
    assert provider.removed


@needs_pebble
def test_http_routes_end_to_end(pebble, client):
    resp = client.post('/api/acme/order', json={'domains': ['route.example.test'], 'directory': DIRECTORY})
    assert resp.status_code == 200, resp.get_json()
    start = resp.get_json()['result']
    publish_dns(start['challenges'])
    resp = client.post('/api/acme/complete', json={
        'directory': DIRECTORY, 'account_key_pem': start['account_key_pem'],
        'order_url': start['order_url'], 'csr_pem': start['csr_pem']})
    assert resp.status_code == 200 and 'BEGIN CERTIFICATE' in resp.get_json()['result']['certificate_pem']
