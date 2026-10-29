import pytest

from app.services import caa_dane


def fake_dns(monkeypatch, zone):
    """zone: {name: [(flags, tag, value)]}; 'FAIL' marks a SERVFAIL; unknown names are NXDOMAIN."""
    asked = []

    def lookup(name):
        asked.append(name)
        entry = zone.get(name)
        if entry == 'FAIL':
            return [], 'FAILURE: SERVFAIL'
        if entry is None:
            return [], 'NXDOMAIN'
        return list(entry), None

    monkeypatch.setattr(caa_dane, '_caa_lookup', lookup)
    return asked


def messages(result, severity=None):
    return [f['message'] for f in result['findings'] if severity in (None, f['severity'])]


# --------------------------------------------------------------------------- check_caa
def test_policy_from_the_name_itself(monkeypatch):
    fake_dns(monkeypatch, {'www.example.com': [(0, 'issue', 'letsencrypt.org')]})
    r = caa_dane.check_caa('www.example.com')
    assert r['policy_name'] == 'www.example.com'
    assert [i['ca'] for i in r['issuers']] == ['letsencrypt.org']
    assert r['issuers'][0]['name'] == "Let's Encrypt"
    assert r['any_ca_may_issue'] is False


def test_climbs_to_parent_and_stops_before_the_tld(monkeypatch):
    asked = fake_dns(monkeypatch, {'example.com': [(0, 'issue', 'digicert.com')]})
    r = caa_dane.check_caa('a.b.example.com')
    assert asked == ['a.b.example.com', 'b.example.com', 'example.com']
    assert r['policy_name'] == 'example.com'
    assert any('inherited' in m.lower() for m in messages(r, 'info'))

    asked = fake_dns(monkeypatch, {})
    r = caa_dane.check_caa('example.com')
    assert asked == ['example.com']  # the bare TLD is never queried
    assert r['policy_name'] is None and r['any_ca_may_issue'] is True
    assert any('any CA may issue' in m for m in messages(r, 'warning'))


def test_dns_failure_is_an_error_not_no_caa(monkeypatch):
    fake_dns(monkeypatch, {'example.com': 'FAIL'})
    r = caa_dane.check_caa('example.com')
    assert r['lookup_failed'] is True
    assert any('SERVFAIL' in m for m in messages(r, 'error'))
    assert not any('any CA may issue' in m for m in messages(r))


def test_input_is_normalised_or_rejected():
    for bad in ('', 'not a domain', 'localhost', None):
        with pytest.raises(ValueError):
            caa_dane.check_caa(bad)


def test_trailing_dot_and_case_are_normalised(monkeypatch):
    fake_dns(monkeypatch, {'example.com': [(0, 'issue', 'sectigo.com')]})
    assert caa_dane.check_caa('Example.COM.')['domain'] == 'example.com'


def test_issuewild_takes_precedence_for_wildcards(monkeypatch):
    fake_dns(monkeypatch, {'example.com': [(0, 'issue', 'letsencrypt.org'), (0, 'issuewild', 'digicert.com')]})
    r = caa_dane.check_caa('example.com')
    assert [i['ca'] for i in r['issuers']] == ['letsencrypt.org']
    assert [i['ca'] for i in r['wildcard_issuers']] == ['digicert.com']
    assert any('differs' in m for m in messages(r, 'info'))


def test_wildcards_follow_issue_without_issuewild(monkeypatch):
    fake_dns(monkeypatch, {'example.com': [(0, 'issue', 'letsencrypt.org')]})
    r = caa_dane.check_caa('example.com')
    assert [i['ca'] for i in r['wildcard_issuers']] == ['letsencrypt.org']


def test_semicolon_blocks_all_issuance(monkeypatch):
    fake_dns(monkeypatch, {'example.com': [(0, 'issue', ';')]})
    r = caa_dane.check_caa('example.com')
    assert r['issuance_blocked'] is True and r['wildcard_blocked'] is True
    assert r['issuers'] == [] and r['any_ca_may_issue'] is False


def test_semicolon_next_to_other_issuers_is_flagged(monkeypatch):
    fake_dns(monkeypatch, {'example.com': [(0, 'issue', ';'), (0, 'issue', 'letsencrypt.org')]})
    r = caa_dane.check_caa('example.com')
    assert r['issuance_blocked'] is False
    assert any('no effect' in m for m in messages(r, 'warning'))


def test_parameters_are_parsed(monkeypatch):
    fake_dns(monkeypatch, {'example.com': [(0, 'issue', 'letsencrypt.org; validationmethods=dns-01; accounturi=https://x/1')]})
    params = caa_dane.check_caa('example.com')['issuers'][0]['params']
    assert params == {'validationmethods': 'dns-01', 'accounturi': 'https://x/1'}


def test_unknown_critical_tag_is_an_error(monkeypatch):
    fake_dns(monkeypatch, {'example.com': [(128, 'futuretag', 'x'), (0, 'issue', 'letsencrypt.org')]})
    r = caa_dane.check_caa('example.com')
    assert any('futuretag' in m for m in messages(r, 'error'))
    assert r['records'][0]['critical'] is True


@pytest.mark.parametrize('value,ok', [
    ('mailto:security@example.com', True), ('https://example.com/report', True),
    ('security@example.com', False), ('http://example.com', False), ('mailto:', False)])
def test_iodef_validation(monkeypatch, value, ok):
    fake_dns(monkeypatch, {'example.com': [(0, 'issue', 'letsencrypt.org'), (0, 'iodef', value)]})
    warned = any('iodef' in m for m in messages(caa_dane.check_caa('example.com'), 'warning'))
    assert warned is (not ok)


# --------------------------------------------------------------------------- generate_caa
def test_generate_basic():
    r = caa_dane.generate_caa('example.com', ['letsencrypt.org', 'digicert.com'])
    assert r['records'] == [
        'example.com. IN CAA 0 issue "letsencrypt.org"',
        'example.com. IN CAA 0 issue "digicert.com"',
    ]
    assert r['summary']


def test_generate_dns01_only_and_iodef_and_no_wildcards():
    r = caa_dane.generate_caa('example.com', ['letsencrypt.org'], allow_wildcards=False, dns01_only=True,
                              iodef='mailto:security@example.com')
    assert 'example.com. IN CAA 0 issue "letsencrypt.org; validationmethods=dns-01"' in r['records']
    assert 'example.com. IN CAA 0 issuewild ";"' in r['records']
    assert 'example.com. IN CAA 0 iodef "mailto:security@example.com"' in r['records']


def test_generate_separate_wildcard_issuers():
    r = caa_dane.generate_caa(None, ['letsencrypt.org'], wildcard_issuers=['digicert.com'])
    assert '@ IN CAA 0 issuewild "digicert.com"' in r['records']


def test_generate_block_all_is_explicit():
    r = caa_dane.generate_caa('example.com', [], block_all=True)
    assert r['records'] == ['example.com. IN CAA 0 issue ";"', 'example.com. IN CAA 0 issuewild ";"']
    with pytest.raises(ValueError):
        caa_dane.generate_caa('example.com', [])
    with pytest.raises(ValueError):
        caa_dane.generate_caa('example.com', ['letsencrypt.org'], block_all=True)


@pytest.mark.parametrize('bad', ['bad"name', 'a b.com', 'x;y.com', 'ca.com"; issue "evil.com', '', 'nodots', '-a.com'])
def test_generate_rejects_injection_in_ca_names(bad):
    with pytest.raises(ValueError):
        caa_dane.generate_caa('example.com', [bad])


@pytest.mark.parametrize('bad', ['mailto:', 'ftp://x', 'a@b.com', 'mailto:a@b.com"; issue "x'])
def test_generate_rejects_bad_iodef(bad):
    with pytest.raises(ValueError):
        caa_dane.generate_caa('example.com', ['letsencrypt.org'], iodef=bad)


# --------------------------------------------------------------------------- TLSA
import hashlib
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DER = serialization.Encoding.DER
SPKI = serialization.PublicFormat.SubjectPublicKeyInfo


def _make_cert(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode(), cert.public_bytes(DER), cert.public_key().public_bytes(DER, SPKI)


def _digest(data, matching):
    return {0: data, 1: hashlib.sha256(data).digest(), 2: hashlib.sha512(data).digest()}[matching]


@pytest.mark.parametrize('selector', [0, 1])
@pytest.mark.parametrize('matching', [0, 1, 2])
@pytest.mark.parametrize('usage', [0, 1, 2, 3])
def test_generate_tlsa_all_combinations(usage, selector, matching):
    pem, der, spki = _make_cert('leaf.example.com')
    r = caa_dane.generate_tlsa(pem, 'leaf.example.com', 443, 'tcp', usage, selector, matching)
    data = _digest(der if selector == 0 else spki, matching).hex()
    assert r['name'] == '_443._tcp.leaf.example.com'
    assert r['rdata'] == f'{usage} {selector} {matching} {data}'
    assert r['record'] == f'_443._tcp.leaf.example.com. IN TLSA {usage} {selector} {matching} {data}'


def test_generate_tlsa_chain_uses_first_certificate_and_says_so():
    pem1, der1, spki1 = _make_cert('one.example.com')
    pem2, _, _ = _make_cert('two.example.com')
    r = caa_dane.generate_tlsa(pem1 + pem2, 'one.example.com')
    assert r['rdata'].endswith(hashlib.sha256(spki1).hexdigest())
    assert any('first' in n for n in r['notes'])


@pytest.mark.parametrize('pem', ['', 'garbage', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----', None])
def test_generate_tlsa_rejects_bad_certificates(pem):
    with pytest.raises(ValueError):
        caa_dane.generate_tlsa(pem, 'example.com')


@pytest.mark.parametrize('kwargs', [{'usage': 4}, {'selector': 2}, {'matching_type': 3}, {'port': 0}, {'port': 70000},
                                    {'protocol': 'icmp'}, {'host': 'not a host'}])
def test_generate_tlsa_rejects_bad_parameters(kwargs):
    pem, _, _ = _make_cert('example.com')
    args = {'host': 'example.com', **kwargs}
    with pytest.raises(ValueError):
        caa_dane.generate_tlsa(pem, **args)


def fake_tlsa(monkeypatch, records, ad=True, error=None, chain=None, chain_error=None):
    monkeypatch.setattr(caa_dane, '_tlsa_lookup', lambda name: (records, ad, error))

    def fetch(host, port, timeout=10):
        if chain_error:
            raise OSError(chain_error)
        return chain

    monkeypatch.setattr(caa_dane, '_fetch_peer_chain', fetch)


def test_check_tlsa_match(monkeypatch):
    _, leaf, spki = _make_cert('example.com')
    fake_tlsa(monkeypatch, [(3, 1, 1, hashlib.sha256(spki).digest())], chain=[leaf])
    r = caa_dane.check_tlsa('example.com')
    assert r['name'] == '_443._tcp.example.com'
    assert r['matched'] is True and r['records'][0]['match'] is True and r['dnssec_ad'] is True
    assert not [f for f in r['findings'] if f['severity'] in ('error', 'warning')]


def test_check_tlsa_mismatch_is_an_error(monkeypatch):
    _, leaf, _ = _make_cert('example.com')
    fake_tlsa(monkeypatch, [(3, 1, 1, b'\x00' * 32)], chain=[leaf])
    r = caa_dane.check_tlsa('example.com')
    assert r['matched'] is False and r['records'][0]['match'] is False
    assert any(f['severity'] == 'error' and 'None of the TLSA records' in f['message'] for f in r['findings'])


def test_check_tlsa_usage_2_matches_a_chain_certificate(monkeypatch):
    _, leaf, _ = _make_cert('leaf.example.com')
    _, ca, _ = _make_cert('ca.example.com')
    fake_tlsa(monkeypatch, [(2, 0, 1, hashlib.sha256(ca).digest())], chain=[leaf, ca])
    assert caa_dane.check_tlsa('leaf.example.com')['matched'] is True
    fake_tlsa(monkeypatch, [(3, 0, 1, hashlib.sha256(ca).digest())], chain=[leaf, ca])  # usage 3 is leaf only
    assert caa_dane.check_tlsa('leaf.example.com')['matched'] is False


def test_check_tlsa_without_record_does_not_connect(monkeypatch):
    fake_tlsa(monkeypatch, [], chain_error='must not connect')
    r = caa_dane.check_tlsa('example.com')
    assert r['records'] == [] and r['matched'] is False
    assert any('No TLSA record' in f['message'] for f in r['findings'])


def test_check_tlsa_warns_without_dnssec(monkeypatch):
    _, leaf, spki = _make_cert('example.com')
    fake_tlsa(monkeypatch, [(3, 1, 1, hashlib.sha256(spki).digest())], ad=False, chain=[leaf])
    r = caa_dane.check_tlsa('example.com')
    assert r['dnssec_ad'] is False
    assert any(f['severity'] == 'warning' and 'DNSSEC' in f['message'] for f in r['findings'])


def test_check_tlsa_connection_failure_is_reported(monkeypatch):
    fake_tlsa(monkeypatch, [(3, 1, 1, b'\x00' * 32)], chain_error='connection refused')
    r = caa_dane.check_tlsa('example.com')
    assert r['records'][0]['match'] is None and r['matched'] is False
    assert any(f['severity'] == 'error' and 'connection refused' in f['message'] for f in r['findings'])


def test_check_tlsa_dns_failure(monkeypatch):
    fake_tlsa(monkeypatch, [], error='FAILURE: Timeout')
    r = caa_dane.check_tlsa('example.com')
    assert any(f['severity'] == 'error' and 'Timeout' in f['message'] for f in r['findings'])


@pytest.mark.parametrize('kwargs', [{'port': 0}, {'protocol': 'x'}, {'host': ''}])
def test_check_tlsa_validates_input(kwargs):
    with pytest.raises(ValueError):
        caa_dane.check_tlsa(**{'host': 'example.com', **kwargs})


# --------------------------------------------------------------------------- routes
def test_route_caa_check(client, monkeypatch):
    fake_dns(monkeypatch, {'example.com': [(0, 'issue', 'letsencrypt.org')]})
    resp = client.post('/api/caa/check', json={'domain': 'example.com'})
    body = resp.get_json()
    assert resp.status_code == 200 and body['success'] is True
    assert body['result']['issuers'][0]['ca'] == 'letsencrypt.org'


def test_route_caa_check_bad_input_is_400(client):
    assert client.post('/api/caa/check', json={}).status_code == 400
    assert client.post('/api/caa/check', json={'domain': 'not a domain'}).status_code == 400
    assert client.post('/api/caa/check', data='nope', content_type='text/plain').status_code == 400


def test_route_caa_generate(client):
    resp = client.post('/api/caa/generate', json={'domain': 'example.com', 'issuers': ['letsencrypt.org'], 'dns01_only': True})
    assert resp.status_code == 200
    assert 'validationmethods=dns-01' in resp.get_json()['result']['records'][0]
    bad = client.post('/api/caa/generate', json={'domain': 'example.com', 'issuers': []})
    assert bad.status_code == 400 and 'error' in bad.get_json()


def test_route_dane_generate(client, sample_cert_pem):
    resp = client.post('/api/dane/generate', json={'certificate': sample_cert_pem, 'host': 'test.example.com'})
    assert resp.status_code == 200
    assert resp.get_json()['result']['name'] == '_443._tcp.test.example.com'
    assert client.post('/api/dane/generate', json={'certificate': 'junk', 'host': 'example.com'}).status_code == 400
    assert client.post('/api/dane/generate', json={'certificate': 'x' * 70000, 'host': 'example.com'}).status_code == 400


def test_route_dane_check(client, monkeypatch):
    fake_tlsa(monkeypatch, [])
    resp = client.post('/api/dane/check', json={'host': 'example.com'})
    assert resp.status_code == 200 and resp.get_json()['result']['port'] == 443
    assert client.post('/api/dane/check', json={'host': 'example.com', 'port': 'abc'}).status_code == 400


def test_route_unexpected_failure_is_a_generic_500(client, monkeypatch):
    def boom(domain):
        raise RuntimeError('secret internals')
    monkeypatch.setattr(caa_dane, 'check_caa', boom)
    resp = client.post('/api/caa/check', json={'domain': 'example.com'})
    assert resp.status_code == 500 and 'secret internals' not in resp.get_data(as_text=True)
