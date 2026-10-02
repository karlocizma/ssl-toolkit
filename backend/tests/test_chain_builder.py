from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from app.services import chain_builder as cb

NOW = datetime.now(timezone.utc)
REAL_TRUST_STORE = cb._trust_store  # the autouse fixture below replaces cb._trust_store


def make(subject, issuer_name, key, signer, ca, days=365, start=-1, aia=None, hash_=hashes.SHA256()):
    builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
               .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(NOW + timedelta(days=start)).not_valid_after(NOW + timedelta(days=days))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if aia:
        builder = builder.add_extension(x509.AuthorityInformationAccess(
            [x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier(aia))]), critical=False)
    return builder.sign(signer, hash_)


@pytest.fixture(scope='module')
def pki():
    k = {n: ec.generate_private_key(ec.SECP256R1()) for n in ('root', 'int', 'leaf', 'other')}
    root = make('Test Root', 'Test Root', k['root'], k['root'], True, days=3650)
    inter = make('Test Intermediate', 'Test Root', k['int'], k['root'], True, days=1800)
    leaf = make('www.example.test', 'Test Intermediate', k['leaf'], k['int'], False, aia='http://aia.test/int.cer')
    stray = make('Unrelated CA', 'Unrelated CA', k['other'], k['other'], True)
    return {'root': root, 'int': inter, 'leaf': leaf, 'stray': stray, 'keys': k}


def pem(*certs):
    return ''.join(c.public_bytes(serialization.Encoding.PEM).decode() for c in certs)


@pytest.fixture(autouse=True)
def trust_test_root(pki, monkeypatch):
    monkeypatch.setattr(cb, '_trust_store', lambda: {pki['root'].subject.public_bytes(): [pki['root']]})
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)


class Resp:
    def __init__(self, content=b'', status=200):
        self.content, self.status_code = content, status


def serve(monkeypatch, body, status=200):
    calls = []
    monkeypatch.setattr(cb, 'safe_get', lambda url, **kw: calls.append(url) or Resp(body, status))
    return calls


def test_leaf_only_downloads_intermediate_via_aia(pki, monkeypatch):
    calls = serve(monkeypatch, pki['int'].public_bytes(serialization.Encoding.DER))
    r = cb.run({'certificate': pem(pki['leaf'])})
    assert calls == ['http://aia.test/int.cer']
    assert r['complete'] and r['trusted'] and [e['role'] for e in r['chain']] == ['leaf', 'intermediate', 'root']
    assert r['chain'][1]['source'] == 'downloaded from http://aia.test/int.cer' and r['chain'][2]['source'] == 'trust store'
    assert r['fullchain_pem'] == pem(pki['leaf'], pki['int'])  # root excluded by default
    assert r['chain_pem'] == pem(pki['int'])
    assert not [f for f in r['findings'] if f['severity'] == 'error']


def test_include_root_option(pki, monkeypatch):
    serve(monkeypatch, pki['int'].public_bytes(serialization.Encoding.DER))
    r = cb.run({'certificate': pem(pki['leaf']), 'include_root': True})
    assert r['fullchain_pem'] == pem(pki['leaf'], pki['int'], pki['root'])


def test_misordered_bundle_is_reordered_and_extras_dropped(pki, monkeypatch):
    serve(monkeypatch, b'', 404)
    r = cb.run({'certificate': pem(pki['root'], pki['stray'], pki['int'], pki['leaf'])})
    assert r['fullchain_pem'] == pem(pki['leaf'], pki['int'])
    assert r['removed_unused'] == 1 and r['complete']
    msgs = [f['message'] for f in r['findings']]
    assert any('wrong order' in m for m in msgs) and any('not part of this chain' in m for m in msgs)


@pytest.mark.parametrize('body,status,expect', [
    (b'garbage', 200, 'did not return the issuing certificate'),
    (b'', 404, 'HTTP 404'),
])
def test_incomplete_chain_reports_why(pki, monkeypatch, body, status, expect):
    serve(monkeypatch, body, status)
    r = cb.run({'certificate': pem(pki['leaf'])})
    assert not r['complete'] and not r['trusted']
    msgs = [f['message'] for f in r['findings']]
    assert any('could not be completed' in m and 'Test Intermediate' in m for m in msgs)
    assert any(expect in m for m in msgs)


def test_no_aia_extension_is_incomplete(pki):
    plain = make('plain.test', 'Test Intermediate', pki['keys']['leaf'], pki['keys']['int'], False)
    r = cb.run({'certificate': pem(plain)})
    assert not r['complete'] and r['fullchain_pem'] == pem(plain)


def test_pkcs7_aia_response(pki, monkeypatch):
    p7 = pkcs7.serialize_certificates([pki['int'], pki['stray']], serialization.Encoding.DER)
    serve(monkeypatch, p7)
    assert cb.run({'certificate': pem(pki['leaf'])})['complete']


def test_pem_aia_response(pki, monkeypatch):
    serve(monkeypatch, pem(pki['int']).encode())
    assert cb.run({'certificate': pem(pki['leaf'])})['complete']


def test_expired_intermediate_and_weak_signature_flagged(pki, monkeypatch):
    old_int = make('Test Intermediate', 'Test Root', pki['keys']['int'], pki['keys']['root'], True, days=-5, start=-400)
    leaf = make('www.example.test', 'Test Intermediate', pki['keys']['leaf'], pki['keys']['int'], False, hash_=hashes.SHA256())
    serve(monkeypatch, b'', 404)
    r = cb.run({'certificate': pem(leaf, old_int)})
    assert any(f['severity'] == 'error' and 'expired' in f['message'] and 'Intermediate' in f['message'] for f in r['findings'])


def test_untrusted_private_root_warns(pki, monkeypatch):
    monkeypatch.setattr(cb, '_trust_store', lambda: {})
    serve(monkeypatch, b'', 404)
    r = cb.run({'certificate': pem(pki['leaf'], pki['int'], pki['root'])})
    assert r['complete'] and not r['trusted']
    assert any('not in the Mozilla trust store' in f['message'] for f in r['findings'])


def test_aia_is_ssrf_guarded(pki, monkeypatch):
    from app.utils.net_safety import UnsafeTargetError

    def blocked(url, **kw):
        raise UnsafeTargetError('Target resolves to a non-public address (169.254.169.254)')
    monkeypatch.setattr(cb, 'safe_get', blocked)
    r = cb.run({'certificate': pem(pki['leaf'])})
    assert not r['complete'] and any('non-public' in f['message'] for f in r['findings'])


def test_input_validation(pki):
    for params in ({}, {'certificate': 'not a cert'}, {'certificate': pem(pki['leaf']) * 21}):
        with pytest.raises(cb.ChainError):
            cb.run(params)
    with pytest.raises(cb.ChainError, match='malformed'):
        cb.run({'certificate': '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'})


def test_hostname_mode_detects_missing_intermediate(pki, monkeypatch):
    monkeypatch.setattr(cb, 'fetch_served_chain', lambda host, port=443: [pki['leaf']])
    serve(monkeypatch, pki['int'].public_bytes(serialization.Encoding.DER))
    r = cb.run({'hostname': 'www.example.test'})
    assert r['source'] == 'server' and r['complete']
    assert r['findings'][0]['severity'] == 'error' and 'sends only the leaf' in r['findings'][0]['message']


def test_hostname_mode_blocks_internal_targets():
    with pytest.raises(cb.ChainError, match='non-public'):
        cb.run({'hostname': '127.0.0.1'})


def test_real_trust_store_loads_and_knows_mozilla_roots():
    REAL_TRUST_STORE.cache_clear()
    assert sum(len(v) for v in REAL_TRUST_STORE().values()) > 100


def test_route(client, pki, monkeypatch):
    assert client.post('/api/chain/build', json={}).status_code == 400
    serve(monkeypatch, pki['int'].public_bytes(serialization.Encoding.DER))
    resp = client.post('/api/chain/build', json={'certificate': pem(pki['leaf'])})
    assert resp.status_code == 200 and resp.get_json()['result']['complete']


# ---- real handshakes (regression: pyOpenSSL raised WantReadError on sockets with a timeout) ----
def test_real_server_chain_fetch(local_tls, monkeypatch):
    monkeypatch.setenv('ALLOW_PRIVATE_TARGETS', 'true')
    certs = cb.fetch_served_chain('127.0.0.1', local_tls)
    assert len(certs) == 1
    r = cb.run({'hostname': '127.0.0.1', 'port': local_tls})
    assert r['source'] == 'server' and r['complete'] and r['chain'][0]['role'] == 'leaf'


def test_existing_chain_checker_works_against_a_real_server(local_tls, monkeypatch):
    from app.services.ssl_checker import check_certificate_chain
    monkeypatch.setenv('ALLOW_PRIVATE_TARGETS', 'true')
    r = check_certificate_chain('127.0.0.1', local_tls, 5)
    assert 'error' not in r and r['chain_length'] == 1
    assert r['chain_valid'] is False and 'self-signed' in r['verification_error']
    assert r['certificates'][0]['subject']['common_name'] == 'test.example.com'
