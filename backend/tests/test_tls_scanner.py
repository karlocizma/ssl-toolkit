import socket
import ssl
import threading

import pytest

from app.services import security_headers as sh
from app.services import tls_scanner as tls


def proto(supported, ciphers=()):
    return {'supported': supported, 'ciphers': [
        {'name': n, 'forward_secrecy': n.startswith('ECDHE'), **({'weakness': tls.classify_cipher(n)} if tls.classify_cipher(n) else {})}
        for n in ciphers]}


GOOD = {'TLSv1.0': proto(False), 'TLSv1.1': proto(False),
        'TLSv1.2': proto(True, ['ECDHE-RSA-AES128-GCM-SHA256']), 'TLSv1.3': proto(True, ['TLS_AES_256_GCM_SHA384'])}


def test_modern_config_is_a():
    assert tls.grade_results(GOOD, True)['grade'] == 'A'


def test_no_tls13_is_a_minus():
    p = dict(GOOD, **{'TLSv1.3': proto(False)})
    assert tls.grade_results(p, True)['grade'] == 'A-'


def test_legacy_protocol_caps_at_b():
    assert tls.grade_results(dict(GOOD, **{'TLSv1.0': proto(True)}), True)['grade'] == 'B'


def test_weak_cipher_caps_at_c_and_critical_is_f():
    p = dict(GOOD, **{'TLSv1.2': proto(True, ['ECDHE-RSA-AES128-GCM-SHA256', 'DES-CBC3-SHA'])})
    assert tls.grade_results(p, True)['grade'] == 'C'
    p = dict(GOOD, **{'TLSv1.2': proto(True, ['ECDHE-RSA-AES128-GCM-SHA256', 'NULL-SHA'])})
    assert tls.grade_results(p, True)['grade'] == 'F'


def test_untrusted_cert_and_no_modern_tls_fail():
    assert tls.grade_results(GOOD, False)['grade'] == 'F'
    old = {'TLSv1.0': proto(True), 'TLSv1.1': proto(False), 'TLSv1.2': proto(False), 'TLSv1.3': proto(False)}
    assert tls.grade_results(old, True)['grade'] == 'F'


def test_no_forward_secrecy_caps_at_b():
    p = dict(GOOD, **{'TLSv1.2': proto(True, ['AES128-GCM-SHA256'])})
    assert tls.grade_results(p, True)['grade'] == 'B'


@pytest.fixture
def tls_server(tmp_path, sample_cert_pem, sample_key_pem):
    cert, key = tmp_path / 'c.pem', tmp_path / 'k.pem'
    cert.write_text(sample_cert_pem)
    key.write_text(sample_key_pem)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(64)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            try:
                ctx.wrap_socket(conn, server_side=True).close()
            except (ssl.SSLError, OSError):
                conn.close()
    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1]
    stop.set()
    srv.close()


def test_live_scan_against_local_server(tls_server, monkeypatch):
    monkeypatch.setenv('ALLOW_PRIVATE_TARGETS', 'true')
    result = tls.scan_tls('127.0.0.1', tls_server, timeout=3)
    assert result['reachable']
    assert result['protocols']['TLSv1.2']['supported'] and result['protocols']['TLSv1.3']['supported']
    assert not result['protocols']['TLSv1.0']['supported']
    assert result['certificate_trusted'] is False  # self-signed
    assert result['grade'] == 'F'


def test_scan_blocks_internal_by_default(client, monkeypatch):
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    resp = client.post('/api/check/tls', json={'hostname': '127.0.0.1'})
    assert resp.status_code == 400
    assert client.post('/api/check/tls', json={}).status_code == 400
    assert client.post('/api/check/headers', json={'url': 'http://169.254.169.254/'}).status_code == 400


GOOD_HEADERS = {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'server': 'nginx',
}


def test_header_audit_perfect_score():
    result = sh.audit_headers(GOOD_HEADERS, [], True)
    assert result['score'] == 100 and result['grade'] == 'A+'


def test_header_audit_empty_is_f():
    result = sh.audit_headers({}, [], True)
    assert result['grade'] == 'F'


def test_csp_unsafe_inline_penalised():
    h = dict(GOOD_HEADERS, **{'Content-Security-Policy': "default-src 'self' 'unsafe-inline'"})
    csp = next(c for c in sh.audit_headers(h, [], True)['checks'] if c['header'] == 'Content-Security-Policy')
    assert csp['status'] == 'warn'


def test_hsts_short_max_age_and_http():
    assert sh.check_hsts('max-age=300', True)['status'] == 'warn'
    assert sh.check_hsts('max-age=31536000', False)['status'] == 'fail'


def test_version_disclosure_and_cookies():
    assert sh.check_disclosure({'server': 'Apache/2.4.1', 'x-powered-by': 'PHP/8'})['status'] == 'warn'
    assert sh.check_cookies(['sid=1; Path=/'], True)['status'] == 'warn'
    assert sh.check_cookies(['sid=1; Secure; HttpOnly; SameSite=Lax'], True)['status'] == 'pass'
