import json
import socket
import ssl
import threading

import pytest

from app import cli


def run(capsys, *argv):
    code = cli.main(list(argv))
    return code, capsys.readouterr().out


@pytest.mark.parametrize('value,expected', [
    ('example.com', ('example.com', 443)), ('example.com:8443', ('example.com', 8443)),
    ('https://example.com/path?q=1', ('example.com', 443)), ('http://example.com:8080/x', ('example.com', 8080)),
    ('  example.com  ', ('example.com', 443)), ('2001:db8::1', ('2001:db8::1', 443)),
])
def test_split_host(value, expected):
    assert cli.split_host(value) == expected


@pytest.mark.parametrize('grade,minimum,ok', [('A', 'B', True), ('B', 'B', True), ('A-', 'A', False),
                                              ('C', 'B', False), ('A+', 'A', True), ('X', 'B', False)])
def test_grade_at_least(grade, minimum, ok):
    assert cli.grade_at_least(grade, minimum) is ok


def cert_result(days, secure=True, valid_host=True):
    return {'connection_secure': secure, 'valid_for_hostname': valid_host,
            'certificate': {'validity': {'days_until_expiry': days}, 'issuer': {'common_name': "Let's Encrypt R3"}},
            'errors': [] if secure else ['Certificate verification failed: expired']}


def test_check_exit_codes_and_threshold(monkeypatch, capsys):
    monkeypatch.setattr('app.services.ssl_checker.check_ssl_certificate',
                        lambda host, port, timeout: cert_result({'ok.test': 60, 'soon.test': 5}[host]))
    code, out = run(capsys, 'check', 'ok.test')
    assert code == 0 and 'OK' in out and 'expires in 60 day(s)' in out
    code, out = run(capsys, 'check', 'soon.test')
    assert code == 1 and 'FAIL' in out and 'threshold 14' in out
    assert run(capsys, 'check', 'soon.test', '--fail-under', '3')[0] == 0
    code, out = run(capsys, 'check', 'ok.test', 'soon.test')  # several targets: worst result wins
    assert code == 1 and out.count('\n') == 2


def test_check_failures(monkeypatch, capsys):
    monkeypatch.setattr('app.services.ssl_checker.check_ssl_certificate',
                        lambda host, port, timeout: cert_result(30, secure=False) if host == 'bad.test' else cert_result(30, valid_host=False))
    code, out = run(capsys, 'check', 'bad.test')
    assert code == 1 and 'expired' in out
    code, out = run(capsys, 'check', 'mismatch.test')
    assert code == 1 and 'hostname does not match' in out


def test_errors_give_exit_code_2_and_do_not_stop_other_targets(monkeypatch, capsys):
    def fake(host, port, timeout):
        if host == 'boom.test':
            raise RuntimeError('network down')
        return cert_result(60)
    monkeypatch.setattr('app.services.ssl_checker.check_ssl_certificate', fake)
    code, out = run(capsys, 'check', 'boom.test', 'ok.test')
    assert code == 2 and 'ERROR boom.test' in out and 'OK' in out


def test_json_output(monkeypatch, capsys):
    monkeypatch.setattr('app.services.ssl_checker.check_ssl_certificate', lambda h, p, t: cert_result(40))
    code, out = run(capsys, 'check', 'a.test:8443', '--json')
    payload = json.loads(out)
    assert code == 0 and payload['exit_code'] == 0 and payload['results'][0]['passed'] is True
    assert payload['results'][0]['result']['certificate']['validity']['days_until_expiry'] == 40


def test_tls_min_grade(monkeypatch, capsys):
    monkeypatch.setattr('app.services.tls_scanner.scan_tls', lambda h, p, t: {
        'reachable': True, 'grade': 'C', 'findings': [{'severity': 'warning', 'message': 'TLSv1.0 is deprecated'}]})
    code, out = run(capsys, 'tls', 'a.test')
    assert code == 1 and 'grade C (minimum B)' in out and 'TLSv1.0 is deprecated' in out
    assert run(capsys, 'tls', 'a.test', '--min-grade', 'C')[0] == 0
    monkeypatch.setattr('app.services.tls_scanner.scan_tls', lambda h, p, t: {'reachable': False, 'error': 'refused'})
    assert run(capsys, 'tls', 'a.test')[0] == 1


def test_headers_email_chain_ct_autodiscover(monkeypatch, capsys):
    monkeypatch.setattr('app.services.security_headers.check_security_headers', lambda t: {
        'score': 55, 'grade': 'C', 'checks': [{'status': 'fail', 'header': 'Content-Security-Policy', 'detail': 'missing'}]})
    code, out = run(capsys, 'headers', 'https://a.test')
    assert code == 1 and 'Content-Security-Policy' in out and run(capsys, 'headers', 'a.test', '--min-score', '50')[0] == 0
    monkeypatch.setattr('app.services.deliverability.check_deliverability', lambda d: {
        'domain': d, 'score': 90, 'grade': 'A', 'findings': [{'severity': 'info', 'message': 'hidden'}]})
    code, out = run(capsys, 'email', 'a.test')
    assert code == 0 and 'score 90/100' in out and 'hidden' not in out
    monkeypatch.setattr('app.services.chain_builder.run', lambda p: {
        'complete': False, 'chain': [{}], 'findings': [{'severity': 'error', 'message': 'issuer missing'}]})
    code, out = run(capsys, 'chain', 'a.test')
    assert code == 1 and 'INCOMPLETE' in out and 'issuer missing' in out
    seen = {}

    def fake_ct(d, expected_issuers=None):
        seen['expected'] = expected_issuers
        return {'domain': d, 'total_certificates': 3, 'subdomains': [1], 'active_certificates': 2,
                'findings': [{'severity': 'warning', 'message': 'issued by an unexpected CA: Evil'}]}
    monkeypatch.setattr('app.services.ct_lookup.lookup', fake_ct)
    code, out = run(capsys, 'ct', 'a.test', '--expected-issuer', "Let's Encrypt", '--expected-issuer', 'DigiCert')
    assert code == 1 and seen['expected'] == ["Let's Encrypt", 'DigiCert'] and 'unexpected CA' in out
    monkeypatch.setattr('app.services.autodiscover.check_autodiscover', lambda d: {'domain': d, 'status': 'partial', 'findings': []})
    assert run(capsys, 'autodiscover', 'a.test')[0] == 1


def test_usage_errors_exit_2():
    with pytest.raises(SystemExit) as e:
        cli.main(['check'])
    assert e.value.code == 2
    with pytest.raises(SystemExit) as e:
        cli.main(['nonsense', 'x'])
    assert e.value.code == 2


def test_private_targets_allowed_by_default():
    import os
    assert os.environ.get('ALLOW_PRIVATE_TARGETS') in ('true', 'false')  # set by the CLI unless the user chose


# ---- real runs against a local TLS server (no mocks) ------------------------------------------
def test_real_check_against_untrusted_self_signed_server(local_tls, capsys):
    code, out = run(capsys, 'check', f'127.0.0.1:{local_tls}')
    assert code == 1 and 'FAIL' in out  # self-signed: verification fails, which is the correct CI result


def test_real_tls_against_local_server(local_tls, capsys):
    code, out = run(capsys, 'tls', f'127.0.0.1:{local_tls}', '--timeout', '3')
    assert code == 1 and 'grade F' in out  # untrusted certificate caps the grade


def test_real_chain_against_local_server(local_tls, capsys):
    # a self-signed server certificate is a complete chain of one, but not a trusted one
    code, out = run(capsys, 'chain', f'127.0.0.1:{local_tls}')
    assert code == 0 and 'chain complete, 1 certificate(s)' in out
