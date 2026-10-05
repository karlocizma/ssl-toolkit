import base64
import gzip
import json
from datetime import datetime, timezone

import pytest
import requests

from app.services import mail_transport as mt

POLICY = 'version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.mx.example.com\r\nmax_age: 1209600\r\n'


class Resp:
    def __init__(self, status=200, text=POLICY, ctype='text/plain'):
        self.status_code, self.text, self.headers = status, text, {'Content-Type': ctype}


@pytest.fixture
def dns(monkeypatch):
    state = {'txt': {'_mta-sts.example.com': ['v=STSv1; id=20260101000000']}, 'mx': ['mail.example.com', 'a.mx.example.com']}
    monkeypatch.setattr(mt, '_txt', lambda name: (state['txt'].get(name, []), None))
    monkeypatch.setattr(mt, '_mx_hosts', lambda d: state['mx'])
    return state


def messages(result, severity=None):
    return [f['message'] for f in result['findings'] if severity in (None, f['severity'])]


@pytest.mark.parametrize('pattern,host,expected', [
    ('mail.example.com', 'MAIL.example.com.', True), ('*.example.com', 'a.example.com', True),
    ('*.example.com', 'a.b.example.com', False), ('*.example.com', 'example.com', False),
    ('mail.example.com', 'other.example.com', False)])
def test_mx_pattern_matching(pattern, host, expected):
    assert mt._mx_matches(pattern, host) is expected


def test_valid_policy_is_ok(dns, monkeypatch):
    monkeypatch.setattr(mt, 'safe_get', lambda url, **kw: Resp())
    r = mt.check_mta_sts('example.com')
    assert r['status'] == 'ok' and r['policy']['mode'] == 'enforce' and r['id'] == '20260101000000'
    assert all(c['covered'] for c in r['mx_coverage'])


def test_missing_record(dns, monkeypatch):
    dns['txt'] = {}
    r = mt.check_mta_sts('example.com')
    assert r['status'] == 'missing' and 'No MTA-STS record' in messages(r)[0]


def test_enforce_with_uncovered_mx_is_an_error(dns, monkeypatch):
    dns['mx'].append('backup.other.net')
    monkeypatch.setattr(mt, 'safe_get', lambda url, **kw: Resp())
    r = mt.check_mta_sts('example.com')
    assert r['status'] == 'error' and any('backup.other.net' in m and 'refuse' in m for m in messages(r, 'error'))


def test_testing_mode_and_short_max_age_warn(dns, monkeypatch):
    monkeypatch.setattr(mt, 'safe_get', lambda url, **kw: Resp(text=POLICY.replace('enforce', 'testing')))
    assert any('testing' in m for m in messages(mt.check_mta_sts('example.com'), 'warning'))
    monkeypatch.setattr(mt, 'safe_get', lambda url, **kw: Resp(text=POLICY.replace('1209600', '3600')))
    assert any('under a day' in m for m in messages(mt.check_mta_sts('example.com'), 'warning'))


@pytest.mark.parametrize('resp,expected', [
    (Resp(301), 'redirects'), (Resp(404), 'HTTP 404'),
    (Resp(text='mode: enforce\r\nmx: mail.example.com\r\nmax_age: x'), 'STSv1')])
def test_policy_problems(dns, monkeypatch, resp, expected):
    monkeypatch.setattr(mt, 'safe_get', lambda url, **kw: resp)
    r = mt.check_mta_sts('example.com')
    assert r['status'] == 'error' and any(expected in m for m in messages(r, 'error'))


def test_certificate_and_fetch_errors(dns, monkeypatch):
    def bad_cert(url, **kw):
        raise requests.exceptions.SSLError('x')
    monkeypatch.setattr(mt, 'safe_get', bad_cert)
    assert any('not valid' in m for m in messages(mt.check_mta_sts('example.com'), 'error'))
    monkeypatch.setattr(mt, 'safe_get', lambda url, **kw: (_ for _ in ()).throw(ConnectionError('down')))
    assert any('could not be fetched' in m for m in messages(mt.check_mta_sts('example.com'), 'error'))


def test_duplicate_records_and_bad_id(dns, monkeypatch):
    dns['txt']['_mta-sts.example.com'] = ['v=STSv1; id=bad id!', 'v=STSv1; id=2']
    monkeypatch.setattr(mt, 'safe_get', lambda url, **kw: Resp())
    errors = messages(mt.check_mta_sts('example.com'), 'error')
    assert any('Several' in m for m in errors) and any('id of 1 to 32' in m for m in errors)


def test_verify_mx_flags_missing_starttls_and_untrusted_certificates(dns, monkeypatch):
    monkeypatch.setattr(mt, 'safe_get', lambda url, **kw: Resp())
    scans = {'mail.example.com': {'reachable': True, 'starttls': False},
             'a.mx.example.com': {'reachable': True, 'starttls': True, 'certificate_trusted': False, 'grade': 'F'}}
    import app.services.mail_tls as mail_tls
    monkeypatch.setattr(mail_tls, 'scan_mail', lambda host, *a, **k: scans[host])
    errors = messages(mt.check_mta_sts('example.com', verify_mx=True), 'error')
    assert any('mail.example.com does not offer STARTTLS' in m for m in errors)
    assert any('a.mx.example.com presents a certificate' in m for m in errors)


def test_generate_policy_and_record():
    r = mt.generate_mta_sts('example.com', 'enforce', ['Mail.Example.com.', '*.mx.example.com'], 86400,
                            now=datetime(2026, 10, 5, 12, 30, 1, tzinfo=timezone.utc))
    assert r['policy'] == 'version: STSv1\r\nmode: enforce\r\nmx: mail.example.com\r\nmx: *.mx.example.com\r\nmax_age: 86400\r\n'
    assert r['dns_record'] == 'v=STSv1; id=20261005123001'
    assert r['policy_url'] == 'https://mta-sts.example.com/.well-known/mta-sts.txt'
    for bad in (dict(mode='strict'), dict(max_age=-1), dict(mx=['bad host'])):
        with pytest.raises(ValueError):
            mt.generate_mta_sts('example.com', **{'mode': 'testing', 'mx': ['a.example.com'], **bad})


def test_generate_policy_uses_mx_records_by_default(dns):
    assert 'mx: mail.example.com' in mt.generate_mta_sts('example.com')['policy']
    dns['mx'] = []
    with pytest.raises(ValueError, match='No MX hosts'):
        mt.generate_mta_sts('example.com')


def test_tls_rpt_check_and_generate(monkeypatch):
    txt = {'_smtp._tls.example.com': ['v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://rpt.example.com/in']}
    monkeypatch.setattr(mt, '_txt', lambda name: (txt.get(name, []), None))
    r = mt.check_tls_rpt('example.com')
    assert r['status'] == 'ok' and [d['valid'] for d in r['destinations']] == [True, True]
    txt['_smtp._tls.example.com'] = ['v=TLSRPTv1; rua=http://insecure.example.com,mailto:nobody']
    bad = mt.check_tls_rpt('example.com')
    assert bad['status'] == 'error' and len(messages(bad, 'error')) == 2
    txt.clear()
    assert mt.check_tls_rpt('example.com')['status'] == 'missing'
    assert mt.generate_tls_rpt('example.com', ['tlsrpt@example.com', 'https://rpt.example.com/x'])['dns_record'] == \
        'v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://rpt.example.com/x'
    for rua in ([], ['nope'], ['http://x.example']):
        with pytest.raises(ValueError):
            mt.generate_tls_rpt('example.com', rua)


REPORT = {
    'organization-name': 'Google Inc.', 'report-id': 'r1', 'contact-info': 'smtp-tls-reporting@google.com',
    'date-range': {'start-datetime': '2026-10-04T00:00:00Z', 'end-datetime': '2026-10-04T23:59:59Z'},
    'policies': [{'policy': {'policy-type': 'sts', 'policy-domain': 'example.com', 'mx-host': ['mail.example.com']},
                  'summary': {'total-successful-session-count': 90, 'total-failure-session-count': 10},
                  'failure-details': [{'result-type': 'certificate-expired', 'receiving-mx-hostname': 'mail.example.com',
                                       'sending-mta-ip': '203.0.113.5', 'failed-session-count': 10}]}]}


@pytest.mark.parametrize('params', [
    {'json': json.dumps(REPORT)},
    {'file_base64': base64.b64encode(gzip.compress(json.dumps(REPORT).encode())).decode()}])
def test_parse_tls_rpt_report(params):
    r = mt.parse_tls_rpt_report(params)
    assert r['successful'] == 90 and r['failed'] == 10 and r['success_rate'] == 90.0
    assert r['organization'] == 'Google Inc.' and r['policies'][0]['failures'][0]['count'] == 10
    assert 'certificate has expired' in r['findings'][0]['message']


@pytest.mark.parametrize('params', [{}, {'json': 'nope'}, {'json': '{"a": 1}'}, {'file_base64': '!!'}])
def test_parse_tls_rpt_report_rejects_bad_input(params):
    with pytest.raises(ValueError):
        mt.parse_tls_rpt_report(params)


def test_routes(client, dns, monkeypatch):
    monkeypatch.setattr(mt, 'safe_get', lambda url, **kw: Resp())
    assert client.post('/api/email/mta-sts', json={'domain': 'example.com'}).get_json()['result']['status'] == 'ok'
    assert client.post('/api/email/mta-sts', json={'domain': 'bad'}).status_code == 400
    r = client.post('/api/email/mta-sts/generate', json={'domain': 'example.com', 'mode': 'enforce'})
    assert r.get_json()['result']['policy'].startswith('version: STSv1')
    assert client.post('/api/email/mta-sts/generate', json={'domain': 'example.com', 'mode': 'x'}).status_code == 400
    assert client.post('/api/email/tls-rpt/generate', json={'domain': 'example.com', 'rua': ['a@example.com']}).status_code == 200
    assert client.post('/api/email/tls-rpt/generate', json={'domain': 'example.com'}).status_code == 400
    ok = client.post('/api/email/tls-rpt/report', json={'json': json.dumps(REPORT)})
    assert ok.get_json()['result']['failed'] == 10
    assert client.post('/api/email/tls-rpt/report', json={}).status_code == 400
    assert client.post('/api/email/tls-rpt', json={'domain': 'example.com'}).status_code == 200


def test_cli(dns, monkeypatch, capsys):
    from app import cli
    monkeypatch.setattr(mt, 'safe_get', lambda url, **kw: Resp())
    assert cli.main(['mtasts', 'example.com', '--require-enforce']) == 0
    monkeypatch.setattr(mt, 'safe_get', lambda url, **kw: Resp(text=POLICY.replace('enforce', 'testing')))
    assert cli.main(['mtasts', 'example.com', '--require-enforce']) == 1
    assert 'FAIL' in capsys.readouterr().out
