import pytest
import requests

from app.services import autodiscover as ad

POX_OK = """<?xml version="1.0"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
<Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
<Account><AccountType>email</AccountType><Action>settings</Action>
<Protocol><Type>IMAP</Type><Server>imap.example.com</Server><Port>993</Port><SSL>on</SSL><LoginName>a@example.com</LoginName></Protocol>
<Protocol><Type>SMTP</Type><Server>smtp.example.com</Server><Port>587</Port></Protocol>
</Account></Response></Autodiscover>"""
POX_REDIRECT = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
<Response><Account><Action>redirectAddr</Action><RedirectAddr>user@other.example</RedirectAddr></Account></Response></Autodiscover>"""
POX_ERROR = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
<Response><Error><Message>The email address can't be found.</Message></Error></Response></Autodiscover>"""
AUTOCONFIG = """<clientConfig version="1.1"><emailProvider id="example.com"><displayName>Example Mail</displayName>
<incomingServer type="imap"><hostname>imap.example.com</hostname><port>993</port><socketType>SSL</socketType>
<authentication>password-cleartext</authentication><username>%EMAILADDRESS%</username></incomingServer>
<outgoingServer type="smtp"><hostname>smtp.example.com</hostname><port>587</port><socketType>STARTTLS</socketType></outgoingServer>
</emailProvider></clientConfig>"""


def test_parse_pox_settings_redirect_and_error():
    parsed = ad.parse_pox_response(POX_OK)
    assert [p['Type'] for p in parsed['protocols']] == ['IMAP', 'SMTP']
    assert parsed['protocols'][0]['Server'] == 'imap.example.com' and parsed['protocols'][0]['Port'] == '993'
    assert ad.parse_pox_response(POX_REDIRECT)['redirect_address'] == 'user@other.example'
    assert "can't be found" in ad.parse_pox_response(POX_ERROR)['error']


def test_parse_autoconfig():
    parsed = ad.parse_autoconfig(AUTOCONFIG)
    assert parsed['provider'] == 'Example Mail'
    assert parsed['servers'][0] == {'direction': 'incoming', 'type': 'imap', 'hostname': 'imap.example.com',
                                    'port': '993', 'security': 'SSL', 'authentication': 'password-cleartext',
                                    'username': '%EMAILADDRESS%'}
    assert parsed['servers'][1]['direction'] == 'outgoing'


@pytest.mark.parametrize('text', ['not xml', '', '<a><b></a>',
                                  '<!DOCTYPE x [<!ENTITY a "aaaa">]><clientConfig>&a;</clientConfig>'])
def test_malformed_and_entity_xml_rejected(text):
    assert ad.parse_pox_response(text) == {'valid_xml': False}
    assert ad.parse_autoconfig(text) == {'valid_xml': False}


@pytest.mark.parametrize('domain,email,expected', [
    ('Example.COM.', None, ('example.com', 'test@example.com')),
    ('', 'bob@Example.com', ('example.com', 'bob@Example.com')),
])
def test_normalize_target(domain, email, expected):
    assert ad.normalize_target(domain, email) == expected


@pytest.mark.parametrize('domain,email', [('not a domain', None), ('localhost', None), ('x.com/path', None),
                                          ('127.0.0.1', None), ('', 'bob@10.0.0.1'), ('', 'no-at-sign'), ('example.com', 'a b@example.com')])
def test_normalize_target_rejects(domain, email):
    with pytest.raises(ValueError):
        ad.normalize_target(domain, email)


class FakeResp:
    def __init__(self, status=200, text='', headers=None):
        self.status_code, self.text, self.headers = status, text, headers or {}


def fake_http(table):
    """table: {url: FakeResp | Exception}; unknown URLs fail to resolve."""
    def _http(method, url, **kw):
        result = table.get(url)
        if result is None:
            raise requests.exceptions.ConnectionError("Failed to resolve: Name or service not known")
        if isinstance(result, Exception):
            raise result
        return result
    return _http


def test_probe_reports_401_as_live_endpoint(monkeypatch):
    url = 'https://autodiscover.example.com/autodiscover/autodiscover.xml'
    monkeypatch.setattr(ad, '_http', fake_http({url: FakeResp(401, headers={'WWW-Authenticate': 'Basic realm="x"'})}))
    step = ad._probe('s', 'POST', url, 'outlook', 'body')
    ad._interpret_pox(step)
    assert step['ok'] and 'requires authentication (Basic)' in step['result']


def test_probe_follows_redirects_and_records_hops(monkeypatch):
    start = 'http://autodiscover.example.com/autodiscover/autodiscover.xml'
    final = 'https://mail.example.com/autodiscover/autodiscover.xml'
    monkeypatch.setattr(ad, '_http', fake_http({
        start: FakeResp(302, headers={'Location': final}), final: FakeResp(200, POX_OK)}))
    step = ad._probe('s', 'GET', start, 'outlook')
    ad._interpret_pox(step)
    assert [h['status'] for h in step['hops']] == [302, 200] and step['final_url'] == final
    assert step['ok'] and len(step['parsed']['protocols']) == 2


def test_redirect_loop_and_dns_failure(monkeypatch):
    loop = 'https://a.example.com/x'
    monkeypatch.setattr(ad, '_http', fake_http({loop: FakeResp(302, headers={'Location': loop})}))
    step = ad._probe('s', 'GET', loop, 'outlook')
    assert 'redirects' in step['error']
    step = ad._probe('s', 'GET', 'https://nothing.example.com/x', 'outlook')
    ad._interpret_pox(step)
    assert not step['ok'] and step['result'] == 'DNS name does not resolve'


def test_unresolvable_host_raised_as_gaierror(monkeypatch):
    import socket

    def boom(method, url, **kw):
        raise socket.gaierror(-5, 'No address associated with hostname')
    monkeypatch.setattr(ad, '_http', boom)
    step = ad._probe('s', 'GET', 'https://autodiscover.example.com/x', 'outlook')
    ad._interpret_pox(step)
    assert step['result'] == 'DNS name does not resolve'


def test_tls_certificate_problem_is_explained(monkeypatch):
    url = 'https://autodiscover.example.com/autodiscover/autodiscover.xml'
    err = requests.exceptions.SSLError("certificate verify failed: Hostname mismatch, certificate is not valid for 'autodiscover.example.com'. (_ssl.c:1000)")
    monkeypatch.setattr(ad, '_http', fake_http({url: err}))
    step = ad._probe('s', 'POST', url, 'outlook', 'b')
    assert 'TLS certificate problem' in step['error'] and 'Hostname mismatch' in step['error']


def test_ssrf_guard_applies_to_probes(monkeypatch):
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    step = ad._probe('s', 'GET', 'http://127.0.0.1/autodiscover/autodiscover.xml', 'outlook')
    assert 'non-public' in step['error']


def test_full_check_with_mocked_network(monkeypatch):
    domain = 'example.com'
    table = {
        f'https://autodiscover.{domain}/autodiscover/autodiscover.xml': FakeResp(401, headers={'WWW-Authenticate': 'Negotiate'}),
        f'https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress=test%40example.com': FakeResp(200, AUTOCONFIG),
    }
    monkeypatch.setattr(ad, '_http', fake_http(table))
    monkeypatch.setattr(ad, 'lookup_cname_and_mx', lambda d: {'autodiscover_cname': None, 'mx': ['mail.example.com']})
    monkeypatch.setattr(ad, 'lookup_srv', lambda name: (
        {'name': name, 'found': True, 'records': [{'priority': 0, 'weight': 1, 'port': 993, 'target': 'imap.example.com'}]}
        if name.startswith('_imaps') else {'name': name, 'found': False, 'records': []}))
    result = ad.check_autodiscover(domain)
    assert result['status'] == 'ok' and result['outlook_autodiscover'] and result['thunderbird_autoconfig']
    assert result['rfc6186_srv']
    assert [s['step'][:2] for s in result['steps'][:3]] == ['1.', '2.', '3.']
    assert any('no submission' in f['message'] or 'submission' in f['message'] for f in result['findings'])


def test_nothing_configured_is_failed(monkeypatch):
    monkeypatch.setattr(ad, '_http', fake_http({}))
    monkeypatch.setattr(ad, 'lookup_cname_and_mx', lambda d: {'autodiscover_cname': None, 'mx': []})
    monkeypatch.setattr(ad, 'lookup_srv', lambda name: {'name': name, 'found': False, 'records': []})
    result = ad.check_autodiscover('example.org')
    assert result['status'] == 'failed'
    assert any(f['severity'] == 'error' for f in result['findings'])


def test_microsoft365_cname_warning(monkeypatch):
    monkeypatch.setattr(ad, '_http', fake_http({}))
    monkeypatch.setattr(ad, 'lookup_cname_and_mx',
                        lambda d: {'autodiscover_cname': None, 'mx': ['example-com.mail.protection.outlook.com']})
    monkeypatch.setattr(ad, 'lookup_srv', lambda name: {'name': name, 'found': False, 'records': []})
    result = ad.check_autodiscover('example.net')
    assert any('autodiscover.outlook.com' in f['message'] for f in result['findings'])


def test_route(client, monkeypatch):
    assert client.post('/api/check/autodiscover', json={}).status_code == 400
    assert client.post('/api/check/autodiscover', json={'domain': 'bad domain'}).status_code == 400
    monkeypatch.setattr(ad, 'check_autodiscover', lambda d, e=None: {'domain': d, 'status': 'ok'})
    resp = client.post('/api/check/autodiscover', json={'domain': 'example.com'})
    assert resp.status_code == 200 and resp.get_json()['result']['status'] == 'ok'
