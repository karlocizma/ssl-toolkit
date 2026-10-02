import base64
import gzip
import io
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.services import deliverability as dv


def fake_dns(monkeypatch, txt=None, hosts=(), mx=None):
    txt = txt or {}
    monkeypatch.setattr(dv, '_txt', lambda name: ([txt[name]] if isinstance(txt.get(name), str) else txt.get(name, []),
                                                  None if name in txt else 'NXDOMAIN'))
    monkeypatch.setattr(dv, '_address_exists', lambda name: name in hosts)
    monkeypatch.setattr(dv, '_mx_hosts', lambda name: (mx or {}).get(name, []))


# ------------------------------------------------------------------ SPF
def test_spf_counts_nested_lookups(monkeypatch):
    fake_dns(monkeypatch, txt={
        'example.com': 'v=spf1 include:_spf.a.com include:_spf.b.com a mx ip4:1.2.3.4 -all',
        '_spf.a.com': 'v=spf1 include:_spf.c.com ip4:5.6.7.8 ~all',
        '_spf.b.com': 'v=spf1 ip4:9.9.9.9 -all',
        '_spf.c.com': 'v=spf1 a:mail.c.com -all'},
        hosts={'example.com', 'mail.c.com'}, mx={'example.com': ['mx.example.com']})
    r = dv.analyze_spf('example.com')
    assert r['lookups'] == 6 and r['status'] == 'ok' and r['qualifier_all'] == '-'
    assert [c['domain'] for c in r['tree']['children']] == ['_spf.a.com', '_spf.b.com']
    assert r['tree']['children'][0]['children'][0]['domain'] == '_spf.c.com'


def test_spf_over_limit_is_error(monkeypatch):
    includes = ' '.join(f'include:s{i}.example.net' for i in range(11))
    txt = {'example.com': f'v=spf1 {includes} -all'}
    txt.update({f's{i}.example.net': 'v=spf1 ip4:1.1.1.1 -all' for i in range(11)})
    fake_dns(monkeypatch, txt=txt)
    r = dv.analyze_spf('example.com')
    assert r['lookups'] == 11 and r['status'] == 'error'
    assert any('exceed the limit' in f['message'] for f in r['findings'])


def test_spf_near_limit_warns(monkeypatch):
    includes = ' '.join(f'include:s{i}.example.net' for i in range(9))
    txt = {'example.com': f'v=spf1 {includes} -all'}
    txt.update({f's{i}.example.net': 'v=spf1 ip4:1.1.1.1 -all' for i in range(9)})
    fake_dns(monkeypatch, txt=txt)
    r = dv.analyze_spf('example.com')
    assert r['status'] == 'warning' and 'little room' in r['findings'][0]['message']


@pytest.mark.parametrize('record,sev,text', [
    ('v=spf1 +all', 'error', '+all'), ('v=spf1 ?all', 'warning', '?all'),
    ('v=spf1 ip4:1.2.3.4', 'warning', 'No "all"'), ('v=spf1 ptr -all', 'warning', 'ptr'),
    ('v=spf1 ip4:1.2.3.4 ~all', 'info', 'softfail'),
])
def test_spf_qualifier_findings(monkeypatch, record, sev, text):
    fake_dns(monkeypatch, txt={'example.com': record})
    r = dv.analyze_spf('example.com')
    assert any(f['severity'] == sev and text in f['message'] for f in r['findings'])


def test_spf_missing_multiple_loops_and_voids(monkeypatch):
    fake_dns(monkeypatch)
    assert dv.analyze_spf('example.com')['status'] == 'missing'
    fake_dns(monkeypatch, txt={'example.com': ['v=spf1 -all', 'v=spf1 +all']})
    assert any('2 SPF records' in f['message'] for f in dv.analyze_spf('example.com')['findings'])
    fake_dns(monkeypatch, txt={'example.com': 'v=spf1 include:a.net -all', 'a.net': 'v=spf1 include:example.com -all'})
    assert any('loop' in f['message'] for f in dv.analyze_spf('example.com')['findings'])
    fake_dns(monkeypatch, txt={'example.com': 'v=spf1 a:x.net a:y.net a:z.net -all'})
    r = dv.analyze_spf('example.com')
    assert r['void_lookups'] == 3 and any('no data' in f['message'] for f in r['findings'])


def test_spf_macro_not_followed(monkeypatch):
    fake_dns(monkeypatch, txt={'example.com': 'v=spf1 exists:%{i}._spf.example.com include:%{d}.x.net -all'})
    r = dv.analyze_spf('example.com')
    assert r['lookups'] == 2 and r['tree']['children'][0]['note'] == 'macro, not followed'


# ------------------------------------------------------------------ DKIM
def make_p(bits=2048):
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


@pytest.fixture(scope='module')
def p2048():
    return make_p(2048)


def test_dkim_discovery_and_key_strength(monkeypatch, p2048):
    weak = make_p(1024)
    fake_dns(monkeypatch, txt={f'google._domainkey.example.com': f'v=DKIM1; k=rsa; p={p2048}',
                               f'old._domainkey.example.com': f'v=DKIM1; k=rsa; p={weak}; t=y',
                               f'gone._domainkey.example.com': 'v=DKIM1; p='})
    r = dv.discover_dkim('example.com', extra_selectors=['old', 'gone', 'bad name!'])
    by = {f['selector']: f for f in r['found']}
    assert set(by) == {'google', 'old', 'gone'}
    assert by['google']['key'] == {'type': 'rsa', 'bits': 2048} and not by['google']['warnings']
    assert any('weak' in w for w in by['old']['warnings']) and any('Testing mode' in w for w in by['old']['warnings'])
    assert by['gone']['warnings'] == ['Key is revoked (empty p=)']
    assert r['status'] == 'warning'


def test_dkim_none_found_explains_custom_selectors(monkeypatch):
    fake_dns(monkeypatch)
    r = dv.discover_dkim('example.com')
    assert r['status'] == 'missing' and 'custom selector' in r['findings'][0]['message']


# ------------------------------------------------------------------ DMARC report
REPORT = """<?xml version="1.0"?><feedback>
<report_metadata><org_name>google.com</org_name><report_id>123</report_id>
<date_range><begin>1700000000</begin><end>1700086400</end></date_range></report_metadata>
<policy_published><domain>example.com</domain><adkim>r</adkim><aspf>r</aspf><p>none</p><pct>100</pct></policy_published>
<record><row><source_ip>203.0.113.5</source_ip><count>40</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
<identifiers><header_from>example.com</header_from></identifiers>
<auth_results><dkim><domain>example.com</domain><result>pass</result></dkim><spf><domain>example.com</domain><result>pass</result></spf></auth_results></record>
<record><row><source_ip>198.51.100.9</source_ip><count>7</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
<reason><type>forwarded</type></reason></policy_evaluated></row>
<identifiers><header_from>example.com</header_from></identifiers>
<auth_results><spf><domain>spammer.net</domain><result>pass</result></spf></auth_results></record>
<record><row><source_ip>203.0.113.5</source_ip><count>3</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>pass</spf></policy_evaluated></row>
<identifiers><header_from>example.com</header_from></identifiers></record>
</feedback>"""


def test_parse_report_aggregates_by_source():
    r = dv.parse_dmarc_report(REPORT)
    assert r['reporter'] == 'google.com' and r['policy']['p'] == 'none'
    assert r['total_messages'] == 50 and r['passed_messages'] == 43 and r['pass_rate'] == 86.0
    assert [s['source_ip'] for s in r['sources']] == ['198.51.100.9', '203.0.113.5']  # failures first
    ok = r['sources'][1]
    assert ok['count'] == 43 and ok['dkim_pass'] == 40 and ok['spf_pass'] == 43 and ok['fail_count'] == 0
    bad = r['sources'][0]
    assert bad['fail_count'] == 7 and bad['overrides'] == ['forwarded'] and 'spammer.net (pass)' in bad['spf_domains']
    assert 'failed DMARC' in r['findings'][0]['message']


def test_report_formats_and_limits():
    xml = REPORT.encode()
    gz = gzip.compress(xml)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('report.xml', xml)
    for payload in (xml, gz, buf.getvalue()):
        r = dv.analyze_dmarc_report({'file_base64': base64.b64encode(payload).decode()})
        assert r['total_messages'] == 50
    assert dv.analyze_dmarc_report({'xml': REPORT})['reporter'] == 'google.com'
    bomb = gzip.compress(b'<feedback>' + b'a' * (dv.MAX_REPORT_BYTES + 10) + b'</feedback>')
    with pytest.raises(ValueError, match='5 MB'):
        dv.analyze_dmarc_report({'file_base64': base64.b64encode(bomb).decode()})


@pytest.mark.parametrize('params,msg', [
    ({}, 'Provide'), ({'xml': 'nope'}, 'not valid XML'), ({'xml': '<other/>'}, 'Not a DMARC'),
    ({'xml': '<!DOCTYPE x [<!ENTITY a "b">]><feedback/>'}, 'DTD'),
])
def test_report_rejects_bad_input(params, msg):
    with pytest.raises(ValueError, match=msg):
        dv.analyze_dmarc_report(params)


# ------------------------------------------------------------------ blocklists
def test_blocklist_ip_listed_and_error_codes(monkeypatch):
    def fake(zone, qname):
        assert qname == '4.3.2.1'  # reversed
        if zone == 'bl.spamcop.net':
            return {'list': zone, 'listed': True, 'codes': ['127.0.0.2'], 'reason': 'spam source'}
        if zone == 'zen.spamhaus.org':
            return {'list': zone, 'listed': False, 'error': 'refused'}
        return {'list': zone, 'listed': False}
    monkeypatch.setattr(dv, '_query_rbl', fake)
    r = dv.check_blocklists('1.2.3.4')
    assert r['status'] == 'listed' and r['listed'][0]['list'] == 'bl.spamcop.net'
    assert any('listed on bl.spamcop.net: spam source' in f['message'] for f in r['findings'])
    assert any('could not be queried' in f['message'] for f in r['findings'])


@pytest.mark.parametrize('target', ['10.0.0.1', '127.0.0.1', '2001:db8::1', '', 'not a host'])
def test_blocklist_rejects_private_and_invalid(target):
    with pytest.raises(ValueError):
        dv.check_blocklists(target)


def test_query_rbl_interprets_codes(monkeypatch):
    class A(str):
        pass

    class Res:
        def __init__(self, answers):
            self.answers = answers

        def resolve(self, name, rtype):
            if isinstance(self.answers, Exception):
                raise self.answers
            if rtype == 'TXT':
                raise dv.dns.resolver.NXDOMAIN()
            return [A(a) for a in self.answers]
    monkeypatch.setattr(dv, '_resolver', lambda: Res(['127.255.255.254']))
    assert 'refused' in dv._query_rbl('zen.spamhaus.org', '4.3.2.1')['error']
    monkeypatch.setattr(dv, '_resolver', lambda: Res(['127.0.0.2']))
    assert dv._query_rbl('bl.spamcop.net', '4.3.2.1')['listed'] is True
    monkeypatch.setattr(dv, '_resolver', lambda: Res(dv.dns.resolver.NXDOMAIN()))
    assert dv._query_rbl('bl.spamcop.net', '4.3.2.1') == {'list': 'bl.spamcop.net', 'listed': False}


# ------------------------------------------------------------------ overview
def test_overview_scores_a_well_configured_domain(monkeypatch, p2048):
    fake_dns(monkeypatch, txt={
        'example.com': 'v=spf1 ip4:1.2.3.4 -all',
        'selector1._domainkey.example.com': f'v=DKIM1; k=rsa; p={p2048}',
        '_dmarc.example.com': 'v=DMARC1; p=reject; rua=mailto:r@example.com',
        '_mta-sts.example.com': 'v=STSv1; id=1', '_smtp._tls.example.com': 'v=TLSRPTv1; rua=mailto:t@example.com'},
        mx={'example.com': ['mx.example.com']})
    monkeypatch.setattr(dv, 'safe_get', lambda url, **kw: type('R', (), {
        'status_code': 200, 'text': 'version: STSv1\nmode: enforce\nmx: mx.example.com\nmax_age: 86400'})())
    r = dv.check_deliverability('example.com')
    assert r['score'] == 100 and r['grade'] == 'A+'
    assert r['mta_sts']['policy']['mode'] == 'enforce' and r['tls_rpt']


def test_overview_scores_an_unprotected_domain(monkeypatch):
    fake_dns(monkeypatch)
    r = dv.check_deliverability('example.com')
    assert r['score'] == 0 and r['grade'] == 'F'
    assert {f['severity'] for f in r['findings']} >= {'error', 'warning'}


def test_overview_dmarc_none_gets_partial_credit(monkeypatch):
    fake_dns(monkeypatch, txt={'example.com': 'v=spf1 -all', '_dmarc.example.com': 'v=DMARC1; p=none'},
             mx={'example.com': ['mx.example.com']})
    r = dv.check_deliverability('example.com')
    dmarc = next(c for c in r['checks'] if c['check'] == 'DMARC')
    assert dmarc['points'] == 8 and any('only monitors' in f['message'] for f in r['findings'])


# ------------------------------------------------------------------ routes
def test_routes(client, monkeypatch):
    for path in ('/api/email/deliverability', '/api/email/spf/analyze', '/api/email/dkim/discover',
                 '/api/email/blocklist'):
        assert client.post(path, json={}).status_code == 400
    assert client.post('/api/email/dmarc/report', json={}).status_code == 400
    assert client.post('/api/email/dmarc/report', json={'xml': REPORT}).get_json()['result']['total_messages'] == 50
    fake_dns(monkeypatch, txt={'example.com': 'v=spf1 -all'})
    r = client.post('/api/email/spf/analyze', json={'domain': 'example.com'})
    assert r.status_code == 200 and r.get_json()['result']['has_spf']
    assert client.post('/api/email/spf/analyze', json={'domain': 'bad domain'}).status_code == 400
    assert client.post('/api/email/blocklist', json={'target': '192.168.1.1'}).status_code == 400
