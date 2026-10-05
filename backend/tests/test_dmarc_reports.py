import base64
import gzip

import pytest

from app.services import dmarc_reports as dr


def report(org='google.com', rid='1', begin=1759536000, rows=(), domain='example.com', p='none'):
    records = ''.join(f"""<record><row><source_ip>{ip}</source_ip><count>{n}</count>
        <policy_evaluated><disposition>{disp}</disposition><dkim>{dkim}</dkim><spf>{spf}</spf></policy_evaluated></row>
        <identifiers><header_from>{domain}</header_from></identifiers>
        <auth_results><dkim><domain>{domain}</domain><result>{dkim}</result></dkim><spf><domain>{domain}</domain><result>{spf}</result></spf></auth_results></record>"""
                      for ip, n, dkim, spf, disp in rows)
    return f"""<?xml version="1.0"?><feedback><report_metadata><org_name>{org}</org_name><report_id>{rid}</report_id>
      <date_range><begin>{begin}</begin><end>{begin + 86399}</end></date_range></report_metadata>
      <policy_published><domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf><p>{p}</p><pct>100</pct></policy_published>
      {records}</feedback>"""


GOOD = ('203.0.113.1', 100, 'pass', 'pass', 'none')
SPF_ONLY = ('203.0.113.2', 50, 'fail', 'pass', 'none')
BAD = ('198.51.100.9', 20, 'fail', 'fail', 'none')


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    monkeypatch.setattr(dr, '_ptr', lambda ip: 'mail.example.net' if ip == '203.0.113.1' else None)


def files(*xmls):
    return [{'name': f'r{i}.xml', 'xml': x} for i, x in enumerate(xmls)]


def test_merges_reports_across_providers_and_days():
    r = dr.analyze_dmarc_reports(files(
        report('google.com', '1', 1759536000, [GOOD, SPF_ONLY, BAD]),
        report('google.com', '2', 1759622400, [GOOD, BAD]),
        report('yahoo.com', '3', 1759622400, [GOOD])))
    assert r['reports'] == 3 and r['total_messages'] == 100 + 50 + 20 + 100 + 20 + 100
    assert r['domains'] == ['example.com'] and r['policies']['example.com']['p'] == 'none'
    assert [d['date'] for d in r['daily']] == ['2025-10-04', '2025-10-05']
    assert r['daily'][0]['total'] == 170 and r['daily'][1]['total'] == 220
    assert [x['name'] for x in r['reporters']] == ['google.com', 'yahoo.com'] and r['reporters'][0]['reports'] == 2
    good = next(s for s in r['sources'] if s['source_ip'] == '203.0.113.1')
    assert good['count'] == 300 and good['status'] == 'authenticated' and good['ptr'] == 'mail.example.net'
    assert good['reporters'] == ['google.com', 'yahoo.com']
    bad = next(s for s in r['sources'] if s['source_ip'] == '198.51.100.9')
    assert bad['count'] == 40 and bad['status'] == 'failing' and bad['pass_count'] == 0
    assert r['period']['start'].startswith('2025-10-04') and r['period']['end'].startswith('2025-10-05')
    assert r['pass_rate'] == round(100 * (r['passed_messages']) / r['total_messages'], 2)
    assert r['dispositions'] == {'none': r['total_messages']}


def test_findings_flag_failing_and_spf_only_sources():
    r = dr.analyze_dmarc_reports(files(report(rows=[GOOD, SPF_ONLY, BAD])))
    text = ' '.join(f['message'] for f in r['findings'])
    assert '198.51.100.9' in text and 'none passed DMARC' in text
    assert '203.0.113.2 passes through SPF only' in text


def test_duplicates_and_unreadable_files_are_reported_not_fatal():
    good = report(rows=[GOOD])
    r = dr.analyze_dmarc_reports(files(good, good, '<html/>') + [{'name': 'x', 'file_base64': '!!!'}, {'name': 'empty'}])
    assert r['reports'] == 1 and r['duplicates_skipped'] == 1
    assert {e['file'] for e in r['errors']} == {'r2.xml', 'x', 'empty'}


def test_gzip_and_base64_inputs():
    gz = base64.b64encode(gzip.compress(report(rows=[GOOD]).encode())).decode()
    r = dr.analyze_dmarc_reports([{'name': 'a.xml.gz', 'file_base64': gz}])
    assert r['total_messages'] == 100


@pytest.mark.parametrize('bad', [None, [], 'x', [{'xml': '<nope/>'}]])
def test_rejects_unusable_input(bad):
    with pytest.raises(ValueError):
        dr.analyze_dmarc_reports(bad)


def test_limits():
    with pytest.raises(ValueError, match='At most'):
        dr.analyze_dmarc_reports([{'xml': 'x'}] * (dr.MAX_FILES + 1))


def test_ptr_can_be_skipped(monkeypatch):
    monkeypatch.setattr(dr, '_ptr', lambda ip: (_ for _ in ()).throw(AssertionError('no lookups wanted')))
    r = dr.analyze_dmarc_reports(files(report(rows=[GOOD])), lookup_ptr=False)
    assert r['sources'][0]['ptr'] is None


def test_route(client):
    body = {'files': files(report(rows=[GOOD, BAD])), 'lookup_ptr': False}
    r = client.post('/api/email/dmarc/reports', json=body)
    assert r.status_code == 200 and r.get_json()['result']['reports'] == 1
    assert client.post('/api/email/dmarc/reports', json={}).status_code == 400
    assert client.post('/api/email/dmarc/reports', json={'files': [{'xml': 'junk'}]}).status_code == 400
