import pytest

from app.services import dmarc_advisor as adv
from app.services import dmarc_reports as dr
from tests.test_dmarc_reports import report


@pytest.fixture(autouse=True)
def no_dns(monkeypatch):
    monkeypatch.setattr(dr, '_ptr', lambda ip: 'mail.example.net' if ip == '203.0.113.1' else None)


def analysis(days=14, per_day=(('203.0.113.1', 500, 'pass', 'pass', 'none'),), p='none', pct='100', extra=()):
    xmls = []
    for d in range(days):
        rows = list(per_day) + list(extra)
        xmls.append({'name': f'd{d}', 'xml': report(rid=str(d), begin=1759536000 + d * 86400, rows=rows, p=p).replace('<pct>100</pct>', f'<pct>{pct}</pct>')})
    return dr.analyze_dmarc_reports(xmls)


def advice_for(result, **kw):
    return adv.advise(result, **kw)['domains'][0]


@pytest.mark.parametrize('p,pct,index', [('none', '100', 0), ('quarantine', '10', 1), ('quarantine', '100', 4),
                                         ('reject', '25', 6), ('reject', '100', 8), ('reject', '30', 7), ('bogus', '100', None)])
def test_stage_index(p, pct, index):
    assert adv.stage_index({'p': p, 'pct': pct}) == index


def test_clean_data_over_two_weeks_is_ready_for_first_quarantine_step():
    a = advice_for(analysis())
    assert a['verdict'] == 'ready' and a['next'] == {'p': 'quarantine', 'pct': 10, 'required_pass_rate': 98.0}
    assert a['next_record']['value'].startswith('v=DMARC1; p=quarantine; pct=10;')
    assert a['next_record']['name'] == '_dmarc.example.com' and a['next_record']['rua_assumed'] is True
    assert any('placeholder' in n for n in a['notes'])


def test_too_little_history_is_insufficient_data_and_hides_the_record():
    a = advice_for(analysis(days=5))
    assert a['verdict'] == 'insufficient_data' and a['next_record'] is None and a['preview_record']
    assert any('at least 14' in b for b in a['blockers'])
    a = advice_for(analysis(days=14, per_day=(('203.0.113.1', 5, 'pass', 'pass', 'none'),)))
    assert a['verdict'] == 'insufficient_data' and any('too little' in b for b in a['blockers'])


def test_failing_source_blocks_until_fixed_or_ignored():
    bad = ('198.51.100.9', 50, 'fail', 'fail', 'none')
    result = analysis(extra=(bad,))
    a = advice_for(result)
    assert a['verdict'] == 'not_ready'
    assert any('198.51.100.9' in b and 'ignore list' in b for b in a['blockers'])
    assert a['failing_sources'][0]['source_ip'] == '198.51.100.9' and a['failing_sources'][0]['share'] > 8
    ignored = advice_for(result, ignore_ips=['198.51.100.9'])
    assert ignored['verdict'] == 'ready' and ignored['data']['ignored_messages'] == 50 * 14
    assert ignored['data']['pass_rate'] == 100.0


def test_small_failures_below_threshold_do_not_block():
    a = advice_for(analysis(extra=(('198.51.100.9', 1, 'fail', 'fail', 'none'),)))
    assert a['verdict'] == 'ready' and a['data']['pass_rate'] > 99


def test_later_steps_need_a_week_and_higher_rates():
    a = advice_for(analysis(days=7, p='quarantine', pct='10'))
    assert a['verdict'] == 'ready' and a['next'] == {'p': 'quarantine', 'pct': 25, 'required_pass_rate': 99.0}
    assert any('roll back to p=quarantine; pct=10' in n for n in a['notes'])
    a = advice_for(analysis(days=7, p='quarantine', pct='100'))
    assert a['next'] == {'p': 'reject', 'pct': 10, 'required_pass_rate': 99.5}
    mixed = analysis(days=7, p='quarantine', pct='100', extra=(('198.51.100.9', 6, 'fail', 'fail', 'none'),))
    assert advice_for(mixed)['verdict'] == 'not_ready'  # 99.2% < 99.5%


def test_reject_is_the_end_of_the_road():
    a = advice_for(analysis(p='reject', pct='100'))
    assert a['verdict'] == 'done' and a['next'] is None


def test_current_record_tags_are_kept():
    rec = 'v=DMARC1; p=none; rua=mailto:agg@example.com; ruf=mailto:f@example.com; fo=1; adkim=s'
    a = advice_for(analysis(), current_records={'Example.com': rec})
    value = a['next_record']['value']
    assert value == 'v=DMARC1; p=quarantine; pct=10; rua=mailto:agg@example.com; ruf=mailto:f@example.com; fo=1; adkim=s'
    assert a['next_record']['rua_assumed'] is False


def test_published_tags_are_kept_without_a_current_record():
    row = [('203.0.113.1', 500, 'pass', 'pass', 'none')]
    xmls = [{'xml': report(rid=str(i), begin=1759536000 + i * 86400, rows=row).replace('<p>none</p>', '<p>none</p><sp>reject</sp>')}
            for i in range(14)]
    value = advice_for(dr.analyze_dmarc_reports(xmls))['preview_record']['value']
    assert value == 'v=DMARC1; p=quarantine; pct=10; sp=reject; adkim=r; aspf=r; rua=mailto:dmarc-reports@example.com'


def test_route_includes_advice(client):
    files = [{'name': f'd{d}', 'xml': report(rid=str(d), begin=1759536000 + d * 86400, rows=[('203.0.113.1', 500, 'pass', 'pass', 'none')])} for d in range(14)]
    r = client.post('/api/email/dmarc/reports', json={'files': files, 'lookup_ptr': False})
    advice = r.get_json()['result']['advice']['domains'][0]
    assert advice['verdict'] == 'ready' and advice['domain'] == 'example.com'
    bad = client.post('/api/email/dmarc/reports', json={'files': files, 'ignore_ips': 'nope'})
    assert bad.status_code == 400
