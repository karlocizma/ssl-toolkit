import pytest

from app.services import spf_flatten as sf

ZONE = {
    'example.com': 'v=spf1 ip4:192.0.2.0/25 a mx include:_spf.mail.net include:other.org ~all',
    '_spf.mail.net': 'v=spf1 ip4:198.51.100.0/25 ip4:198.51.100.128/25 include:_deep.mail.net -all',
    '_deep.mail.net': 'v=spf1 ip6:2001:db8::/32 ip4:203.0.113.7 ?all',
    'other.org': 'v=spf1 a:relay.other.org/28 -ip4:10.0.0.1 ip4:203.0.113.9 -all',
}
ADDR = {'example.com': ['192.0.2.200', '2001:db8:aaaa::1'], 'mx1.example.com': ['192.0.2.250'],
        'relay.other.org': ['203.0.113.34']}


@pytest.fixture
def dns(monkeypatch):
    zone = dict(ZONE)
    monkeypatch.setattr(sf, '_spf_record', lambda name: ([zone[name]] if name in zone else [], None))
    monkeypatch.setattr(sf, '_addresses', lambda host: ADDR.get(host, []))
    monkeypatch.setattr(sf, '_mx_hosts', lambda host: ['mx1.example.com'] if host == 'example.com' else [])
    monkeypatch.setattr(sf, 'analyze_spf', lambda d: {'lookups': 6})
    return zone


def terms(result):
    return result['records'][0]['value'].split()


def test_flattens_everything_into_one_record_when_it_fits(dns):
    r = sf.flatten_spf('example.com')
    assert len(r['records']) == 1 and r['lookups_after'] == 0 and r['original_lookups'] == 6
    t = terms(r)
    assert t[0] == 'v=spf1' and t[-1] == '~all'
    assert 'ip4:192.0.2.0/25' in t and 'ip4:198.51.100.0/24' in t        # adjacent /25s collapsed
    assert 'ip4:192.0.2.200' in t and 'ip4:192.0.2.250' in t              # a and mx expanded
    assert 'ip6:2001:db8::/32' in t and 'ip4:203.0.113.9' in t            # nested include, other.org
    assert 'ip4:203.0.113.32/28' in t                                     # a:host/28 keeps the prefix
    assert not any(x.startswith('include:') for x in t)
    assert 'ip4:10.0.0.1' not in t                                        # negative term inside an include is not allowed
    assert any('-ip4:10.0.0.1' in w and 'ignored' in w for w in r['warnings'])
    assert r['network_count'] == len(t) - 2


def test_splits_into_helper_records_when_too_long(dns):
    r = sf.flatten_spf('example.com', max_record_length=100)
    main, helpers = r['records'][0], r['records'][1:]
    assert helpers and r['lookups_after'] == len(helpers)
    assert main['value'].startswith('v=spf1 include:_spf1.example.com') and main['value'].endswith('~all')
    assert all(h['name'].startswith('_spf') and h['value'].endswith('?all') and h['length'] <= 100 for h in helpers)
    published = ' '.join(h['value'] for h in helpers)
    assert 'ip4:198.51.100.0/24' in published and 'ip6:2001:db8::/32' in published


def test_keep_preserves_an_include(dns):
    r = sf.flatten_spf('example.com', keep=['_spf.mail.net'])
    t = terms(r)
    assert 'include:_spf.mail.net' in t and 'ip4:198.51.100.0/24' not in t and r['lookups_after'] == 1
    assert 'ip4:203.0.113.9' in t


def test_unflattenable_and_qualified_terms_are_kept_with_a_warning(dns):
    dns['example.com'] = 'v=spf1 exists:%{i}.sbl.example.net -ip4:192.0.2.5 ip4:192.0.2.0/24 ptr -all'
    r = sf.flatten_spf('example.com')
    t = terms(r)
    assert 'exists:%{i}.sbl.example.net' in t and '-ip4:192.0.2.5' in t and 'ptr' in t and t[-1] == '-all'
    assert r['lookups_after'] == 2 and len(r['warnings']) >= 3


def test_redirect_and_loops(dns):
    dns['example.com'] = 'v=spf1 redirect=other.org'
    assert 'ip4:203.0.113.9' in terms(sf.flatten_spf('example.com'))
    dns['example.com'] = 'v=spf1 include:a.example.com ~all'
    dns['a.example.com'] = 'v=spf1 include:example.com ip4:192.0.2.1 -all'
    r = sf.flatten_spf('example.com')
    assert 'ip4:192.0.2.1' in terms(r) and any('loop' in w for w in r['warnings'])


def test_missing_all_and_plus_all_are_flagged(dns):
    dns['example.com'] = 'v=spf1 ip4:192.0.2.1'
    r = sf.flatten_spf('example.com')
    assert terms(r)[-1] == '~all' and any('no "all"' in w for w in r['warnings'])
    dns['example.com'] = 'v=spf1 ip4:192.0.2.1 +all'
    assert any('every sender' in w for w in sf.flatten_spf('example.com')['warnings'])


def test_errors(dns):
    dns.clear()
    with pytest.raises(ValueError, match='no SPF record'):
        sf.flatten_spf('example.com')
    with pytest.raises(ValueError):
        sf.flatten_spf('bad')


def test_cidr_parsing():
    assert sf._split_cidr('', 'x.com') == ('x.com', None, None)
    assert sf._split_cidr('/24', 'x.com') == ('x.com', 24, None)
    assert sf._split_cidr('/24//64', 'x.com') == ('x.com', 24, 64)
    assert sf._split_cidr('h.com//64', 'x.com') == ('h.com', None, 64)


def test_route(client, dns):
    r = client.post('/api/email/spf/flatten', json={'domain': 'example.com', 'keep': ['other.org']})
    body = r.get_json()['result']
    assert r.status_code == 200 and 'include:other.org' in body['records'][0]['value']
    assert client.post('/api/email/spf/flatten', json={'domain': 'nospf.example'}).status_code == 400
    assert client.post('/api/email/spf/flatten', json={}).status_code == 400
