import json
from datetime import datetime, timezone

import pytest

from app.services import ct_lookup as ct
from app.services import domain_monitor

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def entry(id_, serial, names, issuer="C=US, O=Let's Encrypt, CN=R3", nb='2026-01-01T00:00:00', na='2026-04-01T00:00:00'):
    return {'id': id_, 'serial_number': serial, 'issuer_name': issuer, 'common_name': names[0],
            'name_value': '\n'.join(names), 'not_before': nb, 'not_after': na, 'entry_timestamp': nb + '.123'}


ENTRIES = [
    entry(1, 'aa', ['example.com', 'www.example.com'], nb='2026-03-01T00:00:00', na='2026-09-01T00:00:00'),
    entry(2, 'aa', ['example.com', 'www.example.com'], nb='2026-03-01T00:00:00', na='2026-09-01T00:00:00'),  # precert duplicate
    entry(3, 'bb', ['old.example.com'], nb='2025-01-01T00:00:00', na='2025-04-01T00:00:00'),
    entry(4, 'cc', ['*.example.com', 'example.com'], issuer='C=US, O=DigiCert Inc, CN=DigiCert TLS RSA', nb='2026-02-01T00:00:00', na='2027-02-01T00:00:00'),
    entry(5, 'dd', ['mail.example.com', 'unrelated.org', 'notexample.com'], nb='2026-05-01T00:00:00', na='2026-08-01T00:00:00'),
]


def test_dedupes_precerts_and_extracts_subdomains():
    r = ct.analyze(ENTRIES, 'example.com', now=NOW)
    assert r['total_certificates'] == 4
    assert [s['name'] for s in r['subdomains']] == ['example.com', 'mail.example.com', 'old.example.com', 'www.example.com']
    assert 'unrelated.org' not in str(r['subdomains']) and 'notexample.com' not in str(r['subdomains'])


def test_active_expired_and_ordering():
    r = ct.analyze(ENTRIES, 'example.com', now=NOW)
    assert r['active_certificates'] == 3
    by_name = {s['name']: s for s in r['subdomains']}
    assert by_name['old.example.com']['active'] is False and by_name['www.example.com']['active'] is True
    assert by_name['example.com']['certificates'] == 2
    assert [c['serial_number'] for c in r['certificates']][0] == 'dd'  # newest first


def test_include_expired_false():
    r = ct.analyze(ENTRIES, 'example.com', include_expired=False, now=NOW)
    assert r['total_certificates'] == 3 and 'old.example.com' not in [s['name'] for s in r['subdomains']]


def test_wildcard_reported_not_listed_as_subdomain():
    r = ct.analyze(ENTRIES, 'example.com', now=NOW)
    assert all(not s['name'].startswith('*') for s in r['subdomains'])
    assert any('Wildcard' in f['message'] and '*.example.com' in f['message'] for f in r['findings'])


def test_unexpected_issuer_flagged():
    r = ct.analyze(ENTRIES, 'example.com', expected_issuers=["Let's Encrypt"], now=NOW)
    msgs = [f['message'] for f in r['findings'] if f['severity'] == 'warning']
    assert len(msgs) == 1 and 'DigiCert' in msgs[0]
    assert ct.analyze(ENTRIES, 'example.com', now=NOW)['issuers'][0]['count'] == 3


@pytest.mark.parametrize('bad', ['', 'localhost', '10.0.0.1', 'a b.com', 'http://x.com', 'x.com/path'])
def test_domain_validation(bad):
    with pytest.raises(ValueError):
        ct.normalize_domain(bad)


def test_normalize_strips_wildcard_and_case():
    assert ct.normalize_domain('*.Example.COM.') == 'example.com'


class Resp:
    def __init__(self, status, text='', headers=None):
        self.status_code, self.text, self.headers = status, text, headers or {}


@pytest.fixture(autouse=True)
def _clear_cache():
    ct._cache.clear()
    yield
    ct._cache.clear()


def test_fetch_retries_then_succeeds(monkeypatch):
    calls = []
    monkeypatch.setattr(ct.time, 'sleep', lambda s: None)
    monkeypatch.setattr(ct, 'safe_get', lambda url, **kw: calls.append(kw) or (
        Resp(502) if len(calls) == 1 else Resp(200, json.dumps(ENTRIES))))
    assert len(ct.fetch_entries('example.com')) == 5
    assert calls[0]['params'] == {'q': '%.example.com', 'output': 'json'}


def test_fetch_fails_clearly(monkeypatch):
    monkeypatch.setattr(ct.time, 'sleep', lambda s: None)
    monkeypatch.setattr(ct, 'safe_get', lambda url, **kw: Resp(503))
    with pytest.raises(ct.CTLookupError, match='unavailable'):
        ct.fetch_entries('example.com')
    monkeypatch.setattr(ct, 'safe_get', lambda url, **kw: Resp(200, 'not json'))
    with pytest.raises(ct.CTLookupError, match='invalid'):
        ct.fetch_entries('example.com')
    monkeypatch.setattr(ct, 'safe_get', lambda url, **kw: Resp(200, '{"a":1}'))
    with pytest.raises(ct.CTLookupError, match='unexpected'):
        ct.fetch_entries('example.com')


def test_lookup_route(client, monkeypatch):
    assert client.post('/api/ct/lookup', json={}).status_code == 400
    assert client.post('/api/ct/lookup', json={'domain': 'bad domain'}).status_code == 400
    assert client.post('/api/ct/lookup', json={'domain': 'example.com', 'expected_issuers': 'x'}).status_code == 400
    monkeypatch.setattr(ct, 'fetch_entries', lambda d: ENTRIES)
    resp = client.post('/api/ct/lookup', json={'domain': 'example.com', 'expected_issuers': ["Let's Encrypt"]})
    assert resp.status_code == 200 and resp.get_json()['result']['total_certificates'] == 4

    def boom(d):
        raise ct.CTLookupError('down')
    monkeypatch.setattr(ct, 'fetch_entries', boom)
    assert client.post('/api/ct/lookup', json={'domain': 'example.com'}).status_code == 502


# ---- bulk add to monitor -------------------------------------------------
@pytest.fixture
def monitor_file(tmp_path, monkeypatch):
    monkeypatch.setattr(domain_monitor, 'DOMAIN_DATA_FILE', str(tmp_path / 'd.json'))
    monkeypatch.setattr(domain_monitor, '_check_entry', lambda e: [])
    monkeypatch.setattr(domain_monitor, '_validate_host',
                        lambda h, p: 'DNS resolution error: x' if h.startswith('bad') else None)


def test_bulk_add_reports_per_host(monitor_file):
    domain_monitor.add_domains(['dup.example.com'])
    r = domain_monitor.add_domains(['a.example.com', 'A.example.com.', 'dup.example.com', 'bad.example.com'])
    assert r['added'] == 1
    assert {x['hostname']: x['status'] for x in r['results']} == {
        'a.example.com': 'added', 'dup.example.com': 'exists', 'bad.example.com': 'invalid'}
    assert domain_monitor.list_domains()['count'] == 2


@pytest.mark.parametrize('hosts', [[], None, ['x.example.com'] * 0, [f'h{i}.example.com' for i in range(51)]])
def test_bulk_add_limits(monitor_file, hosts):
    with pytest.raises(ValueError):
        domain_monitor.add_domains(hosts)


def test_bulk_route_requires_access_and_validates(client, monitor_file, monkeypatch):
    monkeypatch.setenv('ADMIN_TOKEN', 'secret')
    monkeypatch.delenv('MONITOR_PUBLIC', raising=False)
    assert client.post('/api/monitor/domain/add-bulk', json={'hostnames': ['a.example.com']}).status_code == 401
    h = {'X-Access-Token': 'secret'}
    assert client.post('/api/monitor/domain/add-bulk', json={}, headers=h).status_code == 400
    ok = client.post('/api/monitor/domain/add-bulk', json={'hostnames': ['a.example.com']}, headers=h)
    assert ok.status_code == 200 and ok.get_json()['added'] == 1


def test_rate_limit_is_not_retried_and_is_explained(monkeypatch):
    calls = []
    monkeypatch.setattr(ct.time, 'sleep', lambda s: None)
    monkeypatch.setattr(ct, 'safe_get', lambda url, **kw: calls.append(1) or Resp(429, headers={'Retry-After': '120'}))
    with pytest.raises(ct.CTLookupError, match=r'rate-limiting.*2 minute'):
        ct.fetch_entries('example.com')
    assert len(calls) == 1


def test_results_are_cached(monkeypatch):
    calls = []
    monkeypatch.setattr(ct, 'safe_get', lambda url, **kw: calls.append(1) or Resp(200, json.dumps(ENTRIES)))
    assert ct.fetch_entries('example.com') == ct.fetch_entries('example.com')
    assert len(calls) == 1
    ct.fetch_entries('example.org')
    assert len(calls) == 2
    monkeypatch.setattr(ct, 'CT_CACHE_SECONDS', 0)
    ct._cache.clear()
    ct.fetch_entries('example.com')
    ct.fetch_entries('example.com')
    assert len(calls) == 4


def test_failures_are_not_cached(monkeypatch):
    monkeypatch.setattr(ct.time, 'sleep', lambda s: None)
    monkeypatch.setattr(ct, 'safe_get', lambda url, **kw: Resp(503))
    with pytest.raises(ct.CTLookupError):
        ct.fetch_entries('example.com')
    monkeypatch.setattr(ct, 'safe_get', lambda url, **kw: Resp(200, json.dumps(ENTRIES)))
    assert len(ct.fetch_entries('example.com')) == 5
