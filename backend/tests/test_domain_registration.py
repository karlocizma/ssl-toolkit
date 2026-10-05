import json
from datetime import datetime, timedelta, timezone

import pytest

from app.services import alerts, domain_monitor
from app.services import domain_registration as dr

NOW = datetime(2026, 10, 5, tzinfo=timezone.utc)


def rdap(expires_in=100, extra_status=None, with_expiry=True):
    events = [{'eventAction': 'registration', 'eventDate': '2015-01-01T00:00:00Z'},
              {'eventAction': 'last changed', 'eventDate': '2026-01-01T00:00:00Z'}]
    if with_expiry:
        events.append({'eventAction': 'expiration', 'eventDate': (NOW + timedelta(days=expires_in)).isoformat()})
    return {'ldhName': 'EXAMPLE.COM', 'events': events,
            'status': ['client transfer prohibited'] + (extra_status or []),
            'nameservers': [{'ldhName': 'NS2.EXAMPLE.NET'}, {'ldhName': 'ns1.example.net'}],
            'secureDNS': {'delegationSigned': True},
            'entities': [{'roles': ['registrar'], 'vcardArray': ['vcard', [['version', {}, 'text', '4.0'],
                                                                           ['fn', {}, 'text', 'Example Registrar Inc.']]]}]}


class Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body, headers or {}

    def json(self):
        if self._body is None:
            raise ValueError('no json')
        return self._body


BOOTSTRAP = {'services': [[['com', 'net'], ['http://rdap.example/com/', 'https://rdap.example/com/']],
                          [['uk'], ['https://rdap.example/uk/']]]}


@pytest.fixture(autouse=True)
def reset(monkeypatch):
    dr._cache.clear()
    dr._bootstrap.update(at=0.0, map={})
    monkeypatch.setattr(dr, 'datetime', type('D', (datetime,), {'now': classmethod(lambda cls, tz=None: NOW)}))


def serve(monkeypatch, routes):
    calls = []

    def fake(url, **kw):
        calls.append(url)
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                return resp() if callable(resp) else resp
        return Resp(404)
    monkeypatch.setattr(dr, 'safe_get', fake)
    return calls


def test_parse_registration_details():
    r = dr.parse_rdap(rdap(100), 'example.com', now=NOW)
    assert r['domain'] == 'example.com' and r['days_until_expiry'] == 100
    assert r['registrar'] == 'Example Registrar Inc.' and r['dnssec'] is True
    assert r['nameservers'] == ['ns1.example.net', 'ns2.example.net']
    assert not [f for f in r['findings'] if f['severity'] != 'info']


def test_findings_for_expiring_expired_and_hold():
    assert dr.parse_rdap(rdap(10), 'x.com', NOW)['findings'][0]['severity'] == 'warning'
    expired = dr.parse_rdap(rdap(-3, ['redemption period']), 'x.com', NOW)
    assert {f['severity'] for f in expired['findings']} == {'critical'} and len(expired['findings']) == 2
    held = dr.parse_rdap(rdap(100, ['client hold']), 'x.com', NOW)
    assert any('does not resolve' in f['message'] for f in held['findings'])


def test_registry_without_expiry_date_says_so():
    r = dr.parse_rdap(rdap(with_expiry=False), 'example.de', NOW)
    assert r['expires'] is None and r['days_until_expiry'] is None and 'does not publish' in r['findings'][0]['message']


def test_lookup_strips_subdomains_and_prefers_https(monkeypatch):
    calls = serve(monkeypatch, {'dns.json': Resp(200, BOOTSTRAP), '/domain/example.com': Resp(200, rdap(100))})
    r = dr.lookup('www.mail.Example.com')
    assert r['domain'] == 'example.com' and r['queried'] == 'www.mail.example.com'
    assert all(c.startswith('https://') for c in calls)
    assert calls[-1] == 'https://rdap.example/com/domain/example.com'
    dr.lookup('www.mail.example.com')  # cached
    assert len(calls) == 4


def test_lookup_follows_validated_redirect_and_reports_errors(monkeypatch):
    serve(monkeypatch, {'dns.json': Resp(200, BOOTSTRAP),
                        '/com/domain/example.com': Resp(302, headers={'Location': 'https://registrar.example/rdap/example.com'}),
                        'registrar.example/rdap/example.com': Resp(200, rdap(50))})
    assert dr.lookup('example.com')['days_until_expiry'] == 50
    dr._cache.clear()
    serve(monkeypatch, {'dns.json': Resp(200, BOOTSTRAP)})
    with pytest.raises(dr.RDAPError, match='not registered'):
        dr.lookup('nothere.com')
    serve(monkeypatch, {'dns.json': Resp(200, BOOTSTRAP), '/domain/example.com': Resp(429)})
    with pytest.raises(dr.RDAPError, match='rate-limiting'):
        dr.lookup('example.com')
    with pytest.raises(dr.RDAPError, match='No RDAP service'):
        dr.lookup('example.xyz')
    for bad in ('', 'localhost', 'http://example.com', 'a b.com'):
        with pytest.raises(ValueError):
            dr.normalize(bad)


def test_route_validation_and_error_mapping(client, monkeypatch):
    assert client.post('/api/check/domain-registration', json={}).status_code == 400
    assert client.post('/api/check/domain-registration', json={'domain': 'bad'}).status_code == 400
    monkeypatch.setattr(dr, 'lookup', lambda d: (_ for _ in ()).throw(dr.RDAPError('boom')))
    assert client.post('/api/check/domain-registration', json={'domain': 'example.com'}).status_code == 502
    monkeypatch.setattr(dr, 'lookup', lambda d: {'domain': d})
    assert client.post('/api/check/domain-registration', json={'domain': 'example.com'}).get_json()['result'] == {'domain': 'example.com'}


@pytest.fixture
def monitor(tmp_path, monkeypatch):
    monkeypatch.setattr(domain_monitor, 'DOMAIN_DATA_FILE', str(tmp_path / 'domains.json'))
    monkeypatch.setattr(domain_monitor, '_fetch_single_certificate', lambda h, p, t: None)
    return domain_monitor


def _entry(host, expires, notified=()):
    e = domain_monitor._new_entry(host, 443)
    e['registration'] = {'domain': 'acme.example', 'registrar': 'Reg', 'checked_at': NOW.isoformat(), 'error': None,
                         'expires': expires.isoformat(), 'days_until_expiry': 5, 'status': []}
    e['registration_notified'] = list(notified)
    return e


def test_registration_alert_is_sent_once_per_domain_and_threshold(monitor, monkeypatch):
    soon = datetime.now(timezone.utc) + timedelta(days=5)
    monitor._save({'domains': [_entry('a.acme.example', soon), _entry('b.acme.example', soon)]})
    events = alerts.collect_expiry_events()
    reg = [e for e in events if e['source'] == 'registration']
    assert len(reg) == 1 and reg[0]['hostname'] == 'acme.example' and 'registration expires in' in reg[0]['detail']
    assert alerts.collect_expiry_events() == []  # both hosts were marked as notified


def test_refresh_registration_caches_and_survives_errors(monitor, monkeypatch):
    calls = []
    monkeypatch.setattr(dr, 'lookup', lambda h: calls.append(h) or {
        'domain': 'acme.example', 'registrar': 'Reg', 'expires': '2030-01-01T00:00:00+00:00',
        'days_until_expiry': 1000, 'status': []})
    entry = domain_monitor._new_entry('www.acme.example', 443)
    monitor.refresh_registration(entry)
    monitor.refresh_registration(entry)  # fresh enough: no second lookup
    assert len(calls) == 1 and entry['registration']['domain'] == 'acme.example'
    monkeypatch.setattr(dr, 'lookup', lambda h: (_ for _ in ()).throw(dr.RDAPError('down')))
    monitor.refresh_registration(entry, force=True)
    assert entry['registration']['expires'] == '2030-01-01T00:00:00+00:00' and 'down' in entry['registration']['error']
    ip = domain_monitor._new_entry('192.0.2.1', 443)
    monkeypatch.setattr(dr, 'lookup', lambda h: dr.normalize(h))
    monitor.refresh_registration(ip)
    assert ip['registration'] is None
