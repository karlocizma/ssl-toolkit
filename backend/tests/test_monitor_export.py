import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from app.services import cert_monitor, domain_monitor, monitor_export as me


def iso(days):
    return (datetime.now(timezone.utc) + timedelta(days=days, hours=1)).isoformat()


@pytest.fixture
def data(tmp_path, monkeypatch, sample_cert_pem):
    monkeypatch.setattr(domain_monitor, 'DOMAIN_DATA_FILE', str(tmp_path / 'd.json'))
    monkeypatch.setattr(cert_monitor, 'MONITOR_DATA_FILE', str(tmp_path / 'c.json'))
    monkeypatch.setattr(cert_monitor, 'MONITOR_LOCK_FILE', str(tmp_path / 'c.lock'))
    monkeypatch.setenv('MONITOR_PUBLIC', 'true')

    def dom(host, status, days, label=None, changes=0, port=443):
        e = domain_monitor._new_entry(host, port, label, ['prod', 'web'])
        e.update(status=status, issuer="Let's Encrypt", serial_number='ab12', last_check=iso(0),
                 not_after=iso(days) if days is not None else None, changes=[{}] * changes)
        return e
    domain_monitor._save({'domains': [
        dom('example.com', 'ok', 20, label='Main "site"', changes=2),
        dom('=cmd|calc.example.com', 'error', None),
        dom('mail.example.com', 'ok', -3, port=993)]})
    cert_monitor.add_monitored_certificate(sample_cert_pem, label='Internal\nCA')


def parse_metrics(text):
    out = {}
    for line in text.splitlines():
        if line and not line.startswith('#'):
            m = re.match(r'^([a-z_]+)(\{.*\})? (\S+)$', line)
            assert m, f'malformed line: {line!r}'
            out.setdefault(m.group(1), []).append((m.group(2) or '', float(m.group(3))))
    return out


def test_metrics_exposition(data):
    text = me.render_metrics()
    m = parse_metrics(text)
    assert m['ssl_toolkit_monitored_domains'] == [('', 3.0)]
    assert m['ssl_toolkit_monitored_certificates'] == [('', 1.0)]
    days = {labels: v for labels, v in m['ssl_toolkit_domain_days_until_expiry']}
    assert days['{hostname="example.com",port="443",label="Main \\"site\\""}'] == 20.0  # label escaped
    assert days['{hostname="mail.example.com",port="993",label="mail.example.com"}'] == -3.0
    up = dict(m['ssl_toolkit_domain_up'])
    assert up['{hostname="example.com",port="443",label="Main \\"site\\""}'] == 1.0
    assert up['{hostname="=cmd|calc.example.com",port="443",label="=cmd|calc.example.com"}'] == 0.0
    assert dict(m['ssl_toolkit_domain_certificate_changes_total'])['{hostname="example.com",port="443",label="Main \\"site\\""}'] == 2.0
    assert 'Internal\\nCA' in text and '\nCA' not in text  # newline escaped, not raw
    assert text.count('# TYPE ssl_toolkit_domain_up gauge') == 1 and text.endswith('\n')


def test_csv_export_neutralises_formulas(data):
    rows = list(csv.DictReader(io.StringIO(me.export_csv())))
    assert len(rows) == 4 and rows[0]['type'] == 'domain'
    assert rows[0]['tags'] == 'prod;web' and rows[0]['days_until_expiry'] == '20'
    assert rows[1]['hostname'] == "'=cmd|calc.example.com"  # not interpreted as a formula by spreadsheets
    assert rows[3]['type'] == 'certificate'


def test_json_export(data):
    payload = json.loads(me.export_json())
    assert len(payload['items']) == 4 and payload['items'][0]['hostname'] == 'example.com'


def test_import_parsing():
    text = "hostname,port,label,tags\n# comment\nExample.com\nmail.example.com,993,Mail,prod;web\n\napi.example.com, 8443 ,,a;b\n"
    assert me.parse_import_csv(text) == [
        {'hostname': 'example.com', 'port': 443, 'label': None, 'tags': []},
        {'hostname': 'mail.example.com', 'port': 993, 'label': 'Mail', 'tags': ['prod', 'web']},
        {'hostname': 'api.example.com', 'port': 8443, 'label': None, 'tags': ['a', 'b']}]


@pytest.mark.parametrize('text,msg', [
    ('', 'no hosts'), ('# only a comment\n', 'no hosts'), ('x.example.com,abc', 'Invalid port'),
    ('\n'.join(f'h{i}.example.com' for i in range(101)), 'At most 100'), ('a' * 200_001, '200 KB')])
def test_import_rejects(text, msg):
    with pytest.raises(ValueError, match=msg):
        me.parse_import_csv(text)


def test_import_end_to_end_with_ports_and_labels(data, monkeypatch):
    monkeypatch.setattr(domain_monitor, '_check_entry', lambda e: [])
    monkeypatch.setattr(domain_monitor, '_validate_host', lambda h, p: 'unreachable' if h.startswith('bad') else None)
    r = me.import_csv('example.com\nnew.example.com,8443,New host,x\nbad.example.com\n')
    assert {x['hostname']: x['status'] for x in r['results']} == {
        'example.com': 'exists', 'new.example.com': 'added', 'bad.example.com': 'invalid'}
    added = [d for d in domain_monitor.all_entries() if d['hostname'] == 'new.example.com'][0]
    assert added['port'] == 8443 and added['label'] == 'New host' and added['tags'] == ['x']


def test_same_host_on_different_ports_is_distinct(data, monkeypatch):
    monkeypatch.setattr(domain_monitor, '_check_entry', lambda e: [])
    monkeypatch.setattr(domain_monitor, '_validate_host', lambda h, p: None)
    r = domain_monitor.add_domain_entries([{'hostname': 'mail.example.com', 'port': 993},
                                           {'hostname': 'mail.example.com', 'port': 465}])
    assert [x['status'] for x in r['results']] == ['exists', 'added']  # 993 already monitored in the fixture


# ------------------------------------------------------------------ routes
def test_routes_require_access_and_serve_formats(data, client, monkeypatch):
    monkeypatch.delenv('MONITOR_PUBLIC')
    monkeypatch.setenv('ADMIN_TOKEN', 'tok')
    for path in ('/api/metrics', '/api/monitor/export'):
        assert client.get(path).status_code == 401
    assert client.post('/api/monitor/domain/import', json={'csv': 'a.example.com'}).status_code == 401

    resp = client.get('/api/metrics', headers={'Authorization': 'Bearer tok'})  # what Prometheus sends
    assert resp.status_code == 200 and resp.headers['Content-Type'].startswith('text/plain; version=0.0.4')
    assert 'ssl_toolkit_domain_days_until_expiry' in resp.get_data(as_text=True)

    h = {'X-Access-Token': 'tok'}
    csv_resp = client.get('/api/monitor/export', headers=h)
    assert 'attachment; filename=monitor-export.csv' in csv_resp.headers['Content-Disposition']
    assert csv_resp.get_data(as_text=True).startswith('type,id,hostname')
    js = client.get('/api/monitor/export?format=json', headers=h)
    assert js.headers['Content-Type'] == 'application/json' and json.loads(js.get_data(as_text=True))['items']
    assert client.get('/api/monitor/export?format=xml', headers=h).status_code == 400
    assert client.post('/api/monitor/domain/import', json={'csv': ''}, headers=h).status_code == 400
