import json
import os

import pytest

from app.services import audit_log, cert_monitor, domain_monitor

ADMIN = {'Authorization': 'Bearer admin-secret'}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv('AUDIT_LOG_FILE', str(tmp_path / 'audit.log'))
    monkeypatch.setenv('ADMIN_TOKEN', 'admin-secret')
    monkeypatch.delenv('MONITOR_PUBLIC', raising=False)
    monkeypatch.setattr(domain_monitor, 'DOMAIN_DATA_FILE', str(tmp_path / 'domains.json'))
    monkeypatch.setattr(cert_monitor, 'MONITOR_DATA_FILE', str(tmp_path / 'certs.json'))
    monkeypatch.setattr(cert_monitor, 'MONITOR_LOCK_FILE', str(tmp_path / 'certs.json.lock'))
    monkeypatch.setenv('API_KEYS_FILE', str(tmp_path / 'keys.json'))
    from app.services import api_key_manager
    monkeypatch.setattr(api_key_manager, 'API_KEYS_FILE', str(tmp_path / 'keys.json'))
    monkeypatch.setattr(api_key_manager, '_LOCK_FILE', str(tmp_path / 'keys.json.lock'))
    return tmp_path


def entries():
    return audit_log.query(limit=500)['entries']


def test_records_are_chained_and_verifiable():
    for i in range(5):
        audit_log.record('test.action', actor={'type': 'admin'}, ip='203.0.113.5', target=f't{i}', detail={'n': i})
    es = entries()
    assert [e['target'] for e in es] == ['t4', 't3', 't2', 't1', 't0']  # newest first
    assert es[-1]['prev'] == audit_log.GENESIS and es[0]['prev'] == es[1]['hash']
    assert audit_log.verify() == {'valid': True, 'entries': 5, 'problem': None}


def test_tampering_is_detected():
    for i in range(4):
        audit_log.record('test.action', target=f't{i}')
    path = audit_log._path()
    lines = open(path).read().splitlines()
    # edit one entry
    edited = json.loads(lines[1])
    edited['target'] = 'forged'
    modified = lines[:1] + [json.dumps(edited, sort_keys=True)] + lines[2:]
    open(path, 'w').write('\n'.join(modified) + '\n')
    assert audit_log.verify()['problem']['reason'] == 'entry was modified'
    # remove one entry
    open(path, 'w').write('\n'.join(lines[:1] + lines[2:]) + '\n')
    r = audit_log.verify()
    assert r['valid'] is False and 'chain broken' in r['problem']['reason'] and r['problem']['line'] == 2
    # garbage
    open(path, 'w').write(lines[0] + '\nnot json\n')
    assert audit_log.verify()['problem']['reason'] == 'unreadable line'


def test_rotation_keeps_the_chain_intact(monkeypatch):
    monkeypatch.setenv('AUDIT_LOG_MAX_BYTES', '10000')
    monkeypatch.setenv('AUDIT_LOG_KEEP', '2')
    for i in range(80):
        audit_log.record('test.action', target=f'target-{i}', detail={'pad': 'x' * 150})
    base = audit_log._path()
    assert os.path.exists(base + '.1') and os.path.exists(base + '.2') and not os.path.exists(base + '.3')
    assert audit_log.verify()['valid'] is True
    assert audit_log.query(limit=1)['entries'][0]['target'] == 'target-79'
    assert audit_log.query(search='target-79')['total'] == 1


def test_filters_and_pagination():
    audit_log.record('monitor.domain.add', actor={'type': 'api_key', 'id': 'ci'}, target='a.example')
    audit_log.record('apikey.generate', actor={'type': 'admin'}, target='ci')
    audit_log.record('auth.denied', actor={'type': 'anonymous'}, result='denied', status=401)
    assert audit_log.query(action='monitor.')['total'] == 1
    assert audit_log.query(actor='api_key')['total'] == 1 and audit_log.query(result='denied')['total'] == 1
    assert audit_log.query(search='a.example')['total'] == 1
    assert audit_log.query(since='2999-01-01')['total'] == 0
    page = audit_log.query(limit=1, offset=1)
    assert page['total'] == 3 and len(page['entries']) == 1 and page['entries'][0]['action'] == 'apikey.generate'


def test_values_are_bounded_and_never_raise(monkeypatch):
    e = audit_log.record('x', target='t' * 1000, detail={'k' * 200: 'v' * 1000, 'list': list(range(100))})
    assert len(e['target']) == 200 and len(e['detail']['list']) == 20
    monkeypatch.setenv('AUDIT_LOG_FILE', '/proc/nope/audit.log')
    assert audit_log.record('x') is None  # unwritable: swallowed, request would carry on


def test_csv_export_neutralises_formulas():
    audit_log.record('monitor.domain.add', actor={'type': 'admin'}, target='=HYPERLINK("http://evil")')
    csv_text = audit_log.export('csv')
    assert csv_text.splitlines()[0].startswith('time,action')
    assert "'=HYPERLINK" in csv_text and ',=HYPERLINK' not in csv_text


def test_requests_are_audited_with_actor_and_ip(client, monkeypatch):
    monkeypatch.setattr(domain_monitor, 'add_domain', lambda *a, **k: {'success': True, 'domain_id': 'dom_1'})
    r = client.post('/api/monitor/domain/add', json={'hostname': 'a.example', 'port': 8443, 'label': 'A'},
                    headers={**ADMIN, 'X-Real-IP': '198.51.100.7'})
    assert r.status_code == 200
    e = entries()[0]
    assert e['action'] == 'monitor.domain.add' and e['target'] == 'a.example:8443' and e['detail'] == {'label': 'A'}
    assert e['actor'] == {'type': 'admin'} and e['ip'] == '198.51.100.7' and e['result'] == 'success'


def test_failed_attempts_are_audited_as_failed(client, monkeypatch):
    monkeypatch.setattr(domain_monitor, 'remove_domain', lambda i: {'success': False, 'message': 'Domain not found'})
    client.delete('/api/monitor/domain/dom_x', headers=ADMIN)
    e = entries()[0]
    assert e['action'] == 'monitor.domain.remove' and e['target'] == 'dom_x' and e['result'] == 'failed' and e['status'] == 404


def test_api_key_lifecycle_never_logs_the_key(client):
    r = client.post('/api/admin/apikey/generate', json={'name': 'ci', 'rate_limit': '10 per hour'}, headers=ADMIN)
    key = r.get_json()['api_key']
    client.post('/api/admin/apikey/revoke', json={'api_key': key}, headers=ADMIN)
    raw = open(audit_log._path()).read()
    assert key not in raw and key[:30] not in raw
    actions = [e['action'] for e in entries()]
    assert actions == ['apikey.revoke', 'apikey.generate']
    assert entries()[0]['target'] == key[:15] + '...'


def test_api_key_actor_is_named_without_counting_usage(client, monkeypatch):
    key = client.post('/api/admin/apikey/generate', json={'name': 'ci'}, headers=ADMIN).get_json()['api_key']
    monkeypatch.setattr(domain_monitor, 'remove_domain', lambda i: {'success': True, 'message': 'ok'})
    client.delete('/api/monitor/domain/dom_1', headers={'X-Access-Token': key})
    assert entries()[0]['actor'] == {'type': 'api_key', 'id': 'ci'}
    from app.services import api_key_manager
    usage = [k['usage_count'] for k in api_key_manager._load_api_keys()['keys']]
    assert usage == [1]  # only the authorization itself counted, not the audit lookup


def test_refused_logins_are_recorded(client):
    client.get('/api/monitor/domain/list')                                               # no credentials
    client.get('/api/admin/apikey/list', headers={'Authorization': 'Bearer wrong'})      # wrong token
    denied = [e for e in entries() if e['action'] == 'auth.denied']
    assert len(denied) == 2
    assert denied[1]['detail'] == {'credentials_presented': False} and denied[0]['detail'] == {'credentials_presented': True}
    assert denied[0]['actor'] == {'type': 'anonymous'} and denied[0]['result'] == 'denied'
    assert 'wrong' not in open(audit_log._path()).read()


def test_reads_of_ordinary_endpoints_are_not_logged(client):
    client.get('/api/health')
    client.post('/api/check/tls', json={})
    assert entries() == []


def test_admin_endpoints(client):
    assert client.get('/api/admin/audit').status_code == 401
    audit_log.record('test.one', actor={'type': 'admin'})
    audit_log.record('test.two', actor={'type': 'admin'})
    r = client.get('/api/admin/audit?action=test.t&limit=10', headers=ADMIN).get_json()
    assert r['total'] == 1 and r['entries'][0]['action'] == 'test.two'
    assert client.get('/api/admin/audit?limit=x', headers=ADMIN).status_code == 400
    assert client.get('/api/admin/audit/verify', headers=ADMIN).get_json()['valid'] is True
    csv_resp = client.get('/api/admin/audit/export?format=csv', headers=ADMIN)
    assert csv_resp.mimetype == 'text/csv' and 'attachment' in csv_resp.headers['Content-Disposition']
    assert client.get('/api/admin/audit/export?format=xml', headers=ADMIN).status_code == 400
    assert any(e['action'] == 'audit.export' for e in entries())
