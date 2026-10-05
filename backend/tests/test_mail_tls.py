import socket
import ssl
import threading

import pytest

from app.services import mail_tls


@pytest.fixture
def mail_server(tmp_path, sample_cert_pem, sample_key_pem, monkeypatch):
    """Factory for a throwaway SMTP/IMAP/POP3 server with STARTTLS (or implicit TLS)."""
    monkeypatch.setenv('ALLOW_PRIVATE_TARGETS', 'true')
    cert, key = tmp_path / 'c.pem', tmp_path / 'k.pem'
    cert.write_text(sample_cert_pem)
    key.write_text(sample_key_pem)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    stops = []

    def start(protocol, starttls=True, implicit=False, auth=False):
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(32)
        stop = threading.Event()
        stops.append((stop, srv))

        def handle(conn):
            try:
                conn.settimeout(3)
                if implicit:
                    ssl_conn = ctx.wrap_socket(conn, server_side=True)
                    ssl_conn.close()
                    return
                f = conn.makefile('rwb', buffering=0)
                if protocol == 'smtp':
                    f.write(b'220 mail.test ESMTP ready\r\n')
                    while True:
                        line = f.readline().strip().upper()
                        if line.startswith(b'EHLO'):
                            caps = [b'250-mail.test', b'250-SIZE 1000']
                            if auth:
                                caps.append(b'250-AUTH PLAIN LOGIN')
                            caps.append(b'250 STARTTLS' if starttls else b'250 8BITMIME')
                            f.write(b'\r\n'.join(caps) + b'\r\n')
                        elif line == b'STARTTLS':
                            f.write(b'220 Go ahead\r\n')
                            break
                        else:
                            return
                elif protocol == 'imap':
                    f.write(b'* OK IMAP ready\r\n')
                    assert f.readline().strip() == b'a1 CAPABILITY'
                    f.write(b'* CAPABILITY IMAP4rev1' + (b' STARTTLS' if starttls else b'') + b'\r\na1 OK done\r\n')
                    if not starttls:
                        return
                    assert f.readline().strip() == b'a2 STARTTLS'
                    f.write(b'a2 OK Begin TLS\r\n')
                else:
                    f.write(b'+OK POP3 ready\r\n')
                    assert f.readline().strip() == b'CAPA'
                    f.write(b'+OK\r\nUSER\r\n' + (b'STLS\r\n' if starttls else b'') + b'.\r\n')
                    if not starttls:
                        return
                    assert f.readline().strip() == b'STLS'
                    f.write(b'+OK Begin TLS\r\n')
                ctx.wrap_socket(conn, server_side=True).close()
            except (ssl.SSLError, OSError, AssertionError):
                pass
            finally:
                conn.close()

        def serve():
            srv.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except OSError:
                    continue
                threading.Thread(target=handle, args=(conn,), daemon=True).start()
        threading.Thread(target=serve, daemon=True).start()
        return srv.getsockname()[1]

    yield start
    for stop, srv in stops:
        stop.set()
        srv.close()


@pytest.mark.parametrize('protocol', ['smtp', 'imap', 'pop3'])
def test_starttls_supported(mail_server, protocol):
    port = mail_server(protocol)
    r = mail_tls.scan_mail('127.0.0.1', port, protocol, 'starttls', timeout=3)
    assert r['reachable'] and r['starttls'] is True
    assert r['protocols']['TLSv1.2']['supported'] or r['protocols']['TLSv1.3']['supported']
    assert r['certificate']['subject'] == 'test.example.com'
    assert r['certificate']['trusted'] is False  # self-signed, wrong host
    assert r['grade'] == 'F'  # untrusted certificate
    assert r['banner']


@pytest.mark.parametrize('protocol', ['smtp', 'imap', 'pop3'])
def test_missing_starttls_is_critical(mail_server, protocol):
    port = mail_server(protocol, starttls=False)
    r = mail_tls.scan_mail('127.0.0.1', port, protocol, 'starttls', timeout=3)
    assert r['reachable'] and r['starttls'] is False and r['grade'] == 'F'
    assert 'plaintext' in r['findings'][0]['message']


def test_auth_before_starttls_is_flagged(mail_server):
    port = mail_server('smtp', auth=True)
    r = mail_tls.scan_mail('127.0.0.1', port, 'smtp', 'starttls', timeout=3)
    assert any('before STARTTLS' in f['message'] for f in r['findings'])


def test_implicit_tls(mail_server):
    port = mail_server('smtp', implicit=True)
    r = mail_tls.scan_mail('127.0.0.1', port, 'smtp', 'implicit', timeout=3)
    assert r['reachable'] and r['starttls'] is None and r['protocols']


def test_not_a_mail_server_is_reported(local_tls, monkeypatch):
    monkeypatch.setenv('ALLOW_PRIVATE_TARGETS', 'true')
    r = mail_tls.scan_mail('127.0.0.1', local_tls, 'smtp', 'starttls', timeout=3)
    assert r['reachable'] is False and r['error']


def test_private_targets_blocked_by_default(monkeypatch):
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    from app.utils.net_safety import UnsafeTargetError
    with pytest.raises(UnsafeTargetError):
        mail_tls.scan_mail('127.0.0.1', 25)


def test_default_modes_by_port():
    assert mail_tls.resolve_service(25, None, None) == ('smtp', 'starttls')
    assert mail_tls.resolve_service(465, None, None) == ('smtp', 'implicit')
    assert mail_tls.resolve_service(993, None, None) == ('imap', 'implicit')
    assert mail_tls.resolve_service(2525, None, None) == ('smtp', 'starttls')
    with pytest.raises(ValueError):
        mail_tls.resolve_service(25, 'ftp', None)


def test_domain_scan_uses_mx_records_and_worst_grade(monkeypatch):
    monkeypatch.setattr(mail_tls, '_mx_hosts', lambda d: [(10, 'mx1.example.com'), (20, 'mx2.example.com')])
    grades = {'mx1.example.com': {'host': 'mx1.example.com', 'reachable': True, 'starttls': True, 'grade': 'A'},
              'mx2.example.com': {'host': 'mx2.example.com', 'reachable': True, 'starttls': False, 'grade': 'F'}}
    monkeypatch.setattr(mail_tls, 'scan_mail', lambda host, *a, **k: dict(grades[host]))
    r = mail_tls.scan_mail_domain('example.com')
    assert r['grade'] == 'F' and [m['priority'] for m in r['mx']] == [10, 20]
    assert any('mx2.example.com does not offer STARTTLS' in f['message'] for f in r['findings'])
    monkeypatch.setattr(mail_tls, '_mx_hosts', lambda d: [])
    assert mail_tls.scan_mail_domain('example.com')['findings'][0]['severity'] == 'critical'


def test_route_scans_a_server_and_validates_input(client, mail_server):
    port = mail_server('smtp')
    r = client.post('/api/check/mail-tls', json={'host': '127.0.0.1', 'port': port, 'protocol': 'smtp', 'timeout': 3})
    body = r.get_json()
    assert r.status_code == 200 and body['result']['starttls'] is True
    assert client.post('/api/check/mail-tls', json={}).status_code == 400
    assert client.post('/api/check/mail-tls', json={'host': 'x.example', 'protocol': 'ftp'}).status_code == 400


def test_route_blocks_internal_hosts(client, monkeypatch):
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    r = client.post('/api/check/mail-tls', json={'host': '127.0.0.1', 'port': 25})
    assert r.status_code == 400 and 'non-public' in r.get_json()['error']


def test_cli_mailtls(mail_server, capsys):
    from app import cli
    good = mail_server('smtp', starttls=False)
    code = cli.main(['mailtls', f'127.0.0.1:{good}', '--protocol', 'smtp', '--timeout', '3'])
    out = capsys.readouterr().out
    assert code == 1 and 'FAIL' in out and 'plaintext' in out
