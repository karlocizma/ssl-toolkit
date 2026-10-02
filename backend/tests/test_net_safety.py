import pytest

from app.utils import net_safety
from app.utils.net_safety import UnsafeTargetError, is_public_ip, safe_create_connection, safe_get


@pytest.mark.parametrize('ip', [
    '127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '169.254.169.254',
    '::1', 'fe80::1', '::ffff:127.0.0.1', '0.0.0.0', '224.0.0.1',
])
def test_non_public_ips_rejected(ip):
    assert not is_public_ip(ip)


@pytest.mark.parametrize('ip', ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111'])
def test_public_ips_allowed(ip):
    assert is_public_ip(ip)


@pytest.mark.parametrize('host', ['localhost', '127.0.0.1', '169.254.169.254', '10.1.2.3'])
def test_connection_to_internal_hosts_blocked(host, monkeypatch):
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    with pytest.raises(UnsafeTargetError):
        safe_create_connection((host, 443), timeout=1)


@pytest.mark.parametrize('port', [0, 70000, 'abc', None])
def test_invalid_port_rejected(port):
    with pytest.raises(UnsafeTargetError):
        net_safety.validate_port(port)


@pytest.mark.parametrize('url', [
    'http://127.0.0.1/crl', 'http://169.254.169.254/latest/meta-data',
    'file:///etc/passwd', 'ftp://example.com/x',
])
def test_unsafe_urls_blocked(url, monkeypatch):
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    with pytest.raises(UnsafeTargetError):
        safe_get(url)


def test_private_targets_can_be_enabled(monkeypatch):
    monkeypatch.setenv('ALLOW_PRIVATE_TARGETS', 'true')
    assert net_safety.resolve_public('127.0.0.1', 443)


def test_domain_check_route_blocks_internal(client, monkeypatch):
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    resp = client.post('/api/check/domain', json={'hostname': '127.0.0.1', 'port': 22})
    body = resp.get_json()
    assert body['result']['connection_secure'] is False
    assert 'non-public' in body['result']['errors'][0]


def test_dns_rebinding_between_check_and_request_is_blocked(monkeypatch):
    """The name must not be resolved a second time by the HTTP client (public first, loopback second)."""
    monkeypatch.delenv('ALLOW_PRIVATE_TARGETS', raising=False)
    import socket
    answers = iter([[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 80))],
                    [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 80))]])
    monkeypatch.setattr(net_safety.socket, 'getaddrinfo', lambda *a, **k: next(answers))
    with pytest.raises(UnsafeTargetError):
        safe_get('http://rebind.example/')


def test_safe_get_reads_body_from_allowed_host(monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'ok')

        def log_message(self, *a):
            pass

    server = HTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv('ALLOW_PRIVATE_TARGETS', 'true')
    try:
        assert safe_get(f'http://127.0.0.1:{server.server_port}/').content == b'ok'
    finally:
        server.shutdown()
