"""SSRF protection for every outbound connection made on behalf of a user.

Targets resolving to loopback, private, link-local, multicast or otherwise
non-public addresses are rejected. Set ALLOW_PRIVATE_TARGETS=true to scan
internal hosts (e.g. an internal PKI).
"""
import ipaddress
import os
import socket
from typing import List, Tuple
from urllib.parse import urlsplit

import requests

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # OCSP/CRL/AIA downloads


class UnsafeTargetError(ValueError):
    """Raised when a target host or URL is not allowed."""


def _allow_private() -> bool:
    return os.environ.get('ALLOW_PRIVATE_TARGETS', '').lower() in ('1', 'true', 'yes')


def validate_port(port) -> int:
    try:
        port = int(port)
    except (TypeError, ValueError):
        raise UnsafeTargetError('Port must be an integer')
    if not 1 <= port <= 65535:
        raise UnsafeTargetError('Port must be between 1 and 65535')
    return port


def is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def resolve_public(host: str, port: int) -> List[Tuple]:
    """Resolve host and return getaddrinfo results, all of which must be allowed."""
    if not host or not isinstance(host, str):
        raise UnsafeTargetError('Hostname is required')
    port = validate_port(port)
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not _allow_private():
        for info in infos:
            ip = info[4][0].split('%')[0]
            if not is_public_ip(ip):
                raise UnsafeTargetError(
                    f'Target resolves to a non-public address ({ip}); scanning internal hosts is disabled'
                )
    return infos


def safe_create_connection(address, timeout=10):
    """Drop-in for socket.create_connection that connects only to validated IPs.

    Connecting to the vetted IP (not the name) prevents DNS-rebinding between
    the check and the connect.
    """
    host, port = address
    infos = resolve_public(host, port)
    last_err = None
    for family, socktype, proto, _, sockaddr in infos:
        sock = socket.socket(family, socktype, proto)
        sock.settimeout(timeout)
        try:
            sock.connect(sockaddr)
            return sock
        except OSError as e:
            last_err = e
            sock.close()
    raise last_err or OSError('Connection failed')


def _check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ('http', 'https') or not parts.hostname:
        raise UnsafeTargetError('Only http(s) URLs are allowed')
    resolve_public(parts.hostname, parts.port or (443 if parts.scheme == 'https' else 80))


def _request(method: str, url: str, **kwargs):
    _check_url(url)
    kwargs['allow_redirects'] = False  # a redirect could point at an internal host
    kwargs.setdefault('timeout', 10)
    kwargs['stream'] = True
    response = requests.request(method, url, **kwargs)
    content = b''
    for chunk in response.iter_content(65536):
        content += chunk
        if len(content) > MAX_RESPONSE_BYTES:
            response.close()
            raise UnsafeTargetError('Response too large')
    response._content = content
    return response


def safe_get(url: str, **kwargs):
    return _request('GET', url, **kwargs)


def safe_post(url: str, **kwargs):
    return _request('POST', url, **kwargs)
