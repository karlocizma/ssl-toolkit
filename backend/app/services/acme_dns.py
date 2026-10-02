"""DNS providers for automatic ACME dns-01 validation.

Credentials are supplied per request and kept in memory only. Each provider
implements add_txt() -> handle and remove_txt(handle).
"""
import base64
import os
import time
from typing import Dict, List, Optional

import dns.name
import dns.query
import dns.rcode
import dns.resolver
import dns.tsigkeyring
import dns.update
import requests

from app.utils.net_safety import UnsafeTargetError, resolve_public, validate_port

CLOUDFLARE_API = 'https://api.cloudflare.com/client/v4'
TXT_TTL = 60


class DnsProviderError(Exception):
    pass


class CloudflareProvider:
    def __init__(self, api_token: str, zone_id: Optional[str] = None, api_base: str = CLOUDFLARE_API):
        if not api_token:
            raise DnsProviderError('Cloudflare api_token is required')
        self.session = requests.Session()
        self.session.headers['Authorization'] = f'Bearer {api_token}'
        self.zone_id = zone_id
        self.api = api_base

    def _call(self, method: str, path: str, **kw) -> Dict:
        try:
            resp = self.session.request(method, self.api + path, timeout=15, **kw)
            body = resp.json()
        except (requests.RequestException, ValueError) as e:
            raise DnsProviderError(f'Cloudflare request failed: {e}')
        if not body.get('success'):
            errors = '; '.join(e.get('message', '') for e in body.get('errors', [])) or resp.text[:200]
            raise DnsProviderError(f'Cloudflare error: {errors}')
        return body

    def _zone_for(self, name: str) -> str:
        if self.zone_id:
            return self.zone_id
        labels = name.rstrip('.').split('.')
        for i in range(len(labels) - 1):  # longest suffix first, never a bare TLD
            candidate = '.'.join(labels[i:])
            result = self._call('GET', '/zones', params={'name': candidate}).get('result', [])
            if result:
                return result[0]['id']
        raise DnsProviderError(f'No Cloudflare zone found for {name} (does the token have access?)')

    def add_txt(self, name: str, value: str) -> Dict:
        zone = self._zone_for(name)
        record = self._call('POST', f'/zones/{zone}/dns_records',
                            json={'type': 'TXT', 'name': name, 'content': value, 'ttl': TXT_TTL})
        return {'zone': zone, 'id': record['result']['id']}

    def remove_txt(self, handle: Dict) -> None:
        self._call('DELETE', f"/zones/{handle['zone']}/dns_records/{handle['id']}")


class Rfc2136Provider:
    """Dynamic DNS update (RFC 2136) with TSIG: BIND, Knot, PowerDNS, Windows DNS, ..."""

    def __init__(self, server: str, zone: str, tsig_name: str, tsig_secret: str,
                 tsig_algorithm: str = 'hmac-sha256', port: int = 53):
        if not all([server, zone, tsig_name, tsig_secret]):
            raise DnsProviderError('rfc2136 requires server, zone, tsig_name and tsig_secret')
        try:
            base64.b64decode(tsig_secret, validate=True)
        except Exception:
            raise DnsProviderError('tsig_secret must be base64')
        self.server = server
        self.port = validate_port(port)
        self.zone = dns.name.from_text(zone)
        self.keyring = dns.tsigkeyring.from_text({tsig_name: tsig_secret})
        self.algorithm = tsig_algorithm
        try:
            self.address = resolve_public(server, self.port)[0][4][0]  # SSRF guard + pin the IP
        except UnsafeTargetError as e:
            raise DnsProviderError(str(e))

    def _send(self, update) -> None:
        try:
            response = dns.query.tcp(update, self.address, port=self.port, timeout=15)
        except Exception as e:
            raise DnsProviderError(f'DNS update failed: {e}')
        if response.rcode() != dns.rcode.NOERROR:
            raise DnsProviderError(f'DNS server rejected update: {dns.rcode.to_text(response.rcode())}')

    def _update(self):
        return dns.update.Update(self.zone, keyring=self.keyring, keyalgorithm=self.algorithm)

    def add_txt(self, name: str, value: str) -> Dict:
        update = self._update()
        update.add(dns.name.from_text(name), TXT_TTL, 'TXT', f'"{value}"')
        self._send(update)
        return {'name': name, 'value': value}

    def remove_txt(self, handle: Dict) -> None:
        update = self._update()
        update.delete(dns.name.from_text(handle['name']), 'TXT', f'"{handle["value"]}"')
        self._send(update)


class AcmeDnsProvider:
    """acme-dns (github.com/joohoi/acme-dns): works with any DNS host via a one-time CNAME.

    Create an account on the acme-dns server, then add
        _acme-challenge.<your domain>  CNAME  <subdomain>.<acme-dns zone>
    at your DNS provider (Hetzner, Route 53, anything). Challenges are answered through acme-dns.
    """

    def __init__(self, server_url: str, username: str, password: str, subdomain: str):
        if not all([server_url, username, password, subdomain]):
            raise DnsProviderError('acme-dns requires server_url, username, password and subdomain')
        if not server_url.startswith(('http://', 'https://')):
            raise DnsProviderError('server_url must start with http:// or https://')
        self.url = server_url.rstrip('/')
        self.headers = {'X-Api-User': username, 'X-Api-Key': password}
        self.subdomain = subdomain

    def add_txt(self, name: str, value: str) -> Dict:
        from app.utils.net_safety import safe_post
        try:
            resp = safe_post(f'{self.url}/update', json={'subdomain': self.subdomain, 'txt': value},
                             headers=self.headers, timeout=15)
        except UnsafeTargetError as e:
            raise DnsProviderError(str(e))
        except requests.RequestException as e:
            raise DnsProviderError(f'acme-dns request failed: {e}')
        if resp.status_code != 200:
            raise DnsProviderError(f'acme-dns rejected the update (HTTP {resp.status_code}); check username, password and subdomain')
        return {'name': name, 'value': value}

    def remove_txt(self, handle: Dict) -> None:
        pass  # acme-dns keeps only the two most recent values and has no delete call


def build_provider(cfg: Dict):
    cfg = cfg or {}
    kind = cfg.get('type')
    if kind == 'cloudflare':
        return CloudflareProvider(cfg.get('api_token', ''), cfg.get('zone_id'))
    if kind == 'rfc2136':
        return Rfc2136Provider(cfg.get('server', ''), cfg.get('zone', ''), cfg.get('tsig_name', ''),
                               cfg.get('tsig_secret', ''), cfg.get('tsig_algorithm', 'hmac-sha256'),
                               cfg.get('port', 53))
    if kind == 'acme-dns':
        return AcmeDnsProvider(cfg.get('server_url', ''), cfg.get('username', ''), cfg.get('password', ''),
                               cfg.get('subdomain', ''))
    raise DnsProviderError("dns_provider.type must be 'cloudflare', 'rfc2136' or 'acme-dns'")


def _resolvers() -> List[str]:
    raw = os.environ.get('ACME_DNS_RESOLVERS', '1.1.1.1,8.8.8.8')
    return [r.strip() for r in raw.split(',') if r.strip()]


def wait_for_txt(name: str, value: str, timeout: int = 90) -> None:
    """Block until a TXT record is visible through the configured public resolvers."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [r.split(':')[0] for r in _resolvers()]
    resolver.port = int(_resolvers()[0].split(':')[1]) if ':' in _resolvers()[0] else 53
    resolver.lifetime = 5
    deadline = time.time() + timeout
    while True:
        try:
            answers = resolver.resolve(name, 'TXT', raise_on_no_answer=False)
            if any(value in b''.join(r.strings).decode() for r in answers):
                return
        except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
            pass
        if time.time() > deadline:
            raise DnsProviderError(f'TXT record {name} did not become visible within {timeout}s')
        time.sleep(2)
