"""Mail client auto-configuration checker (Outlook Autodiscover, Thunderbird autoconfig, RFC 6186).

Walks the same lookup sequence real mail clients use and reports every step with its
status, redirects and any settings found. No credentials are sent: an Exchange server
answering 401 is the *expected* result and proves the endpoint is live.

Command line:  python -m app.services.autodiscover example.com [user@example.com]
"""
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlsplit
import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import Element

import dns.exception
import dns.resolver
import requests

from app.utils.net_safety import UnsafeTargetError, safe_request

STEP_TIMEOUT = 8
MAX_REDIRECTS = 5
_HOSTNAME_RE = re.compile(r'^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')
_EMAIL_RE = re.compile(r'^[A-Za-z0-9._%+-]{1,64}@([A-Za-z0-9.-]+)$')
USER_AGENT = 'ssl-toolkit-autodiscover/1.0'

POX_BODY = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">'
    '<Request><EMailAddress>{email}</EMailAddress>'
    '<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'
    '</AcceptableResponseSchema></Request></Autodiscover>'
)
RFC6186_SERVICES = [
    ('_imaps._tcp', 'IMAP over TLS'), ('_imap._tcp', 'IMAP (STARTTLS)'),
    ('_pop3s._tcp', 'POP3 over TLS'), ('_submissions._tcp', 'SMTP submission over TLS'),
    ('_submission._tcp', 'SMTP submission (STARTTLS)'),
]


# --------------------------------------------------------------------------- parsing
def _safe_xml(text: str) -> Optional[Element]:
    """Parse XML from an untrusted server; DTDs/entities are refused outright."""
    if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        return None
    try:
        return ET.fromstring(text)
    except (ET.ParseError, DefusedXmlException):
        return None


def _local(tag: str) -> str:
    return tag.rsplit('}', 1)[-1]


def _child_text(node: Element, name: str) -> Optional[str]:
    for child in node.iter():
        if _local(child.tag) == name and child.text and child.text.strip():
            return child.text.strip()
    return None


def parse_pox_response(text: str) -> Dict:
    """Extract protocols, errors or redirects from an Exchange Autodiscover (POX) response."""
    root = _safe_xml(text)
    if root is None:
        return {'valid_xml': False}
    out: Dict = {'valid_xml': True, 'protocols': []}
    for node in root.iter():
        name = _local(node.tag)
        if name == 'Protocol':
            proto = {k: _child_text(node, k) for k in
                     ('Type', 'Server', 'Port', 'SSL', 'LoginName', 'AuthPackage', 'ASUrl', 'OABUrl', 'EwsUrl')}
            out['protocols'].append({k: v for k, v in proto.items() if v})
        elif name == 'Error':
            out['error'] = _child_text(node, 'Message') or 'Autodiscover returned an error'
        elif name == 'Action' and node.text == 'redirectAddr':
            out['redirect_address'] = _child_text(root, 'RedirectAddr')
        elif name == 'Action' and node.text == 'redirectUrl':
            out['redirect_url'] = _child_text(root, 'RedirectUrl')
    return out


def parse_autoconfig(text: str) -> Dict:
    """Extract servers from a Thunderbird/Mozilla autoconfig (config-v1.1.xml) document."""
    root = _safe_xml(text)
    if root is None or _local(root.tag) != 'clientConfig':
        return {'valid_xml': False}
    servers = []
    for node in root.iter():
        kind = _local(node.tag)
        if kind in ('incomingServer', 'outgoingServer'):
            servers.append({
                'direction': 'incoming' if kind == 'incomingServer' else 'outgoing',
                'type': node.get('type'),
                'hostname': _child_text(node, 'hostname'), 'port': _child_text(node, 'port'),
                'security': _child_text(node, 'socketType'), 'authentication': _child_text(node, 'authentication'),
                'username': _child_text(node, 'username'),
            })
    provider = _child_text(root, 'displayName')
    return {'valid_xml': True, 'provider': provider, 'servers': [{k: v for k, v in s.items() if v} for s in servers]}


# --------------------------------------------------------------------------- DNS
def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = r.lifetime = 5
    return r


def lookup_srv(name: str) -> Dict:
    try:
        answers = _resolver().resolve(name, 'SRV')
    except dns.resolver.NXDOMAIN:
        return {'name': name, 'found': False, 'records': []}
    except dns.resolver.NoAnswer:
        return {'name': name, 'found': False, 'records': []}
    except dns.exception.DNSException as e:
        return {'name': name, 'found': False, 'records': [], 'error': str(e) or type(e).__name__}
    records = [{'priority': r.priority, 'weight': r.weight, 'port': r.port,
                'target': str(r.target).rstrip('.') or '.'} for r in answers]
    return {'name': name, 'found': True, 'records': sorted(records, key=lambda r: (r['priority'], -r['weight']))}


def lookup_cname_and_mx(domain: str) -> Dict:
    info: Dict = {'autodiscover_cname': None, 'mx': []}
    res = _resolver()
    try:
        info['autodiscover_cname'] = str(res.resolve(f'autodiscover.{domain}', 'CNAME')[0].target).rstrip('.')
    except dns.exception.DNSException:
        pass
    try:
        info['mx'] = [str(r.exchange).rstrip('.') for r in sorted(res.resolve(domain, 'MX'), key=lambda r: r.preference)]
    except dns.exception.DNSException:
        pass
    return info


# --------------------------------------------------------------------------- HTTP probing
def _http(method: str, url: str, **kw):
    kw.setdefault('timeout', STEP_TIMEOUT)
    kw.setdefault('headers', {}).setdefault('User-Agent', USER_AGENT)
    return safe_request(method, url, **kw)


def _describe_error(exc: Exception) -> str:
    if isinstance(exc, UnsafeTargetError):
        return str(exc)
    if isinstance(exc, socket.gaierror):
        return 'DNS name does not resolve'
    if isinstance(exc, requests.exceptions.SSLError):
        text = str(exc)
        if 'CERTIFICATE_VERIFY_FAILED' in text or 'certificate' in text.lower():
            m = re.search(r'\(_ssl\.c:\d+\)|certificate verify failed: ([^(]+)', text)
            return 'TLS certificate problem: ' + (m.group(1).strip() if m and m.group(1) else 'certificate verification failed')
        return 'TLS error: ' + text[:160]
    if isinstance(exc, requests.exceptions.ConnectTimeout) or isinstance(exc, requests.exceptions.ReadTimeout):
        return 'Timed out'
    if isinstance(exc, requests.exceptions.ConnectionError):
        text = str(exc)
        if 'Name or service not known' in text or 'getaddrinfo' in text or 'nodename nor servname' in text:
            return 'DNS name does not resolve'
        return 'Connection failed: ' + text[:140]
    return f'{type(exc).__name__}: {str(exc)[:140]}'


def _probe(label: str, method: str, url: str, kind: str, body: Optional[str] = None) -> Dict:
    """Request a URL following redirects manually (every hop passes the SSRF guard)."""
    step: Dict = {'step': label, 'kind': kind, 'method': method, 'url': url, 'hops': []}
    started = time.time()
    current, cur_method, data = url, method, body
    try:
        for _ in range(MAX_REDIRECTS + 1):
            headers = {'Content-Type': 'text/xml'} if data else {}
            resp = _http(cur_method, current, data=data, headers=headers)
            step['hops'].append({'url': current, 'status': resp.status_code})
            location = resp.headers.get('Location')
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                current = urljoin(current, location)
                if resp.status_code in (301, 302, 303):
                    cur_method, data = 'GET', None
                continue
            step['status'] = resp.status_code
            step['final_url'] = current
            step['www_authenticate'] = resp.headers.get('WWW-Authenticate')
            step['content_type'] = resp.headers.get('Content-Type', '')
            step['_text'] = resp.text if resp.status_code == 200 else ''
            break
        else:
            step['error'] = f'More than {MAX_REDIRECTS} redirects'
    except Exception as exc:
        step['error'] = _describe_error(exc)
    step['elapsed_ms'] = int((time.time() - started) * 1000)
    return step


def _interpret_pox(step: Dict) -> None:
    if 'error' in step:
        step['ok'], step['result'] = False, step['error']
        return
    status = step.get('status')
    if status == 200:
        parsed = parse_pox_response(step.pop('_text', ''))
        step['parsed'] = parsed
        if parsed.get('protocols'):
            step['ok'], step['result'] = True, f"Autodiscover answered with {len(parsed['protocols'])} protocol settings"
        elif parsed.get('redirect_address') or parsed.get('redirect_url'):
            step['ok'], step['result'] = True, 'Autodiscover answered with a redirect: ' + (
                parsed.get('redirect_address') or parsed.get('redirect_url'))
        elif parsed.get('error'):
            step['ok'], step['result'] = True, 'Endpoint is live but reported: ' + parsed['error']
        else:
            step['ok'], step['result'] = False, '200 OK but the body is not a valid Autodiscover response'
    elif status == 401:
        scheme = (step.get('www_authenticate') or '').split(',')[0].split(' ')[0] or 'unknown'
        step['ok'], step['result'] = True, f'Endpoint is live and requires authentication ({scheme}); expected without credentials'
    elif status in (403, 405):
        step['ok'], step['result'] = True, f'Endpoint responded {status} (reachable, but not usable anonymously)'
    elif status == 404:
        step['ok'], step['result'] = False, 'Not found (404)'
    else:
        step['ok'], step['result'] = False, f'Unexpected HTTP status {status}'
    step.pop('_text', None)


def _interpret_autoconfig(step: Dict) -> None:
    if 'error' in step:
        step['ok'], step['result'] = False, step['error']
        return
    status = step.get('status')
    if status == 200:
        parsed = parse_autoconfig(step.pop('_text', ''))
        step['parsed'] = parsed
        if parsed.get('servers'):
            step['ok'], step['result'] = True, f"Found autoconfig with {len(parsed['servers'])} server definitions"
        else:
            step['ok'], step['result'] = False, '200 OK but not a valid clientConfig document'
    elif status == 404:
        step['ok'], step['result'] = False, 'Not found (404)'
    else:
        step['ok'], step['result'] = False, f'Unexpected HTTP status {status}'
    step.pop('_text', None)


# --------------------------------------------------------------------------- orchestration
def normalize_target(domain: str, email: Optional[str]) -> tuple:
    domain = (domain or '').strip().lower().rstrip('.')
    email = (email or '').strip()
    if email:
        m = _EMAIL_RE.match(email)
        if not m:
            raise ValueError('email is not a valid address')
        domain = m.group(1).lower()
    if not _HOSTNAME_RE.match(domain) or domain.rsplit('.', 1)[-1].isdigit():  # rejects IP addresses
        raise ValueError('A valid domain name is required')
    return domain, email or f'test@{domain}'


def check_autodiscover(domain: str, email: Optional[str] = None) -> Dict:
    domain, email = normalize_target(domain, email)
    body = POX_BODY.format(email=email.replace('&', '&amp;').replace('<', '&lt;'))
    enc_email = requests.utils.quote(email)

    dns_info = lookup_cname_and_mx(domain)
    srv_autodiscover = lookup_srv(f'_autodiscover._tcp.{domain}')

    # Outlook (Exchange POX) sequence, in the order Outlook tries it.
    pox_plan = [
        ('1. HTTPS root domain', 'POST', f'https://{domain}/autodiscover/autodiscover.xml'),
        ('2. HTTPS autodiscover host', 'POST', f'https://autodiscover.{domain}/autodiscover/autodiscover.xml'),
        ('3. HTTP redirect check', 'GET', f'http://autodiscover.{domain}/autodiscover/autodiscover.xml'),
    ]
    if srv_autodiscover['found']:
        for rec in srv_autodiscover['records'][:2]:
            if rec['target'] != '.':
                pox_plan.append((f"4. SRV target {rec['target']}", 'POST',
                                 f"https://{rec['target']}:{rec['port']}/autodiscover/autodiscover.xml"
                                 if rec['port'] != 443 else f"https://{rec['target']}/autodiscover/autodiscover.xml"))
    cfg_plan = [
        ('Autoconfig (HTTPS subdomain)', 'GET', f'https://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={enc_email}'),
        ('Autoconfig (HTTPS well-known)', 'GET', f'https://{domain}/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress={enc_email}'),
        ('Autoconfig (HTTP subdomain)', 'GET', f'http://autoconfig.{domain}/mail/config-v1.1.xml?emailaddress={enc_email}'),
    ]
    jobs = [(l, m, u, 'outlook', body if m == 'POST' else None) for l, m, u in pox_plan] + \
           [(l, m, u, 'thunderbird', None) for l, m, u in cfg_plan]
    with ThreadPoolExecutor(max_workers=6) as pool:
        steps = list(pool.map(lambda j: _probe(*j), jobs))
        srv_checks = list(pool.map(lookup_srv, [f'{p}.{domain}' for p, _ in RFC6186_SERVICES]))
    for step in steps:
        (_interpret_pox if step['kind'] == 'outlook' else _interpret_autoconfig)(step)

    rfc6186 = []
    for (prefix, label), res in zip(RFC6186_SERVICES, srv_checks):
        res['service'] = label
        rfc6186.append(res)

    summary = _summarize(domain, steps, srv_autodiscover, rfc6186, dns_info)
    return {'domain': domain, 'email': email, 'dns': {**dns_info, 'srv_autodiscover': srv_autodiscover},
            'steps': steps, 'rfc6186': rfc6186, **summary}


def _summarize(domain, steps, srv_autodiscover, rfc6186, dns_info) -> Dict:
    outlook_ok = [s for s in steps if s['kind'] == 'outlook' and s.get('ok') and s['method'] == 'POST']
    thunderbird_ok = [s for s in steps if s['kind'] == 'thunderbird' and s.get('ok')]
    srv_ok = [r for r in rfc6186 if r['found']]
    findings: List[Dict] = []

    def add(severity, message):
        findings.append({'severity': severity, 'message': message})

    if not outlook_ok:
        add('error', 'No working Outlook/Exchange Autodiscover endpoint was found')
    for s in steps:
        if s['kind'] == 'outlook' and 'error' in s and 'certificate' in s['error'].lower():
            add('error', f"{s['url']}: {s['error']}. Outlook refuses endpoints whose certificate does not "
                         f"cover the autodiscover host name")
    cname = dns_info.get('autodiscover_cname')
    if cname:
        add('info', f'autodiscover.{domain} is a CNAME to {cname}')
    if any('protection.outlook.com' in mx for mx in dns_info.get('mx', [])) and not (
            cname and 'outlook.com' in cname):
        add('warning', 'MX points to Microsoft 365 but autodiscover.%s does not CNAME to autodiscover.outlook.com' % domain)
    if not thunderbird_ok:
        add('warning', 'No Thunderbird/Mozilla autoconfig found (Thunderbird falls back to its public database)')
    if not srv_ok:
        add('info', 'No RFC 6186 SRV records (_imaps/_submission…) are published')
    elif not any(r['service'].startswith('SMTP') and r['found'] for r in rfc6186):
        add('warning', 'RFC 6186 IMAP/POP3 SRV records exist but no submission (SMTP) record')
    if any(r.get('records') and r['records'][0]['target'] == '.' for r in rfc6186 + [srv_autodiscover]):
        add('info', 'A SRV record with target "." means the service is explicitly not offered')
    status = 'ok' if outlook_ok else ('partial' if (thunderbird_ok or srv_ok) else 'failed')
    return {'status': status, 'outlook_autodiscover': bool(outlook_ok),
            'thunderbird_autoconfig': bool(thunderbird_ok), 'rfc6186_srv': bool(srv_ok), 'findings': findings}


def _print_report(result: Dict) -> None:
    print(f"Autodiscover check for {result['domain']} ({result['email']}): {result['status'].upper()}")
    for s in result['steps']:
        mark = 'OK  ' if s.get('ok') else 'FAIL'
        print(f"  [{mark}] {s['step']}: {s['result']}\n         {s['method']} {s['url']}")
        for hop in s['hops'][:-1]:
            print(f"         -> {hop['status']} {hop['url']}")
    for r in result['rfc6186']:
        recs = ', '.join(f"{x['target']}:{x['port']}" for x in r['records']) or 'none'
        print(f"  SRV {r['name']} ({r['service']}): {recs}")
    for f in result['findings']:
        print(f"  {f['severity'].upper()}: {f['message']}")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    arg = sys.argv[1]
    try:
        _print_report(check_autodiscover(arg if '@' not in arg else '',
                                         arg if '@' in arg else (sys.argv[2] if len(sys.argv) > 2 else None)))
    except ValueError as e:
        sys.exit(f'error: {e}')
