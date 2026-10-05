"""Mail-server TLS test: SMTP / IMAP / POP3 with STARTTLS or implicit TLS.

Reuses the TLS scanner (protocols, ciphers, grade) after running the plaintext STARTTLS prelude of
each protocol. By default only the negotiated cipher per protocol is recorded (a handful of
connections), because mail servers rate-limit and greylist; deep=True enumerates every cipher.

Note: many hosting providers block outbound port 25. A timeout there is not a server fault.
"""
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

from app.services.deliverability import _resolver
from app.services.tls_scanner import GRADE_ORDER, scan_tls
from app.utils.net_safety import UnsafeTargetError, safe_create_connection, validate_port
from app.utils.ssl_utils import get_certificate_info

# port -> (protocol, mode)
PORTS = {
    25: ('smtp', 'starttls'), 587: ('smtp', 'starttls'), 465: ('smtp', 'implicit'),
    143: ('imap', 'starttls'), 993: ('imap', 'implicit'),
    110: ('pop3', 'starttls'), 995: ('pop3', 'implicit'),
}
EHLO_NAME = 'ssl-toolkit.invalid'
MAX_LINE = 4096


class MailProtocolError(Exception):
    """The server did not speak the expected protocol."""


class StartTLSNotOffered(MailProtocolError):
    pass


def _readline(sock: socket.socket, buf: bytearray) -> str:
    while b'\n' not in buf:
        chunk = sock.recv(1024)
        if not chunk:
            raise MailProtocolError('Connection closed by the server')
        buf += chunk
        if len(buf) > MAX_LINE * 8:
            raise MailProtocolError('Unexpectedly long server response')
    line, _, rest = bytes(buf).partition(b'\n')
    buf[:] = rest
    return line.decode('ascii', 'replace').rstrip('\r')


def _smtp_reply(sock, buf) -> Tuple[int, List[str]]:
    lines = []
    while True:
        line = _readline(sock, buf)
        lines.append(line)
        if len(line) < 3 or not line[:3].isdigit():
            raise MailProtocolError('Not an SMTP server (unexpected greeting)')
        if len(line) == 3 or line[3] != '-':
            return int(line[:3]), lines


def prelude_smtp(sock, info: Optional[Dict] = None) -> None:
    buf = bytearray()
    code, lines = _smtp_reply(sock, buf)
    if code != 220:
        raise MailProtocolError(f'SMTP server greeted with {code}')
    if info is not None:
        info['banner'] = lines[0][4:].strip()
    sock.sendall(f'EHLO {EHLO_NAME}\r\n'.encode())
    code, lines = _smtp_reply(sock, buf)
    caps = [l[4:].strip().upper() for l in lines[1:]] if code == 250 else []
    if info is not None:
        info['capabilities'] = caps
    if not any(c == 'STARTTLS' for c in caps):
        raise StartTLSNotOffered('The server does not offer STARTTLS')
    sock.sendall(b'STARTTLS\r\n')
    code, _ = _smtp_reply(sock, buf)
    if code != 220:
        raise MailProtocolError(f'STARTTLS was refused ({code})')


def prelude_imap(sock, info: Optional[Dict] = None) -> None:
    buf = bytearray()
    greeting = _readline(sock, buf)
    if not greeting.startswith('* OK'):
        raise MailProtocolError('Not an IMAP server (unexpected greeting)')
    if info is not None:
        info['banner'] = greeting[4:].strip()
    sock.sendall(b'a1 CAPABILITY\r\n')
    caps: List[str] = []
    while True:
        line = _readline(sock, buf)
        if line.startswith('* CAPABILITY'):
            caps = line.split()[2:]
        elif line.startswith('a1 '):
            break
    if info is not None:
        info['capabilities'] = [c.upper() for c in caps]
    if 'STARTTLS' not in [c.upper() for c in caps]:
        raise StartTLSNotOffered('The server does not offer STARTTLS')
    sock.sendall(b'a2 STARTTLS\r\n')
    while True:
        line = _readline(sock, buf)
        if line.startswith('a2 '):
            if not line.startswith('a2 OK'):
                raise MailProtocolError('STARTTLS was refused')
            return


def prelude_pop3(sock, info: Optional[Dict] = None) -> None:
    buf = bytearray()
    greeting = _readline(sock, buf)
    if not greeting.startswith('+OK'):
        raise MailProtocolError('Not a POP3 server (unexpected greeting)')
    if info is not None:
        info['banner'] = greeting[3:].strip()
    sock.sendall(b'CAPA\r\n')
    first = _readline(sock, buf)
    caps: List[str] = []
    if first.startswith('+OK'):
        while True:
            line = _readline(sock, buf)
            if line == '.':
                break
            caps.append(line.strip().upper())
    if info is not None:
        info['capabilities'] = caps
    if 'STLS' not in caps:
        raise StartTLSNotOffered('The server does not offer STLS (POP3 STARTTLS)')
    sock.sendall(b'STLS\r\n')
    if not _readline(sock, buf).startswith('+OK'):
        raise MailProtocolError('STLS was refused')


PRELUDES: Dict[str, Callable] = {'smtp': prelude_smtp, 'imap': prelude_imap, 'pop3': prelude_pop3}


def resolve_service(port: int, protocol: Optional[str], mode: Optional[str]) -> Tuple[str, str]:
    known = PORTS.get(port)
    protocol = (protocol or (known[0] if known else 'smtp')).lower()
    if protocol not in PRELUDES:
        raise ValueError('protocol must be smtp, imap or pop3')
    mode = (mode or (known[1] if known and known[0] == protocol else 'starttls')).lower()
    if mode not in ('starttls', 'implicit'):
        raise ValueError('mode must be starttls or implicit')
    return protocol, mode


def _certificate(host: str, port: int, opener, timeout: float) -> Dict:
    """Certificate details plus whether it validates for the hostname."""
    errors: List[str] = []
    secure = False
    for verify in (True, False):
        ctx = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        try:
            with safe_create_connection((host, port), timeout=timeout) as sock:
                if opener:
                    opener(sock)
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
            secure = verify
            break
        except ssl.SSLCertVerificationError as e:
            errors.append(e.verify_message or str(e))
        except UnsafeTargetError:
            raise
        except (ssl.SSLError, OSError, MailProtocolError) as e:
            errors.append(str(e)[:150])
            return {'connection_secure': False, 'valid_for_hostname': False, 'errors': errors}
    cert = get_certificate_info(ssl.DER_cert_to_PEM_cert(der))
    return {'connection_secure': secure, 'valid_for_hostname': secure or not errors,
            'errors': errors, 'certificate': cert}


def scan_mail(host: str, port=25, protocol: Optional[str] = None, mode: Optional[str] = None,
              timeout: float = 6.0, deep: bool = False) -> Dict:
    host = (host or '').strip().rstrip('.')
    if not host:
        raise ValueError('Host is required')
    port = validate_port(port)
    timeout = max(2.0, min(float(timeout), 12.0))
    protocol, mode = resolve_service(port, protocol, mode)
    result: Dict = {'host': host, 'port': port, 'protocol': protocol, 'mode': mode}
    findings: List[Dict] = []

    opener = None
    if mode == 'starttls':
        info: Dict = {}
        prelude = PRELUDES[protocol]
        try:
            with safe_create_connection((host, port), timeout=timeout) as sock:
                prelude(sock, info)
        except UnsafeTargetError:
            raise
        except StartTLSNotOffered as e:
            result.update(reachable=True, starttls=False, banner=info.get('banner'), grade='F',
                          findings=[{'severity': 'critical', 'message': f'{e}: mail is exchanged in plaintext'}])
            return result
        except (MailProtocolError, OSError) as e:
            hint = ' (many hosting providers block outbound port 25)' if port == 25 else ''
            result.update(reachable=False, error=f'{type(e).__name__}: {str(e)[:150]}{hint}')
            return result
        result.update(starttls=True, banner=info.get('banner'))
        if protocol == 'smtp' and any(c.startswith('AUTH') for c in info.get('capabilities', [])):
            findings.append({'severity': 'warning',
                             'message': 'Authentication is advertised before STARTTLS (credentials could be sent unencrypted)'})
        opener = prelude
    else:
        result['starttls'] = None

    holder: Dict = {}

    def cert_check():
        holder['cert'] = _certificate(host, port, opener, timeout)
        return holder['cert']

    scan = scan_tls(host, port, timeout, opener=opener, cert_check=cert_check, enumerate_ciphers=deep)
    if not scan.get('reachable'):
        result.update(reachable=False, error=scan.get('error'))
        return result
    result.update(reachable=True, protocols=scan['protocols'], certificate_trusted=scan['certificate_trusted'],
                  grade=scan['grade'], findings=findings + scan['findings'])
    result['certificate'] = _summarize(holder.get('cert'), result)
    return result


def _summarize(cert_result: Optional[Dict], result: Dict) -> Optional[Dict]:
    cert = (cert_result or {}).get('certificate')
    if not cert:
        return None
    days = cert['validity']['days_until_expiry']
    if days < 0:
        result['findings'].append({'severity': 'critical', 'message': f'Certificate expired {-days} day(s) ago'})
        result['grade'] = 'F'
    elif days <= 14:
        result['findings'].append({'severity': 'warning', 'message': f'Certificate expires in {days} day(s)'})
    return {'subject': cert['subject'].get('common_name'), 'issuer': cert['issuer'].get('common_name'),
            'not_after': cert['validity']['not_after'], 'days_until_expiry': days,
            'san': cert.get('subject_alternative_names', []), 'trusted': cert_result['connection_secure'],
            'errors': cert_result.get('errors', [])}


def _mx_hosts(domain: str) -> List[Tuple[int, str]]:
    try:
        answers = _resolver().resolve(domain, 'MX')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as e:
        raise ValueError(f'MX lookup failed: {type(e).__name__}')
    hosts = sorted((int(r.preference), str(r.exchange).rstrip('.')) for r in answers)
    return [(p, h) for p, h in hosts if h]


def scan_mail_domain(domain: str, timeout: float = 6.0, max_hosts: int = 5) -> Dict:
    """STARTTLS test of every MX host of a domain on port 25 (light mode)."""
    domain = (domain or '').strip().lower().rstrip('.')
    if not domain or '.' not in domain:
        raise ValueError('A domain name is required')
    mx = _mx_hosts(domain)[:max(1, min(int(max_hosts), 10))]
    if not mx:
        return {'domain': domain, 'mx': [], 'grade': None,
                'findings': [{'severity': 'critical', 'message': 'The domain has no MX records'}]}

    def run(item):
        priority, host = item
        try:
            r = scan_mail(host, 25, 'smtp', 'starttls', timeout)
        except (UnsafeTargetError, ValueError) as e:
            r = {'host': host, 'port': 25, 'reachable': False, 'error': str(e)}
        r['priority'] = priority
        return r

    with ThreadPoolExecutor(max_workers=min(5, len(mx))) as pool:
        results = list(pool.map(run, mx))
    graded = [r['grade'] for r in results if r.get('grade') in GRADE_ORDER]
    findings = []
    for r in results:
        if not r.get('reachable'):
            findings.append({'severity': 'warning', 'message': f"{r['host']}: {r.get('error', 'unreachable')}"})
        elif r.get('starttls') is False:
            findings.append({'severity': 'critical', 'message': f"{r['host']} does not offer STARTTLS"})
    worst = max(graded, key=GRADE_ORDER.index) if graded else None
    return {'domain': domain, 'mx': results, 'grade': worst, 'findings': findings}
