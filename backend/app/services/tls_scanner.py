"""TLS protocol / cipher-suite scanner with a simple A-F grade."""
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from app.services.ssl_checker import check_ssl_certificate
from app.utils.net_safety import UnsafeTargetError, safe_create_connection, validate_port

PROTOCOLS = [
    ('TLSv1.0', ssl.TLSVersion.TLSv1),
    ('TLSv1.1', ssl.TLSVersion.TLSv1_1),
    ('TLSv1.2', ssl.TLSVersion.TLSv1_2),
    ('TLSv1.3', ssl.TLSVersion.TLSv1_3),
]
LEGACY = {'TLSv1.0', 'TLSv1.1'}
# Substrings (OpenSSL cipher names) -> reason. Order matters: first match wins.
WEAK_CIPHER_MARKERS = [
    ('NULL', 'no encryption', 'critical'),
    ('EXP', 'export-grade cipher', 'critical'),
    ('ADH', 'anonymous key exchange', 'critical'),
    ('AECDH', 'anonymous key exchange', 'critical'),
    ('RC4', 'RC4 is broken', 'weak'),
    ('RC2', 'RC2 is broken', 'weak'),
    ('DES-CBC-', 'single DES is broken', 'weak'),
    ('DES-CBC3', '3DES is vulnerable to Sweet32', 'weak'),
    ('3DES', '3DES is vulnerable to Sweet32', 'weak'),
    ('MD5', 'MD5 MAC is weak', 'weak'),
]
FORWARD_SECRET_PREFIXES = ('ECDHE', 'DHE', 'EDH')
GRADE_ORDER = ['A', 'A-', 'B', 'C', 'D', 'F']


def classify_cipher(name: str) -> Optional[Dict]:
    for marker, reason, severity in WEAK_CIPHER_MARKERS:
        if marker in name:
            return {'reason': reason, 'severity': severity}
    return None


def _context(version: ssl.TLSVersion) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ctx.maximum_version = version
    if version != ssl.TLSVersion.TLSv1_3:
        try:  # legacy protocols/ciphers are refused by default on modern OpenSSL
            ctx.set_ciphers('ALL:COMPLEMENTOFALL:@SECLEVEL=0')
        except ssl.SSLError:
            pass
    return ctx


def _handshake(hostname: str, port: int, ctx: ssl.SSLContext, timeout: float) -> Optional[Dict]:
    """Return negotiated details, or None if the handshake was refused."""
    try:
        with safe_create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                name, _, bits = ssock.cipher()
                return {'cipher': name, 'bits': bits, 'version': ssock.version()}
    except UnsafeTargetError:
        raise
    except (ssl.SSLError, OSError, ValueError):
        return None


def _supported_ciphers(hostname: str, port: int, version: ssl.TLSVersion, timeout: float) -> List[Dict]:
    """Probe each cipher individually (TLS <= 1.2)."""
    names = [c['name'] for c in _context(version).get_ciphers() if c.get('protocol') != 'TLSv1.3']

    def probe(name):
        ctx = _context(version)
        try:
            ctx.set_ciphers(f'{name}:@SECLEVEL=0')
        except ssl.SSLError:
            return None
        result = _handshake(hostname, port, ctx, timeout)
        return result['cipher'] if result and result['cipher'] == name else None

    with ThreadPoolExecutor(max_workers=8) as pool:
        accepted = [n for n in pool.map(probe, names) if n]
    found = []
    for name in sorted(set(accepted)):
        entry = {'name': name, 'forward_secrecy': name.startswith(FORWARD_SECRET_PREFIXES)}
        weakness = classify_cipher(name)
        if weakness:
            entry['weakness'] = weakness
        found.append(entry)
    return found


def grade_results(protocols: Dict[str, Dict], certificate_trusted: Optional[bool]) -> Dict:
    """Pure grading logic so it can be tested without a network."""
    findings, cap = [], 'A'

    def limit(grade: str):
        nonlocal cap
        if GRADE_ORDER.index(grade) > GRADE_ORDER.index(cap):
            cap = grade

    supported = {p for p, d in protocols.items() if d['supported']}
    if not supported & {'TLSv1.2', 'TLSv1.3'}:
        findings.append({'severity': 'critical', 'message': 'Neither TLS 1.2 nor TLS 1.3 is supported'})
        limit('F')
    for proto in sorted(supported & LEGACY):
        findings.append({'severity': 'warning', 'message': f'{proto} is deprecated and should be disabled'})
        limit('B')

    all_ciphers = [c for d in protocols.values() for c in d.get('ciphers', [])]
    for c in all_ciphers:
        weakness = c.get('weakness')
        if weakness:
            findings.append({'severity': weakness['severity'],
                             'message': f"Weak cipher {c['name']}: {weakness['reason']}"})
            limit('F' if weakness['severity'] == 'critical' else 'C')
    tls12 = protocols.get('TLSv1.2', {})
    if tls12.get('supported') and tls12.get('ciphers') and not any(c['forward_secrecy'] for c in tls12['ciphers']):
        findings.append({'severity': 'warning', 'message': 'TLS 1.2 offers no forward-secret cipher suites'})
        limit('B')
    if 'TLSv1.2' in supported and 'TLSv1.3' not in supported:
        findings.append({'severity': 'info', 'message': 'TLS 1.3 is not supported'})
        limit('A-')
    if certificate_trusted is False:
        findings.append({'severity': 'critical', 'message': 'Certificate is not trusted for this hostname'})
        limit('F')
    return {'grade': cap, 'findings': findings}


def scan_tls(hostname: str, port=443, timeout: float = 5.0) -> Dict:
    port = validate_port(port)
    timeout = max(1.0, min(float(timeout), 10.0))
    protocols = {}
    for label, version in PROTOCOLS:
        try:
            neg = _handshake(hostname, port, _context(version), timeout)
        except UnsafeTargetError:
            raise
        entry = {'supported': neg is not None}
        if neg:
            entry['negotiated_cipher'] = neg['cipher']
            if version == ssl.TLSVersion.TLSv1_3:
                entry['ciphers'] = [{'name': neg['cipher'], 'forward_secrecy': True}]
            else:
                entry['ciphers'] = _supported_ciphers(hostname, port, version, timeout)
        protocols[label] = entry

    if not any(p['supported'] for p in protocols.values()):
        return {'hostname': hostname, 'port': port, 'reachable': False,
                'error': 'No TLS handshake succeeded (host unreachable or not a TLS service)'}

    cert = check_ssl_certificate(hostname, port, int(timeout) + 5)
    trusted = bool(cert.get('connection_secure')) and cert.get('valid_for_hostname', True)
    graded = grade_results(protocols, trusted)
    return {'hostname': hostname, 'port': port, 'reachable': True, 'protocols': protocols,
            'certificate_trusted': trusted, 'grade': graded['grade'], 'findings': graded['findings']}
