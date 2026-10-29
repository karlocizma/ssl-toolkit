"""CAA (RFC 8659, RFC 8657) and DANE/TLSA (RFC 6698) checks and generators.

Everything here is outbound only: DNS lookups and, for the TLSA check, one TLS connection. Nothing is stored
and no credentials are involved.
"""
import hashlib
import re
from typing import Dict, List, Optional, Tuple

import dns.exception
import dns.flags
import dns.resolver
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from OpenSSL import SSL

from app.services.deliverability import _resolver, valid_domain
from app.services.ssl_checker import pyopenssl_handshake
from app.utils.net_safety import safe_create_connection, validate_port

# CAA "issue" domain -> the CA's common name. Unknown values are shown as they are published.
KNOWN_CAS = {
    'letsencrypt.org': "Let's Encrypt",
    'digicert.com': 'DigiCert',
    'sectigo.com': 'Sectigo',
    'comodoca.com': 'Sectigo (Comodo)',
    'globalsign.com': 'GlobalSign',
    'pki.goog': 'Google Trust Services',
    'amazon.com': 'Amazon Trust Services',
    'amazontrust.com': 'Amazon Trust Services',
    'amazonaws.com': 'Amazon Trust Services',
    'awstrust.com': 'Amazon Trust Services',
    'ssl.com': 'SSL.com',
    'buypass.com': 'Buypass',
    'certum.pl': 'Certum',
    'entrust.net': 'Entrust',
    'actalis.it': 'Actalis',
    'telia.com': 'Telia',
    'harica.gr': 'HARICA',
}
KNOWN_TAGS = ('issue', 'issuewild', 'iodef')
_CRITICAL = 128
_HOST_RE = re.compile(r'^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$', re.I)
_IODEF_RE = re.compile(r'^(mailto:[^@\s;"]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|https://[^\s;"]+)$')


def _domain(value) -> str:
    """valid_domain, but JSON of the wrong type is a plain validation error."""
    if value is not None and not isinstance(value, str):
        raise ValueError('A valid domain name is required')
    return valid_domain(value)


def _string_list(value, label: str) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f'{label} must be a list of CA domain names')
    return value


def _finding(severity: str, message: str) -> Dict:
    return {'severity': severity, 'message': message}


# --------------------------------------------------------------------------- CAA check
def _caa_lookup(name: str) -> Tuple[List[Tuple[int, str, str]], Optional[str]]:
    """([(flags, tag, value)], error). error is 'NXDOMAIN', None (no CAA at this name) or 'FAILURE: ...'."""
    try:
        answer = _resolver().resolve(name, 'CAA')
    except dns.resolver.NXDOMAIN:
        return [], 'NXDOMAIN'
    except dns.resolver.NoAnswer:
        return [], None
    except dns.exception.DNSException as e:
        return [], f'FAILURE: {e.__class__.__name__}' + (f' ({e})' if str(e) else '')
    records = []
    for rr in answer:
        tag = rr.tag.decode('ascii', 'replace') if isinstance(rr.tag, bytes) else str(rr.tag)
        value = rr.value.decode('utf-8', 'replace') if isinstance(rr.value, bytes) else str(rr.value)
        records.append((int(rr.flags), tag, value))
    return records, None


def _split_issue_value(value: str) -> Tuple[str, Dict[str, str]]:
    """'letsencrypt.org; validationmethods=dns-01' -> ('letsencrypt.org', {'validationmethods': 'dns-01'})."""
    head, *rest = [p.strip() for p in value.split(';')]
    params = {}
    for part in rest:
        if '=' in part:
            k, v = part.split('=', 1)
            params[k.strip().lower()] = v.strip()
    return head.strip().lower(), params


def _issuers(records: List[Dict], tag: str) -> Tuple[List[Dict], bool, bool]:
    """(issuers, tag_present, blocked) for one tag across the parsed records."""
    present = [r for r in records if r['tag'] == tag]
    issuers = []
    for r in present:
        ca, params = _split_issue_value(r['value'])
        if ca:
            issuers.append({'ca': ca, 'name': KNOWN_CAS.get(ca), 'params': params})
    return issuers, bool(present), bool(present) and not issuers


def check_caa(domain: str) -> Dict:
    """Find the CAA policy that applies to a domain (climbing to parents, RFC 8659) and explain it."""
    domain = _domain(domain)
    labels = domain.split('.')
    names = ['.'.join(labels[i:]) for i in range(len(labels) - 1)]  # never the bare TLD
    findings: List[Dict] = []
    raw: List[Tuple[int, str, str]] = []
    policy_name = None

    for name in names:
        found, error = _caa_lookup(name)
        if error and error.startswith('FAILURE'):
            findings.append(_finding('error', f'DNS lookup for CAA at {name} failed ({error[9:]}); the policy could not be determined.'))
            return {'domain': domain, 'policy_name': None, 'records': [], 'issuers': [], 'wildcard_issuers': [],
                    'any_ca_may_issue': None, 'wildcard_any_ca_may_issue': None, 'issuance_blocked': False,
                    'wildcard_blocked': False, 'lookup_failed': True, 'findings': findings}
        if found:
            raw, policy_name = found, name
            break

    records = [{'flags': f, 'critical': bool(f & _CRITICAL), 'tag': t.lower(), 'value': v} for f, t, v in raw]
    issuers, has_issue, blocked = _issuers(records, 'issue')
    wild, has_wild, wild_blocked = _issuers(records, 'issuewild')
    if not has_wild:
        wild, wild_blocked = issuers, blocked
    any_ca = not has_issue
    wild_any_ca = not has_issue and not has_wild

    if not records:
        findings.append(_finding('warning', 'No CAA records are published: any CA may issue certificates for this domain.'))
    else:
        if policy_name != domain:
            findings.append(_finding('info', f'The policy is inherited from {policy_name}; {domain} has no CAA records of its own.'))
        if blocked:
            findings.append(_finding('info', 'Certificate issuance is blocked: every issue record is ";".'))
        elif any(not _split_issue_value(r['value'])[0] for r in records if r['tag'] == 'issue'):
            findings.append(_finding('warning', 'An issue ";" record next to other issue records has no effect: the other CAs are still allowed.'))
        if has_wild and {i['ca'] for i in wild} != {i['ca'] for i in issuers}:
            findings.append(_finding('info', 'Wildcard certificates follow issuewild, which differs from issue.'))
        for r in records:
            if r['tag'] in ('issue', 'issuewild'):
                ca = _split_issue_value(r['value'])[0]
                if ca and not _HOST_RE.match(ca):
                    findings.append(_finding('warning', f'{r["tag"]} value "{r["value"]}" does not start with a valid CA domain.'))
            elif r['tag'] == 'iodef':
                if not _IODEF_RE.match(r['value']):
                    findings.append(_finding('warning', f'iodef value "{r["value"]}" is not a mailto: address or an https:// URL.'))
            elif r['critical']:
                findings.append(_finding('error', f'Unknown tag "{r["tag"]}" is marked critical: CAs that do not understand it must refuse to issue.'))
            else:
                findings.append(_finding('info', f'Unknown tag "{r["tag"]}" (not critical) is ignored by CAs.'))
        if not any(r['tag'] == 'iodef' for r in records):
            findings.append(_finding('info', 'No iodef record: CAs have no address to report policy violations to.'))

    return {'domain': domain, 'policy_name': policy_name, 'records': records, 'issuers': issuers,
            'wildcard_issuers': wild, 'any_ca_may_issue': any_ca, 'wildcard_any_ca_may_issue': wild_any_ca,
            'issuance_blocked': blocked, 'wildcard_blocked': wild_blocked, 'lookup_failed': False, 'findings': findings}


# --------------------------------------------------------------------------- CAA generator
def _clean_ca(value) -> str:
    ca = (value or '').strip().lower() if isinstance(value, str) else ''
    if not _HOST_RE.match(ca):
        raise ValueError(f'"{str(value)[:60]}" is not a valid CA domain name (for example letsencrypt.org)')
    return ca


def generate_caa(domain: Optional[str], issuers: List[str], wildcard_issuers: Optional[List[str]] = None,
                 allow_wildcards: bool = True, block_all: bool = False, iodef: Optional[str] = None,
                 dns01_only: bool = False) -> Dict:
    """Build CAA records in zone-file form. Blocking all issuance has to be asked for explicitly."""
    owner = f'{_domain(domain)}.' if domain else '@'
    issuers = _string_list(issuers, 'issuers')
    wildcard_issuers = _string_list(wildcard_issuers, 'wildcard_issuers')
    if block_all and issuers:
        raise ValueError('Choose either a list of CAs or "block all issuance", not both')
    if not block_all and not issuers:
        raise ValueError('Add at least one CA, or choose "block all issuance" explicitly')
    if iodef and not (isinstance(iodef, str) and _IODEF_RE.match(iodef.strip())):
        raise ValueError('iodef must be a mailto: address or an https:// URL')

    suffix = '; validationmethods=dns-01' if dns01_only else ''
    lines: List[str] = []

    def add(tag: str, value: str):
        lines.append(f'{owner} IN CAA 0 {tag} "{value}"')

    if block_all:
        add('issue', ';')
        add('issuewild', ';')
        summary = 'No CA may issue certificates for this domain (including wildcards).'
    else:
        cas = [_clean_ca(c) for c in issuers]
        for ca in cas:
            add('issue', ca + suffix)
        if not allow_wildcards:
            add('issuewild', ';')
        elif wildcard_issuers:
            for ca in [_clean_ca(c) for c in wildcard_issuers]:
                add('issuewild', ca + suffix)
        summary = 'Only ' + ', '.join(KNOWN_CAS.get(c, c) for c in cas) + ' may issue certificates'
        summary += ' (wildcards not allowed)' if not allow_wildcards else ''
        summary += ', and only through DNS-01 validation.' if dns01_only else '.'
    if iodef:
        add('iodef', iodef.strip())
    return {'records': lines, 'summary': summary}


# --------------------------------------------------------------------------- TLSA (DANE)
PROTOCOLS = ('tcp', 'udp', 'sctp')
_PEM_RE = re.compile(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)
_HASHES = {1: hashlib.sha256, 2: hashlib.sha512}


def _tlsa_name(host: str, port, protocol: str) -> Tuple[str, str, int, str]:
    host = _domain(host)
    port = validate_port(port)
    protocol = protocol.strip().lower() if isinstance(protocol, str) else ''
    if protocol not in PROTOCOLS:
        raise ValueError('protocol must be tcp, udp or sctp')
    return f'_{port}._{protocol}.{host}', host, port, protocol


def _tlsa_data(cert_der: bytes, selector: int, matching_type: int) -> bytes:
    """The certificate association data for one TLSA selector/matching type (RFC 6698 section 2.1)."""
    if selector == 0:
        data = cert_der
    elif selector == 1:
        data = x509.load_der_x509_certificate(cert_der).public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    else:
        raise ValueError('selector must be 0 (full certificate) or 1 (public key)')
    if matching_type == 0:
        return data
    if matching_type in _HASHES:
        return _HASHES[matching_type](data).digest()
    raise ValueError('matching type must be 0 (exact), 1 (SHA-256) or 2 (SHA-512)')


def _in_range(value, low: int, high: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f'{label} must be a number from {low} to {high}')
    return value


def generate_tlsa(certificate_pem: Optional[str], host: str, port=443, protocol: str = 'tcp', usage: int = 3,
                  selector: int = 1, matching_type: int = 1) -> Dict:
    """Compute a TLSA record from a PEM certificate (the first one if several are pasted)."""
    name, host, port, protocol = _tlsa_name(host, port, protocol)
    usage = _in_range(usage, 0, 3, 'usage')
    selector = _in_range(selector, 0, 1, 'selector')
    matching_type = _in_range(matching_type, 0, 2, 'matching type')
    pems = _PEM_RE.findall(certificate_pem or '') if isinstance(certificate_pem, str) else []
    if not pems:
        raise ValueError('Paste a certificate in PEM format (-----BEGIN CERTIFICATE-----)')
    try:
        cert = x509.load_pem_x509_certificate(pems[0].encode())
    except ValueError:
        raise ValueError('The certificate could not be parsed; check that the PEM is complete') from None
    data = _tlsa_data(cert.public_bytes(serialization.Encoding.DER), selector, matching_type).hex()
    rdata = f'{usage} {selector} {matching_type} {data}'
    notes = []
    if len(pems) > 1:
        notes.append(f'{len(pems)} certificates were pasted; the first one was used.')
    if usage in (0, 2):
        notes.append('Usage 0 and 2 should describe a CA certificate from the chain, not the server certificate.')
    notes.append('DANE only works if the zone is DNSSEC-signed; clients ignore unsigned TLSA records.')
    return {'name': name, 'rdata': rdata, 'record': f'{name}. IN TLSA {rdata}', 'usage': usage,
            'selector': selector, 'matching_type': matching_type, 'notes': notes}


def _tlsa_lookup(name: str) -> Tuple[List[Tuple[int, int, int, bytes]], bool, Optional[str]]:
    """([(usage, selector, matching_type, data)], resolver_set_AD, error). error: None, 'NXDOMAIN' or 'FAILURE: ...'."""
    resolver = _resolver()
    resolver.use_edns(0, dns.flags.DO, 1232)
    try:
        answer = resolver.resolve(name, 'TLSA')
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return [], False, None
    except dns.exception.DNSException as e:
        return [], False, f'FAILURE: {e.__class__.__name__}' + (f' ({e})' if str(e) else '')
    ad = bool(answer.response.flags & dns.flags.AD)
    return [(int(r.usage), int(r.selector), int(r.mtype), bytes(r.cert)) for r in answer], ad, None


def _fetch_peer_chain(host: str, port: int, timeout: float = 10) -> List[bytes]:
    """DER certificates the server presents, leaf first. Connects only to validated addresses."""
    context = SSL.Context(SSL.TLS_CLIENT_METHOD)
    context.set_verify(SSL.VERIFY_NONE, lambda *args: True)
    sock = safe_create_connection((host, port), timeout=timeout)
    conn = SSL.Connection(context, sock)
    try:
        conn.set_connect_state()
        conn.set_tlsext_host_name(host.encode())
        pyopenssl_handshake(conn, sock, timeout)
        chain = conn.get_peer_cert_chain() or []
        return [c.to_cryptography().public_bytes(serialization.Encoding.DER) for c in chain]
    finally:
        try:
            conn.shutdown()
        except Exception:
            pass
        conn.close()
        sock.close()


def check_tlsa(host: str, port=443, protocol: str = 'tcp') -> Dict:
    """Compare a host's published TLSA records with the certificate chain it presents."""
    name, host, port, protocol = _tlsa_name(host, port, protocol)
    findings: List[Dict] = []
    result = {'name': name, 'host': host, 'port': port, 'protocol': protocol, 'records': [], 'dnssec_ad': False,
              'matched': False, 'certificates': 0, 'findings': findings}

    found, ad, error = _tlsa_lookup(name)
    result['dnssec_ad'] = ad
    if error:
        findings.append(_finding('error', f'DNS lookup for {name} failed ({error[9:]}).'))
        return result
    if not found:
        findings.append(_finding('warning', f'No TLSA record is published at {name}.'))
        return result

    records = [{'usage': u, 'selector': s, 'matching_type': m, 'data': d.hex(), 'match': None} for u, s, m, d in found]
    result['records'] = records
    if ad:
        findings.append(_finding('info', 'The resolver reports the answer as DNSSEC-authenticated (AD flag; reported by the resolver, not validated here).'))
    else:
        findings.append(_finding('warning', 'The resolver did not report the answer as DNSSEC-authenticated (no AD flag). '
                                 'DANE clients ignore TLSA records from an unsigned zone; this is the resolver\'s report, not validated here.'))

    try:
        chain = _fetch_peer_chain(host, port)
    except Exception as e:  # connection, handshake and SSRF-guard failures all end up as one clear finding
        findings.append(_finding('error', f'Could not read the server certificate from {host}:{port}: {e}'))
        return result
    if not chain:
        findings.append(_finding('error', f'{host}:{port} did not present a certificate.'))
        return result
    result['certificates'] = len(chain)

    for rec in records:
        # Usage 1 and 3 describe the server certificate; 0 and 2 a CA certificate above it (2 may also be a self-signed leaf).
        candidates = chain[:1] if rec['usage'] in (1, 3) else chain[1:] + (chain[:1] if rec['usage'] == 2 else [])
        try:
            rec['match'] = any(_tlsa_data(c, rec['selector'], rec['matching_type']).hex() == rec['data'] for c in candidates)
        except ValueError as e:
            findings.append(_finding('warning', f'TLSA record "{rec["usage"]} {rec["selector"]} {rec["matching_type"]}" cannot be checked: {e}.'))
    result['matched'] = any(r['match'] for r in records)
    if not result['matched']:
        findings.append(_finding('error', 'None of the TLSA records match the certificate the server presents: DANE clients will reject this host.'))
    return result
