"""Certificate chain builder: assemble a correct, correctly ordered chain for a leaf certificate.

Missing intermediates are downloaded from the certificate's Authority Information Access
(AIA "CA Issuers") URL; completeness is judged against the Mozilla root store bundled with
`certifi`. The result is ready to use as `fullchain.pem`.
"""
import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from OpenSSL import SSL, crypto

from app.services.ssl_checker import pyopenssl_handshake
from app.utils.net_safety import UnsafeTargetError, safe_create_connection, safe_get, validate_port

MAX_CHAIN = 8
MAX_POOL = 20
_PEM_RE = re.compile(r'-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----')
WEAK_SIG = ('md5', 'sha1')


class ChainError(ValueError):
    pass


def _utc(cert: x509.Certificate, which: str) -> datetime:
    value = getattr(cert, f'not_valid_{which}_utc', None) or getattr(cert, f'not_valid_{which}').replace(tzinfo=timezone.utc)
    return value


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def parse_pem_bundle(text: str) -> List[x509.Certificate]:
    certs = []
    for block in _PEM_RE.findall(text or ''):
        try:
            certs.append(x509.load_pem_x509_certificate(block.encode()))
        except ValueError:
            raise ChainError('The input contains a malformed certificate block')
    return certs


@lru_cache(maxsize=1)
def _trust_store() -> Dict[bytes, List[x509.Certificate]]:
    """Mozilla roots keyed by subject DER, so issuers can be looked up quickly."""
    with open(certifi.where()) as f:
        roots = parse_pem_bundle(f.read())
    index: Dict[bytes, List[x509.Certificate]] = {}
    for r in roots:
        index.setdefault(r.subject.public_bytes(), []).append(r)
    return index


def _in_trust_store(cert: x509.Certificate) -> bool:
    return any(fingerprint(r) == fingerprint(cert) for r in _trust_store().get(cert.subject.public_bytes(), []))


def _issued_by(cert: x509.Certificate, candidate: x509.Certificate) -> bool:
    if cert.issuer != candidate.subject:
        return False
    try:
        cert.verify_directly_issued_by(candidate)
        return True
    except Exception:
        return False


def _is_self_issued(cert: x509.Certificate) -> bool:
    return _issued_by(cert, cert)


def _aia_urls(cert: x509.Certificate) -> List[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return []
    return [d.access_location.value for d in ext
            if d.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
            and isinstance(d.access_location, x509.UniformResourceIdentifier)]


def _load_downloaded(body: bytes) -> List[x509.Certificate]:
    """AIA responses are DER certificates, PEM, or PKCS#7 bundles (.p7c)."""
    for loader in (lambda b: [x509.load_der_x509_certificate(b)], lambda b: parse_pem_bundle(b.decode('ascii', 'ignore')),
                   pkcs7.load_der_pkcs7_certificates, pkcs7.load_pem_pkcs7_certificates):
        try:
            certs = loader(body)
            if certs:
                return certs
        except Exception:
            continue
    return []


def _fetch_issuer(cert: x509.Certificate, notes: List[str]) -> Optional[Tuple[x509.Certificate, str]]:
    for url in _aia_urls(cert):
        if urlsplit(url).scheme not in ('http', 'https'):
            continue
        try:
            resp = safe_get(url, timeout=10)
        except UnsafeTargetError as e:
            notes.append(f'AIA URL {url} was not fetched: {e}')
            continue
        except Exception as e:
            notes.append(f'AIA URL {url} could not be fetched ({type(e).__name__})')
            continue
        if resp.status_code != 200:
            notes.append(f'AIA URL {url} answered HTTP {resp.status_code}')
            continue
        for candidate in _load_downloaded(resp.content):
            if _issued_by(cert, candidate):
                return candidate, url
        notes.append(f'AIA URL {url} did not return the issuing certificate')
    return None


def _describe(cert: x509.Certificate, role: str, source: str) -> Dict:
    def cn(name):
        for a in name:
            if a.oid == x509.NameOID.COMMON_NAME:
                return a.value
        return name.rfc4514_string()
    try:
        sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else 'unknown'
    except Exception:
        sig = 'unknown'
    not_after = _utc(cert, 'after')
    return {'role': role, 'source': source, 'subject': cn(cert.subject), 'issuer': cn(cert.issuer),
            'not_before': _utc(cert, 'before').isoformat(), 'not_after': not_after.isoformat(),
            'expired': not_after < datetime.now(timezone.utc), 'signature_hash': sig,
            'sha256': fingerprint(cert),
            'pem': cert.public_bytes(serialization.Encoding.PEM).decode()}


def build_chain(leaf: x509.Certificate, pool: List[x509.Certificate], include_root: bool = False) -> Dict:
    pool_by_fp = {fingerprint(c): c for c in pool if fingerprint(c) != fingerprint(leaf)}
    chain: List[Tuple[x509.Certificate, str]] = [(leaf, 'provided')]
    seen = {fingerprint(leaf)}
    findings: List[Dict] = []
    notes: List[str] = []
    current = leaf
    complete, trusted_root = False, False

    def add(sev, msg):
        findings.append({'severity': sev, 'message': msg})

    while len(chain) <= MAX_CHAIN:
        if _is_self_issued(current):
            trusted_root = _in_trust_store(current)
            complete = True
            break
        issuer, source = None, None
        for fp, cand in pool_by_fp.items():
            if fp not in seen and _issued_by(current, cand):
                issuer, source = cand, 'provided'
                break
        if issuer is None:
            for cand in _trust_store().get(current.issuer.public_bytes(), []):
                if _issued_by(current, cand):
                    issuer, source = cand, 'trust store'
                    break
        if issuer is None:
            fetched = _fetch_issuer(current, notes)
            if fetched:
                issuer, source = fetched[0], f'downloaded from {fetched[1]}'
        if issuer is None:
            break
        fp = fingerprint(issuer)
        if fp in seen:
            add('error', 'The chain loops back on itself')
            break
        seen.add(fp)
        chain.append((issuer, source))
        current = issuer
        if source == 'trust store' or _in_trust_store(issuer):
            complete, trusted_root = True, True
            break

    if not complete:
        d = _describe(current, '', '')
        add('error', f"The chain could not be completed: the issuer {d['issuer']!r} of {d['subject']!r} was not "
                     'found in the input, in the trust store, or via its AIA URL')
        for n in notes:
            add('info', n)
    elif not trusted_root:
        add('warning', 'The chain ends in a self-signed root that is not in the Mozilla trust store '
                       '(fine for a private CA; public clients will not trust it)')

    entries = []
    for i, (cert, source) in enumerate(chain):
        if i == 0:
            role = 'leaf'
        elif _is_self_issued(cert):
            role = 'root'
        elif complete and i == len(chain) - 1 and trusted_root and source == 'trust store':
            role = 'root'
        else:
            role = 'intermediate'
        entries.append(_describe(cert, role, source))
    for e in entries:
        if e['expired']:
            add('error', f"{e['role'].capitalize()} certificate {e['subject']!r} has expired ({e['not_after'][:10]})")
        if e['signature_hash'] in WEAK_SIG and e['role'] != 'root':
            add('warning', f"{e['subject']!r} is signed with {e['signature_hash'].upper()}")
    unused = [c for fp, c in pool_by_fp.items() if fp not in seen]
    if unused:
        add('info', f'{len(unused)} supplied certificate(s) are not part of this chain and were left out')

    served = [e for e in entries if e['role'] != 'root' or include_root]
    return {'complete': complete, 'trusted': complete and trusted_root, 'chain': entries,
            'fullchain_pem': ''.join(e['pem'] for e in served),
            'chain_pem': ''.join(e['pem'] for e in served if e['role'] != 'leaf'),
            'findings': findings, 'removed_unused': len(unused)}


def fetch_served_chain(hostname: str, port: int = 443) -> List[x509.Certificate]:
    port = validate_port(port)
    ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
    ctx.set_min_proto_version(SSL.TLS1_2_VERSION)
    ctx.set_options(SSL.OP_NO_SSLv2 | SSL.OP_NO_SSLv3 | SSL.OP_NO_TLSv1 | SSL.OP_NO_TLSv1_1)  # no TLS < 1.2 (the TLS scanner covers legacy protocols)
    ctx.set_verify(SSL.VERIFY_NONE, lambda *a: True)
    sock = safe_create_connection((hostname, port), timeout=10)
    conn = SSL.Connection(ctx, sock)
    try:
        conn.set_tlsext_host_name(hostname.encode())
        conn.set_connect_state()
        pyopenssl_handshake(conn, sock, 10)
        chain = conn.get_peer_cert_chain() or []
        return [x509.load_pem_x509_certificate(crypto.dump_certificate(crypto.FILETYPE_PEM, c)) for c in chain]
    finally:
        try:
            conn.close()
        except Exception:
            pass
        sock.close()


def run(params: Dict) -> Dict:
    include_root = bool(params.get('include_root'))
    if params.get('hostname'):
        hostname = str(params['hostname']).strip()
        try:
            certs = fetch_served_chain(hostname, params.get('port', 443))
        except UnsafeTargetError as e:
            raise ChainError(str(e))
        except Exception as e:
            raise ChainError(f'Could not fetch the certificate chain from {hostname}: {type(e).__name__}')
        if not certs:
            raise ChainError('The server presented no certificate')
        source = 'server'
    elif params.get('certificate'):
        certs = parse_pem_bundle(params['certificate'])
        if not certs:
            raise ChainError('No PEM certificate found in the input')
        source = 'input'
    else:
        raise ChainError('Provide "certificate" (PEM leaf or bundle) or "hostname"')
    if len(certs) > MAX_POOL:
        raise ChainError(f'At most {MAX_POOL} certificates may be supplied')
    leaf = next((c for c in certs if not _is_ca(c)), certs[0])
    pool = [c for c in certs if fingerprint(c) != fingerprint(leaf)]
    result = build_chain(leaf, pool, include_root)
    order_in = [fingerprint(c) for c in certs]
    order_out = [e['sha256'] for e in result['chain']]
    given = [h for h in order_in if h in order_out]
    if len(certs) > 1 and given != [h for h in order_out if h in given]:
        result['findings'].insert(0, {'severity': 'warning', 'message':
                                      f'The {source} presented the chain in the wrong order; the output is correctly ordered (leaf first)'})
    elif source == 'server' and result['complete'] and len(certs) == 1 and len(result['chain']) > 2:
        result['findings'].insert(0, {'severity': 'error', 'message':
                                      'The server sends only the leaf certificate. Clients without the intermediate cached '
                                      'will fail: configure it with the fullchain below'})
    result['source'] = source
    result['leaf'] = result['chain'][0]['subject']
    return result


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False
