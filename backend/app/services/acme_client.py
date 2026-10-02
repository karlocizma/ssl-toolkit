"""Minimal, dependency-free ACME (RFC 8555) client.

Stateless by design: the caller owns the account key and domain key, and the
order is identified by its URL, so the server never has to store anything.
All HTTP goes through the SSRF guard. Operators can trust a private ACME CA
(e.g. Pebble, step-ca) with ACME_CA_BUNDLE=/path/to/ca.pem.
"""
import base64
import hashlib
import hmac
import json
import os
import time
from typing import Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.x509.oid import NameOID

from app.utils.net_safety import safe_request

DIRECTORIES = {
    'letsencrypt': 'https://acme-v02.api.letsencrypt.org/directory',
    'letsencrypt-staging': 'https://acme-staging-v02.api.letsencrypt.org/directory',
}
USER_AGENT = 'ssl-toolkit-acme/1.0'


class AcmeError(Exception):
    def __init__(self, message: str, problem_type: Optional[str] = None):
        super().__init__(message)
        self.problem_type = problem_type


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def resolve_directory(directory: Optional[str]) -> str:
    directory = directory or 'letsencrypt-staging'  # safe default: staging has no rate-limit risk
    return DIRECTORIES.get(directory, directory)


def load_account_key(pem: str):
    try:
        key = serialization.load_pem_private_key(pem.encode(), None)
    except Exception:
        raise AcmeError('account_key_pem is not a valid unencrypted PEM private key')
    if not isinstance(key, (ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey)):
        raise AcmeError('Account key must be an EC or RSA key')
    if isinstance(key, ec.EllipticCurvePrivateKey) and key.curve.name != 'secp256r1':
        raise AcmeError('EC account keys must use P-256')
    return key


def new_account_key():
    return ec.generate_private_key(ec.SECP256R1())


def key_to_pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _jwk(key) -> Dict:
    pub = key.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        nums = pub.public_numbers()
        return {'crv': 'P-256', 'kty': 'EC', 'x': b64u(nums.x.to_bytes(32, 'big')),
                'y': b64u(nums.y.to_bytes(32, 'big'))}
    nums = pub.public_numbers()
    return {'e': b64u(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, 'big')), 'kty': 'RSA',
            'n': b64u(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, 'big'))}


def _sign(key, data: bytes) -> Tuple[str, bytes]:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        der = key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return 'ES256', r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    return 'RS256', key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def thumbprint(key) -> str:
    canonical = json.dumps(_jwk(key), sort_keys=True, separators=(',', ':')).encode()
    digest = hashes.Hash(hashes.SHA256())
    digest.update(canonical)
    return b64u(digest.finalize())


def key_authorization(token: str, key) -> str:
    return f'{token}.{thumbprint(key)}'


def dns_txt_value(token: str, key) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key_authorization(token, key).encode())
    return b64u(digest.finalize())


def challenge_dns_name(domain: str) -> str:
    return '_acme-challenge.' + domain[2:] if domain.startswith('*.') else '_acme-challenge.' + domain


def make_csr(domains: List[str], key) -> str:
    sans = x509.SubjectAlternativeName([x509.DNSName(d) for d in domains])
    algo = hashes.SHA256()
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0][:64])]))
           .add_extension(sans, critical=False).sign(key, algo))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


class AcmeClient:
    def __init__(self, directory: str, account_key, timeout: int = 20):
        self.directory_url = resolve_directory(directory)
        self.key = account_key
        self.kid: Optional[str] = None
        self.timeout = timeout
        self._directory: Optional[Dict] = None
        self._nonce: Optional[str] = None

    # -- transport ---------------------------------------------------
    def _http(self, method, url, **kw):
        kw.setdefault('timeout', self.timeout)
        kw.setdefault('verify', os.environ.get('ACME_CA_BUNDLE') or True)
        kw.setdefault('headers', {})['User-Agent'] = USER_AGENT
        return safe_request(method, url, **kw)

    @property
    def directory(self) -> Dict:
        if self._directory is None:
            resp = self._http('GET', self.directory_url)
            if resp.status_code != 200:
                raise AcmeError(f'Could not fetch ACME directory ({resp.status_code})')
            self._directory = resp.json()
        return self._directory

    def _new_nonce(self) -> str:
        resp = self._http('HEAD', self.directory['newNonce'])
        nonce = resp.headers.get('Replay-Nonce')
        if not nonce:
            raise AcmeError('ACME server did not return a nonce')
        return nonce

    def _post(self, url: str, payload: Optional[Dict], use_jwk: bool = False, _retry: bool = True):
        """Signed POST. payload=None means POST-as-GET."""
        protected = {'alg': _sign(self.key, b'')[0], 'nonce': self._nonce or self._new_nonce(), 'url': url}
        if use_jwk or not self.kid:
            protected['jwk'] = _jwk(self.key)
        else:
            protected['kid'] = self.kid
        p64 = b64u(json.dumps(protected).encode())
        d64 = '' if payload is None else b64u(json.dumps(payload).encode())
        _, sig = _sign(self.key, f'{p64}.{d64}'.encode())
        body = json.dumps({'protected': p64, 'payload': d64, 'signature': b64u(sig)})
        resp = self._http('POST', url, data=body, headers={'Content-Type': 'application/jose+json'})
        self._nonce = resp.headers.get('Replay-Nonce')
        if resp.status_code >= 400:
            problem = {}
            try:
                problem = resp.json()
            except ValueError:
                pass
            if problem.get('type', '').endswith('badNonce') and _retry:
                self._nonce = None
                return self._post(url, payload, use_jwk, _retry=False)
            detail = problem.get('detail') or resp.text[:200]
            raise AcmeError(f'ACME server error: {detail}', problem.get('type'))
        return resp

    # -- account / order ---------------------------------------------
    def _external_account_binding(self, eab_kid: str, eab_hmac_key: str) -> Dict:
        """RFC 8555 7.3.4: bind this account key to an account at a CA that requires it (ZeroSSL, Google, ...)."""
        try:  # strict: the default decoder silently drops invalid characters
            normalized = eab_hmac_key.strip().replace('-', '+').replace('_', '/')
            mac_key = base64.b64decode(normalized + '=' * (-len(normalized) % 4), validate=True)
            if not mac_key:
                raise ValueError
        except Exception:
            raise AcmeError('eab_hmac_key must be base64url encoded')
        protected = b64u(json.dumps({'alg': 'HS256', 'kid': eab_kid, 'url': self.directory['newAccount']}).encode())
        payload = b64u(json.dumps(_jwk(self.key)).encode())
        signature = hmac.new(mac_key, f'{protected}.{payload}'.encode(), hashlib.sha256).digest()
        return {'protected': protected, 'payload': payload, 'signature': b64u(signature)}

    def register(self, email: Optional[str] = None, eab_kid: Optional[str] = None,
                 eab_hmac_key: Optional[str] = None) -> str:
        payload = {'termsOfServiceAgreed': True}
        if email:
            payload['contact'] = [f'mailto:{email}']
        if eab_kid or eab_hmac_key:
            if not (eab_kid and eab_hmac_key):
                raise AcmeError('Both eab_kid and eab_hmac_key are required for external account binding')
            payload['externalAccountBinding'] = self._external_account_binding(eab_kid, eab_hmac_key)
        elif self.directory.get('meta', {}).get('externalAccountRequired'):
            raise AcmeError('This CA requires external account binding: provide eab_kid and eab_hmac_key '
                            'from your CA account')
        resp = self._post(self.directory['newAccount'], payload, use_jwk=True)
        self.kid = resp.headers['Location']
        return self.kid

    def lookup_account(self) -> str:
        """Find the account for this key without creating one."""
        resp = self._post(self.directory['newAccount'], {'onlyReturnExisting': True}, use_jwk=True)
        self.kid = resp.headers['Location']
        return self.kid

    def new_order(self, domains: List[str]) -> Tuple[Dict, str]:
        identifiers = [{'type': 'dns', 'value': d} for d in domains]
        resp = self._post(self.directory['newOrder'], {'identifiers': identifiers})
        return resp.json(), resp.headers['Location']

    def get_order(self, order_url: str) -> Dict:
        return self._post(order_url, None).json()

    def get_authorization(self, url: str) -> Dict:
        return self._post(url, None).json()

    def describe_challenges(self, order: Dict, challenge_type: str) -> List[Dict]:
        """Everything the user (or a DNS provider) must publish for each authorization."""
        out = []
        for authz_url in order['authorizations']:
            authz = self.get_authorization(authz_url)
            domain = authz['identifier']['value']
            wildcard = authz.get('wildcard', False)
            challenge = next((c for c in authz['challenges'] if c['type'] == challenge_type), None)
            if challenge is None:
                raise AcmeError(f'CA does not offer {challenge_type} for {domain}')
            item = {'domain': f'*.{domain}' if wildcard else domain, 'type': challenge_type,
                    'status': authz['status'], 'authorization_url': authz_url,
                    'challenge_url': challenge['url'], 'token': challenge['token']}
            if challenge_type == 'dns-01':
                item.update(dns_name=challenge_dns_name(item['domain']), dns_type='TXT',
                            dns_value=dns_txt_value(challenge['token'], self.key))
            else:
                item.update(http_url=f"http://{domain}/.well-known/acme-challenge/{challenge['token']}",
                            http_content=key_authorization(challenge['token'], self.key))
            out.append(item)
        return out

    # -- completion --------------------------------------------------
    def answer_and_wait(self, challenges: List[Dict], timeout: int = 120) -> None:
        for ch in challenges:
            if ch['status'] == 'pending':
                self._post(ch['challenge_url'], {})
        deadline = time.time() + timeout
        for ch in challenges:
            while True:
                authz = self.get_authorization(ch['authorization_url'])
                if authz['status'] == 'valid':
                    break
                if authz['status'] != 'pending':
                    detail = next((c.get('error', {}).get('detail') for c in authz['challenges']
                                   if c.get('error')), authz['status'])
                    raise AcmeError(f"Validation of {ch['domain']} failed: {detail}")
                if time.time() > deadline:
                    raise AcmeError(f"Timed out waiting for validation of {ch['domain']}")
                time.sleep(1)

    def finalize(self, order: Dict, order_url: str, csr_pem: str, timeout: int = 120) -> str:
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
        except Exception:
            raise AcmeError('csr_pem is not a valid PEM certificate request')
        if order['status'] == 'pending' or order['status'] == 'ready':
            order = self._post(order['finalize'],
                               {'csr': b64u(csr.public_bytes(serialization.Encoding.DER))}).json()
        deadline = time.time() + timeout
        while order['status'] in ('processing', 'ready', 'pending'):
            if time.time() > deadline:
                raise AcmeError('Timed out waiting for certificate issuance')
            time.sleep(1)
            order = self.get_order(order_url)
        if order['status'] != 'valid':
            raise AcmeError(f"Order ended with status '{order['status']}'")
        resp = self._post(order['certificate'], None)
        return resp.text


def certificate_id(cert: x509.Certificate) -> str:
    """ARI certificate identifier (RFC 9773): base64url(AKI keyIdentifier) '.' base64url(serial)."""
    try:
        aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    except x509.ExtensionNotFound:
        aki = None
    if not aki:
        raise AcmeError('The certificate has no Authority Key Identifier, so its renewal information cannot be queried')
    serial = cert.serial_number
    serial_bytes = serial.to_bytes((serial.bit_length() // 8) + 1, 'big')  # minimal two's complement, sign byte kept
    return f'{b64u(aki)}.{b64u(serial_bytes)}'


def fetch_renewal_info(directory: str, cert_pem: str) -> Dict:
    """Ask the CA when this certificate should be renewed (ACME Renewal Information)."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
    except Exception:
        raise AcmeError('certificate is not a valid PEM certificate')
    client = AcmeClient(directory, new_account_key())  # ARI is unauthenticated: no account needed
    base = client.directory.get('renewalInfo')
    if not base:
        raise AcmeError('This CA does not support ACME Renewal Information (ARI)')
    resp = client._http('GET', f"{base.rstrip('/')}/{certificate_id(cert)}")
    if resp.status_code == 404:
        raise AcmeError('The CA does not know this certificate (was it issued by this CA?)')
    if resp.status_code != 200:
        raise AcmeError(f'Renewal info request failed ({resp.status_code})')
    info = resp.json()
    window = info.get('suggestedWindow') or {}
    return {'suggested_window_start': window.get('start'), 'suggested_window_end': window.get('end'),
            'explanation_url': info.get('explanationURL'), 'retry_after': resp.headers.get('Retry-After')}
