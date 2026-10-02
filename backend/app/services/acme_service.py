"""ACME orchestration: manual (2-step) and automatic dns-01 issuance.

Nothing is persisted. The client keeps the account key and domain key; an order
is addressed by its URL, which must live on the same host as the ACME directory.
"""
import re
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from cryptography import x509

from app.services import acme_dns
from app.services.acme_client import (
    AcmeClient, AcmeError, key_to_pem, load_account_key, make_csr, new_account_key, resolve_directory,
)
from app.utils.net_safety import UnsafeTargetError
from app.utils.ssl_utils import generate_private_key

MAX_DOMAINS = 20
_LABEL = r'[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
_DOMAIN_RE = re.compile(rf'^(\*\.)?({_LABEL}\.)+{_LABEL}$')


def normalize_domains(domains) -> List[str]:
    if not isinstance(domains, list) or not domains:
        raise ValueError('domains must be a non-empty list')
    out = []
    for d in domains:
        d = str(d).strip().lower().rstrip('.')
        if not _DOMAIN_RE.match(d) or len(d) > 253:
            raise ValueError(f'Invalid domain name: {d}')
        if d not in out:
            out.append(d)
    if len(out) > MAX_DOMAINS:
        raise ValueError(f'At most {MAX_DOMAINS} domains per certificate')
    return out


def _challenge_type(params: Dict, domains: List[str]) -> str:
    ctype = params.get('challenge_type', 'dns-01')
    if ctype not in ('dns-01', 'http-01'):
        raise ValueError("challenge_type must be 'dns-01' or 'http-01'")
    if ctype == 'http-01' and any(d.startswith('*.') for d in domains):
        raise ValueError('Wildcard certificates require dns-01')
    return ctype


def _csr_domains(csr_pem: str) -> List[str]:
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode())
        sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except Exception:
        raise ValueError('csr must be a valid PEM request containing subject alternative names')
    if not csr.is_signature_valid:
        raise ValueError('CSR signature is invalid')
    return normalize_domains(sans.get_values_for_type(x509.DNSName))


def _prepare_csr(params: Dict, domains: List[str]):
    """Return (domains, csr_pem, generated_private_key_pem or None)."""
    if params.get('csr'):
        csr_domains = _csr_domains(params['csr'])
        if domains and set(domains) != set(csr_domains):
            raise ValueError('domains do not match the names in the supplied CSR')
        return csr_domains, params['csr'], None
    if not domains:
        raise ValueError('domains (or a csr) is required')
    key = generate_private_key(params.get('key_type', 'EC'), params.get('key_size', 2048), 'secp256r1')
    return domains, make_csr(domains, key), key_to_pem(key)


def _client(params: Dict, register: bool):
    directory = resolve_directory(params.get('directory'))
    if params.get('account_key_pem'):
        key, generated = load_account_key(params['account_key_pem']), False
    else:
        key, generated = new_account_key(), True
    client = AcmeClient(directory, key)
    if register:
        client.register(params.get('email'), params.get('eab_kid'), params.get('eab_hmac_key'))
    else:
        client.lookup_account()
    return client, generated


def _check_order_url(client: AcmeClient, order_url: str) -> None:
    if urlsplit(order_url).netloc != urlsplit(client.directory_url).netloc:
        raise ValueError('order_url must be on the same host as the ACME directory')


def _wrap(fn, params):
    try:
        return fn(params or {})
    except AcmeError as e:
        raise ValueError(str(e))
    except (UnsafeTargetError, acme_dns.DnsProviderError) as e:
        raise ValueError(str(e))


def start_order(params: Dict) -> Dict:
    """Step 1 of the manual flow: create the order and describe what to publish."""
    return _wrap(_start_order, params)


def _start_order(params: Dict) -> Dict:
    domains = normalize_domains(params['domains']) if params.get('domains') else []
    domains, csr_pem, domain_key = _prepare_csr(params, domains)
    ctype = _challenge_type(params, domains)
    client, generated = _client(params, register=True)
    order, order_url = client.new_order(domains)
    challenges = client.describe_challenges(order, ctype)
    result = {'success': True, 'directory': client.directory_url, 'order_url': order_url,
              'order_status': order['status'], 'challenge_type': ctype, 'domains': domains,
              'csr_pem': csr_pem, 'challenges': challenges,
              'instructions': _instructions(ctype)}
    # The account key is only echoed back when we generated it for the caller.
    result['account_key_pem'] = key_to_pem(client.key) if generated else None
    if domain_key:
        result['private_key_pem'] = domain_key
    return result


def _instructions(ctype: str) -> str:
    if ctype == 'dns-01':
        return ('Create each TXT record below, wait for DNS to propagate, then call /acme/complete. '
                'Wildcard and apex names of the same domain share one record name: create both values.')
    return ('Serve each http_content at its http_url (plain text, port 80), then call /acme/complete.')


def complete_order(params: Dict) -> Dict:
    """Step 2 of the manual flow: validate, finalize and return the certificate."""
    return _wrap(_complete_order, params)


def _complete_order(params: Dict) -> Dict:
    for field in ('order_url', 'account_key_pem', 'csr_pem'):
        if not params.get(field):
            raise ValueError(f'{field} is required')
    client, _ = _client(params, register=False)
    _check_order_url(client, params['order_url'])
    order = client.get_order(params['order_url'])
    ctype = params.get('challenge_type', 'dns-01')
    if order['status'] == 'invalid':
        raise ValueError('The order is invalid or expired; start a new order')
    if order['status'] == 'pending':
        challenges = client.describe_challenges(order, ctype)
        client.answer_and_wait(challenges, timeout=int(params.get('timeout', 90)))
        order = client.get_order(params['order_url'])
    pem = client.finalize(order, params['order_url'], params['csr_pem'])
    return _cert_result(pem)


def _cert_result(chain_pem: str) -> Dict:
    from app.utils.ssl_utils import get_certificate_info
    certs = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\n?', chain_pem, re.S)
    leaf = certs[0]
    return {'success': True, 'certificate_pem': leaf, 'chain_pem': ''.join(certs[1:]),
            'fullchain_pem': chain_pem, 'certificate_info': get_certificate_info(leaf)}


def issue_automatic(params: Dict) -> Dict:
    """Single call: create order, publish dns-01 records via a provider, validate, finalize, clean up."""
    return _wrap(_issue_automatic, params)


def _issue_automatic(params: Dict) -> Dict:
    domains = normalize_domains(params['domains']) if params.get('domains') else []
    domains, csr_pem, domain_key = _prepare_csr(params, domains)
    provider = acme_dns.build_provider(params.get('dns_provider'))
    timeout = max(10, min(int(params.get('propagation_timeout', 90)), 180))
    client, generated = _client(params, register=True)
    order, order_url = client.new_order(domains)
    challenges = client.describe_challenges(order, 'dns-01')

    created = []
    try:
        for ch in challenges:
            if ch['status'] != 'pending':
                continue
            created.append(provider.add_txt(ch['dns_name'], ch['dns_value']))
        for ch in challenges:
            if ch['status'] == 'pending':
                acme_dns.wait_for_txt(ch['dns_name'], ch['dns_value'], timeout)
        client.answer_and_wait(challenges, timeout=timeout)
        order = client.get_order(order_url)
        pem = client.finalize(order, order_url, csr_pem)
    finally:
        cleanup_errors = []
        for handle in created:
            try:
                provider.remove_txt(handle)
            except Exception as e:  # never mask the real error with a cleanup failure
                cleanup_errors.append(str(e))

    result = _cert_result(pem)
    if domain_key:
        result['private_key_pem'] = domain_key
    if generated:
        result['account_key_pem'] = key_to_pem(client.key)
    if cleanup_errors:
        result['cleanup_warnings'] = cleanup_errors
    return result


def renewal_info(params: Dict) -> Dict:
    """When does the CA suggest renewing this certificate? (ARI, RFC 9773)"""
    return _wrap(_renewal_info, params)


def _renewal_info(params: Dict) -> Dict:
    from datetime import datetime, timezone
    from app.services.acme_client import fetch_renewal_info
    if not params.get('certificate'):
        raise ValueError('certificate is required')
    info = fetch_renewal_info(resolve_directory(params.get('directory')), params['certificate'])
    now = datetime.now(timezone.utc)
    start = datetime.fromisoformat(info['suggested_window_start'].replace('Z', '+00:00')) if info['suggested_window_start'] else None
    end = datetime.fromisoformat(info['suggested_window_end'].replace('Z', '+00:00')) if info['suggested_window_end'] else None
    if start and now >= start:
        info['status'], info['message'] = 'renew_now', 'The CA recommends renewing now (the suggested window has opened).'
    elif start:
        days = (start - now).days
        info['status'], info['message'] = 'wait', f'The CA suggests renewing in about {days} day(s), from {start.date()}.'
    else:
        info['status'], info['message'] = 'unknown', 'The CA did not suggest a renewal window.'
    info['days_until_window'] = (start - now).days if start else None
    return info
