import base64
import hashlib
import ipaddress
import math
import re
import secrets
import string
from datetime import datetime
from email.parser import Parser
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional, Tuple

import dns.exception
import dns.resolver
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DEFAULT_DNS_TIMEOUT = 5
DMARC_POLICIES = {'none', 'quarantine', 'reject'}
ALIGNMENT_MODES = {'r', 's'}
DEFAULT_CHARSETS = {
    'upper': string.ascii_uppercase,
    'lower': string.ascii_lowercase,
    'digits': string.digits,
    'symbols': '!@#$%^&*()-_=+[]{}|;:,.<>?'
}
AUTH_RESULT_PATTERN = re.compile(r'(spf|dkim|dmarc)=([a-zA-Z]+)(?:\s+([^;]+))?', re.IGNORECASE)
RECEIVED_SECTION_PATTERN = re.compile(r'(from|by|with)\s+([^;]+)', re.IGNORECASE)
IP_PATTERN = re.compile(r'\[([0-9a-fA-F:.]+)\]')


def _normalize_mailto_list(entries):
    if not entries:
        return []
    if isinstance(entries, str):
        entries = [item.strip() for item in entries.replace('\n', ',').split(',') if item.strip()]
    normalized = []
    for entry in entries:
        if not entry:
            continue
        entry = entry.strip()
        if not entry:
            continue
        if not entry.lower().startswith('mailto:'):
            entry = f'mailto:{entry}'
        normalized.append(entry)
    return normalized


def _resolve_txt_records(name: str, timeout: int = DEFAULT_DNS_TIMEOUT) -> Tuple[List[str], Optional[str]]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(name, 'TXT')
        records = []
        for rdata in answers:
            try:
                strings = getattr(rdata, 'strings', None)
                if strings:
                    records.append(''.join(part.decode('utf-8') for part in strings))
                else:
                    text = rdata.to_text().strip('"')
                    records.append(text.replace('""', '"'))
            except Exception:
                records.append(rdata.to_text().strip('"'))
        return records, None
    except dns.resolver.NXDOMAIN:
        return [], 'NXDOMAIN'
    except dns.exception.DNSException as exc:
        return [], str(exc)


def _parse_tag_record(record: str) -> Dict[str, str]:
    tags = {}
    if not record:
        return tags
    pieces = [segment.strip() for segment in record.split(';') if segment.strip()]
    for piece in pieces:
        if '=' not in piece:
            continue
        key, value = piece.split('=', 1)
        tags[key.strip()] = value.strip()
    return tags


def generate_dmarc_record(config: Dict):
    domain = (config or {}).get('domain')
    if not domain:
        raise ValueError('Domain is required to build a DMARC record')

    policy = (config.get('policy') or 'reject').lower()
    if policy not in DMARC_POLICIES:
        raise ValueError('DMARC policy must be one of: none, quarantine, reject')

    tags = {
        'v': 'DMARC1',
        'p': policy,
    }

    subdomain_policy = (config.get('subdomain_policy') or '').lower()
    if subdomain_policy in DMARC_POLICIES:
        tags['sp'] = subdomain_policy

    adkim = (config.get('adkim') or '').lower()
    if adkim in ALIGNMENT_MODES:
        tags['adkim'] = adkim

    aspf = (config.get('aspf') or '').lower()
    if aspf in ALIGNMENT_MODES:
        tags['aspf'] = aspf

    rua = _normalize_mailto_list(config.get('rua'))
    if rua:
        tags['rua'] = ','.join(rua)

    ruf = _normalize_mailto_list(config.get('ruf'))
    if ruf:
        tags['ruf'] = ','.join(ruf)

    pct = config.get('pct', 100)
    try:
        pct = max(1, min(100, int(pct)))
    except (TypeError, ValueError):
        pct = 100
    tags['pct'] = str(pct)

    report_interval = config.get('report_interval', 86400)
    try:
        report_interval = max(3600, int(report_interval))
    except (TypeError, ValueError):
        report_interval = 86400
    tags['ri'] = str(report_interval)

    forensic_options = config.get('fo')
    if forensic_options:
        tags['fo'] = forensic_options

    record = '; '.join(f'{key}={value}' for key, value in tags.items())

    recommendations = []
    if not rua:
        recommendations.append('Add a rua mailbox to receive aggregate DMARC reports.')
    if policy == 'none':
        recommendations.append('Start with policy=none only for monitoring; move to quarantine/reject after review.')
    if pct < 100:
        recommendations.append('pct is below 100%; increase to enforce DMARC for all mail when ready.')

    return {
        'domain': domain,
        'dns_host': f'_dmarc.{domain}',
        'record': record,
        'tags': tags,
        'recommendations': recommendations
    }


def validate_dmarc_record(config: Dict):
    config = config or {}
    record = config.get('record')
    domain = config.get('domain')
    timeout = config.get('timeout', DEFAULT_DNS_TIMEOUT)

    dns_records = []
    dns_error = None
    record_source = 'input'

    if domain:
        dns_records, dns_error = _resolve_txt_records(f'_dmarc.{domain}', timeout)
        if not record:
            record = next((r for r in dns_records if r.lower().startswith('v=dmarc1')), None)
            if record:
                record_source = 'dns'

    if not record:
        return {
            'domain': domain,
            'record_source': None,
            'record_present': False,
            'record': None,
            'tags': {},
            'valid': False,
            'errors': ['No DMARC record was provided or discovered.'],
            'warnings': [],
            'dns_records': dns_records,
            'dns_error': dns_error
        }

    tags = _parse_tag_record(record)
    errors = []
    warnings = []

    version = tags.get('v')
    if not version or version.upper() != 'DMARC1':
        errors.append('The DMARC record must start with v=DMARC1.')

    policy = (tags.get('p') or '').lower()
    if policy not in DMARC_POLICIES:
        errors.append('Policy (p=) must be one of none, quarantine, reject.')

    rua = tags.get('rua')
    if not rua:
        warnings.append('Aggregate report address (rua) is missing; you will not receive DMARC reports.')

    pct = tags.get('pct')
    if pct:
        try:
            pct_value = int(pct)
            if pct_value < 100:
                warnings.append('pct is below 100%; DMARC is not fully enforced for all mail.')
        except ValueError:
            warnings.append('pct must be an integer between 1 and 100.')

    fo = tags.get('fo')
    if fo and not all(part in {'0', '1', 'd', 's'} for part in fo.split(':')):
        warnings.append('fo contains unknown failure reporting options.')

    adkim = (tags.get('adkim') or '').lower()
    if adkim and adkim not in ALIGNMENT_MODES:
        warnings.append('adkim must be relaxed (r) or strict (s).')

    aspf = (tags.get('aspf') or '').lower()
    if aspf and aspf not in ALIGNMENT_MODES:
        warnings.append('aspf must be relaxed (r) or strict (s).')

    valid = len(errors) == 0

    return {
        'domain': domain,
        'record_source': record_source,
        'record_present': True,
        'record': record,
        'tags': tags,
        'valid': valid,
        'errors': errors,
        'warnings': warnings,
        'dns_records': dns_records,
        'dns_error': dns_error
    }


def _normalize_ip_list(entries, version='ipv4'):
    if not entries:
        return []
    if isinstance(entries, str):
        entries = [item.strip() for item in entries.replace('\n', ',').split(',') if item.strip()]
    filtered = []
    for entry in entries:
        try:
            ip_obj = ipaddress.ip_address(entry.strip())
            if version == 'ipv4' and isinstance(ip_obj, ipaddress.IPv4Address):
                filtered.append(str(ip_obj))
            elif version == 'ipv6' and isinstance(ip_obj, ipaddress.IPv6Address):
                filtered.append(str(ip_obj))
        except ValueError:
            continue
    return filtered


def generate_spf_record(config: Dict):
    domain = (config or {}).get('domain')
    if not domain:
        raise ValueError('Domain is required to build an SPF record')

    ipv4_list = _normalize_ip_list(config.get('ipv4'), version='ipv4')
    ipv6_list = _normalize_ip_list(config.get('ipv6'), version='ipv6')
    includes = config.get('include') or []
    if isinstance(includes, str):
        includes = [item.strip() for item in includes.replace('\n', ',').split(',') if item.strip()]

    parts = ['v=spf1']
    mechanisms = []

    if config.get('include_a'):
        parts.append('a')
        mechanisms.append('a')
    if config.get('include_mx'):
        parts.append('mx')
        mechanisms.append('mx')

    for ip4 in ipv4_list:
        part = f'ip4:{ip4}'
        parts.append(part)
        mechanisms.append(part)

    for ip6 in ipv6_list:
        part = f'ip6:{ip6}'
        parts.append(part)
        mechanisms.append(part)

    for include_domain in includes:
        if include_domain:
            part = f'include:{include_domain}'
            parts.append(part)
            mechanisms.append(part)

    redirect = config.get('redirect')
    if redirect:
        part = f'redirect={redirect}'
        parts.append(part)
        mechanisms.append(part)

    exp = config.get('exp')
    if exp:
        part = f'exp={exp}'
        parts.append(part)
        mechanisms.append(part)

    qualifier = config.get('all') or '~all'
    qualifier = qualifier.strip()
    if qualifier and not qualifier.endswith('all'):
        if qualifier[0] in {'+', '-', '~', '?'}:
            qualifier = f'{qualifier}all'
        else:
            qualifier = f'{qualifier} all'
    if 'all' not in qualifier:
        qualifier = '~all'
    parts.append(qualifier)
    mechanisms.append(qualifier)

    record = ' '.join(parts)

    notes = []
    if len(mechanisms) > 10:
        notes.append('SPF has more than 10 mechanisms; DNS lookups may exceed RFC limits.')
    if len(record) > 255:
        notes.append('SPF record exceeds 255 characters; ensure it is split across multiple TXT chunks if needed.')

    return {
        'domain': domain,
        'record': record,
        'mechanisms': mechanisms,
        'notes': notes
    }


def _parse_spf_mechanisms(record: str):
    tokens = record.split()
    mechanisms = []
    for token in tokens[1:]:
        if ':' in token or '=' in token or token in {'a', 'mx', 'ptr', 'ip4', 'ip6', 'include'} or token.endswith('all'):
            mechanisms.append(token)
    return mechanisms


def validate_spf_record(config: Dict):
    config = config or {}
    record = config.get('record')
    domain = config.get('domain')
    timeout = config.get('timeout', DEFAULT_DNS_TIMEOUT)

    dns_records = []
    dns_error = None
    record_source = 'input'

    if domain:
        dns_records, dns_error = _resolve_txt_records(domain, timeout)
        if not record:
            record = next((r for r in dns_records if r.lower().startswith('v=spf1')), None)
            if record:
                record_source = 'dns'

    if not record:
        return {
            'domain': domain,
            'record_source': None,
            'record_present': False,
            'record': None,
            'valid': False,
            'errors': ['No SPF record was provided or discovered.'],
            'warnings': [],
            'mechanisms': [],
            'dns_records': dns_records,
            'dns_error': dns_error
        }

    if not record.lower().startswith('v=spf1'):
        return {
            'domain': domain,
            'record_source': record_source,
            'record_present': True,
            'record': record,
            'valid': False,
            'errors': ['SPF record must start with v=spf1'],
            'warnings': [],
            'mechanisms': _parse_spf_mechanisms(record),
            'dns_records': dns_records,
            'dns_error': dns_error
        }

    tokens = record.split()
    mechanisms = _parse_spf_mechanisms(record)
    errors = []
    warnings = []

    if not any(token.endswith('all') for token in tokens):
        warnings.append('SPF record should end with an ~all, -all, +all, or ?all mechanism.')

    include_count = len([token for token in tokens if token.startswith('include:')])
    if include_count > 10:
        warnings.append('More than 10 include mechanisms detected; this may exceed DNS lookup limits.')

    if len(tokens) > 10:
        warnings.append('Total SPF mechanisms may trigger the 10-DNS-lookup limit. Review includes and redirects.')

    if len(record) > 255:
        warnings.append('SPF record exceeds 255 characters; ensure it is split into multiple quoted strings in DNS.')

    valid = len(errors) == 0

    return {
        'domain': domain,
        'record_source': record_source,
        'record_present': True,
        'record': record,
        'valid': valid,
        'errors': errors,
        'warnings': warnings,
        'mechanisms': mechanisms,
        'dns_records': dns_records,
        'dns_error': dns_error
    }


def _parse_received_header(value: str):
    parsed = {
        'raw': value,
        'from': None,
        'by': None,
        'with': None,
        'ip': None,
        'timestamp': None
    }
    timestamp_obj = None

    for match in RECEIVED_SECTION_PATTERN.finditer(value):
        section = match.group(1).lower()
        data = match.group(2).strip()
        if section == 'from' and not parsed['from']:
            parsed['from'] = data
        elif section == 'by' and not parsed['by']:
            parsed['by'] = data
        elif section == 'with' and not parsed['with']:
            parsed['with'] = data

    ip_match = IP_PATTERN.search(value)
    if ip_match:
        parsed['ip'] = ip_match.group(1)

    if ';' in value:
        timestamp_str = value.split(';')[-1].strip()
        if timestamp_str:
            try:
                timestamp_obj = parsedate_to_datetime(timestamp_str)
                parsed['timestamp'] = timestamp_obj.isoformat()
            except Exception:
                parsed['timestamp'] = timestamp_str

    return parsed, timestamp_obj


def _extract_authentication_results(headers: List[str]):
    summary = {
        'spf': None,
        'dkim': None,
        'dmarc': None,
        'details': [],
        'raw': headers
    }
    for header in headers or []:
        for match in AUTH_RESULT_PATTERN.finditer(header):
            mechanism = match.group(1).lower()
            result = match.group(2).lower()
            context = (match.group(3) or '').strip()
            summary[mechanism] = f'{result} {context}'.strip()
            summary['details'].append({
                'mechanism': mechanism,
                'result': result,
                'detail': context
            })
    return summary


def analyze_email_headers(config: Dict):
    headers = (config or {}).get('headers')
    if not headers or not headers.strip():
        raise ValueError('Raw email headers are required for analysis')

    parser = Parser()
    normalized_headers = headers.strip('\n') + '\n\n'
    message = parser.parsestr(normalized_headers)

    received_entries = []
    hop_timestamps = []
    for raw_received in message.get_all('Received', []):
        parsed, ts_obj = _parse_received_header(raw_received)
        received_entries.append(parsed)
        if ts_obj:
            hop_timestamps.append(ts_obj)

    auth_results = _extract_authentication_results(message.get_all('Authentication-Results', []))

    warnings = []
    if not received_entries:
        warnings.append('No Received headers were found; unable to build a delivery timeline.')
    if auth_results['spf'] and auth_results['spf'].startswith('fail'):
        warnings.append('SPF reported a failure for this message.')
    if auth_results['dkim'] and auth_results['dkim'].startswith('fail'):
        warnings.append('DKIM reported a failure for this message.')
    if auth_results['dmarc'] and auth_results['dmarc'].startswith('fail'):
        warnings.append('DMARC reported a failure for this message.')

    hop_summary = {
        'hop_count': len(received_entries),
        'start': None,
        'end': None,
        'duration_seconds': None
    }
    if len(hop_timestamps) >= 2:
        hop_timestamps.sort()
        start = hop_timestamps[0]
        end = hop_timestamps[-1]
        hop_summary['start'] = start.isoformat()
        hop_summary['end'] = end.isoformat()
        hop_summary['duration_seconds'] = (end - start).total_seconds()

    metadata = {
        'subject': message.get('Subject'),
        'from': message.get('From'),
        'to': message.get('To'),
        'date': message.get('Date'),
        'message_id': message.get('Message-ID')
    }

    header_map = {key: value for key, value in message.items()}

    return {
        'metadata': metadata,
        'received_chain': received_entries,
        'hop_summary': hop_summary,
        'authentication': auth_results,
        'warnings': warnings,
        'header_map': header_map
    }


def _build_character_pool(character_sets: Dict[str, bool]):
    pool = ''
    included_sets = {}
    for key, enabled in character_sets.items():
        charset = DEFAULT_CHARSETS.get(key)
        if enabled and charset:
            pool += charset
            included_sets[key] = True
        else:
            included_sets[key] = False
    return pool, included_sets


def _derive_fernet_key(raw_key: Optional[str] = None, passphrase: Optional[str] = None):
    if raw_key:
        try:
            key_bytes = raw_key.encode('utf-8')
            Fernet(key_bytes)  # validate format
            return key_bytes, 'provided'
        except Exception:
            raise ValueError('Provided encryption key is not a valid Fernet key')
    if passphrase:
        digest = hashlib.sha256(passphrase.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest), 'derived'
    return Fernet.generate_key(), 'generated'


def _generate_password(length: int, pool: str, sets: Dict[str, bool]):
    if length < sum(1 for enabled in sets.values() if enabled):
        raise ValueError('Password length is too short for the selected character requirements')

    password_chars = []
    for key, enabled in sets.items():
        if enabled:
            charset = DEFAULT_CHARSETS[key]
            password_chars.append(secrets.choice(charset))

    remaining = length - len(password_chars)
    password_chars.extend(secrets.choice(pool) for _ in range(remaining))
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)


def generate_password_bundle(config: Dict):
    config = config or {}
    length = int(config.get('length', 16))
    character_sets = config.get('character_sets') or {
        'upper': True,
        'lower': True,
        'digits': True,
        'symbols': False
    }

    pool, selected_sets = _build_character_pool(character_sets)
    if not pool:
        raise ValueError('At least one character set must be selected')

    password = _generate_password(length, pool, selected_sets)

    hash_algorithms = config.get('hash_algorithms') or ['sha256', 'sha512']
    hashes = {}
    unsupported = []
    for algo in hash_algorithms:
        algo_name = algo.lower()
        if algo_name in hashlib.algorithms_available:
            hasher = hashlib.new(algo_name)
            hasher.update(password.encode('utf-8'))
            hashes[algo_name] = hasher.hexdigest()
        else:
            unsupported.append(algo)

    entropy_bits = round(math.log2(len(pool)) * length, 2)

    encryption_config = config.get('encryption') or {}
    encryption_result = {
        'enabled': False,
        'encrypted_password': None,
        'key': None,
        'key_source': None
    }

    if encryption_config.get('enabled'):
        key, key_source = _derive_fernet_key(
            raw_key=encryption_config.get('key'),
            passphrase=encryption_config.get('passphrase')
        )
        fernet = Fernet(key)
        encrypted_password = fernet.encrypt(password.encode('utf-8')).decode('utf-8')
        encryption_result.update({
            'enabled': True,
            'encrypted_password': encrypted_password,
            'key_source': key_source,
            'key': key.decode('utf-8') if key_source in {'generated', 'derived'} else None
        })

    warnings = []
    if unsupported:
        warnings.append(f'Unsupported hash algorithms ignored: {", ".join(unsupported)}')
    if length < 12:
        warnings.append('Passwords shorter than 12 characters are discouraged for production use.')

    return {
        'password': password,
        'hashes': hashes,
        'character_sets': selected_sets,
        'entropy_bits': entropy_bits,
        'encryption': encryption_result,
        'warnings': warnings
    }


def _format_dns_record(record_type: str, rdata):
    if record_type == 'MX':
        return {
            'priority': int(getattr(rdata, 'preference', 0)),
            'host': str(getattr(rdata, 'exchange', '')).rstrip('.')
        }
    if record_type == 'TXT':
        try:
            strings = getattr(rdata, 'strings', None)
            if strings:
                return ''.join(part.decode('utf-8') for part in strings)
        except Exception:
            pass
        text = rdata.to_text().strip('"')
        return text.replace('""', '"')
    if record_type == 'NS':
        return str(getattr(rdata, 'target', rdata)).rstrip('.')
    if record_type == 'CNAME':
        return str(getattr(rdata, 'target', rdata)).rstrip('.')
    return rdata.to_text()


def lookup_dns_records(config: Dict):
    config = config or {}
    domain = config.get('domain')
    if not domain:
        raise ValueError('Domain is required for DNS lookups')

    record_types = config.get('record_types') or ['A', 'AAAA', 'MX', 'TXT', 'NS']
    timeout = config.get('timeout', DEFAULT_DNS_TIMEOUT)

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    results = {}

    for record_type in record_types:
        record_type = record_type.upper()
        try:
            answers = resolver.resolve(domain, record_type)
            ttl = answers.rrset.ttl if answers.rrset else None
            records = [_format_dns_record(record_type, rdata) for rdata in answers]
            results[record_type] = {
                'records': records,
                'ttl': ttl,
                'error': None
            }
        except dns.resolver.NoAnswer:
            results[record_type] = {
                'records': [],
                'ttl': None,
                'error': 'No answer'
            }
        except dns.exception.DNSException as exc:
            results[record_type] = {
                'records': [],
                'ttl': None,
                'error': str(exc)
            }

    return {
        'domain': domain,
        'record_types': record_types,
        'results': results,
        'queried_at': datetime.utcnow().isoformat() + 'Z'
    }


# ---------------------------------------------------------------------------
# DKIM Record Generator / Validator
# ---------------------------------------------------------------------------

def generate_dkim_record(params: dict) -> dict:
    params = params or {}
    domain = params.get('domain', '').strip()
    selector = params.get('selector', '').strip()
    if not domain:
        raise ValueError('domain is required')
    if not selector:
        raise ValueError('selector is required')

    key_size = int(params.get('key_size', 2048))
    if key_size not in (1024, 2048, 4096):
        raise ValueError('key_size must be 1024, 2048, or 4096')

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode('utf-8')

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')

    # DER-encode the public key, base64 (no newlines) for the DNS TXT value
    pub_der = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_b64 = base64.b64encode(pub_der).decode('ascii')

    dns_host = f"{selector}._domainkey.{domain}"
    dns_record = f"v=DKIM1; k=rsa; p={pub_b64}"

    return {
        'success': True,
        'private_key_pem': private_key_pem,
        'public_key_pem': public_key_pem,
        'dns_host': dns_host,
        'dns_record': dns_record,
        'selector': selector,
        'domain': domain,
        'key_size': key_size,
    }


def validate_dkim_record(params: dict) -> dict:
    params = params or {}
    domain = params.get('domain', '').strip()
    selector = params.get('selector', '').strip()
    inline_record = params.get('record', '').strip()

    errors: List[str] = []
    warnings: List[str] = []
    record_source = None
    raw_record = None

    if inline_record:
        raw_record = inline_record
        record_source = 'inline'
    elif domain and selector:
        lookup_name = f"{selector}._domainkey.{domain}"
        records, err = _resolve_txt_records(lookup_name)
        if err or not records:
            return {
                'valid': False,
                'record': None,
                'record_source': 'dns',
                'parsed_tags': {},
                'errors': [err or f'No TXT record found at {lookup_name}'],
                'warnings': [],
            }
        raw_record = records[0]
        record_source = 'dns'
    else:
        raise ValueError("Provide 'record' for inline validation, or both 'domain' and 'selector' for DNS lookup")

    tags = _parse_tag_record(raw_record)

    if tags.get('v') != 'DKIM1':
        errors.append("Record does not start with v=DKIM1")

    k = tags.get('k', 'rsa')
    if k not in ('rsa', 'ed25519'):
        warnings.append(f"Unrecognised key type k={k}")

    if not tags.get('p'):
        errors.append("Public key (p=) is missing or empty")

    t = tags.get('t', '')
    if t:
        flags = [f.strip() for f in t.split(':')]
        if 'y' in flags:
            warnings.append("t=y flag means this key is in test mode — mail may not be rejected on failure")

    return {
        'valid': len(errors) == 0,
        'record': raw_record,
        'record_source': record_source,
        'parsed_tags': tags,
        'errors': errors,
        'warnings': warnings,
    }


# ---------------------------------------------------------------------------
# SSL/TLS Config Snippet Generator
# ---------------------------------------------------------------------------

_NGINX_TEMPLATE = """\
server {{
    listen 443 ssl{http2_flag};
    server_name {domain};

    ssl_certificate     {cert_path};
    ssl_certificate_key {key_path};
{chain_line}
    ssl_protocols {protocols};
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
{hsts_line}
{ocsp_lines}
    # Your site configuration here
}}
"""

_APACHE_TEMPLATE = """\
<VirtualHost *:443>
    ServerName {domain}

    SSLEngine on
    SSLCertificateFile    {cert_path}
    SSLCertificateKeyFile {key_path}
{chain_line}
    SSLProtocol {protocols}
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    SSLHonorCipherOrder off
    SSLSessionTickets off
{hsts_line}
{ocsp_lines}
    # Your site configuration here
</VirtualHost>
"""

_HAPROXY_TEMPLATE = """\
frontend https_in
    bind *:443 ssl crt {cert_path}{chain_flag} alpn h2,http/1.1
    {protocols_acl}

    # Your ACLs / backend routing here
    default_backend my_servers

backend my_servers
    balance roundrobin
    option forwardfor
    server app1 127.0.0.1:8080 check
"""


def generate_ssl_config(params: dict) -> dict:
    params = params or {}
    server = params.get('server', '').lower().strip()
    domain = params.get('domain', '').strip()
    cert_path = params.get('cert_path', '').strip()
    key_path = params.get('key_path', '').strip()

    if server not in ('nginx', 'apache', 'haproxy'):
        raise ValueError("server must be one of: nginx, apache, haproxy")
    if not domain:
        raise ValueError("domain is required")
    if not cert_path:
        raise ValueError("cert_path is required")
    if not key_path:
        raise ValueError("key_path is required")

    chain_path = params.get('chain_path', '').strip()
    min_tls = params.get('min_tls', 'TLSv1.2').strip()
    hsts = bool(params.get('hsts', True))
    ocsp_stapling = bool(params.get('ocsp_stapling', True))

    notes: List[str] = []

    if server == 'nginx':
        http2_flag = ' http2'
        if min_tls == 'TLSv1.3':
            protocols = 'TLSv1.3'
            notes.append("TLSv1.3-only mode: very secure but may exclude older clients.")
        else:
            protocols = 'TLSv1.2 TLSv1.3'

        chain_line = f"    ssl_trusted_certificate {chain_path};\n" if chain_path else ""
        hsts_line = '    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;' if hsts else ""
        if ocsp_stapling:
            ocsp_lines = "    ssl_stapling on;\n    ssl_stapling_verify on;\n    resolver 1.1.1.1 8.8.8.8 valid=300s;\n    resolver_timeout 5s;"
        else:
            ocsp_lines = ""

        snippet = _NGINX_TEMPLATE.format(
            domain=domain,
            cert_path=cert_path,
            key_path=key_path,
            chain_line=chain_line,
            protocols=protocols,
            http2_flag=http2_flag,
            hsts_line=hsts_line,
            ocsp_lines=ocsp_lines,
        )

    elif server == 'apache':
        if min_tls == 'TLSv1.3':
            protocols = 'all -SSLv3 -TLSv1 -TLSv1.1 -TLSv1.2'
            notes.append("TLSv1.3-only: requires Apache 2.4.36+ with OpenSSL 1.1.1+.")
        else:
            protocols = 'all -SSLv3 -TLSv1 -TLSv1.1'

        chain_line = f"    SSLCertificateChainFile {chain_path}" if chain_path else ""
        hsts_line = '    Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"' if hsts else ""
        if ocsp_stapling:
            ocsp_lines = "    SSLUseStapling on\n    SSLStaplingCache shmcb:/run/ocsp(128000)"
        else:
            ocsp_lines = ""

        snippet = _APACHE_TEMPLATE.format(
            domain=domain,
            cert_path=cert_path,
            key_path=key_path,
            chain_line=chain_line,
            protocols=protocols,
            hsts_line=hsts_line,
            ocsp_lines=ocsp_lines,
        )
        if hsts:
            notes.append("Ensure mod_headers is enabled: a2enmod headers")

    else:  # haproxy
        if chain_path:
            chain_flag = f" ca-file {chain_path}"
        else:
            chain_flag = ""
        if min_tls == 'TLSv1.3':
            protocols_acl = "ssl-min-ver TLSv1.3"
        else:
            protocols_acl = "ssl-min-ver TLSv1.2"

        snippet = _HAPROXY_TEMPLATE.format(
            cert_path=cert_path,
            chain_flag=chain_flag,
            protocols_acl=protocols_acl,
        )
        notes.append("HAProxy expects a single PEM file containing cert + key (+ chain). Concatenate them.")

    if hsts:
        notes.append("HSTS preload requires registration at hstspreload.org after deployment.")

    return {
        'success': True,
        'server': server,
        'domain': domain,
        'config_snippet': snippet,
        'notes': notes,
    }
