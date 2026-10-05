"""MTA-STS (RFC 8461) and TLS-RPT (RFC 8460): checks, generators and a TLS-RPT report parser.

MTA-STS lets a domain tell sending mail servers "only deliver to my MX hosts over validated TLS".
A wrong policy can make mail bounce, so the checker compares the policy with the real MX records and
(optionally) with what the MX servers actually present.
"""
import base64
import gzip
import io
import json
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

from app.services.deliverability import _mx_hosts, _txt, valid_domain
from app.utils.net_safety import safe_get

MAX_REPORT_BYTES = 5 * 1024 * 1024
MODES = ('enforce', 'testing', 'none')
MAX_AGE_LIMIT = 31557600  # one year, the RFC maximum
_ID_RE = re.compile(r'^[A-Za-z0-9]{1,32}$')
_MAILTO_RE = re.compile(r'^mailto:[^@\s,;]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
_HTTPS_RE = re.compile(r'^https://[^\s,;]+$')

RESULT_EXPLANATIONS = {
    'starttls-not-supported': 'The receiving MX did not offer STARTTLS',
    'certificate-host-mismatch': 'The MX certificate does not cover the MX host name',
    'certificate-expired': 'The MX certificate has expired',
    'certificate-not-trusted': 'The MX certificate is not signed by a trusted CA',
    'validation-failure': 'TLS validation failed for another reason',
    'tlsa-invalid': 'The DANE TLSA record did not match',
    'dnssec-invalid': 'DNSSEC validation failed for the MX records',
    'dane-required': 'DANE was required but not published',
    'sts-policy-fetch-error': 'The sender could not fetch the MTA-STS policy',
    'sts-policy-invalid': 'The MTA-STS policy is invalid',
    'sts-webpki-invalid': 'The certificate of the MTA-STS policy host is invalid',
}


def _finding(severity: str, message: str) -> Dict:
    return {'severity': severity, 'message': message}


def _mx_matches(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower().rstrip('.'), host.lower().rstrip('.')
    if pattern.startswith('*.'):
        suffix = pattern[1:]  # ".example.com": the wildcard stands for exactly one label
        return host.endswith(suffix) and '.' not in host[:-len(suffix)] and len(host) > len(suffix)
    return pattern == host


def parse_policy(text: str) -> Dict:
    kv: Dict[str, List[str]] = {}
    for line in text.splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            kv.setdefault(key.strip().lower(), []).append(value.strip())
    return {'version': (kv.get('version') or [None])[0], 'mode': (kv.get('mode') or [None])[0],
            'mx': kv.get('mx', []), 'max_age': (kv.get('max_age') or [None])[0]}


def check_mta_sts(domain: str, verify_mx: bool = False) -> Dict:
    domain = valid_domain(domain)
    findings: List[Dict] = []
    records, _ = _txt(f'_mta-sts.{domain}')
    sts_records = [r for r in records if r.lower().startswith('v=stsv1')]
    result: Dict = {'domain': domain, 'dns_record': sts_records[0] if sts_records else None, 'id': None,
                    'policy': None, 'mx_hosts': [], 'mx_coverage': [], 'findings': findings, 'status': 'missing'}
    if not sts_records:
        findings.append(_finding('info', f'No MTA-STS record at _mta-sts.{domain}: senders will not enforce TLS to your MX hosts'))
        return result
    if len(sts_records) > 1:
        findings.append(_finding('error', 'Several MTA-STS TXT records exist; senders ignore MTA-STS when there is more than one'))
    tags = dict(p.strip().split('=', 1) for p in sts_records[0].split(';') if '=' in p)
    result['id'] = tags.get('id')
    if not result['id'] or not _ID_RE.match(result['id']):
        findings.append(_finding('error', 'The MTA-STS record needs an id of 1 to 32 letters or digits (change it whenever the policy changes)'))

    url = f'https://mta-sts.{domain}/.well-known/mta-sts.txt'
    try:
        resp = safe_get(url, timeout=8, headers={'User-Agent': 'ssl-toolkit-mta-sts/1.0'})
    except requests.exceptions.SSLError:
        findings.append(_finding('error', 'The certificate of mta-sts.%s is not valid; senders will not fetch the policy' % domain))
        return _finish(result)
    except Exception as e:
        findings.append(_finding('error', f'The policy file could not be fetched from {url} ({type(e).__name__})'))
        return _finish(result)
    if 300 <= resp.status_code < 400:
        findings.append(_finding('error', 'The policy URL redirects; MTA-STS forbids redirects, serve the file directly'))
        return _finish(result)
    if resp.status_code != 200:
        findings.append(_finding('error', f'The policy URL answered HTTP {resp.status_code}'))
        return _finish(result)
    if 'text/plain' not in (resp.headers.get('Content-Type') or '').lower():
        findings.append(_finding('warning', 'The policy should be served as Content-Type: text/plain'))

    policy = parse_policy(resp.text)
    result['policy'] = policy
    if policy['version'] != 'STSv1':
        findings.append(_finding('error', 'The policy must start with "version: STSv1"'))
    if policy['mode'] not in MODES:
        findings.append(_finding('error', 'mode must be enforce, testing or none'))
    elif policy['mode'] == 'testing':
        findings.append(_finding('warning', 'mode is "testing": senders report problems but still deliver unencrypted. Move to "enforce" once TLS-RPT shows no failures'))
    elif policy['mode'] == 'none':
        findings.append(_finding('warning', 'mode is "none": the policy is disabled'))
    try:
        max_age = int(policy['max_age'])
        if max_age < 0 or max_age > MAX_AGE_LIMIT:
            findings.append(_finding('error', f'max_age must be between 0 and {MAX_AGE_LIMIT} seconds'))
        elif policy['mode'] == 'enforce' and max_age < 86400:
            findings.append(_finding('warning', 'max_age is under a day; senders re-fetch the policy constantly and get little protection'))
        elif policy['mode'] == 'enforce' and max_age < 604800:
            findings.append(_finding('info', 'A max_age of at least a week (604800) is recommended once the policy is stable'))
    except (TypeError, ValueError):
        findings.append(_finding('error', 'max_age is missing or not a number'))
    if not policy['mx']:
        findings.append(_finding('error', 'The policy lists no mx hosts'))

    mx_hosts = _mx_hosts(domain)
    result['mx_hosts'] = mx_hosts
    enforcing = policy['mode'] == 'enforce'
    for host in mx_hosts:
        pattern = next((p for p in policy['mx'] if _mx_matches(p, host)), None)
        result['mx_coverage'].append({'host': host, 'covered': bool(pattern), 'pattern': pattern})
        if not pattern:
            findings.append(_finding('error' if enforcing else 'warning',
                                     f'MX host {host} is not listed in the policy' +
                                     ('; senders will refuse to deliver mail to it' if enforcing else '')))
    for pattern in policy['mx']:
        if mx_hosts and not any(_mx_matches(pattern, h) for h in mx_hosts):
            findings.append(_finding('info', f'Policy entry {pattern} matches none of the current MX records'))
    if not mx_hosts:
        findings.append(_finding('warning', 'The domain has no MX records to compare the policy with'))

    if verify_mx and mx_hosts:
        from app.services.mail_tls import scan_mail
        for host in mx_hosts[:5]:
            try:
                scan = scan_mail(host, 25, 'smtp', 'starttls', 6)
            except Exception as e:
                findings.append(_finding('warning', f'{host}: TLS test failed ({type(e).__name__})'))
                continue
            if not scan.get('reachable'):
                findings.append(_finding('warning', f"{host}: {scan.get('error', 'unreachable')}"))
            elif scan.get('starttls') is False:
                findings.append(_finding('error', f'{host} does not offer STARTTLS; enforcing senders cannot deliver to it'))
            elif not scan.get('certificate_trusted'):
                findings.append(_finding('error', f'{host} presents a certificate that does not validate for its host name; '
                                                  'enforcing senders will refuse delivery'))
            result.setdefault('mx_tls', []).append({'host': host, 'starttls': scan.get('starttls'),
                                                    'trusted': scan.get('certificate_trusted'), 'grade': scan.get('grade')})
    return _finish(result)


def _finish(result: Dict) -> Dict:
    severities = {f['severity'] for f in result['findings']}
    result['status'] = 'error' if 'error' in severities else 'warning' if 'warning' in severities else 'ok'
    return result


def generate_mta_sts(domain: str, mode: str = 'testing', mx: Optional[List[str]] = None,
                     max_age: int = 604800, now: Optional[datetime] = None) -> Dict:
    domain = valid_domain(domain)
    if mode not in MODES:
        raise ValueError('mode must be enforce, testing or none')
    max_age = int(max_age)
    if not 0 <= max_age <= MAX_AGE_LIMIT:
        raise ValueError(f'max_age must be between 0 and {MAX_AGE_LIMIT}')
    hosts = [h.strip().lower().rstrip('.') for h in (mx or _mx_hosts(domain)) if h and h.strip()]
    if not hosts:
        raise ValueError('No MX hosts: pass "mx" or publish MX records first')
    for h in hosts:
        if not re.match(r'^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$', h):
            raise ValueError(f'Invalid MX host: {h}')
    now = now or datetime.now(timezone.utc)
    policy = '\r\n'.join(['version: STSv1', f'mode: {mode}'] + [f'mx: {h}' for h in hosts] + [f'max_age: {max_age}']) + '\r\n'
    return {
        'domain': domain, 'policy': policy, 'policy_url': f'https://mta-sts.{domain}/.well-known/mta-sts.txt',
        'dns_name': f'_mta-sts.{domain}', 'dns_record': f'v=STSv1; id={now.strftime("%Y%m%d%H%M%S")}',
        'steps': [
            f'Serve the policy at https://mta-sts.{domain}/.well-known/mta-sts.txt over HTTPS with a valid certificate for mta-sts.{domain} (no redirects, Content-Type text/plain).',
            f'Publish the TXT record at _mta-sts.{domain}; change its id every time the policy changes.',
            'Start with mode "testing", watch your TLS-RPT reports, then switch to "enforce".',
        ],
    }


# --------------------------------------------------------------------------- TLS-RPT
def parse_tls_rpt_record(record: str) -> Dict:
    tags = {}
    for part in record.split(';'):
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_tls_rpt(domain: str) -> Dict:
    domain = valid_domain(domain)
    records, _ = _txt(f'_smtp._tls.{domain}')
    rpt = [r for r in records if r.lower().startswith('v=tlsrptv1')]
    findings: List[Dict] = []
    result: Dict = {'domain': domain, 'record': rpt[0] if rpt else None, 'destinations': [], 'findings': findings}
    if not rpt:
        findings.append(_finding('info', f'No TLS-RPT record at _smtp._tls.{domain}: you will not learn about TLS delivery failures'))
        result['status'] = 'missing'
        return result
    if len(rpt) > 1:
        findings.append(_finding('error', 'Several TLS-RPT TXT records exist; senders ignore them when there is more than one'))
    tags = parse_tls_rpt_record(rpt[0])
    rua = tags.get('rua', '')
    if not rua:
        findings.append(_finding('error', 'The record has no rua= destination'))
    for dest in [d.strip() for d in rua.split(',') if d.strip()]:
        ok = bool(_MAILTO_RE.match(dest) or _HTTPS_RE.match(dest))
        result['destinations'].append({'uri': dest, 'valid': ok})
        if not ok:
            findings.append(_finding('error', f'Invalid report destination "{dest}" (use mailto:address or https://URL)'))
    result['status'] = 'error' if any(f['severity'] == 'error' for f in findings) else 'ok'
    return result


def generate_tls_rpt(domain: str, rua: List[str]) -> Dict:
    domain = valid_domain(domain)
    dests = []
    for item in rua or []:
        item = str(item).strip()
        if '@' in item and not item.startswith(('mailto:', 'https://')):
            item = 'mailto:' + item
        if not (_MAILTO_RE.match(item) or _HTTPS_RE.match(item)):
            raise ValueError(f'Invalid report destination: {item}')
        dests.append(item)
    if not dests:
        raise ValueError('At least one report destination (rua) is required')
    return {'domain': domain, 'dns_name': f'_smtp._tls.{domain}', 'dns_record': f'v=TLSRPTv1; rua={",".join(dests)}'}


def _load_report_bytes(raw: bytes) -> bytes:
    if raw[:2] == b'\x1f\x8b':
        out = gzip.GzipFile(fileobj=io.BytesIO(raw)).read(MAX_REPORT_BYTES + 1)
        if len(out) > MAX_REPORT_BYTES:
            raise ValueError('The decompressed report is too large')
        return out
    return raw


def parse_tls_rpt_report(params: Dict) -> Dict:
    """Summarise an RFC 8460 JSON report (plain or gzip, text or base64)."""
    if params.get('file_base64'):
        try:
            raw = base64.b64decode(params['file_base64'], validate=True)
        except ValueError:
            raise ValueError('file_base64 is not valid base64')
    elif params.get('json'):
        raw = str(params['json']).encode()
    else:
        raise ValueError('Provide json or file_base64')
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError('The report is too large (5 MB limit)')
    try:
        data = json.loads(_load_report_bytes(raw))
    except (ValueError, OSError):
        raise ValueError('The report is not valid JSON')
    if not isinstance(data, dict) or not isinstance(data.get('policies'), list):
        raise ValueError('This does not look like a TLS-RPT report (no "policies" list)')
    rng = data.get('date-range') or {}
    policies, ok_total, fail_total = [], 0, 0
    failures: Counter = Counter()
    findings: List[Dict] = []
    for p in data['policies']:
        policy = p.get('policy') or {}
        summary = p.get('summary') or {}
        ok, bad = int(summary.get('total-successful-session-count') or 0), int(summary.get('total-failure-session-count') or 0)
        ok_total, fail_total = ok_total + ok, fail_total + bad
        details = []
        for d in p.get('failure-details') or []:
            count = int(d.get('failed-session-count') or 0)
            kind = d.get('result-type') or 'unknown'
            failures[kind] += count
            details.append({'type': kind, 'explanation': RESULT_EXPLANATIONS.get(kind), 'count': count,
                            'receiving_mx': d.get('receiving-mx-hostname'), 'sending_ip': d.get('sending-mta-ip'),
                            'reason': d.get('additional-information') or d.get('failure-reason-code')})
        policies.append({'type': policy.get('policy-type'), 'domain': policy.get('policy-domain'),
                         'mx_hosts': policy.get('mx-host') or [], 'successful': ok, 'failed': bad, 'failures': details})
    for kind, count in failures.most_common():
        findings.append(_finding('error' if kind != 'unknown' else 'warning',
                                 f"{count} failed session(s): {RESULT_EXPLANATIONS.get(kind, kind)} ({kind})"))
    total = ok_total + fail_total
    return {'organization': data.get('organization-name'), 'report_id': data.get('report-id'),
            'start': rng.get('start-datetime'), 'end': rng.get('end-datetime'), 'contact': data.get('contact-info'),
            'successful': ok_total, 'failed': fail_total,
            'success_rate': round(100 * ok_total / total, 2) if total else None,
            'policies': policies, 'findings': findings}
