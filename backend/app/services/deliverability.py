"""Email deliverability: SPF lookup counting, DKIM selector discovery, DMARC aggregate
report parsing, DNS blocklist (RBL) checks and a combined score.

All DNS access goes through the small helpers at the top so tests can replace them.
"""
import base64
import gzip
import io
import ipaddress
import os
import re
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional
import xml.etree.ElementTree as ET

import dns.exception
import dns.resolver
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.services.sysadmin_tools import _parse_tag_record, _resolve_txt_records, validate_dmarc_record
from app.utils.net_safety import is_public_ip, safe_get

MAX_REPORT_BYTES = 5 * 1024 * 1024
SPF_LOOKUP_LIMIT = 10
SPF_VOID_LIMIT = 2
_DOMAIN_RE = re.compile(r'^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$')

COMMON_DKIM_SELECTORS = [
    'default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'dkim', 'mail', 'smtp',
    'mandrill', 'mxvault', 'zoho', 'protonmail', 'protonmail2', 'protonmail3', 'fm1', 'fm2', 'fm3',
    'mta', 'sendgrid', 'smtpapi', 'mailjet', 'amazonses', 'everlytickey1', 'everlytickey2', 'cm',
    'scph0123', 'pic', 'dk', 'email', 'key1', 'key2', 'sig1', 'turbo-smtp', 'ses', 'sparkpost', 'm1',
]
DEFAULT_RBLS = {
    'ip': ['zen.spamhaus.org', 'bl.spamcop.net', 'psbl.surriel.com', 'dnsbl-1.uceprotect.net',
           'all.s5h.net', 'dnsbl.dronebl.org', 'b.barracudacentral.org'],
    'domain': ['dbl.spamhaus.org', 'multi.uribl.com'],
}
# Spamhaus answers these when the *querying resolver* is blocked, not when the target is listed.
RBL_ERROR_CODES = {'127.255.255.252', '127.255.255.254', '127.255.255.255', '127.0.1.255'}


def valid_domain(domain: Optional[str]) -> str:
    d = (domain or '').strip().lower().rstrip('.')
    if not _DOMAIN_RE.match(d):
        raise ValueError('A valid domain name is required')
    return d


# --------------------------------------------------------------------------- DNS helpers
def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = r.lifetime = 4
    custom = [x.strip() for x in os.environ.get('RBL_RESOLVERS', '').split(',') if x.strip()]
    if custom:
        r.nameservers = custom
    return r


def _txt(name: str):
    """(records, error). error is 'NXDOMAIN' for non-existent names, None otherwise."""
    return _resolve_txt_records(name)


def _address_exists(name: str) -> bool:
    for rtype in ('A', 'AAAA'):
        try:
            _resolver().resolve(name, rtype)
            return True
        except dns.exception.DNSException:
            continue
    return False


def _mx_hosts(name: str) -> List[str]:
    try:
        return [str(r.exchange).rstrip('.') for r in sorted(_resolver().resolve(name, 'MX'), key=lambda r: r.preference)]
    except dns.exception.DNSException:
        return []


def _dmarc(domain: str) -> Dict:
    """DMARC policy via the injectable TXT helper, validated by the existing DMARC validator."""
    records, _ = _txt(f'_dmarc.{domain}')
    record = next((r for r in records if r.lower().startswith('v=dmarc1')), None)
    if not record:
        return {'record_present': False, 'tags': {}, 'errors': ['No DMARC record is published.'], 'warnings': []}
    return validate_dmarc_record({'record': record})  # record only: no second DNS lookup


# --------------------------------------------------------------------------- SPF
def _spf_record(domain: str):
    records, err = _txt(domain)
    spf = [r for r in records if r.lower().startswith('v=spf1')]
    return spf, err


def analyze_spf(domain: str) -> Dict:
    """Recursively evaluate an SPF policy the way receivers count DNS lookups (RFC 7208 §4.6.4)."""
    domain = valid_domain(domain)
    state = {'lookups': 0, 'voids': 0, 'seen': set()}
    findings: List[Dict] = []

    def add(sev, msg):
        findings.append({'severity': sev, 'message': msg})

    def walk(name: str, depth: int) -> Dict:
        node = {'domain': name, 'record': None, 'mechanisms': [], 'children': []}
        records, err = _spf_record(name)
        if len(records) > 1:
            add('error', f'{name} publishes {len(records)} SPF records; receivers return permerror')
        if not records:
            if err == 'NXDOMAIN' or err is None:
                state['voids'] += 1
            node['error'] = 'No SPF record' if depth else None
            return node
        record = records[0]
        node['record'] = record
        if depth >= 10:
            add('error', 'SPF include chain is deeper than 10 levels')
            return node
        for term in record.split()[1:]:
            qual = term[0] if term[0] in '+-~?' else '+'
            body = term[1:] if term[0] in '+-~?' else term
            low = body.lower()
            mech = {'term': term}
            if low.startswith('redirect='):
                state['lookups'] += 1
                target = body.split('=', 1)[1]
                mech['type'] = 'redirect'
                node['mechanisms'].append(mech)
                _recurse(node, target, depth)
            elif low.startswith('include:'):
                state['lookups'] += 1
                mech['type'] = 'include'
                node['mechanisms'].append(mech)
                _recurse(node, body.split(':', 1)[1], depth)
            elif low == 'a' or low.startswith('a:') or low.startswith('a/'):
                state['lookups'] += 1
                mech['type'] = 'a'
                node['mechanisms'].append(mech)
                target = body.split(':', 1)[1].split('/')[0] if ':' in body else name
                if not _address_exists(target):
                    state['voids'] += 1
            elif low == 'mx' or low.startswith('mx:') or low.startswith('mx/'):
                state['lookups'] += 1
                mech['type'] = 'mx'
                node['mechanisms'].append(mech)
                target = body.split(':', 1)[1].split('/')[0] if ':' in body else name
                if not _mx_hosts(target):
                    state['voids'] += 1
            elif low.startswith('exists:'):
                state['lookups'] += 1
                mech['type'] = 'exists'
                node['mechanisms'].append(mech)
            elif low.startswith('ptr'):
                state['lookups'] += 1
                mech['type'] = 'ptr'
                node['mechanisms'].append(mech)
                add('warning', 'The "ptr" mechanism is deprecated (RFC 7208) and slow; replace it with ip4/ip6 or a')
            elif low.startswith(('ip4:', 'ip6:')):
                mech['type'] = low[:3]
                node['mechanisms'].append(mech)
            elif low == 'all':
                mech['type'] = 'all'
                mech['qualifier'] = qual
                node['mechanisms'].append(mech)
                if depth == 0:
                    node['all'] = qual
        return node

    def _recurse(node, target, depth):
        target = target.lower().rstrip('.')
        if '%' in target:  # macros are expanded per message; cannot be followed statically
            node['children'].append({'domain': target, 'record': None, 'mechanisms': [], 'children': [],
                                     'note': 'macro, not followed'})
            return
        if target in state['seen']:
            add('error', f'SPF loop: {target} is included more than once in the chain')
            return
        state['seen'].add(target)
        node['children'].append(walk(target, depth + 1))

    state['seen'].add(domain)
    tree = walk(domain, 0)
    if not tree['record']:
        return {'domain': domain, 'has_spf': False, 'lookups': 0, 'lookup_limit': SPF_LOOKUP_LIMIT,
                'findings': [{'severity': 'error', 'message': 'No SPF record is published'}], 'tree': tree,
                'status': 'missing'}
    total = state['lookups']
    if total > SPF_LOOKUP_LIMIT:
        add('error', f'{total} DNS lookups exceed the limit of {SPF_LOOKUP_LIMIT}: receivers return permerror and SPF fails')
    elif total >= 8:
        add('warning', f'{total} of {SPF_LOOKUP_LIMIT} allowed DNS lookups used; there is little room to add senders')
    if state['voids'] > SPF_VOID_LIMIT:
        add('error', f"{state['voids']} lookups returned no data (limit {SPF_VOID_LIMIT}); remove dead includes")
    all_q = tree.get('all')
    if all_q is None and not any(m.get('type') == 'redirect' for m in tree['mechanisms']):
        add('warning', 'No "all" mechanism or redirect: unlisted senders are treated as neutral')
    elif all_q == '+':
        add('error', '"+all" authorizes every sender on the internet')
    elif all_q == '?':
        add('warning', '"?all" (neutral) gives no protection; use "~all" or "-all"')
    elif all_q == '~':
        add('info', '"~all" (softfail) is acceptable while rolling out; "-all" is stricter')
    status = 'error' if any(f['severity'] == 'error' for f in findings) else (
        'warning' if any(f['severity'] == 'warning' for f in findings) else 'ok')
    return {'domain': domain, 'has_spf': True, 'record': tree['record'], 'lookups': total,
            'void_lookups': state['voids'], 'lookup_limit': SPF_LOOKUP_LIMIT, 'qualifier_all': all_q,
            'findings': findings, 'tree': tree, 'status': status}


# --------------------------------------------------------------------------- DKIM
def _key_info(p_value: str) -> Dict:
    p = re.sub(r'\s+', '', p_value or '')
    if not p:
        return {'revoked': True}
    try:
        key = serialization.load_der_public_key(base64.b64decode(p + '=' * (-len(p) % 4)))
    except Exception:
        return {'error': 'public key (p=) is not valid base64 DER'}
    if isinstance(key, rsa.RSAPublicKey):
        return {'type': 'rsa', 'bits': key.key_size}
    return {'type': type(key).__name__.replace('PublicKey', '').lower() or 'unknown'}


def _probe_selector(domain: str, selector: str) -> Optional[Dict]:
    name = f'{selector}._domainkey.{domain}'
    records, err = _txt(name)
    rec = next((r for r in records if 'p=' in r.replace(' ', '').lower() or r.lower().startswith('v=dkim1')), None)
    if rec is None:
        return None
    tags = _parse_tag_record(rec)
    info = _key_info(tags.get('p', ''))
    warnings = []
    if info.get('revoked'):
        warnings.append('Key is revoked (empty p=)')
    elif info.get('error'):
        warnings.append(info['error'])
    elif info.get('type') == 'rsa' and info['bits'] < 1024:
        warnings.append(f"RSA key of {info['bits']} bits is insecure")
    elif info.get('type') == 'rsa' and info['bits'] < 2048:
        warnings.append(f"RSA key of {info['bits']} bits is weak; use 2048 or more")
    if tags.get('t', '').lower() == 'y':
        warnings.append('Testing mode (t=y): receivers may ignore failures')
    return {'selector': selector, 'name': name, 'record': rec[:300], 'key': info, 'warnings': warnings}


def discover_dkim(domain: str, extra_selectors: Optional[List[str]] = None) -> Dict:
    domain = valid_domain(domain)
    selectors = list(COMMON_DKIM_SELECTORS)
    for s in extra_selectors or []:
        s = str(s).strip().lower()
        if re.fullmatch(r'[a-z0-9._-]{1,63}', s) and s not in selectors:
            selectors.insert(0, s)
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda s: _probe_selector(domain, s), selectors[:100]))
    found = [r for r in results if r]
    findings = []
    if not found:
        findings.append({'severity': 'warning', 'message': 'No DKIM key found for the common selectors. '
                         'Your provider may use a custom selector: pass it in "selectors" '
                         '(it is shown in the DKIM-Signature "s=" header of a sent message)'})
    for f in found:
        for w in f['warnings']:
            findings.append({'severity': 'warning', 'message': f"{f['selector']}: {w}"})
    return {'domain': domain, 'selectors_tried': len(selectors[:100]), 'found': found, 'findings': findings,
            'status': 'ok' if found and not any(f['warnings'] for f in found) else ('warning' if found else 'missing')}


# --------------------------------------------------------------------------- DMARC reports
def _read_limited(stream, limit=MAX_REPORT_BYTES) -> bytes:
    data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Report is larger than the 5 MB limit once decompressed')
    return data


def extract_report_xml(raw: bytes) -> str:
    """Accept plain XML, gzip or a zip (the three formats mail providers use)."""
    if raw[:2] == b'\x1f\x8b':
        raw = _read_limited(gzip.GzipFile(fileobj=io.BytesIO(raw)))
    elif raw[:4] == b'PK\x03\x04':
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                names = [n for n in z.namelist() if n.lower().endswith('.xml')]
                if not names:
                    raise ValueError('The zip archive contains no .xml report')
                info = z.getinfo(names[0])
                if info.file_size > MAX_REPORT_BYTES:
                    raise ValueError('Report is larger than the 5 MB limit once decompressed')
                raw = _read_limited(z.open(names[0]))
        except zipfile.BadZipFile:
            raise ValueError('Not a valid zip file')
    elif len(raw) > MAX_REPORT_BYTES:
        raise ValueError('Report is larger than the 5 MB limit')
    try:
        return raw.decode('utf-8')
    except UnicodeDecodeError:
        return raw.decode('latin-1')


def _t(node, path, default=None):
    found = node.find(path) if node is not None else None
    return found.text.strip() if found is not None and found.text and found.text.strip() else default


def parse_dmarc_report(xml_text: str) -> Dict:
    if '<!DOCTYPE' in xml_text.upper() or '<!ENTITY' in xml_text.upper():
        raise ValueError('Report XML must not contain a DTD or entity declarations')
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        raise ValueError('The report is not valid XML')
    if root.tag != 'feedback':
        raise ValueError('Not a DMARC aggregate report (no <feedback> root element)')
    meta = root.find('report_metadata')
    policy = root.find('policy_published')
    sources: Dict[str, Dict] = defaultdict(lambda: {'count': 0, 'pass': 0, 'dkim_pass': 0, 'spf_pass': 0,
                                                    'dispositions': Counter(), 'header_from': set(),
                                                    'dkim_domains': set(), 'spf_domains': set(), 'overrides': set()})
    total = passed = 0
    for rec in root.findall('record'):
        row = rec.find('row')
        ip = _t(row, 'source_ip', 'unknown')
        count = int(_t(row, 'count', '1') or 1)
        pe = row.find('policy_evaluated') if row is not None else None
        dkim, spf = _t(pe, 'dkim', 'fail'), _t(pe, 'spf', 'fail')
        s = sources[ip]
        s['count'] += count
        s['dkim_pass'] += count if dkim == 'pass' else 0
        s['spf_pass'] += count if spf == 'pass' else 0
        ok = dkim == 'pass' or spf == 'pass'  # DMARC passes when either aligned mechanism passes
        s['pass'] += count if ok else 0
        s['dispositions'][_t(pe, 'disposition', 'none')] += count
        s['header_from'].add(_t(rec.find('identifiers'), 'header_from', ''))
        for r in rec.findall('auth_results/dkim'):
            if _t(r, 'domain'):
                s['dkim_domains'].add(f"{_t(r, 'domain')} ({_t(r, 'result', '?')})")
        for r in rec.findall('auth_results/spf'):
            if _t(r, 'domain'):
                s['spf_domains'].add(f"{_t(r, 'domain')} ({_t(r, 'result', '?')})")
        for r in pe.findall('reason') if pe is not None else []:
            if _t(r, 'type'):
                s['overrides'].add(_t(r, 'type'))
        total += count
        passed += count if ok else 0
    rows = []
    for ip, s in sources.items():
        rows.append({'source_ip': ip, 'count': s['count'], 'pass_count': s['pass'], 'fail_count': s['count'] - s['pass'],
                     'dkim_pass': s['dkim_pass'], 'spf_pass': s['spf_pass'],
                     'dispositions': dict(s['dispositions']), 'header_from': sorted(x for x in s['header_from'] if x),
                     'dkim_domains': sorted(s['dkim_domains']), 'spf_domains': sorted(s['spf_domains']),
                     'overrides': sorted(s['overrides'])})
    rows.sort(key=lambda r: (-r['fail_count'], -r['count']))
    findings = []
    failing = [r for r in rows if r['fail_count']]
    if failing:
        findings.append({'severity': 'warning', 'message': f"{sum(r['fail_count'] for r in failing)} message(s) from "
                         f"{len(failing)} source(s) failed DMARC. Check whether they are legitimate senders that need SPF/DKIM."})
    return {
        'reporter': _t(meta, 'org_name'), 'report_id': _t(meta, 'report_id'),
        'date_begin': _t(meta, 'date_range/begin'), 'date_end': _t(meta, 'date_range/end'),
        'policy': {k: _t(policy, k) for k in ('domain', 'adkim', 'aspf', 'p', 'sp', 'pct') if _t(policy, k)},
        'total_messages': total, 'passed_messages': passed,
        'pass_rate': round(100 * passed / total, 1) if total else None,
        'sources': rows, 'findings': findings,
    }


def analyze_dmarc_report(params: Dict) -> Dict:
    if params.get('file_base64'):
        try:
            raw = base64.b64decode(params['file_base64'], validate=False)
        except Exception:
            raise ValueError('file_base64 is not valid base64')
        xml_text = extract_report_xml(raw)
    elif params.get('xml'):
        xml_text = extract_report_xml(params['xml'].encode('utf-8'))
    else:
        raise ValueError('Provide "xml" (report text) or "file_base64" (xml, .gz or .zip)')
    return parse_dmarc_report(xml_text)


# --------------------------------------------------------------------------- blocklists
def _reverse_ip(ip: str) -> str:
    return '.'.join(reversed(ip.split('.')))


def _query_rbl(zone: str, qname: str) -> Dict:
    try:
        answers = _resolver().resolve(f'{qname}.{zone}', 'A')
    except dns.resolver.NXDOMAIN:
        return {'list': zone, 'listed': False}
    except dns.exception.DNSException as e:
        return {'list': zone, 'listed': False, 'error': str(e) or type(e).__name__}
    codes = [str(a) for a in answers]
    if any(c in RBL_ERROR_CODES for c in codes):
        return {'list': zone, 'listed': False,
                'error': 'The list refused the query (public/open resolver blocked); set RBL_RESOLVERS to your own resolver'}
    txt = None
    try:
        txt = ' '.join(b''.join(r.strings).decode() for r in _resolver().resolve(f'{qname}.{zone}', 'TXT'))[:200]
    except dns.exception.DNSException:
        pass
    return {'list': zone, 'listed': True, 'codes': codes, 'reason': txt}


def check_blocklists(target: str) -> Dict:
    target = (target or '').strip().lower()
    try:
        ip = str(ipaddress.ip_address(target))
        is_ip = True
    except ValueError:
        is_ip = False
    ips: List[str] = []
    domain_checks: List[Dict] = []
    if is_ip:
        if ipaddress.ip_address(ip).version != 4:
            raise ValueError('Only IPv4 addresses can be checked against these blocklists')
        if not is_public_ip(ip):
            raise ValueError('Only public IP addresses can be checked')
        ips = [ip]
    else:
        domain = valid_domain(target)
        resolver = _resolver()
        hosts = [domain] + _mx_hosts(domain)[:4]
        for h in hosts:
            try:
                for a in resolver.resolve(h, 'A'):
                    if is_public_ip(str(a)) and str(a) not in ips:
                        ips.append(str(a))
            except dns.exception.DNSException:
                continue
        ips = ips[:6]
        with ThreadPoolExecutor(max_workers=6) as pool:
            domain_checks = list(pool.map(lambda z: _query_rbl(z, domain), DEFAULT_RBLS['domain']))
    zones = [z.strip() for z in os.environ.get('RBL_LISTS', '').split(',') if z.strip()] or DEFAULT_RBLS['ip']
    jobs = [(ip_, z) for ip_ in ips for z in zones]
    with ThreadPoolExecutor(max_workers=12) as pool:
        raw = list(pool.map(lambda j: {**_query_rbl(j[1], _reverse_ip(j[0])), 'ip': j[0]}, jobs))
    listed = [r for r in raw if r['listed']] + [dict(c, ip=None) for c in domain_checks if c['listed']]
    errors = [r for r in raw + domain_checks if r.get('error')]
    findings = [{'severity': 'error', 'message': f"{r.get('ip') or target} is listed on {r['list']}"
                 + (f": {r['reason']}" if r.get('reason') else '')} for r in listed]
    if errors:
        findings.append({'severity': 'info', 'message': f'{len(errors)} list(s) could not be queried reliably'})
    if not ips and not is_ip:
        findings.append({'severity': 'warning', 'message': 'The domain has no public A records to check'})
    return {'target': target, 'ips': ips, 'checked_lists': len(zones) * len(ips) + len(domain_checks),
            'listed': listed, 'results': raw + domain_checks, 'findings': findings,
            'status': 'listed' if listed else 'clean'}


# --------------------------------------------------------------------------- overview
def _mta_sts(domain: str) -> Dict:
    records, _ = _txt(f'_mta-sts.{domain}')
    rec = next((r for r in records if r.lower().startswith('v=stsv1')), None)
    result = {'dns_record': rec, 'policy': None}
    if rec:
        try:
            resp = safe_get(f'https://mta-sts.{domain}/.well-known/mta-sts.txt', timeout=6)
            if resp.status_code == 200:
                kv = {}
                for line in resp.text.splitlines():
                    if ':' in line:
                        k, v = line.split(':', 1)
                        kv.setdefault(k.strip().lower(), []).append(v.strip())
                result['policy'] = {'mode': (kv.get('mode') or [None])[0], 'mx': kv.get('mx', []),
                                    'max_age': (kv.get('max_age') or [None])[0]}
        except Exception:
            result['policy_error'] = 'The MTA-STS policy file could not be fetched'
    return result


def check_deliverability(domain: str) -> Dict:
    domain = valid_domain(domain)
    with ThreadPoolExecutor(max_workers=5) as pool:
        f_spf = pool.submit(analyze_spf, domain)
        f_dkim = pool.submit(discover_dkim, domain)
        f_dmarc = pool.submit(_dmarc, domain)
        f_mx = pool.submit(_mx_hosts, domain)
        f_sts = pool.submit(_mta_sts, domain)
        f_tls = pool.submit(_txt, f'_smtp._tls.{domain}')
        spf, dkim, dmarc, mx, sts = (f.result() for f in (f_spf, f_dkim, f_dmarc, f_mx, f_sts))
        tls_rpt = any(r.lower().startswith('v=tlsrptv1') for r in f_tls.result()[0])

    score, checks = 0, []

    def add(name, points, max_points, detail):
        nonlocal score
        score += points
        checks.append({'check': name, 'points': points, 'max_points': max_points, 'detail': detail})

    if mx:
        add('MX records', 10, 10, f'{len(mx)} mail server(s)')
    else:
        add('MX records', 0, 10, 'No MX records (the domain cannot receive mail)')
    spf_pts = 0 if not spf['has_spf'] else (30 if spf['status'] in ('ok',) else (22 if spf['status'] == 'warning' else 8))
    add('SPF', spf_pts, 30, 'Missing' if not spf['has_spf'] else f"{spf['lookups']}/10 lookups, all={spf.get('qualifier_all')}")
    add('DKIM', 20 if dkim['status'] == 'ok' else (12 if dkim['status'] == 'warning' else 0), 20,
        f"{len(dkim['found'])} key(s) found" if dkim['found'] else 'No key found for common selectors')
    pol = (dmarc.get('tags') or {}).get('p', '').lower() if dmarc.get('record_present') else None
    dmarc_pts = {None: 0, 'none': 12, 'quarantine': 24, 'reject': 30}.get(pol, 8)
    if dmarc.get('record_present') and not (dmarc.get('tags') or {}).get('rua'):
        dmarc_pts = max(dmarc_pts - 4, 0)
    add('DMARC', dmarc_pts, 30, 'Missing' if pol is None else f'p={pol}')
    transport = (6 if sts.get('policy') and sts['policy'].get('mode') == 'enforce' else (3 if sts.get('dns_record') else 0)) + (4 if tls_rpt else 0)
    add('Transport security (MTA-STS / TLS-RPT)', transport, 10,
        ', '.join(x for x in [f"MTA-STS {sts['policy']['mode']}" if sts.get('policy') else ('MTA-STS record only' if sts.get('dns_record') else ''),
                              'TLS-RPT' if tls_rpt else ''] if x) or 'Not configured')
    grade = 'A+' if score >= 95 else 'A' if score >= 85 else 'B' if score >= 70 else 'C' if score >= 55 else 'D' if score >= 40 else 'F'
    findings = list(spf['findings']) + list(dkim['findings'])
    findings += [{'severity': 'error', 'message': e} for e in dmarc.get('errors', [])]
    findings += [{'severity': 'warning', 'message': w} for w in dmarc.get('warnings', [])]
    if pol == 'none':
        findings.append({'severity': 'info', 'message': 'DMARC p=none only monitors; move to quarantine/reject once reports look clean'})
    return {'domain': domain, 'score': score, 'grade': grade, 'checks': checks, 'findings': findings,
            'mx': mx, 'spf': spf, 'dkim': dkim, 'dmarc': dmarc, 'mta_sts': sts, 'tls_rpt': tls_rpt}
