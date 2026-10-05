"""DMARC aggregate reports in bulk: merge many reports into one picture.

A single report shows one provider's view of one day. Mail providers send one per domain per day,
so the useful questions (which sources send as my domain, do they authenticate, is it safe to
tighten the policy?) need all of them together. Nothing is stored: the files are processed in
memory and only the summary is returned.
"""
import base64
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Dict, List, Optional

import dns.exception
import dns.resolver
import dns.reversename

from app.services.deliverability import _resolver, extract_report_xml, parse_dmarc_report

MAX_FILES = 100
MAX_TOTAL_BYTES = 25 * 1024 * 1024
PTR_LOOKUPS = 15  # top sources only: reverse DNS is slow and only matters for the biggest senders
AUTHENTICATED_RATE = 99.0  # a source at or above this is treated as properly authenticated


def _epoch_day(value: Optional[str]) -> Optional[str]:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).date().isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _iso(value: Optional[str]) -> Optional[str]:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _ptr(ip: str) -> Optional[str]:
    try:
        resolver = _resolver()
        resolver.lifetime = resolver.timeout = 3
        answer = resolver.resolve(dns.reversename.from_address(ip), 'PTR')
        return str(answer[0]).rstrip('.')
    except (dns.exception.DNSException, ValueError):
        return None


def _decode(item: Dict) -> bytes:
    if item.get('file_base64'):
        try:
            return base64.b64decode(item['file_base64'], validate=False)
        except Exception:
            raise ValueError('not valid base64')
    if item.get('xml'):
        return str(item['xml']).encode('utf-8')
    raise ValueError('neither xml nor file_base64 given')


def _classify(source: Dict) -> str:
    rate = 100 * source['pass'] / source['count'] if source['count'] else 0
    if rate >= AUTHENTICATED_RATE:
        return 'authenticated'
    return 'failing' if source['pass'] == 0 else 'partial'


def analyze_dmarc_reports(items: List[Dict], lookup_ptr: bool = True) -> Dict:
    if not isinstance(items, list) or not items:
        raise ValueError('Provide a non-empty "files" list')
    if len(items) > MAX_FILES:
        raise ValueError(f'At most {MAX_FILES} reports can be analysed at once')

    reports, errors, seen, duplicates, total_bytes = [], [], set(), 0, 0
    for i, item in enumerate(items):
        name = str((item or {}).get('name') or f'report {i + 1}')[:120]
        try:
            raw = _decode(item or {})
            total_bytes += len(raw)
            if total_bytes > MAX_TOTAL_BYTES:
                raise ValueError('the combined size of the reports exceeds 25 MB')
            report = parse_dmarc_report(extract_report_xml(raw))
        except ValueError as e:
            errors.append({'file': name, 'error': str(e)})
            continue
        key = (report['reporter'], report['report_id'])
        if report['report_id'] and key in seen:
            duplicates += 1
            continue
        seen.add(key)
        report['file'] = name
        reports.append(report)
    if not reports:
        raise ValueError('None of the files is a readable DMARC aggregate report' +
                         (f" (first problem: {errors[0]['file']}: {errors[0]['error']})" if errors else ''))

    sources: Dict[str, Dict] = defaultdict(lambda: {
        'count': 0, 'pass': 0, 'dkim_pass': 0, 'spf_pass': 0, 'dispositions': Counter(), 'header_from': set(),
        'dkim_domains': set(), 'spf_domains': set(), 'overrides': set(), 'reporters': set()})
    daily: Dict[str, Dict] = defaultdict(lambda: {'total': 0, 'pass': 0})
    reporters: Dict[str, Dict] = defaultdict(lambda: {'reports': 0, 'messages': 0})
    policies: Dict[str, Dict] = {}
    by_domain: Dict[str, Dict] = defaultdict(lambda: {'total': 0, 'pass': 0, 'days': set(), 'sources': defaultdict(lambda: {'count': 0, 'pass': 0})})
    begins, ends = [], []
    totals = Counter()

    for r in reports:
        name = r['reporter'] or 'unknown'
        reporters[name]['reports'] += 1
        reporters[name]['messages'] += r['total_messages']
        day = _epoch_day(r['date_begin'])
        if day:
            daily[day]['total'] += r['total_messages']
            daily[day]['pass'] += r['passed_messages']
        for stamp, bucket in ((r['date_begin'], begins), (r['date_end'], ends)):
            if stamp and str(stamp).isdigit():
                bucket.append(int(stamp))
        pdom = (r['policy'] or {}).get('domain')
        dom = by_domain[pdom or 'unknown']
        dom['total'] += r['total_messages']
        dom['pass'] += r['passed_messages']
        if day:
            dom['days'].add(day)
        for s in r['sources']:
            dom['sources'][s['source_ip']]['count'] += s['count']
            dom['sources'][s['source_ip']]['pass'] += s['pass_count']
        if pdom and (pdom not in policies or int(r['date_begin'] or 0) >= policies[pdom]['_at']):
            policies[pdom] = {**r['policy'], '_at': int(r['date_begin'] or 0)}
        for s in r['sources']:
            m = sources[s['source_ip']]
            m['count'] += s['count']
            m['pass'] += s['pass_count']
            m['dkim_pass'] += s['dkim_pass']
            m['spf_pass'] += s['spf_pass']
            m['dispositions'].update(s['dispositions'])
            m['header_from'].update(s['header_from'])
            m['dkim_domains'].update(s['dkim_domains'])
            m['spf_domains'].update(s['spf_domains'])
            m['overrides'].update(s['overrides'])
            m['reporters'].add(name)
            totals['messages'] += s['count']
            totals['pass'] += s['pass_count']
            totals['dkim_pass'] += s['dkim_pass']
            totals['spf_pass'] += s['spf_pass']
            for disp, n in s['dispositions'].items():
                totals['disposition_' + disp] += n

    merged = []
    for ip, m in sources.items():
        row = {'source_ip': ip, 'count': m['count'], 'pass_count': m['pass'], 'fail_count': m['count'] - m['pass'],
               'pass_rate': round(100 * m['pass'] / m['count'], 1) if m['count'] else None,
               'dkim_pass': m['dkim_pass'], 'spf_pass': m['spf_pass'],
               'dispositions': dict(m['dispositions']), 'header_from': sorted(x for x in m['header_from'] if x),
               'dkim_domains': sorted(m['dkim_domains'])[:5], 'spf_domains': sorted(m['spf_domains'])[:5],
               'overrides': sorted(m['overrides']), 'reporters': sorted(m['reporters']), 'ptr': None}
        row['status'] = _classify(m)
        merged.append(row)
    merged.sort(key=lambda r: -r['count'])
    if lookup_ptr:
        top = [r for r in merged[:PTR_LOOKUPS] if r['source_ip'] != 'unknown']
        with ThreadPoolExecutor(max_workers=8) as pool:
            for row, ptr in zip(top, pool.map(lambda r: _ptr(r['source_ip']), top)):
                row['ptr'] = ptr

    messages = totals['messages']
    pass_rate = round(100 * totals['pass'] / messages, 2) if messages else None
    findings = _findings(merged, messages)
    for p in policies.values():
        p.pop('_at', None)
    return {
        'reports': len(reports), 'duplicates_skipped': duplicates, 'errors': errors,
        'period': {'start': _iso(min(begins)) if begins else None, 'end': _iso(max(ends)) if ends else None},
        'domains': sorted(policies), 'policies': policies,
        'total_messages': messages, 'passed_messages': totals['pass'], 'pass_rate': pass_rate,
        'dkim_aligned_pass': totals['dkim_pass'], 'spf_aligned_pass': totals['spf_pass'],
        'dispositions': {k[len('disposition_'):]: v for k, v in totals.items() if k.startswith('disposition_')},
        'daily': [{'date': d, **v, 'pass_rate': round(100 * v['pass'] / v['total'], 1) if v['total'] else None}
                  for d, v in sorted(daily.items())],
        'reporters': sorted(({'name': k, **v} for k, v in reporters.items()), key=lambda x: -x['messages']),
        'by_domain': {d: {'total_messages': v['total'], 'passed_messages': v['pass'], 'days': sorted(v['days']),
                          'sources': [{'source_ip': ip, 'count': s['count'], 'pass_count': s['pass'],
                                       'fail_count': s['count'] - s['pass']} for ip, s in v['sources'].items()]}
                      for d, v in by_domain.items()},
        'sources': merged, 'findings': findings,
    }


def _findings(sources: List[Dict], messages: int) -> List[Dict]:
    findings: List[Dict] = []
    if not messages:
        return [{'severity': 'info', 'message': 'The reports contain no messages'}]
    failing = [s for s in sources if s['status'] == 'failing']
    partial = [s for s in sources if s['status'] == 'partial']
    for s in failing[:5]:
        who = f" ({s['ptr']})" if s.get('ptr') else ''
        findings.append({'severity': 'warning' if s['count'] / messages >= 0.01 else 'info',
                         'message': f"{s['source_ip']}{who} sent {s['count']} message(s) as your domain and none passed DMARC: "
                                    'either an unauthorised sender (spoofing) or a legitimate service that needs SPF/DKIM set up'})
    if len(failing) > 5:
        findings.append({'severity': 'info', 'message': f'{len(failing) - 5} more source(s) failed DMARC entirely'})
    for s in partial[:3]:
        findings.append({'severity': 'warning', 'message': f"{s['source_ip']} passes only {s['pass_rate']}% of its {s['count']} message(s): "
                                                           'an unstable setup (for example DKIM key rotation, or forwarding that breaks SPF)'})
    fragile = [s for s in sources if s['status'] == 'authenticated' and s['dkim_pass'] == 0 and s['spf_pass'] > 0 and s['count'] >= 10]
    for s in fragile[:3]:
        findings.append({'severity': 'info', 'message': f"{s['source_ip']} passes through SPF only; add DKIM signing so mail "
                                                        'still passes when it is forwarded'})
    return findings
