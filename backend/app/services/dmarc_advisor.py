"""DMARC policy ramp advisor: from merged aggregate reports to "is it safe to tighten the policy?".

DMARC enforcement is rolled out in steps (p=none, then quarantine with a growing pct, then reject).
Moving too early sends real mail to spam or bounces it; moving too late leaves the domain open to
spoofing. The advisor compares the data with conservative thresholds and names exactly what blocks
the next step. It never changes DNS: it produces the record to publish and explains why.

Mail from sources you tell it to ignore (spoofers, confirmed foreign senders) is excluded from the
numbers, because tightening the policy is precisely what should stop them.
"""
from typing import Dict, List, Optional, Sequence, Tuple

# (policy, pct) in rollout order
STAGES: List[Tuple[str, int]] = [
    ('none', 100), ('quarantine', 10), ('quarantine', 25), ('quarantine', 50), ('quarantine', 100),
    ('reject', 10), ('reject', 25), ('reject', 50), ('reject', 100),
]
MIN_MESSAGES = 200            # below this the data says little about real mail flows
FIRST_STEP_DAYS = 14          # watch p=none for two weeks before the first enforcement
LATER_STEP_DAYS = 7
BLOCKING_SHARE = 0.5          # a failing source above this share of the mail blocks the step (percent)


def _required_rate(target: Tuple[str, int]) -> float:
    if target[0] == 'quarantine' and target[1] == 10:
        return 98.0
    return 99.5 if target[0] == 'reject' else 99.0


def stage_index(policy: Dict) -> Optional[int]:
    p = (policy.get('p') or '').lower()
    try:
        pct = int(policy.get('pct') or 100)
    except ValueError:
        pct = 100
    if p == 'none':
        return 0
    if p not in ('quarantine', 'reject'):
        return None
    candidates = [i for i, (sp, spct) in enumerate(STAGES) if sp == p and spct >= pct]
    return candidates[0] if candidates else len(STAGES) - 1


def build_record(domain: str, stage: Tuple[str, int], base_record: Optional[str], published: Dict) -> Dict:
    """DMARC TXT record for `stage`, keeping every other tag of the current record."""
    tags: List[Tuple[str, str]] = []
    if base_record:
        for part in base_record.split(';'):
            if '=' in part:
                k, v = part.split('=', 1)
                tags.append((k.strip().lower(), v.strip()))
    else:
        tags = [('v', 'DMARC1')]
        for key in ('sp', 'adkim', 'aspf'):
            if published.get(key):
                tags.append((key, published[key]))
    tags = [(k, v) for k, v in tags if k not in ('p', 'pct')]
    out = [('v', 'DMARC1'), ('p', stage[0])]
    if stage[1] < 100:
        out.append(('pct', str(stage[1])))
    out += [(k, v) for k, v in tags if k != 'v']
    rua_assumed = not any(k == 'rua' for k, _ in out)
    if rua_assumed:
        out.append(('rua', f'mailto:dmarc-reports@{domain}'))
    return {'name': f'_dmarc.{domain}', 'value': '; '.join(f'{k}={v}' for k, v in out), 'rua_assumed': rua_assumed}


def advise_domain(domain: str, policy: Dict, stats: Dict, source_info: Dict[str, Dict], ignore: set,
                  base_record: Optional[str] = None) -> Dict:
    idx = stage_index(policy)
    pct_text = str(policy.get('pct') or '100')
    advice: Dict = {'domain': domain, 'current': {'p': policy.get('p'), 'pct': int(pct_text) if pct_text.isdigit() else 100},
                    'blockers': [], 'notes': []}
    if idx is None:
        advice.update(verdict='unknown', summary=f"The published policy p={policy.get('p')} is not recognised")
        return advice

    ignored = [s for s in stats['sources'] if s['source_ip'] in ignore]
    total = stats['total_messages'] - sum(s['count'] for s in ignored)
    passed = stats['passed_messages'] - sum(s['pass_count'] for s in ignored)
    rate = round(100 * passed / total, 2) if total else None
    days = len(stats['days'])
    advice['data'] = {'messages': total, 'pass_rate': rate, 'days': days, 'ignored_sources': [s['source_ip'] for s in ignored],
                      'ignored_messages': stats['total_messages'] - total}

    failing = sorted((s for s in stats['sources'] if s['source_ip'] not in ignore and s['fail_count'] > 0),
                     key=lambda s: -s['fail_count'])
    advice['failing_sources'] = [{
        'source_ip': s['source_ip'], 'ptr': (source_info.get(s['source_ip']) or {}).get('ptr'),
        'messages': s['count'], 'failed': s['fail_count'],
        'share': round(100 * s['fail_count'] / total, 2) if total else None,
        'status': (source_info.get(s['source_ip']) or {}).get('status'),
    } for s in failing[:10]]

    if idx == len(STAGES) - 1:
        advice.update(verdict='done', summary='The policy is already at p=reject; nothing to tighten.', next=None)
        if rate is not None and rate < 99:
            advice['blockers'].append(f'{100 - rate:.2f}% of the mail still fails DMARC and is being rejected: check the failing sources below for legitimate senders')
        return advice

    target = STAGES[idx + 1]
    advice['next'] = {'p': target[0], 'pct': target[1], 'required_pass_rate': _required_rate(target)}
    needed_days = FIRST_STEP_DAYS if idx == 0 else LATER_STEP_DAYS
    blockers: List[str] = advice['blockers']
    data_gaps = 0
    if days < needed_days:
        blockers.append(f'Only {days} day(s) of reports; collect at least {needed_days} before moving on')
        data_gaps += 1
    if total < MIN_MESSAGES:
        blockers.append(f'Only {total} message(s) in the reports; that is too little to tell whether all legitimate mail authenticates')
        data_gaps += 1
    if rate is not None and rate < _required_rate(target):
        blockers.append(f'{rate}% of the mail passes DMARC; {_required_rate(target)}% is needed for the next step')
    for s in advice['failing_sources']:
        if s['share'] is not None and s['share'] >= BLOCKING_SHARE:
            who = f" ({s['ptr']})" if s['ptr'] else ''
            blockers.append(f"{s['source_ip']}{who} fails {s['failed']} of {s['messages']} message(s) ({s['share']}% of all mail): "
                            'fix its SPF/DKIM if it is a legitimate sender, or add it to the ignore list if it is not yours')

    advice['verdict'] = 'ready' if not blockers else ('insufficient_data' if data_gaps == len(blockers) else 'not_ready')
    record = build_record(domain, target, base_record, policy)
    advice['next_record'] = record if advice['verdict'] == 'ready' else None
    advice['preview_record'] = record
    if record['rua_assumed']:
        advice['notes'].append('The record uses a placeholder report address (rua); replace it with your own, or pass your current record so it is kept')
    if idx >= 1:
        advice['notes'].append(f"If legitimate mail is affected, roll back to p={STAGES[idx][0]}" + (f"; pct={STAGES[idx][1]}" if STAGES[idx][1] < 100 else ''))
    advice['notes'].append('Keep each step for one to two weeks, then analyse the new reports again before the next step')
    advice['summary'] = (f"Ready for p={target[0]}" + (f"; pct={target[1]}" if target[1] < 100 else '') if advice['verdict'] == 'ready'
                         else f"Not ready for p={target[0]}" + (f"; pct={target[1]}" if target[1] < 100 else '') + f": {len(blockers)} thing(s) to resolve")
    return advice


def advise(analysis: Dict, ignore_ips: Optional[Sequence[str]] = None, current_records: Optional[Dict[str, str]] = None) -> Dict:
    """Advice per domain found in an analyze_dmarc_reports result."""
    ignore = {str(i).strip() for i in (ignore_ips or []) if str(i).strip()}
    current_records = {k.lower(): v for k, v in (current_records or {}).items() if isinstance(v, str)}
    info = {s['source_ip']: s for s in analysis['sources']}
    domains = []
    for domain, stats in sorted(analysis['by_domain'].items()):
        policy = analysis['policies'].get(domain)
        if not policy:
            continue
        domains.append(advise_domain(domain, policy, stats, info, ignore, current_records.get(domain)))
    return {'domains': domains, 'ignored': sorted(ignore)}
