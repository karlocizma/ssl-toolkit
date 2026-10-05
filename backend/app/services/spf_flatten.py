"""SPF flattening: replace include/a/mx mechanisms by the IP ranges they stand for.

SPF allows at most 10 DNS lookups. Many senders (Microsoft 365, Google, newsletter tools) each use
several, so a growing domain hits the limit and SPF fails with a permerror. Flattening resolves
everything once and publishes the addresses directly (ip4/ip6 cost no lookups), split over a few
helper records when they do not fit into one.

The catch, and the reason this only generates records and never publishes anything: providers
change their addresses. A flattened record is a snapshot and must be regenerated regularly.
"""
import ipaddress
from typing import Dict, List, Optional, Tuple

import dns.exception
import dns.resolver

from app.services.deliverability import SPF_LOOKUP_LIMIT, _mx_hosts, _resolver, _spf_record, analyze_spf, valid_domain

MAX_DEPTH = 10
MAX_NETWORKS = 2000
DEFAULT_RECORD_LENGTH = 450  # keeps each TXT answer inside one UDP packet


def _addresses(host: str) -> List[str]:
    found = []
    for rtype in ('A', 'AAAA'):
        try:
            found += [str(r) for r in _resolver().resolve(host, rtype)]
        except dns.exception.DNSException:
            continue
    return found


def _split_cidr(spec: str, default_name: str) -> Tuple[str, Optional[int], Optional[int]]:
    """'example.com/24//64' -> ('example.com', 24, 64); the host part is optional."""
    host_part, _, rest = spec.partition('/')
    v4 = v6 = None
    if rest or spec.endswith('/'):
        v4_text, _, v6_text = rest.partition('/')
        v6_text = v6_text.lstrip('/')
        v4 = int(v4_text) if v4_text.isdigit() else None
        v6 = int(v6_text) if v6_text.isdigit() else None
    return (host_part or default_name).lower().rstrip('.'), v4, v6


def _network(address: str, v4: Optional[int], v6: Optional[int]):
    ip = ipaddress.ip_address(address)
    prefix = v4 if ip.version == 4 else v6
    return ipaddress.ip_network(f'{ip}/{prefix}' if prefix is not None else ip, strict=False)


def flatten_spf(domain: str, max_record_length: int = DEFAULT_RECORD_LENGTH, keep: Optional[List[str]] = None) -> Dict:
    domain = valid_domain(domain)
    max_record_length = max(100, min(int(max_record_length), 2000))
    keep_names = {k.strip().lower().rstrip('.') for k in (keep or []) if k and k.strip()}
    records, _ = _spf_record(domain)
    if not records:
        raise ValueError(f'{domain} has no SPF record to flatten')
    if len(records) > 1:
        raise ValueError(f'{domain} publishes {len(records)} SPF records; fix that first (receivers return permerror)')

    warnings: List[str] = []
    networks: Dict[str, Dict] = {}  # network text -> {'net': obj, 'origin': str}
    kept: List[str] = []             # mechanisms that cannot or should not be flattened
    state = {'all': None, 'seen': {domain}, 'truncated': False}

    def add_network(net, origin: str):
        if len(networks) >= MAX_NETWORKS:
            state['truncated'] = True
            return
        networks.setdefault(str(net), {'net': net, 'origin': origin})

    def expand(name: str, record: str, depth: int, top: bool) -> None:
        for term in record.split()[1:]:
            qual = term[0] if term[0] in '+-~?' else '+'
            body = term[1:] if term[0] in '+-~?' else term
            low = body.lower()
            if low == 'all':
                if top:
                    state['all'] = qual
                continue
            if low.startswith(('exp=', 'v=')):
                continue
            if low.startswith('redirect='):
                target = body.split('=', 1)[1].lower().rstrip('.')
                if '%' in target:
                    kept.append(term)
                    warnings.append(f'redirect to {target} uses macros and was kept as is')
                elif target in state['seen']:
                    warnings.append(f'SPF loop at {target} skipped')
                else:
                    state['seen'].add(target)
                    sub, _ = _spf_record(target)
                    if sub and depth < MAX_DEPTH:
                        expand(target, sub[0], depth + 1, top)
                    else:
                        warnings.append(f'redirect target {target} has no usable SPF record')
                continue
            if qual != '+':
                if top:
                    kept.append(term)
                    warnings.append(f'"{term}" is kept as is: a qualifier other than + depends on mechanism order, which flattening changes')
                else:
                    warnings.append(f'"{term}" inside {name} is ignored: its negative result only affects that include')
                continue
            if low.startswith('include:'):
                target = body.split(':', 1)[1].lower().rstrip('.')
                if '%' in target or low.startswith('include:%'):
                    kept.append(term)
                    warnings.append(f'include {target} uses macros and was kept as is')
                elif target in keep_names:
                    kept.append(term)
                elif target in state['seen']:
                    warnings.append(f'SPF loop at {target} skipped')
                elif depth >= MAX_DEPTH:
                    warnings.append(f'include chain deeper than {MAX_DEPTH}: {target} skipped')
                else:
                    state['seen'].add(target)
                    sub, _ = _spf_record(target)
                    if not sub:
                        warnings.append(f'include {target} has no SPF record and was dropped')
                    else:
                        expand(target, sub[0], depth + 1, False)
            elif low.startswith(('ip4:', 'ip6:')):
                try:
                    add_network(ipaddress.ip_network(body.split(':', 1)[1], strict=False), name)
                except ValueError:
                    warnings.append(f'invalid address "{term}" in {name} skipped')
            elif low == 'a' or low.startswith(('a:', 'a/')):
                host, v4, v6 = _split_cidr(body[1:].lstrip(':') if body[1:2] == ':' else body[1:], name)
                for ip in _addresses(host):
                    add_network(_network(ip, v4, v6), f'a:{host}')
            elif low == 'mx' or low.startswith(('mx:', 'mx/')):
                host, v4, v6 = _split_cidr(body[2:].lstrip(':') if body[2:3] == ':' else body[2:], name)
                for mx in _mx_hosts(host):
                    for ip in _addresses(mx):
                        add_network(_network(ip, v4, v6), f'mx:{host}')
            elif low.startswith('exists:') or low.startswith('ptr'):
                kept.append(term)
                warnings.append(f'"{term}" cannot be flattened (it depends on the sender at delivery time) and was kept as is')

    expand(domain, records[0], 0, True)
    if state['truncated']:
        warnings.append(f'More than {MAX_NETWORKS} networks: the list was cut off, so the result is incomplete. Keep some includes instead')

    v4 = sorted((v['net'] for v in networks.values() if v['net'].version == 4), key=lambda n: (int(n.network_address), n.prefixlen))
    v6 = sorted((v['net'] for v in networks.values() if v['net'].version == 6), key=lambda n: (int(n.network_address), n.prefixlen))
    v4, v6 = list(ipaddress.collapse_addresses(v4)), list(ipaddress.collapse_addresses(v6))
    terms = [f"ip4:{n.network_address}" + (f'/{n.prefixlen}' if n.prefixlen != 32 else '') for n in v4] + \
            [f"ip6:{n.network_address}" + (f'/{n.prefixlen}' if n.prefixlen != 128 else '') for n in v6]
    tail = {'-': '-all', '~': '~all', '?': '?all', '+': '+all', None: '~all'}[state['all']]
    if state['all'] is None:
        warnings.append('The original record has no "all" mechanism; "~all" was used')
    if state['all'] == '+':
        warnings.append('"+all" authorizes every sender on the internet; fix this regardless of flattening')

    out = _pack(domain, kept, terms, tail, max_record_length)
    if out['lookups'] > SPF_LOOKUP_LIMIT:
        warnings.append(f"Even flattened this needs {out['lookups']} lookups (limit {SPF_LOOKUP_LIMIT}); keep fewer includes or reduce the sender list")
    before = analyze_spf(domain)
    return {
        'domain': domain, 'original_record': records[0], 'original_lookups': before.get('lookups'),
        'records': out['records'], 'lookups_after': out['lookups'], 'network_count': len(terms),
        'kept_mechanisms': kept, 'warnings': warnings,
        'sources': sorted({v['origin'] for v in networks.values()}),
        'notes': [
            'Providers change their sending addresses. A flattened record is a snapshot: regenerate it regularly (at least monthly) and compare.',
            'Publish the helper records first, then the main record, so the main record never points to something that does not exist yet.',
            'Records longer than 255 characters are stored as several quoted strings; most DNS providers do this for you.',
        ],
    }


def _join(parts: List[str]) -> str:
    return ' '.join(parts)


def _pack(domain: str, kept: List[str], terms: List[str], tail: str, limit: int) -> Dict:
    """Fit everything into the main record if possible, otherwise spread it over _spfN helper records."""
    single = _join(['v=spf1'] + kept + terms + [tail])
    def costs_lookup(term: str) -> bool:
        t = term.lower().lstrip('+-~?')
        return t in ('a', 'mx') or t.startswith(('include:', 'a:', 'a/', 'mx:', 'mx/', 'exists:', 'ptr', 'redirect='))

    kept_lookups = sum(1 for k in kept if costs_lookup(k))
    if len(single) <= limit:
        return {'records': [{'name': domain, 'type': 'TXT', 'value': single, 'length': len(single)}], 'lookups': kept_lookups}

    chunks: List[List[str]] = []
    current: List[str] = []
    overhead = len('v=spf1  ?all')
    for term in terms:
        if current and overhead + len(_join(current)) + 1 + len(term) > limit:
            chunks.append(current)
            current = []
        current.append(term)
    if current:
        chunks.append(current)
    names = [f'_spf{i + 1}.{domain}' for i in range(len(chunks))]
    helpers = [{'name': n, 'type': 'TXT', 'value': _join(['v=spf1'] + c + ['?all']), 'length': 0} for n, c in zip(names, chunks)]
    main_value = _join(['v=spf1'] + kept + [f'include:{n}' for n in names] + [tail])
    records = [{'name': domain, 'type': 'TXT', 'value': main_value, 'length': len(main_value)}] + helpers
    for r in records:
        r['length'] = len(r['value'])
    return {'records': records, 'lookups': kept_lookups + len(names)}
