"""Command line interface for CI pipelines and quick checks.

    python -m app.cli check example.com --fail-under 14
    python -m app.cli tls example.com:8443 --min-grade B
    python -m app.cli headers https://example.com --min-score 70
    python -m app.cli email example.com --min-score 70
    python -m app.cli chain example.com
    python -m app.cli ct example.com --expected-issuer "Let's Encrypt"
    python -m app.cli autodiscover example.com

Exit codes: 0 = all checks passed, 1 = a threshold was not met, 2 = usage error or the check could not run.
Add --json for machine-readable output. Private/internal hosts are allowed unless ALLOW_PRIVATE_TARGETS=false.
"""
import argparse
import json
import os
import sys
from typing import Callable, Dict, List, Tuple

# The CLI runs under the user's own account, so the SSRF restriction that protects the web API is off by default.
os.environ.setdefault('ALLOW_PRIVATE_TARGETS', 'true')

GRADE_RANK = ['A+', 'A', 'A-', 'B', 'C', 'D', 'F']
EXIT_OK, EXIT_FAIL, EXIT_ERROR = 0, 1, 2


def split_host(value: str, default_port: int = 443) -> Tuple[str, int]:
    value = value.strip()
    for prefix in ('https://', 'http://'):
        if value.lower().startswith(prefix):
            value = value[len(prefix):]
    value = value.split('/')[0]
    if value.count(':') == 1:
        host, port = value.rsplit(':', 1)
        if port.isdigit():
            return host, int(port)
    return value, default_port


def grade_at_least(grade: str, minimum: str) -> bool:
    if grade not in GRADE_RANK or minimum not in GRADE_RANK:
        return False
    return GRADE_RANK.index(grade) <= GRADE_RANK.index(minimum)


# Each command returns (passed, summary lines, raw result).
def cmd_check(args, target: str):
    from app.services.ssl_checker import check_ssl_certificate
    host, port = split_host(target, args.port)
    r = check_ssl_certificate(host, port, args.timeout)
    if not r.get('connection_secure'):
        return False, [f"FAIL  {host}:{port}  {'; '.join(r.get('errors', [])) or 'connection failed'}"], r
    days = r['certificate']['validity']['days_until_expiry']
    issuer = r['certificate']['issuer'].get('common_name')
    ok = days >= args.fail_under and r.get('valid_for_hostname', True)
    notes = [] if r.get('valid_for_hostname', True) else ['hostname does not match the certificate']
    line = f"{'OK  ' if ok else 'FAIL'}  {host}:{port}  expires in {days} day(s) (threshold {args.fail_under}), issuer {issuer}"
    return ok, [line + ('  ' + '; '.join(notes) if notes else '')], r


def cmd_tls(args, target: str):
    from app.services.tls_scanner import scan_tls
    host, port = split_host(target, args.port)
    r = scan_tls(host, port, args.timeout)
    if not r.get('reachable'):
        return False, [f"FAIL  {host}:{port}  {r.get('error')}"], r
    ok = grade_at_least(r['grade'], args.min_grade)
    lines = [f"{'OK  ' if ok else 'FAIL'}  {host}:{port}  grade {r['grade']} (minimum {args.min_grade})"]
    lines += [f"      {f['severity']}: {f['message']}" for f in r['findings']]
    return ok, lines, r


def cmd_mailtls(args, target: str):
    from app.services.mail_tls import scan_mail, scan_mail_domain
    if args.port is None and '.' in target and ':' not in target and not args.host:
        r = scan_mail_domain(target, args.timeout)
        graded = r['grade']
        ok = bool(graded) and grade_at_least(graded, args.min_grade)
        lines = [f"{'OK  ' if ok else 'FAIL'}  {r['domain']}  {len(r['mx'])} MX host(s), worst grade {graded or '-'} (minimum {args.min_grade})"]
        lines += [f"      {f['severity']}: {f['message']}" for f in r['findings']]
        return ok, lines, r
    host, port = split_host(target, args.port or 25)
    r = scan_mail(host, port, args.protocol, args.mode, args.timeout)
    if not r.get('reachable'):
        return False, [f"FAIL  {host}:{port}  {r.get('error')}"], r
    ok = grade_at_least(r['grade'], args.min_grade)
    lines = [f"{'OK  ' if ok else 'FAIL'}  {host}:{port}  {r['protocol']}/{r['mode']}  grade {r['grade']} (minimum {args.min_grade})"]
    lines += [f"      {f['severity']}: {f['message']}" for f in r['findings']]
    return ok, lines, r


def cmd_headers(args, target: str):
    from app.services.security_headers import check_security_headers
    r = check_security_headers(target)
    ok = r['score'] >= args.min_score
    lines = [f"{'OK  ' if ok else 'FAIL'}  {target}  score {r['score']}/100 grade {r['grade']} (minimum {args.min_score})"]
    lines += [f"      {c['status']}: {c['header']}: {c['detail']}" for c in r['checks'] if c['status'] != 'pass']
    return ok, lines, r


def cmd_email(args, target: str):
    from app.services.deliverability import check_deliverability
    r = check_deliverability(target)
    ok = r['score'] >= args.min_score
    lines = [f"{'OK  ' if ok else 'FAIL'}  {r['domain']}  score {r['score']}/100 grade {r['grade']} (minimum {args.min_score})"]
    lines += [f"      {f['severity']}: {f['message']}" for f in r['findings'] if f['severity'] != 'info']
    return ok, lines, r


def cmd_chain(args, target: str):
    from app.services.chain_builder import run
    host, port = split_host(target, args.port)
    r = run({'hostname': host, 'port': port})
    ok = r['complete'] and not any(f['severity'] == 'error' for f in r['findings'])
    lines = [f"{'OK  ' if ok else 'FAIL'}  {host}:{port}  chain {'complete' if r['complete'] else 'INCOMPLETE'}, "
             f"{len(r['chain'])} certificate(s)"]
    lines += [f"      {f['severity']}: {f['message']}" for f in r['findings'] if f['severity'] != 'info']
    return ok, lines, r


def cmd_ct(args, target: str):
    from app.services.ct_lookup import lookup
    r = lookup(target, expected_issuers=args.expected_issuer)
    warnings = [f for f in r['findings'] if f['severity'] == 'warning']
    ok = not warnings
    lines = [f"{'OK  ' if ok else 'FAIL'}  {r['domain']}  {r['total_certificates']} certificate(s), "
             f"{len(r['subdomains'])} hostname(s), {r['active_certificates']} active"]
    lines += [f"      warning: {f['message']}" for f in warnings]
    return ok, lines, r


def cmd_autodiscover(args, target: str):
    from app.services.autodiscover import check_autodiscover
    r = check_autodiscover(target)
    ok = r['status'] == 'ok'
    lines = [f"{'OK  ' if ok else 'FAIL'}  {r['domain']}  autodiscover {r['status']}"]
    lines += [f"      {f['severity']}: {f['message']}" for f in r['findings'] if f['severity'] != 'info']
    return ok, lines, r


COMMANDS: Dict[str, Tuple[Callable, str]] = {
    'check': (cmd_check, 'certificate expiry and hostname match'),
    'tls': (cmd_tls, 'TLS protocol/cipher grade'),
    'mailtls': (cmd_mailtls, 'mail server STARTTLS/TLS grade (domain = all MX hosts)'),
    'headers': (cmd_headers, 'HTTP security headers score'),
    'email': (cmd_email, 'email authentication score (SPF/DKIM/DMARC/MTA-STS)'),
    'chain': (cmd_chain, 'certificate chain completeness'),
    'ct': (cmd_ct, 'Certificate Transparency: unexpected CAs'),
    'autodiscover': (cmd_autodiscover, 'mail client auto-configuration'),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='ssl-toolkit', description=__doc__.split('\n\n')[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog='Exit codes: 0 pass, 1 threshold not met, 2 usage error / check could not run.')
    sub = parser.add_subparsers(dest='command', required=True)
    for name, (_, helptext) in COMMANDS.items():
        p = sub.add_parser(name, help=helptext)
        p.add_argument('targets', nargs='+', help='host, host:port or domain (several allowed)')
        p.add_argument('--json', action='store_true', help='print the full result as JSON')
        if name in ('check', 'tls', 'chain'):
            p.add_argument('--port', type=int, default=443)
            p.add_argument('--timeout', type=int, default=10 if name != 'tls' else 5)
        if name == 'check':
            p.add_argument('--fail-under', type=int, default=14, metavar='DAYS',
                           help='fail when the certificate expires in fewer days (default 14)')
        if name == 'mailtls':
            p.add_argument('--port', type=int, default=None, help='default 25 (domain mode tests every MX on 25)')
            p.add_argument('--protocol', choices=['smtp', 'imap', 'pop3'], default=None)
            p.add_argument('--mode', choices=['starttls', 'implicit'], default=None)
            p.add_argument('--host', action='store_true', help='treat the target as a single host, not a domain')
            p.add_argument('--timeout', type=int, default=6)
            p.add_argument('--min-grade', default='B', choices=GRADE_RANK, help='lowest acceptable grade (default B)')
        if name == 'tls':
            p.add_argument('--min-grade', default='B', choices=GRADE_RANK, help='lowest acceptable grade (default B)')
        if name in ('headers', 'email'):
            p.add_argument('--min-score', type=int, default=70, help='lowest acceptable score (default 70)')
        if name == 'ct':
            p.add_argument('--expected-issuer', action='append', default=[], metavar='CA',
                           help='flag certificates from any other CA (repeatable)')
    return parser


def main(argv: List[str] = None) -> int:
    args = build_parser().parse_args(argv)
    func = COMMANDS[args.command][0]
    exit_code, results = EXIT_OK, []
    for target in args.targets:
        try:
            ok, lines, raw = func(args, target)
        except Exception as e:  # ValueError for bad input, ChainError, CTLookupError, network errors...
            ok, lines, raw = None, [f'ERROR {target}  {type(e).__name__}: {e}'], {'error': str(e)}
        if ok is None:
            exit_code = EXIT_ERROR
        elif not ok and exit_code != EXIT_ERROR:
            exit_code = EXIT_FAIL
        results.append({'target': target, 'passed': ok, 'result': raw})
        if not args.json:
            print('\n'.join(lines))
    if args.json:
        print(json.dumps({'command': args.command, 'exit_code': exit_code, 'results': results}, indent=2, default=str))
    return exit_code


if __name__ == '__main__':
    sys.exit(main())
