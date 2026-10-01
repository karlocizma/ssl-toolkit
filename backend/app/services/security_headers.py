"""HTTP security-header audit with a 0-100 score."""
import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlsplit

from app.utils.net_safety import UnsafeTargetError, safe_get

MAX_REDIRECTS = 4


def fetch_headers(url: str):
    """Follow redirects manually so every hop is validated against the SSRF rules."""
    for _ in range(MAX_REDIRECTS + 1):
        resp = safe_get(url, timeout=10, read_body=False, headers={'User-Agent': 'ssl-toolkit/1.0'})
        if resp.is_redirect and resp.headers.get('Location'):
            url = urljoin(url, resp.headers['Location'])
            continue
        return resp, url
    raise ValueError('Too many redirects')


def _result(name, points, max_points, status, detail, value=None):
    return {'header': name, 'status': status, 'points': points, 'max_points': max_points,
            'detail': detail, 'value': value}


def check_hsts(value: Optional[str], is_https: bool) -> Dict:
    if not is_https:
        return _result('Strict-Transport-Security', 0, 20, 'fail', 'Site is not served over HTTPS')
    if not value:
        return _result('Strict-Transport-Security', 0, 20, 'fail', 'Header missing')
    m = re.search(r'max-age=(\d+)', value, re.I)
    max_age = int(m.group(1)) if m else 0
    if max_age < 15552000:
        return _result('Strict-Transport-Security', 8, 20, 'warn',
                       f'max-age {max_age} is below 6 months (15552000)', value)
    points = 14 + (3 if 'includesubdomains' in value.lower() else 0) + (3 if 'preload' in value.lower() else 0)
    detail = 'Good' if points == 20 else 'Consider includeSubDomains; preload'
    return _result('Strict-Transport-Security', points, 20, 'pass', detail, value)


def check_csp(value: Optional[str]) -> Dict:
    if not value:
        return _result('Content-Security-Policy', 0, 25, 'fail', 'Header missing')
    issues = []
    if "'unsafe-inline'" in value:
        issues.append("uses 'unsafe-inline'")
    if "'unsafe-eval'" in value:
        issues.append("uses 'unsafe-eval'")
    if re.search(r'(^|[;\s])(default|script)-src[^;]*\s\*(\s|;|$)', value):
        issues.append('wildcard source in default-src/script-src')
    if 'default-src' not in value and 'script-src' not in value:
        issues.append('no default-src or script-src')
    if issues:
        return _result('Content-Security-Policy', 12, 25, 'warn', '; '.join(issues), value)
    return _result('Content-Security-Policy', 25, 25, 'pass', 'Good', value)


def check_nosniff(value: Optional[str]) -> Dict:
    if value and value.strip().lower() == 'nosniff':
        return _result('X-Content-Type-Options', 10, 10, 'pass', 'Good', value)
    return _result('X-Content-Type-Options', 0, 10, 'fail', 'Should be "nosniff"', value)


def check_framing(xfo: Optional[str], csp: Optional[str]) -> Dict:
    if csp and 'frame-ancestors' in csp:
        return _result('X-Frame-Options / frame-ancestors', 10, 10, 'pass', 'CSP frame-ancestors set', csp)
    if xfo and xfo.strip().lower() in ('deny', 'sameorigin'):
        return _result('X-Frame-Options / frame-ancestors', 10, 10, 'pass', 'Good', xfo)
    return _result('X-Frame-Options / frame-ancestors', 0, 10, 'fail', 'Clickjacking protection missing', xfo)


def check_referrer(value: Optional[str]) -> Dict:
    safe = {'no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin',
            'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin'}
    if value and value.split(',')[-1].strip().lower() in safe:
        return _result('Referrer-Policy', 10, 10, 'pass', 'Good', value)
    if value:
        return _result('Referrer-Policy', 3, 10, 'warn', 'Policy may leak full URLs (e.g. unsafe-url)', value)
    return _result('Referrer-Policy', 0, 10, 'fail', 'Header missing')


def check_present(name: str, value: Optional[str], points: int) -> Dict:
    if value:
        return _result(name, points, points, 'pass', 'Present', value)
    return _result(name, 0, points, 'fail', 'Header missing')


def check_disclosure(headers: Dict[str, str]) -> Dict:
    leaks = []
    for name in ('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator'):
        value = headers.get(name.lower())
        if value and (re.search(r'\d+\.\d+', value) or name != 'Server'):
            leaks.append(f'{name}: {value}')
    if leaks:
        return _result('Information disclosure', 0, 5, 'warn', 'Reveals software/version: ' + ', '.join(leaks))
    return _result('Information disclosure', 5, 5, 'pass', 'No version information leaked')


def check_cookies(set_cookies: List[str], is_https: bool) -> Dict:
    if not set_cookies:
        return _result('Cookies', 5, 5, 'pass', 'No cookies set')
    problems = []
    for c in set_cookies:
        name, low = c.split('=', 1)[0], c.lower()
        missing = [attr for attr, ok in (('Secure', 'secure' in low and is_https),
                                         ('HttpOnly', 'httponly' in low),
                                         ('SameSite', 'samesite' in low)) if not ok]
        if missing:
            problems.append(f"{name} lacks {'/'.join(missing)}")
    if problems:
        return _result('Cookies', 1, 5, 'warn', '; '.join(problems))
    return _result('Cookies', 5, 5, 'pass', 'All cookies have Secure, HttpOnly and SameSite')


def grade_for(score: int) -> str:
    for threshold, grade in ((95, 'A+'), (85, 'A'), (70, 'B'), (55, 'C'), (40, 'D')):
        if score >= threshold:
            return grade
    return 'F'


def audit_headers(headers: Dict[str, str], set_cookies: List[str], is_https: bool) -> Dict:
    h = {k.lower(): v for k, v in headers.items()}
    def get(name):
        return h.get(name.lower())

    checks = [
        check_hsts(get('Strict-Transport-Security'), is_https),
        check_csp(get('Content-Security-Policy')),
        check_nosniff(get('X-Content-Type-Options')),
        check_framing(get('X-Frame-Options'), get('Content-Security-Policy')),
        check_referrer(get('Referrer-Policy')),
        check_present('Permissions-Policy', get('Permissions-Policy'), 5),
        check_present('Cross-Origin-Opener-Policy', get('Cross-Origin-Opener-Policy'), 5),
        check_disclosure(h),
        check_cookies(set_cookies, is_https),
    ]
    total = sum(c['max_points'] for c in checks)
    score = round(100 * sum(c['points'] for c in checks) / total)
    return {'score': score, 'grade': grade_for(score), 'checks': checks}


def check_security_headers(hostname_or_url: str) -> Dict:
    target = hostname_or_url.strip()
    if '://' not in target:
        target = f'https://{target}'
    if urlsplit(target).scheme not in ('http', 'https'):
        raise UnsafeTargetError('Only http(s) URLs are allowed')
    resp, final_url = fetch_headers(target)
    set_cookies = resp.raw.headers.getlist('Set-Cookie') if hasattr(resp.raw.headers, 'getlist') else []
    is_https = urlsplit(final_url).scheme == 'https'
    result = audit_headers(dict(resp.headers), set_cookies, is_https)
    result.update({'url': target, 'final_url': final_url, 'status_code': resp.status_code})
    return result
