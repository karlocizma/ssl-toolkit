"""Records state-changing requests and refused logins in the audit log (see services/audit_log.py)."""
import hmac
import os
from typing import Callable, Dict, Optional, Tuple

from flask import request

from app.services import audit_log

# (method, route without the /api prefix) -> (action, target(body, view_args, response) -> str, detail(...) -> dict)
Extractor = Callable[[Dict, Dict, Dict], object]


def _body_fields(*names):
    return lambda body, args, resp: {n: body.get(n) for n in names if body.get(n) is not None}


def _count(name):
    return lambda body, args, resp: {'count': len(body.get(name) or [])}


def _key_target(body, args, resp):
    from app.services.api_key_manager import key_preview
    return key_preview(body['api_key']) if isinstance(body.get('api_key'), str) else None


RULES: Dict[Tuple[str, str], Tuple[str, Extractor, Extractor]] = {
    ('POST', '/monitor/domain/add'): ('monitor.domain.add', lambda b, a, r: f"{b.get('hostname')}:{b.get('port', 443)}", _body_fields('label', 'tags')),
    ('POST', '/monitor/domain/add-bulk'): ('monitor.domain.add_bulk', lambda b, a, r: None, _count('hostnames')),
    ('POST', '/monitor/domain/import'): ('monitor.domain.import', lambda b, a, r: None, lambda b, a, r: {'added': r.get('added')}),
    ('DELETE', '/monitor/domain/<domain_id>'): ('monitor.domain.remove', lambda b, a, r: a.get('domain_id'), lambda b, a, r: {}),
    ('POST', '/monitor/domain/<domain_id>/check'): ('monitor.domain.check', lambda b, a, r: a.get('domain_id'), lambda b, a, r: {}),
    ('PATCH', '/monitor/domain/<domain_id>/public'): ('monitor.domain.publish', lambda b, a, r: a.get('domain_id'), _body_fields('public', 'name')),
    ('POST', '/share'): ('share.create', lambda b, a, r: (r.get('share') or {}).get('id'), lambda b, a, r: {'tool': b.get('tool'), 'title': b.get('title'), 'ttl_hours': b.get('ttl_hours')}),
    ('DELETE', '/share/<share_id>'): ('share.revoke', lambda b, a, r: a.get('share_id'), lambda b, a, r: {}),
    ('POST', '/monitor/certificate/add'): ('monitor.certificate.add', lambda b, a, r: r.get('certificate_id'), _body_fields('label', 'tags')),
    ('DELETE', '/monitor/certificate/remove/<certificate_id>'): ('monitor.certificate.remove', lambda b, a, r: a.get('certificate_id'), lambda b, a, r: {}),
    ('PATCH', '/monitor/certificate/<certificate_id>'): ('monitor.certificate.update', lambda b, a, r: a.get('certificate_id'),
                                                          lambda b, a, r: {'fields': sorted(k for k in b if k in ('label', 'tags'))}),
    ('GET', '/monitor/export'): ('monitor.export', lambda b, a, r: None, lambda b, a, r: {'format': request.args.get('format', 'json')}),
    ('POST', '/monitor/alerts/test'): ('alerts.test', lambda b, a, r: None, lambda b, a, r: {}),
    ('POST', '/monitor/alerts/run'): ('alerts.run', lambda b, a, r: None, lambda b, a, r: {}),
    ('POST', '/admin/apikey/generate'): ('apikey.generate', lambda b, a, r: b.get('name'), _body_fields('rate_limit', 'description')),
    ('POST', '/admin/apikey/revoke'): ('apikey.revoke', _key_target, lambda b, a, r: {}),
    ('DELETE', '/admin/apikey/delete'): ('apikey.delete', _key_target, lambda b, a, r: {}),
    ('GET', '/admin/audit/export'): ('audit.export', lambda b, a, r: None, lambda b, a, r: {'format': request.args.get('format', 'json')}),
}
PROTECTED_PREFIXES = ('/monitor/', '/admin/', '/share')


def client_ip() -> str:
    # Behind the bundled nginx, X-Real-IP is set by the proxy itself (clients cannot choose it).
    return (request.headers.get('X-Real-IP') or request.remote_addr or '')[:64]


def actor() -> Dict:
    admin = os.environ.get('ADMIN_TOKEN')
    bearer = request.headers.get('Authorization', '')
    token = request.headers.get('X-Access-Token', '')
    if admin and ((bearer.startswith('Bearer ') and hmac.compare_digest(bearer[7:], admin)) or (token and hmac.compare_digest(token, admin))):
        return {'type': 'admin'}
    if token:
        from app.services.api_key_manager import identify_api_key
        name = identify_api_key(token)
        if name:
            return {'type': 'api_key', 'id': name}
    return {'type': 'anonymous'}


def after_request(response):
    try:
        rule = request.url_rule.rule if request.url_rule else ''
        if not rule.startswith('/api'):
            return response
        path = rule[len('/api'):]
        status = response.status_code
        spec = RULES.get((request.method, path))
        denied = status in (401, 403) and (spec is not None or path.startswith(PROTECTED_PREFIXES))
        if not spec and not denied:
            return response
        if denied:
            audit_log.record('auth.denied', actor=actor(), ip=client_ip(), target=f'{request.method} {request.path}'[:200],
                             detail={'credentials_presented': bool(request.headers.get('Authorization') or request.headers.get('X-Access-Token'))},
                             result='denied', status=status)
            return response
        action, target_fn, detail_fn = spec
        body = request.get_json(silent=True) if request.is_json else None
        body = body if isinstance(body, dict) else {}
        resp_json = response.get_json(silent=True) if response.is_json else None
        resp_json = resp_json if isinstance(resp_json, dict) else {}
        args = request.view_args or {}
        audit_log.record(action, actor=actor(), ip=client_ip(), target=_safe(target_fn, body, args, resp_json),
                         detail=_safe(detail_fn, body, args, resp_json) or {}, result='success' if status < 400 else 'failed', status=status)
    except Exception:  # auditing must never break a request
        pass
    return response


def _safe(fn, body, args, resp) -> Optional[object]:
    try:
        return fn(body, args, resp)
    except Exception:
        return None
