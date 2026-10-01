"""OpenAPI 3 spec generated from the Flask URL map, served with a bundled Swagger UI.

Summaries come from each view's docstring (or the endpoint name). Request bodies
for the most used endpoints are described in REQUEST_BODIES; everything else is
documented as a free-form JSON object.
"""
import re

from flask import Blueprint, current_app, jsonify
from flask_swagger_ui import get_swaggerui_blueprint

API_PREFIX = '/api'

_STR = {'type': 'string'}
_HOST = {'hostname': {'type': 'string', 'example': 'example.com'},
         'port': {'type': 'integer', 'default': 443}}

REQUEST_BODIES = {
    '/check/domain': {'required': ['hostname'], 'properties': {**_HOST, 'timeout': {'type': 'integer', 'default': 10}}},
    '/check/chain': {'required': ['hostname'], 'properties': {**_HOST, 'timeout': {'type': 'integer', 'default': 10}}},
    '/check/tls': {'required': ['hostname'], 'properties': {**_HOST, 'timeout': {'type': 'number', 'default': 5}}},
    '/check/headers': {'properties': {'url': {'type': 'string', 'example': 'https://example.com'}}},
    '/certificate/decode': {'required': ['certificate'], 'properties': {'certificate': {**_STR, 'description': 'PEM certificate'}}},
    '/csr/decode': {'required': ['csr'], 'properties': {'csr': {**_STR, 'description': 'PEM CSR'}}},
    '/monitor/domain/add': {'required': ['hostname'], 'properties': {
        **_HOST, 'label': _STR, 'tags': {'type': 'array', 'items': _STR}}},
    '/monitor/certificate/add': {'required': ['certificate'], 'properties': {
        'certificate': _STR, 'label': _STR, 'tags': {'type': 'array', 'items': _STR}}},
    '/dns/lookup': {'required': ['domain'], 'properties': {
        'domain': _STR, 'record_types': {'type': 'array', 'items': _STR, 'example': ['A', 'MX', 'TXT']}}},
    '/admin/apikey/generate': {'required': ['name'], 'properties': {
        'name': _STR, 'rate_limit': {**_STR, 'example': '200 per hour'}, 'description': _STR}},
}

TAGS = [
    ('certificate', 'Certificates'), ('csr', 'CSR'), ('key', 'Keys'), ('convert', 'Conversion'),
    ('check', 'Checks'), ('monitor', 'Monitoring'), ('batch', 'Batch'), ('admin', 'Admin'),
    ('dmarc', 'Email security'), ('spf', 'Email security'), ('dkim', 'Email security'),
    ('email', 'Email security'), ('dns', 'DNS'), ('upload', 'Uploads'), ('ssl-config', 'Config'),
]


def _tag_for(path: str) -> str:
    first = path.strip('/').split('/')[0]
    return dict(TAGS).get(first, 'General')


def build_spec(app) -> dict:
    paths = {}
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        if not rule.rule.startswith(API_PREFIX + '/') or rule.endpoint.startswith(('swagger', 'static')):
            continue
        view = app.view_functions[rule.endpoint]
        path = rule.rule[len(API_PREFIX):]
        oa_path = re.sub(r'<(?:[^:>]+:)?([^>]+)>', r'{\1}', path)
        doc = (view.__doc__ or '').strip().split('\n')[0] or rule.endpoint.split('.')[-1].replace('_', ' ')
        for method in sorted(rule.methods - {'HEAD', 'OPTIONS'}):
            op = {
                'summary': doc,
                'tags': [_tag_for(path)],
                'operationId': f"{rule.endpoint.split('.')[-1]}_{method.lower()}",
                'parameters': [{'name': a, 'in': 'path', 'required': True, 'schema': _STR} for a in rule.arguments],
                'responses': {'200': {'description': 'Success'},
                              '400': {'description': 'Invalid input'},
                              '429': {'description': 'Rate limit exceeded'}},
            }
            if method in ('POST', 'PUT', 'PATCH'):
                schema = {'type': 'object', **REQUEST_BODIES.get(path, {})}
                op['requestBody'] = {'content': {'application/json': {'schema': schema}}}
            if getattr(view, 'requires_admin', False):
                op['security'] = [{'adminToken': []}]
                op['responses']['401'] = {'description': 'Missing or invalid admin token'}
            paths.setdefault(oa_path, {})[method.lower()] = op
    return {
        'openapi': '3.0.3',
        'info': {'title': 'SSL Toolkit API', 'version': '1.0.0',
                 'description': 'Certificate, TLS, DNS and email-security tooling. '
                                'Send X-API-Key to rate-limit per key instead of per IP.'},
        'servers': [{'url': API_PREFIX}],
        'components': {'securitySchemes': {
            'adminToken': {'type': 'http', 'scheme': 'bearer', 'description': 'Value of the ADMIN_TOKEN env var'},
            'apiKey': {'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key'}}},
        'paths': paths,
    }


def register_docs(app):
    bp = Blueprint('openapi', __name__)

    @bp.route('/openapi.json')
    def openapi_json():
        """OpenAPI 3 specification"""
        return jsonify(build_spec(current_app))

    app.register_blueprint(bp, url_prefix=API_PREFIX)
    ui = get_swaggerui_blueprint(f'{API_PREFIX}/docs', f'{API_PREFIX}/openapi.json',
                                 config={'app_name': 'SSL Toolkit API'})
    app.register_blueprint(ui, url_prefix=f'{API_PREFIX}/docs')
