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
    '/email/mta-sts': {'required': ['domain'], 'properties': {
        'domain': {**_STR, 'example': 'example.com'},
        'verify_mx': {'type': 'boolean', 'default': False, 'description': 'Also test STARTTLS and certificates of the MX hosts'}}},
    '/email/mta-sts/generate': {'required': ['domain'], 'properties': {
        'domain': {**_STR, 'example': 'example.com'}, 'mode': {'type': 'string', 'enum': ['testing', 'enforce', 'none'], 'default': 'testing'},
        'mx': {'type': 'array', 'items': _STR, 'description': 'Defaults to the domain\'s MX records'},
        'max_age': {'type': 'integer', 'default': 604800}}},
    '/email/tls-rpt': {'required': ['domain'], 'properties': {'domain': {**_STR, 'example': 'example.com'}}},
    '/email/tls-rpt/generate': {'required': ['domain', 'rua'], 'properties': {
        'domain': {**_STR, 'example': 'example.com'}, 'rua': {'type': 'array', 'items': _STR, 'example': ['tlsrpt@example.com']}}},
    '/email/tls-rpt/report': {'properties': {
        'json': {**_STR, 'description': 'Report JSON text'},
        'file_base64': {**_STR, 'description': 'Base64 of the report (.json or .json.gz)'}}},
    '/check/domain-registration': {'required': ['domain'], 'properties': {
        'domain': {**_STR, 'example': 'example.com', 'description': 'Registered domain (sub-domains are reduced to it)'}}},
    '/check/mail-tls': {'properties': {
        'host': {**_STR, 'example': 'mail.example.com', 'description': 'Mail server (use this or domain)'},
        'domain': {**_STR, 'example': 'example.com', 'description': 'Test every MX host of the domain on port 25'},
        'port': {'type': 'integer', 'default': 25},
        'protocol': {'type': 'string', 'enum': ['smtp', 'imap', 'pop3'], 'description': 'Defaults from the port'},
        'mode': {'type': 'string', 'enum': ['starttls', 'implicit'], 'description': 'Defaults from the port'},
        'deep': {'type': 'boolean', 'default': False, 'description': 'Enumerate every cipher (many connections)'}}},
    '/check/autodiscover': {'properties': {
        'domain': {**_STR, 'example': 'example.com'},
        'email': {**_STR, 'description': 'Optional mailbox to test with (defaults to test@<domain>)'}}},
    '/email/deliverability': {'required': ['domain'], 'properties': {'domain': {**_STR, 'example': 'example.com'}}},
    '/email/spf/analyze': {'required': ['domain'], 'properties': {'domain': {**_STR, 'example': 'example.com'}}},
    '/email/dkim/discover': {'required': ['domain'], 'properties': {
        'domain': _STR, 'selectors': {'type': 'array', 'items': _STR, 'description': 'Extra selectors to try'}}},
    '/email/dmarc/report': {'properties': {
        'xml': {**_STR, 'description': 'Report XML text'},
        'file_base64': {**_STR, 'description': 'Report file (xml, .gz or .zip), base64 encoded'}}},
    '/email/blocklist': {'required': ['target'], 'properties': {
        'target': {**_STR, 'description': 'IPv4 address or a domain (its A and MX hosts are checked)'}}},
    '/ct/lookup': {'required': ['domain'], 'properties': {
        'domain': {**_STR, 'example': 'example.com'}, 'include_expired': {'type': 'boolean', 'default': True},
        'expected_issuers': {'type': 'array', 'items': _STR, 'description': "Flag certificates from other CAs, e.g. [\"Let's Encrypt\"]"}}},
    '/monitor/domain/add-bulk': {'required': ['hostnames'], 'properties': {
        'hostnames': {'type': 'array', 'items': _STR}, 'port': {'type': 'integer', 'default': 443},
        'tags': {'type': 'array', 'items': _STR}}},
    '/monitor/domain/import': {'required': ['csv'], 'properties': {
        'csv': {**_STR, 'description': 'One host per line: hostname[,port[,label[,tags]]]'}}},
    '/chain/build': {'properties': {
        'certificate': {**_STR, 'description': 'Leaf certificate or a (possibly incomplete or mis-ordered) PEM bundle'},
        'hostname': {**_STR, 'description': 'Alternatively: fetch and repair the chain a server presents'},
        'port': {'type': 'integer', 'default': 443}, 'include_root': {'type': 'boolean', 'default': False}}},
    '/check/headers': {'properties': {'url': {'type': 'string', 'example': 'https://example.com'}}},
    '/certificate/decode': {'required': ['certificate'], 'properties': {'certificate': {**_STR, 'description': 'PEM certificate'}}},
    '/csr/decode': {'required': ['csr'], 'properties': {'csr': {**_STR, 'description': 'PEM CSR'}}},
    '/monitor/domain/add': {'required': ['hostname'], 'properties': {
        **_HOST, 'label': _STR, 'tags': {'type': 'array', 'items': _STR}}},
    '/monitor/certificate/add': {'required': ['certificate'], 'properties': {
        'certificate': _STR, 'label': _STR, 'tags': {'type': 'array', 'items': _STR}}},
    '/dns/lookup': {'required': ['domain'], 'properties': {
        'domain': _STR, 'record_types': {'type': 'array', 'items': _STR, 'example': ['A', 'MX', 'TXT']}}},
    '/ca/create': {'required': ['common_name'], 'properties': {
        'common_name': _STR, 'organization': _STR, 'validity_days': {'type': 'integer', 'default': 3650},
        'key_type': {**_STR, 'enum': ['RSA', 'EC']}}},
    '/ca/issue': {'required': ['ca_certificate', 'ca_private_key'], 'properties': {
        'ca_certificate': _STR, 'ca_private_key': _STR, 'ca_key_password': _STR, 'csr': _STR,
        'common_name': _STR, 'sans': {'type': 'array', 'items': _STR},
        'usage': {**_STR, 'enum': ['server', 'client', 'both']},
        'validity_days': {'type': 'integer', 'default': 365}, 'pkcs12_password': _STR}},
    '/acme/order': {'properties': {
        'domains': {'type': 'array', 'items': _STR, 'example': ['example.com', '*.example.com']},
        'directory': {**_STR, 'description': "'letsencrypt', 'letsencrypt-staging' (default) or a directory URL"},
        'email': _STR, 'challenge_type': {**_STR, 'enum': ['dns-01', 'http-01']},
        'account_key_pem': {**_STR, 'description': 'Reuse an account; generated and returned if omitted'},
        'eab_kid': {**_STR, 'description': 'External account binding key id (ZeroSSL, Google Trust Services, ...)'},
        'eab_hmac_key': {**_STR, 'description': 'External account binding HMAC key (base64url)'},
        'csr': {**_STR, 'description': 'Optional: your own CSR (the private key then never leaves you)'}}},
    '/acme/renewal-info': {'required': ['certificate'], 'properties': {
        'certificate': {**_STR, 'description': 'PEM certificate issued by the CA'}, 'directory': _STR}},
    '/acme/complete': {'required': ['order_url', 'account_key_pem', 'csr_pem'], 'properties': {
        'directory': _STR, 'order_url': _STR, 'account_key_pem': _STR, 'csr_pem': _STR,
        'challenge_type': {**_STR, 'enum': ['dns-01', 'http-01']}}},
    '/acme/issue': {'required': ['dns_provider'], 'properties': {
        'domains': {'type': 'array', 'items': _STR}, 'directory': _STR, 'email': _STR, 'csr': _STR,
        'account_key_pem': _STR, 'propagation_timeout': {'type': 'integer', 'default': 90},
        'dns_provider': {'type': 'object', 'description': "cloudflare: {type, api_token, zone_id?}; acme-dns: {type, server_url, username, password, subdomain}; "
                         "rfc2136: {type, server, zone, tsig_name, tsig_secret, tsig_algorithm?, port?}"}}},
    '/admin/apikey/generate': {'required': ['name'], 'properties': {
        'name': _STR, 'rate_limit': {**_STR, 'example': '200 per hour'}, 'description': _STR}},
}

TAGS = [
    ('certificate', 'Certificates'), ('csr', 'CSR'), ('key', 'Keys'), ('convert', 'Conversion'),
    ('check', 'Checks'), ('monitor', 'Monitoring'), ('batch', 'Batch'), ('admin', 'Admin'),
    ('dmarc', 'Email security'), ('spf', 'Email security'), ('dkim', 'Email security'),
    ('email', 'Email security'), ('dns', 'DNS'), ('upload', 'Uploads'), ('ssl-config', 'Config'), ('ca', 'Private CA'), ('acme', 'ACME'), ('ct', 'Certificate Transparency'),
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
            if getattr(view, 'requires_access', False):
                op['security'] = [{'accessToken': []}]
                op['responses']['401'] = {'description': 'Missing or invalid access token'}
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
            'accessToken': {'type': 'apiKey', 'in': 'header', 'name': 'X-Access-Token',
                            'description': 'An API key or the ADMIN_TOKEN'},
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
