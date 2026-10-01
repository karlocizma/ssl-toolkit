def test_spec_lists_all_api_routes(client, app):
    spec = client.get('/api/openapi.json').get_json()
    assert spec['openapi'].startswith('3.')
    for path in ('/check/tls', '/check/headers', '/monitor/domain/add', '/certificate/decode',
                 '/monitor/domain/{domain_id}'):
        assert path in spec['paths'], path
    documented = set(spec['paths'])
    for rule in app.url_map.iter_rules():
        if rule.rule.startswith('/api/') and not rule.rule.startswith(('/api/docs', '/api/openapi')):
            path = rule.rule[len('/api'):]
            assert path.replace('<', '{').replace('>', '}') in documented, path


def test_admin_routes_marked_secure_and_bodies_described(client):
    spec = client.get('/api/openapi.json').get_json()
    assert spec['paths']['/admin/apikey/list']['get']['security'] == [{'adminToken': []}]
    body = spec['paths']['/check/tls']['post']['requestBody']['content']['application/json']['schema']
    assert body['required'] == ['hostname']
    assert 'security' not in spec['paths']['/check/tls']['post']


def test_swagger_ui_served(client):
    resp = client.get('/api/docs/')
    assert resp.status_code == 200 and b'swagger' in resp.data.lower()
