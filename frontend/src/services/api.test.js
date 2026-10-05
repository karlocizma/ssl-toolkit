import { accessToken, addAuthHeaders, needsAdminBearer } from './api';

beforeEach(() => accessToken.set(''));

const run = (url) => addAuthHeaders({ url, headers: {} }).headers;

test('monitor requests carry the token as X-Access-Token', () => {
  accessToken.set('tok');
  expect(run('/monitor/domain/list')).toEqual({ 'X-Access-Token': 'tok' });
});

test('admin-only endpoints (alert settings, audit log, API keys) get a bearer token', () => {
  accessToken.set('tok');
  expect(run('/monitor/alerts/config')).toEqual({ 'X-Access-Token': 'tok', Authorization: 'Bearer tok' });
  expect(run('/admin/audit')).toEqual({ Authorization: 'Bearer tok' });
  expect(run('/admin/apikey/list')).toEqual({ Authorization: 'Bearer tok' });
});

test('other requests and requests without a token carry no credentials', () => {
  accessToken.set('tok');
  expect(run('/check/tls')).toEqual({});
  accessToken.set('');
  expect(run('/admin/audit')).toEqual({});
  expect(needsAdminBearer('/monitor/domain/list')).toBe(false);
});
