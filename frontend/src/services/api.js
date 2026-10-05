import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
});

// The monitor needs an API key or the admin token (sent as X-Access-Token). By default it is kept in
// sessionStorage and disappears when the tab closes; "remember on this device" keeps it in
// localStorage instead (readable by any script on this site, so only on a device you trust).
const TOKEN_KEY = 'ssl-toolkit-access-token';
const readFrom = (store) => {
  try { return store.getItem(TOKEN_KEY) || ''; } catch (e) { return ''; }
};
export const accessToken = {
  get: () => readFrom(sessionStorage) || readFrom(localStorage),
  isRemembered: () => !!readFrom(localStorage),
  set: (value, remember = false) => {
    for (const store of [sessionStorage, localStorage]) {  // never leave a stale copy behind
      try { store.removeItem(TOKEN_KEY); } catch (e) { /* storage unavailable */ }
    }
    if (!value) return;
    try { (remember ? localStorage : sessionStorage).setItem(TOKEN_KEY, value); } catch (e) { /* token just won't persist */ }
  }
};

// Admin-only endpoints (API keys, alert settings, audit log) want the admin token as a bearer token;
// an API key sent there is simply refused with 401.
export const needsAdminBearer = (url) => !!url && (url.startsWith('/admin/') || url.startsWith('/monitor/alerts/'));

export const addAuthHeaders = (config) => {
  const token = accessToken.get();
  if (token && config.url && (config.url.startsWith('/monitor/') || config.url.startsWith('/share'))) {
    config.headers['X-Access-Token'] = token;
  }
  if (token && needsAdminBearer(config.url)) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
};

api.interceptors.request.use(addAuthHeaders);

// Certificate operations
export const certificateAPI = {
  decode: (certificateData) => api.post('/certificate/decode', { certificate: certificateData }),
  getFingerprint: (certificateData) => api.post('/certificate/fingerprint', { certificate: certificateData }),
  generateSelfSigned: (data) => api.post('/certificate/self-signed', data),
  upload: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/upload/certificate', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
  }
};

// CSR operations
export const csrAPI = {
  generate: (data) => api.post('/csr/generate', data),
  decode: (csrData) => api.post('/csr/decode', { csr: csrData }),
  upload: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/upload/csr', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
  }
};

// Key operations
export const keyAPI = {
  generate: (data) => api.post('/key/generate', data),
  validate: (data) => api.post('/key/validate', data),
  matchCertificate: (data) => api.post('/key/match-certificate', data)
};

// Certificate conversion
export const conversionAPI = {
  convert: (data) => api.post('/convert', data)
};

// SSL checking
export const sslCheckAPI = {
  checkDomain: (data) => api.post('/check/domain', data),
  checkChain: (data) => api.post('/check/chain', data),
  checkSSLLabs: (data) => api.post('/check/ssl-labs', data),
  checkOCSP: (data) => api.post('/check/ocsp', data),
  checkCRL: (data) => api.post('/check/crl', data),
  scanTLS: (data) => api.post('/check/tls', data, { timeout: 120000 }),
  checkDomainRegistration: (data) => api.post('/check/domain-registration', data, { timeout: 60000 }),
  scanMailTLS: (data) => api.post('/check/mail-tls', data, { timeout: 120000 }),
  checkHeaders: (data) => api.post('/check/headers', data),
  checkAutodiscover: (data) => api.post('/check/autodiscover', data, { timeout: 90000 })
};

// Private CA
export const caAPI = {
  create: (data) => api.post('/ca/create', data, { timeout: 60000 }),
  issue: (data) => api.post('/ca/issue', data, { timeout: 60000 })
};

// ACME (Let's Encrypt & compatible CAs)
export const acmeAPI = {
  order: (data) => api.post('/acme/order', data, { timeout: 120000 }),
  complete: (data) => api.post('/acme/complete', data, { timeout: 300000 }),
  issue: (data) => api.post('/acme/issue', data, { timeout: 300000 }),
  renewalInfo: (data) => api.post('/acme/renewal-info', data, { timeout: 60000 })
};

// Chain builder
export const chainAPI = {
  build: (data) => api.post('/chain/build', data, { timeout: 90000 })
};

// Email deliverability
export const deliverabilityAPI = {
  overview: (data) => api.post('/email/deliverability', data, { timeout: 90000 }),
  mtaSts: (data) => api.post('/email/mta-sts', data, { timeout: 120000 }),
  mtaStsGenerate: (data) => api.post('/email/mta-sts/generate', data),
  tlsRpt: (data) => api.post('/email/tls-rpt', data),
  tlsRptGenerate: (data) => api.post('/email/tls-rpt/generate', data),
  tlsRptReport: (data) => api.post('/email/tls-rpt/report', data),
  spf: (data) => api.post('/email/spf/analyze', data, { timeout: 90000 }),
  spfFlatten: (data) => api.post('/email/spf/flatten', data, { timeout: 120000 }),
  dkim: (data) => api.post('/email/dkim/discover', data, { timeout: 90000 }),
  dmarcReport: (data) => api.post('/email/dmarc/report', data),
  dmarcReports: (data) => api.post('/email/dmarc/reports', data, { timeout: 180000 }),
  blocklist: (data) => api.post('/email/blocklist', data, { timeout: 90000 })
};

// Certificate Transparency
export const ctAPI = {
  lookup: (data) => api.post('/ct/lookup', data, { timeout: 120000 })
};

// Domain monitoring
export const monitorAPI = {
  addDomain: (data) => api.post('/monitor/domain/add', data, { timeout: 60000 }),
  addDomains: (data) => api.post('/monitor/domain/add-bulk', data, { timeout: 300000 }),
  listDomains: () => api.get('/monitor/domain/list'),
  getDomain: (id) => api.get(`/monitor/domain/${id}`),
  removeDomain: (id) => api.delete(`/monitor/domain/${id}`),
  checkDomain: (id) => api.post(`/monitor/domain/${id}/check`, null, { timeout: 60000 }),
  importCsv: (csv) => api.post('/monitor/domain/import', { csv }, { timeout: 300000 }),
  setPublic: (id, data) => api.patch(`/monitor/domain/${id}/public`, data),
  alertsConfig: () => api.get('/monitor/alerts/config'),
  alertsTest: () => api.post('/monitor/alerts/test', null, { timeout: 60000 }),
  exportData: (format) => api.get('/monitor/export', { params: { format }, responseType: 'blob' })
};

// Public status page (no login)
export const statusAPI = {
  get: () => api.get('/status')
};

// Shareable results: create/list/revoke need the access token, reading a link does not
export const shareAPI = {
  create: (data) => api.post('/share', data),
  list: () => api.get('/share'),
  revoke: (id) => api.delete(`/share/${encodeURIComponent(id)}`),
  get: (token) => api.get(`/share/${encodeURIComponent(token)}`)
};

// Audit log (admin token)
export const auditAPI = {
  list: (params) => api.get('/admin/audit', { params }),
  verify: () => api.get('/admin/audit/verify'),
  exportData: (format, params) => api.get('/admin/audit/export', { params: { ...params, format }, responseType: 'blob' })
};

// Sysadmin helpers
export const sysAdminAPI = {
  generateDMARC: (data) => api.post('/dmarc/generate', data),
  validateDMARC: (data) => api.post('/dmarc/validate', data),
  generateSPF: (data) => api.post('/spf/generate', data),
  validateSPF: (data) => api.post('/spf/validate', data),
  analyzeEmailHeaders: (data) => api.post('/email/header/analyze', data),
  generatePassword: (data) => api.post('/security/password/generate', data),
  lookupDNS: (data) => api.post('/dns/lookup', data),
  generateDKIM: (data) => api.post('/dkim/generate', data),
  validateDKIM: (data) => api.post('/dkim/validate', data),
  generateSSLConfig: (data) => api.post('/ssl-config/generate', data),
};

// Health check
export const healthAPI = {
  check: () => api.get('/health')
};

export default api;
