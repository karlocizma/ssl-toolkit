import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || '/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
});

// Certificate operations
export const certificateAPI = {
  decode: (certificateData) => api.post('/certificate/decode', { certificate: certificateData }),
  getFingerprint: (certificateData) => api.post('/certificate/fingerprint', { certificate: certificateData }),
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
  checkCRL: (data) => api.post('/check/crl', data)
};

// Health check
export const healthAPI = {
  check: () => api.get('/health')
};

export default api;

