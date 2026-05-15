import api, {
  certificateAPI,
  csrAPI,
  keyAPI,
  sslCheckAPI,
  sysAdminAPI,
  healthAPI,
} from './api';

describe('api service', () => {
  it('uses /api as the default base URL', () => {
    expect(api.defaults.baseURL).toBe('/api');
  });

  it('has a 30-second timeout', () => {
    expect(api.defaults.timeout).toBe(30000);
  });

  it('exports certificateAPI with expected methods', () => {
    expect(typeof certificateAPI.decode).toBe('function');
    expect(typeof certificateAPI.getFingerprint).toBe('function');
    expect(typeof certificateAPI.upload).toBe('function');
  });

  it('exports csrAPI with expected methods', () => {
    expect(typeof csrAPI.generate).toBe('function');
    expect(typeof csrAPI.decode).toBe('function');
    expect(typeof csrAPI.upload).toBe('function');
  });

  it('exports keyAPI with expected methods', () => {
    expect(typeof keyAPI.generate).toBe('function');
    expect(typeof keyAPI.validate).toBe('function');
    expect(typeof keyAPI.matchCertificate).toBe('function');
  });

  it('exports sslCheckAPI with expected methods', () => {
    expect(typeof sslCheckAPI.checkDomain).toBe('function');
    expect(typeof sslCheckAPI.checkChain).toBe('function');
    expect(typeof sslCheckAPI.checkOCSP).toBe('function');
    expect(typeof sslCheckAPI.checkCRL).toBe('function');
  });

  it('exports sysAdminAPI with expected methods', () => {
    expect(typeof sysAdminAPI.generateDMARC).toBe('function');
    expect(typeof sysAdminAPI.validateDMARC).toBe('function');
    expect(typeof sysAdminAPI.generateSPF).toBe('function');
    expect(typeof sysAdminAPI.lookupDNS).toBe('function');
  });

  it('exports healthAPI.check', () => {
    expect(typeof healthAPI.check).toBe('function');
  });
});
