import React, { useState } from 'react';
import {
  Alert, Box, Button, Checkbox, Chip, FormControlLabel, Grid, MenuItem, Paper, Stack, Tab, Tabs, TextField, Typography,
} from '@mui/material';
import { caaDaneAPI } from '../services/api';

const severityOf = (s) => (s === 'error' || s === 'critical' ? 'error' : s === 'warning' ? 'warning' : 'info');
const errorOf = (err, fallback) => err.response?.data?.error || fallback;

const COMMON_CAS = [
  ['letsencrypt.org', "Let's Encrypt"], ['digicert.com', 'DigiCert'], ['sectigo.com', 'Sectigo'],
  ['globalsign.com', 'GlobalSign'], ['pki.goog', 'Google Trust Services'], ['amazon.com', 'Amazon'],
  ['ssl.com', 'SSL.com'], ['buypass.com', 'Buypass'],
];

const Findings = ({ items }) => (items && items.length > 0 ? (
  <Stack spacing={1} sx={{ mt: 2 }}>
    {items.map((f, i) => <Alert key={i} severity={severityOf(f.severity)}>{f.message}</Alert>)}
  </Stack>
) : null);

const Code = ({ children }) => (
  <Box component="pre" sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1, overflow: 'auto', fontSize: 13, m: 0 }}>{children}</Box>
);

const caLabel = (i) => (i.name ? `${i.name} (${i.ca})` : i.ca);

function CaList({ title, issuers, anyCa, blocked }) {
  return (
    <Box sx={{ mb: 2 }}>
      <Typography variant="subtitle2" gutterBottom>{title}</Typography>
      {blocked && <Alert severity="info">Nobody may issue ("{';'}").</Alert>}
      {!blocked && anyCa && <Alert severity="warning">Any CA may issue (no restriction).</Alert>}
      {!blocked && !anyCa && (
        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
          {issuers.map((i, n) => (
            <Chip key={n} label={caLabel(i) + (i.params && Object.keys(i.params).length
              ? ` — ${Object.entries(i.params).map(([k, v]) => `${k}=${v}`).join(', ')}` : '')} />
          ))}
        </Stack>
      )}
    </Box>
  );
}

function CheckTab() {
  const [domain, setDomain] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!domain.trim()) { setError('Domain is required'); return; }
    setError(''); setResult(null); setLoading(true);
    try {
      const res = await caaDaneAPI.caaCheck({ domain: domain.trim() });
      setResult(res.data.result);
    } catch (err) {
      setError(errorOf(err, 'Check failed.'));
    } finally { setLoading(false); }
  };

  return (
    <Box>
      <Paper sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={9}>
            <TextField label="Domain" fullWidth value={domain} placeholder="example.com"
              onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} />
          </Grid>
          <Grid item xs={12} md={3}>
            <Button variant="contained" fullWidth onClick={run} disabled={loading}>{loading ? 'Checking...' : 'Check'}</Button>
          </Grid>
        </Grid>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>
      {result && !result.lookup_failed && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            {result.policy_name ? `Policy published at ${result.policy_name}` : 'No CAA policy found'}
          </Typography>
          <CaList title="May issue certificates" issuers={result.issuers} anyCa={result.any_ca_may_issue} blocked={result.issuance_blocked} />
          <CaList title="May issue wildcard certificates" issuers={result.wildcard_issuers}
            anyCa={result.wildcard_any_ca_may_issue} blocked={result.wildcard_blocked} />
          {result.records.length > 0 && (
            <Code>{result.records.map((r) => `${r.critical ? 128 : 0} ${r.tag} "${r.value}"`).join('\n')}</Code>
          )}
        </Paper>
      )}
      {result && <Findings items={result.findings} />}
    </Box>
  );
}

function GenerateTab() {
  const [domain, setDomain] = useState('');
  const [cas, setCas] = useState('');
  const [wildcardCas, setWildcardCas] = useState('');
  const [allowWildcards, setAllowWildcards] = useState(true);
  const [blockAll, setBlockAll] = useState(false);
  const [dns01, setDns01] = useState(false);
  const [iodef, setIodef] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const lines = (text) => text.split(/[\s,]+/).map((c) => c.trim()).filter(Boolean);
  const addCa = (ca) => { if (!lines(cas).includes(ca)) setCas((cas.trim() ? `${cas.trim()}\n` : '') + ca + '\n'); };

  const run = async () => {
    const issuers = blockAll ? [] : lines(cas);
    if (!blockAll && issuers.length === 0) { setError('Add at least one CA, or choose "Block all issuance".'); return; }
    setError(''); setResult(null); setLoading(true);
    try {
      const body = { issuers, allow_wildcards: allowWildcards, block_all: blockAll, dns01_only: dns01 };
      if (domain.trim()) body.domain = domain.trim();
      if (!blockAll && wildcardCas.trim()) body.wildcard_issuers = lines(wildcardCas);
      if (iodef.trim()) body.iodef = iodef.trim();
      const res = await caaDaneAPI.caaGenerate(body);
      setResult(res.data.result);
    } catch (err) {
      setError(errorOf(err, 'Could not generate the records.'));
    } finally { setLoading(false); }
  };

  return (
    <Box>
      <Paper sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <TextField label="Domain (optional)" fullWidth value={domain} placeholder="example.com" onChange={(e) => setDomain(e.target.value)}
              helperText="Leave empty to use @ as the record name" />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField label="Report violations to (optional)" fullWidth value={iodef} placeholder="mailto:security@example.com"
              onChange={(e) => setIodef(e.target.value)} />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField label="Allowed CAs (one per line)" fullWidth multiline minRows={3} value={cas} disabled={blockAll}
              placeholder="letsencrypt.org" onChange={(e) => setCas(e.target.value)} />
            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mt: 1 }}>
              {COMMON_CAS.map(([ca, name]) => <Chip key={ca} size="small" label={name} onClick={() => addCa(ca)} disabled={blockAll} />)}
            </Stack>
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField label="Different CAs for wildcards (optional)" fullWidth multiline minRows={3} value={wildcardCas}
              disabled={blockAll || !allowWildcards} onChange={(e) => setWildcardCas(e.target.value)} />
          </Grid>
        </Grid>
        <Stack sx={{ mt: 1 }}>
          <FormControlLabel control={<Checkbox checked={allowWildcards} onChange={(e) => setAllowWildcards(e.target.checked)} disabled={blockAll} />}
            label="Allow wildcard certificates" />
          <FormControlLabel control={<Checkbox checked={dns01} onChange={(e) => setDns01(e.target.checked)} disabled={blockAll} />}
            label="Only allow DNS-01 validation" />
          <FormControlLabel control={<Checkbox checked={blockAll} onChange={(e) => setBlockAll(e.target.checked)} />}
            label="Block all issuance (no CA may issue certificates)" />
        </Stack>
        <Button variant="contained" sx={{ mt: 2 }} onClick={run} disabled={loading}>{loading ? 'Generating...' : 'Generate'}</Button>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>
      {result && (
        <Paper sx={{ p: 3 }}>
          <Typography gutterBottom>{result.summary}</Typography>
          <Code>{result.records.join('\n')}</Code>
        </Paper>
      )}
    </Box>
  );
}

const USAGES = [[0, '0 – PKIX-TA (CA certificate, public CA)'], [1, '1 – PKIX-EE (server certificate, public CA)'],
  [2, '2 – DANE-TA (CA certificate, your own trust anchor)'], [3, '3 – DANE-EE (server certificate only)']];
const SELECTORS = [[0, '0 – full certificate'], [1, '1 – public key']];
const MATCHINGS = [[0, '0 – exact match'], [1, '1 – SHA-256'], [2, '2 – SHA-512']];

function TlsaGenerate() {
  const [pem, setPem] = useState('');
  const [host, setHost] = useState('');
  const [port, setPort] = useState('443');
  const [usage, setUsage] = useState(3);
  const [selector, setSelector] = useState(1);
  const [matching, setMatching] = useState(1);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!pem.trim() || !host.trim()) { setError('Certificate and host are required'); return; }
    setError(''); setResult(null); setLoading(true);
    try {
      const res = await caaDaneAPI.daneGenerate({
        certificate: pem, host: host.trim(), port: Number(port) || 443, protocol: 'tcp', usage, selector, matching_type: matching });
      setResult(res.data.result);
    } catch (err) {
      setError(errorOf(err, 'Could not generate the record.'));
    } finally { setLoading(false); }
  };

  const select = (label, value, set, options) => (
    <TextField select fullWidth label={label} value={value} onChange={(e) => set(Number(e.target.value))}>
      {options.map(([v, text]) => <MenuItem key={v} value={v}>{text}</MenuItem>)}
    </TextField>
  );

  return (
    <Paper sx={{ p: 3, mb: 3 }}>
      <Typography variant="h6" gutterBottom>Generate a TLSA record</Typography>
      <Grid container spacing={2}>
        <Grid item xs={12}>
          <TextField label="Certificate (PEM)" fullWidth multiline minRows={4} value={pem}
            placeholder="-----BEGIN CERTIFICATE-----" onChange={(e) => setPem(e.target.value)} />
        </Grid>
        <Grid item xs={12} md={8}>
          <TextField label="Host (generate)" fullWidth value={host} placeholder="example.com" onChange={(e) => setHost(e.target.value)} />
        </Grid>
        <Grid item xs={12} md={4}>
          <TextField label="Port (generate)" fullWidth value={port} onChange={(e) => setPort(e.target.value)} />
        </Grid>
        <Grid item xs={12} md={4}>{select('Usage', usage, setUsage, USAGES)}</Grid>
        <Grid item xs={12} md={4}>{select('Selector', selector, setSelector, SELECTORS)}</Grid>
        <Grid item xs={12} md={4}>{select('Matching type', matching, setMatching, MATCHINGS)}</Grid>
      </Grid>
      <Button variant="contained" sx={{ mt: 2 }} onClick={run} disabled={loading}>{loading ? 'Generating...' : 'Generate TLSA'}</Button>
      {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      {result && (
        <Box sx={{ mt: 2 }}>
          <Code>{result.record}</Code>
          <Findings items={(result.notes || []).map((message) => ({ severity: 'info', message }))} />
        </Box>
      )}
    </Paper>
  );
}

function TlsaCheck() {
  const [host, setHost] = useState('');
  const [port, setPort] = useState('443');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!host.trim()) { setError('Host is required'); return; }
    setError(''); setResult(null); setLoading(true);
    try {
      const res = await caaDaneAPI.daneCheck({ host: host.trim(), port: Number(port) || 443, protocol: 'tcp' });
      setResult(res.data.result);
    } catch (err) {
      setError(errorOf(err, 'Check failed.'));
    } finally { setLoading(false); }
  };

  return (
    <Paper sx={{ p: 3 }}>
      <Typography variant="h6" gutterBottom>Check a live host</Typography>
      <Grid container spacing={2} alignItems="center">
        <Grid item xs={12} md={6}>
          <TextField label="Host (check)" fullWidth value={host} placeholder="example.com" onChange={(e) => setHost(e.target.value)} />
        </Grid>
        <Grid item xs={6} md={3}>
          <TextField label="Port (check)" fullWidth value={port} onChange={(e) => setPort(e.target.value)} />
        </Grid>
        <Grid item xs={6} md={3}>
          <Button variant="contained" fullWidth onClick={run} disabled={loading}>{loading ? 'Checking...' : 'Check TLSA'}</Button>
        </Grid>
      </Grid>
      {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      {result && (
        <Box sx={{ mt: 2 }}>
          {result.records.length > 0 && (
            <Code>{result.records.map((r) => `${r.match === true ? '✔' : r.match === false ? '✘' : '?'} ${r.usage} ${r.selector} ${r.matching_type} ${r.data}`).join('\n')}</Code>
          )}
          <Findings items={result.findings} />
        </Box>
      )}
    </Paper>
  );
}

function CaaDane() {
  const [tab, setTab] = useState(0);
  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>CAA & DANE</Typography>
      <Typography color="text.secondary" sx={{ mb: 2 }}>
        Control which CAs may issue certificates for your domains, and pin certificates in DNS. Only outbound DNS lookups
        and TLS connections are used; nothing is stored.
      </Typography>
      <Tabs value={tab} onChange={(e, v) => setTab(v)} sx={{ mb: 3 }}>
        <Tab label="Check CAA" />
        <Tab label="Generate CAA" />
        <Tab label="TLSA (DANE)" />
      </Tabs>
      {tab === 0 && <CheckTab />}
      {tab === 1 && <GenerateTab />}
      {tab === 2 && <><TlsaGenerate /><TlsaCheck /></>}
    </Box>
  );
}

export default CaaDane;
