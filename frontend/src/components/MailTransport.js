import React, { useState } from 'react';
import {
  Alert, Box, Button, Checkbox, Chip, FormControlLabel, Grid, MenuItem, Paper, Stack, Tab, Tabs, TextField, Typography,
} from '@mui/material';
import { Shield as ShieldIcon } from '@mui/icons-material';
import { deliverabilityAPI } from '../services/api';
import ResultActions from './ResultActions';

const severityOf = (s) => (s === 'error' || s === 'critical' ? 'error' : s === 'warning' ? 'warning' : 'info');
const statusColor = { ok: 'success', warning: 'warning', error: 'error', missing: 'default' };

const Findings = ({ items }) => (items && items.length > 0 ? (
  <Stack spacing={1} sx={{ mt: 2 }}>
    {items.map((f, i) => <Alert key={i} severity={severityOf(f.severity)}>{f.message}</Alert>)}
  </Stack>
) : null);

const Code = ({ children }) => (
  <Box component="pre" sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1, overflow: 'auto', fontSize: 13, m: 0 }}>{children}</Box>
);

function CheckTab() {
  const [domain, setDomain] = useState('');
  const [verifyMx, setVerifyMx] = useState(false);
  const [sts, setSts] = useState(null);
  const [rpt, setRpt] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!domain.trim()) { setError('Domain is required'); return; }
    setError(''); setSts(null); setRpt(null); setLoading(true);
    try {
      const body = { domain: domain.trim() };
      const [a, b] = await Promise.all([
        deliverabilityAPI.mtaSts({ ...body, verify_mx: verifyMx }),
        deliverabilityAPI.tlsRpt(body),
      ]);
      setSts(a.data.result); setRpt(b.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Check failed.');
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
        <FormControlLabel sx={{ mt: 1 }} control={<Checkbox checked={verifyMx} onChange={(e) => setVerifyMx(e.target.checked)} />}
          label="Also test STARTTLS and certificates of the MX hosts (connects to port 25)" />
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>

      {(sts || rpt) && <ResultActions tool="mta-sts" title={`MTA-STS & TLS-RPT: ${domain}`} result={{ mta_sts: sts, tls_rpt: rpt }} />}
      {sts && (
        <Paper sx={{ p: 3, mb: 2 }}>
          <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap">
            <Typography variant="h6">MTA-STS</Typography>
            <Chip label={sts.policy?.mode ? `mode: ${sts.policy.mode}` : sts.status} color={statusColor[sts.status]} />
            {sts.id && <Chip size="small" variant="outlined" label={`id ${sts.id}`} />}
            {sts.policy?.max_age && <Chip size="small" variant="outlined" label={`max_age ${sts.policy.max_age}s`} />}
          </Stack>
          {sts.mx_coverage.length > 0 && (
            <Stack spacing={0.5} sx={{ mt: 2 }}>
              {sts.mx_coverage.map((c) => (
                <Typography key={c.host} variant="body2" sx={{ fontFamily: 'monospace' }}>
                  {c.covered ? '✔' : '✘'} {c.host}{c.pattern ? ` (matches ${c.pattern})` : ' (not in the policy)'}
                </Typography>
              ))}
            </Stack>
          )}
          {sts.mx_tls && sts.mx_tls.map((t) => (
            <Typography key={t.host} variant="caption" sx={{ display: 'block' }}>
              {t.host}: STARTTLS {String(t.starttls)}, certificate {t.trusted ? 'trusted' : 'not trusted'}, grade {t.grade || '-'}
            </Typography>
          ))}
          <Findings items={sts.findings} />
        </Paper>
      )}

      {rpt && (
        <Paper sx={{ p: 3 }}>
          <Stack direction="row" spacing={2} alignItems="center">
            <Typography variant="h6">TLS-RPT</Typography>
            <Chip label={rpt.status} color={statusColor[rpt.status]} />
          </Stack>
          {rpt.record && <Code>{rpt.record}</Code>}
          <Findings items={rpt.findings} />
        </Paper>
      )}
    </Box>
  );
}

function GenerateTab() {
  const [domain, setDomain] = useState('');
  const [mode, setMode] = useState('testing');
  const [mx, setMx] = useState('');
  const [maxAge, setMaxAge] = useState(604800);
  const [rua, setRua] = useState('');
  const [policy, setPolicy] = useState(null);
  const [record, setRecord] = useState(null);
  const [error, setError] = useState('');

  const generate = async () => {
    if (!domain.trim()) { setError('Domain is required'); return; }
    setError(''); setPolicy(null); setRecord(null);
    try {
      const hosts = mx.split(/[\s,]+/).filter(Boolean);
      const a = await deliverabilityAPI.mtaStsGenerate({
        domain: domain.trim(), mode, max_age: Number(maxAge), mx: hosts.length ? hosts : undefined,
      });
      setPolicy(a.data.result);
      const destinations = rua.split(/[\s,]+/).filter(Boolean);
      if (destinations.length) {
        const b = await deliverabilityAPI.tlsRptGenerate({ domain: domain.trim(), rua: destinations });
        setRecord(b.data.result);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Generation failed.');
    }
  };

  return (
    <Box>
      <Paper sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <TextField label="Domain" fullWidth value={domain} placeholder="example.com" onChange={(e) => setDomain(e.target.value)} />
          </Grid>
          <Grid item xs={6} md={3}>
            <TextField select label="Mode" fullWidth value={mode} onChange={(e) => setMode(e.target.value)}>
              <MenuItem value="testing">testing</MenuItem>
              <MenuItem value="enforce">enforce</MenuItem>
              <MenuItem value="none">none</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={6} md={3}>
            <TextField label="max_age (seconds)" type="number" fullWidth value={maxAge} onChange={(e) => setMaxAge(e.target.value)} />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField label="MX hosts (empty: use the domain's MX records)" fullWidth value={mx}
              placeholder="mail.example.com, *.mx.example.com" onChange={(e) => setMx(e.target.value)} />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField label="TLS-RPT report address (optional)" fullWidth value={rua}
              placeholder="tlsrpt@example.com" onChange={(e) => setRua(e.target.value)} />
          </Grid>
          <Grid item xs={12}>
            <Button variant="contained" onClick={generate}>Generate</Button>
          </Grid>
        </Grid>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>

      {policy && (
        <Paper sx={{ p: 3, mb: 2 }}>
          <Typography variant="h6" gutterBottom>MTA-STS</Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>Policy file, served at {policy.policy_url}</Typography>
          <Code>{policy.policy}</Code>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }} gutterBottom>TXT record at {policy.dns_name}</Typography>
          <Code>{policy.dns_record}</Code>
          <Box component="ol" sx={{ pl: 3, mb: 0 }}>
            {policy.steps.map((s) => <li key={s}><Typography variant="body2">{s}</Typography></li>)}
          </Box>
        </Paper>
      )}
      {record && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>TLS-RPT</Typography>
          <Typography variant="body2" color="text.secondary" gutterBottom>TXT record at {record.dns_name}</Typography>
          <Code>{record.dns_record}</Code>
        </Paper>
      )}
    </Box>
  );
}

function ReportTab() {
  const [text, setText] = useState('');
  const [fileData, setFileData] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const onFile = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setFileData(String(reader.result).split(',')[1] || '');
    reader.readAsDataURL(file);
  };

  const analyze = async () => {
    setError(''); setResult(null);
    try {
      const response = await deliverabilityAPI.tlsRptReport(fileData ? { file_base64: fileData } : { json: text });
      setResult(response.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Could not read the report.');
    }
  };

  return (
    <Box>
      <Paper sx={{ p: 3, mb: 3 }}>
        <Button component="label" size="small" sx={{ mb: 1 }}>
          Choose a report file (.json or .json.gz)<input hidden type="file" onChange={onFile} />
        </Button>
        {fileData && <Chip size="small" label="file loaded" sx={{ ml: 1 }} onDelete={() => setFileData('')} />}
        <TextField label="…or paste the report JSON" multiline minRows={4} maxRows={10} fullWidth value={text}
          onChange={(e) => setText(e.target.value)} sx={{ '& textarea': { fontFamily: 'monospace', fontSize: 12 } }} />
        <Button variant="contained" sx={{ mt: 1 }} disabled={!text.trim() && !fileData} onClick={analyze}>Analyze</Button>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>

      {result && (
        <Paper sx={{ p: 3 }}>
          <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap">
            <Typography variant="h6">{result.organization || 'Report'}</Typography>
            <Chip color="success" label={`${result.successful} successful`} />
            <Chip color={result.failed ? 'error' : 'default'} label={`${result.failed} failed`} />
            {result.success_rate !== null && <Chip variant="outlined" label={`${result.success_rate}% success`} />}
          </Stack>
          <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
            {result.start} – {result.end}
          </Typography>
          <Findings items={result.findings} />
          {result.policies.map((p, i) => (
            <Box key={i} sx={{ mt: 2 }}>
              <Typography variant="subtitle2">{p.type} policy for {p.domain}: {p.successful} ok, {p.failed} failed</Typography>
              {p.failures.map((f, j) => (
                <Typography key={j} variant="body2" sx={{ fontFamily: 'monospace' }}>
                  {f.count}× {f.type} at {f.receiving_mx || '?'} from {f.sending_ip || '?'}
                </Typography>
              ))}
            </Box>
          ))}
        </Paper>
      )}
    </Box>
  );
}

function MailTransport() {
  const [tab, setTab] = useState(0);
  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <ShieldIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        MTA-STS &amp; TLS-RPT
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        MTA-STS tells sending mail servers to deliver to your MX hosts only over validated TLS; TLS-RPT sends you reports about
        failures. Check an existing setup, generate the policy and DNS records, or read a TLS-RPT report.
      </Typography>
      <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
        <Tab label="Check" />
        <Tab label="Generate" />
        <Tab label="Read a report" />
      </Tabs>
      {tab === 0 && <CheckTab />}
      {tab === 1 && <GenerateTab />}
      {tab === 2 && <ReportTab />}
    </Box>
  );
}

export default MailTransport;
