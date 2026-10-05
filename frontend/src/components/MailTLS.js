import React, { useState } from 'react';
import {
  Alert, Box, Button, Checkbox, Chip, FormControlLabel, Grid, MenuItem, Paper, Stack, TextField, ToggleButton,
  ToggleButtonGroup, Typography,
} from '@mui/material';
import { EnhancedEncryption as EnhancedEncryptionIcon } from '@mui/icons-material';
import { sslCheckAPI } from '../services/api';

const gradeColor = (grade) => {
  if (grade === 'A' || grade === 'A-') return 'success';
  if (grade === 'B') return 'info';
  if (grade === 'C') return 'warning';
  return 'error';
};
const severityOf = (s) => (s === 'critical' ? 'error' : s === 'warning' ? 'warning' : 'info');

const PORTS = [
  { port: 25, label: '25 SMTP (STARTTLS)' },
  { port: 587, label: '587 Submission (STARTTLS)' },
  { port: 465, label: '465 SMTPS (implicit TLS)' },
  { port: 143, label: '143 IMAP (STARTTLS)' },
  { port: 993, label: '993 IMAPS (implicit TLS)' },
  { port: 110, label: '110 POP3 (STLS)' },
  { port: 995, label: '995 POP3S (implicit TLS)' },
];

function HostResult({ r }) {
  if (!r.reachable) {
    return (
      <Paper variant="outlined" sx={{ p: 2 }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{r.host}:{r.port}</Typography>
        <Alert severity="warning" sx={{ mt: 1 }}>{r.error}</Alert>
      </Paper>
    );
  }
  return (
    <Paper variant="outlined" sx={{ p: 2 }}>
      <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap">
        <Chip label={`Grade ${r.grade}`} color={gradeColor(r.grade)} />
        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
          {r.host}:{r.port}{r.priority !== undefined ? ` (MX priority ${r.priority})` : ''}
        </Typography>
        <Chip size="small" variant="outlined" label={`${r.protocol.toUpperCase()} · ${r.mode === 'implicit' ? 'implicit TLS' : 'STARTTLS'}`} />
        {r.starttls === true && <Chip size="small" color="success" label="STARTTLS offered" />}
        {r.starttls === false && <Chip size="small" color="error" label="No STARTTLS" />}
      </Stack>
      {r.banner && (
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1, fontFamily: 'monospace' }}>
          {r.banner}
        </Typography>
      )}
      {r.certificate && (
        <Typography variant="body2" sx={{ mt: 1 }}>
          Certificate for <strong>{r.certificate.subject}</strong> from {r.certificate.issuer}, expires in{' '}
          {r.certificate.days_until_expiry} day(s) — {r.certificate.trusted ? 'trusted' : 'NOT trusted for this host name'}
        </Typography>
      )}
      {r.protocols && (
        <Stack direction="row" spacing={1} sx={{ mt: 1 }} flexWrap="wrap">
          {Object.entries(r.protocols).map(([name, data]) => (
            <Chip key={name} size="small" label={`${name}: ${data.supported ? 'yes' : 'no'}`}
              color={data.supported ? (name === 'TLSv1.0' || name === 'TLSv1.1' ? 'warning' : 'success') : 'default'}
              variant={data.supported ? 'filled' : 'outlined'} />
          ))}
        </Stack>
      )}
      {r.findings && r.findings.length > 0 && (
        <Stack spacing={1} sx={{ mt: 2 }}>
          {r.findings.map((f, i) => <Alert key={i} severity={severityOf(f.severity)}>{f.message}</Alert>)}
        </Stack>
      )}
    </Paper>
  );
}

function MailTLS() {
  const [mode, setMode] = useState('domain');
  const [target, setTarget] = useState('');
  const [port, setPort] = useState(25);
  const [deep, setDeep] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!target.trim()) {
      setError(mode === 'domain' ? 'Domain is required' : 'Host is required');
      return;
    }
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const body = mode === 'domain'
        ? { domain: target.trim() }
        : { host: target.trim(), port: Number(port), deep };
      const response = await sslCheckAPI.scanMailTLS(body);
      setResult(response.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Mail server test failed.');
    } finally {
      setLoading(false);
    }
  };

  const hosts = result ? (result.mx || [result]) : [];

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <EnhancedEncryptionIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Mail Server TLS
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Check that mail servers offer STARTTLS (or implicit TLS), which protocol versions and ciphers they accept, and whether
        their certificate is valid for the host name. Enter a domain to test all of its MX hosts on port 25.
        Some hosting providers block outbound port 25.
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <ToggleButtonGroup exclusive size="small" value={mode} onChange={(_, v) => v && setMode(v)} sx={{ mb: 2 }}>
          <ToggleButton value="domain">Domain (all MX hosts)</ToggleButton>
          <ToggleButton value="host">Single server</ToggleButton>
        </ToggleButtonGroup>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={mode === 'domain' ? 9 : 5}>
            <TextField label={mode === 'domain' ? 'Domain' : 'Mail server'} fullWidth value={target}
              placeholder={mode === 'domain' ? 'example.com' : 'mail.example.com'}
              onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} />
          </Grid>
          {mode === 'host' && (
            <Grid item xs={12} md={4}>
              <TextField select label="Port / protocol" fullWidth value={port} onChange={(e) => setPort(e.target.value)}>
                {PORTS.map((p) => <MenuItem key={p.port} value={p.port}>{p.label}</MenuItem>)}
              </TextField>
            </Grid>
          )}
          <Grid item xs={12} md={3}>
            <Button variant="contained" fullWidth onClick={run} disabled={loading}>
              {loading ? 'Testing...' : 'Test'}
            </Button>
          </Grid>
        </Grid>
        {mode === 'host' && (
          <FormControlLabel sx={{ mt: 1 }} control={<Checkbox checked={deep} onChange={(e) => setDeep(e.target.checked)} />}
            label="Test every cipher suite (many connections; some mail servers rate-limit)" />
        )}
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>

      {result && result.mx && (
        <Paper sx={{ p: 3, mb: 2 }}>
          <Stack direction="row" spacing={2} alignItems="center">
            {result.grade && <Chip label={`Worst grade ${result.grade}`} color={gradeColor(result.grade)} />}
            <Typography>{result.domain}: {result.mx.length} MX host(s)</Typography>
          </Stack>
          {result.findings.length > 0 && (
            <Stack spacing={1} sx={{ mt: 2 }}>
              {result.findings.map((f, i) => <Alert key={i} severity={severityOf(f.severity)}>{f.message}</Alert>)}
            </Stack>
          )}
        </Paper>
      )}
      <Stack spacing={2}>
        {hosts.map((h) => <HostResult key={`${h.host}:${h.port}`} r={h} />)}
      </Stack>
    </Box>
  );
}

export default MailTLS;
