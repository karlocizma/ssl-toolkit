import React, { useState } from 'react';
import {
  Alert, Box, Button, Chip, Grid, Paper, Stack, TextField, Typography,
} from '@mui/material';
import { AlternateEmail as AlternateEmailIcon } from '@mui/icons-material';
import { sslCheckAPI } from '../services/api';

const severityMap = { error: 'error', warning: 'warning', info: 'info' };
const statusChip = {
  ok: { label: 'Autodiscover works', color: 'success' },
  partial: { label: 'Partially configured', color: 'warning' },
  failed: { label: 'Not configured', color: 'error' },
};

function StepCard({ step }) {
  const protocols = step.parsed?.protocols || [];
  const servers = step.parsed?.servers || [];
  return (
    <Paper variant="outlined" sx={{ p: 2 }}>
      <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={2}>
        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{step.step}</Typography>
        <Chip size="small" color={step.ok ? 'success' : 'default'} label={step.ok ? 'OK' : 'Failed'} />
      </Stack>
      <Typography variant="body2" sx={{ mt: 0.5 }}>{step.result}</Typography>
      <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace', wordBreak: 'break-all', display: 'block' }}>
        {step.method} {step.url}
      </Typography>
      {step.hops?.length > 1 && (
        <Box sx={{ mt: 1 }}>
          {step.hops.map((h, i) => (
            <Typography key={i} variant="caption" sx={{ fontFamily: 'monospace', display: 'block', wordBreak: 'break-all' }}>
              {i > 0 ? '↳ ' : ''}{h.status} {h.url}
            </Typography>
          ))}
        </Box>
      )}
      {[...protocols, ...servers].map((p, i) => (
        <Typography key={i} variant="body2" sx={{ fontFamily: 'monospace', mt: 0.5 }}>
          {Object.entries(p).map(([k, v]) => `${k}=${v}`).join('  ')}
        </Typography>
      ))}
    </Paper>
  );
}

function AutodiscoverChecker() {
  const [domain, setDomain] = useState('');
  const [email, setEmail] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!domain.trim() && !email.trim()) {
      setError('Enter a domain or an email address');
      return;
    }
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const { data } = await sslCheckAPI.checkAutodiscover({
        domain: domain.trim() || undefined, email: email.trim() || undefined,
      });
      setResult(data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Check failed.');
    } finally {
      setLoading(false);
    }
  };

  const chip = result && statusChip[result.status];

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <AlternateEmailIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Autodiscover Check
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Runs the lookups mail clients use to configure themselves: Outlook Autodiscover, Thunderbird autoconfig and RFC 6186 SRV records. No credentials are sent, so an Exchange server answering "requires authentication" is the expected, healthy result.
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={4}>
            <TextField label="Domain" fullWidth value={domain} placeholder="example.com"
              onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} />
          </Grid>
          <Grid item xs={12} md={5}>
            <TextField label="Mailbox (optional)" fullWidth value={email} placeholder="user@example.com"
              onChange={(e) => setEmail(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} />
          </Grid>
          <Grid item xs={12} md={3}>
            <Button variant="contained" fullWidth onClick={run} disabled={loading}>
              {loading ? 'Checking...' : 'Run check'}
            </Button>
          </Grid>
        </Grid>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>

      {result && (
        <Stack spacing={2}>
          <Paper sx={{ p: 3 }}>
            <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap">
              <Chip label={chip.label} color={chip.color} />
              <Typography>{result.domain} (tested as {result.email})</Typography>
            </Stack>
            <Stack spacing={1} sx={{ mt: 2 }}>
              {result.findings.map((f, i) => (
                <Alert key={i} severity={severityMap[f.severity] || 'info'}>{f.message}</Alert>
              ))}
            </Stack>
          </Paper>

          <Typography variant="h6">Lookup steps</Typography>
          {result.steps.map((s, i) => <StepCard key={i} step={s} />)}

          <Typography variant="h6">RFC 6186 SRV records</Typography>
          <Paper variant="outlined" sx={{ p: 2 }}>
            {[result.dns.srv_autodiscover, ...result.rfc6186].map((r) => (
              <Typography key={r.name} variant="body2" sx={{ fontFamily: 'monospace' }}>
                {r.name}: {r.records.length ? r.records.map((x) => `${x.target}:${x.port}`).join(', ') : 'not published'}
              </Typography>
            ))}
          </Paper>
        </Stack>
      )}
    </Box>
  );
}

export default AutodiscoverChecker;
