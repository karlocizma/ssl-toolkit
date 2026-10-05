import React, { useState } from 'react';
import {
  Alert, Box, Button, Chip, Grid, Paper, Stack, TextField, Typography,
} from '@mui/material';
import { Event as EventIcon } from '@mui/icons-material';
import { sslCheckAPI } from '../services/api';
import ResultActions from './ResultActions';

const severityOf = (s) => (s === 'critical' ? 'error' : s === 'warning' ? 'warning' : 'info');

const expiryChip = (days) => {
  if (days === null || days === undefined) return <Chip label="Expiry not published" />;
  if (days < 0) return <Chip color="error" label={`Expired ${-days} days ago`} />;
  if (days <= 30) return <Chip color="warning" label={`${days} days left`} />;
  return <Chip color="success" label={`${days} days left`} />;
};

const Row = ({ label, children }) => (
  <Stack direction="row" spacing={2} sx={{ py: 0.5 }}>
    <Typography variant="body2" color="text.secondary" sx={{ minWidth: 130 }}>{label}</Typography>
    <Typography variant="body2" sx={{ wordBreak: 'break-word' }}>{children}</Typography>
  </Stack>
);

const fmt = (iso) => (iso ? new Date(iso).toLocaleDateString() : '—');

function DomainExpiry() {
  const [domain, setDomain] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!domain.trim()) {
      setError('Domain is required');
      return;
    }
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const response = await sslCheckAPI.checkDomainRegistration({ domain: domain.trim() });
      setResult(response.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Lookup failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <EventIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Domain Expiry
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        When does the domain registration expire? Looked up over RDAP directly at the registry, so nothing is sent to a
        third-party WHOIS site. Hosts in the Domain Monitor are checked automatically and trigger the same expiry alerts as certificates.
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={9}>
            <TextField label="Domain" fullWidth value={domain} placeholder="example.com"
              onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} />
          </Grid>
          <Grid item xs={12} md={3}>
            <Button variant="contained" fullWidth onClick={run} disabled={loading}>
              {loading ? 'Looking up...' : 'Look up'}
            </Button>
          </Grid>
        </Grid>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>

<ResultActions tool="domain-expiry" title={`Domain expiry: ${domain}`} result={result} />
      {result && (
        <Paper sx={{ p: 3 }}>
          <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2 }}>
            <Typography variant="h6">{result.domain}</Typography>
            {expiryChip(result.days_until_expiry)}
          </Stack>
          <Row label="Expires">{fmt(result.expires)}</Row>
          <Row label="Registered">{fmt(result.registered)}</Row>
          <Row label="Last changed">{fmt(result.last_changed)}</Row>
          <Row label="Registrar">{result.registrar || '—'}</Row>
          <Row label="Status">{result.status.length ? result.status.join(', ') : '—'}</Row>
          <Row label="Name servers">{result.nameservers.length ? result.nameservers.join(', ') : '—'}</Row>
          <Row label="DNSSEC">{result.dnssec ? 'signed' : 'not signed'}</Row>
          {result.findings.length > 0 && (
            <Stack spacing={1} sx={{ mt: 2 }}>
              {result.findings.map((f, i) => <Alert key={i} severity={severityOf(f.severity)}>{f.message}</Alert>)}
            </Stack>
          )}
        </Paper>
      )}
    </Box>
  );
}

export default DomainExpiry;
