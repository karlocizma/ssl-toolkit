import React, { useState } from 'react';
import {
  Alert, Box, Button, Chip, Grid, Paper, Stack, TextField, Typography,
} from '@mui/material';
import { Lock as LockIcon } from '@mui/icons-material';
import { sslCheckAPI } from '../services/api';
import ResultActions from './ResultActions';

const gradeColor = (grade) => {
  if (grade === 'A' || grade === 'A-') return 'success';
  if (grade === 'B') return 'info';
  if (grade === 'C') return 'warning';
  return 'error';
};
const severityColor = { critical: 'error', warning: 'warning', weak: 'warning', info: 'info' };

function TLSScanner() {
  const [hostname, setHostname] = useState('');
  const [port, setPort] = useState(443);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleScan = async () => {
    if (!hostname.trim()) {
      setError('Hostname is required');
      return;
    }
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const response = await sslCheckAPI.scanTLS({ hostname: hostname.trim(), port: Number(port) });
      setResult(response.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Scan failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <LockIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        TLS Scanner
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Test which TLS versions and cipher suites a server accepts, and get a grade. Runs from this server, so nothing is sent to third-party scanners.
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={6}>
            <TextField label="Hostname" fullWidth value={hostname}
              onChange={(e) => setHostname(e.target.value)} placeholder="example.com"
              onKeyDown={(e) => e.key === 'Enter' && handleScan()} />
          </Grid>
          <Grid item xs={6} md={3}>
            <TextField label="Port" type="number" fullWidth value={port} onChange={(e) => setPort(e.target.value)} />
          </Grid>
          <Grid item xs={6} md={3}>
            <Button variant="contained" fullWidth onClick={handleScan} disabled={loading}>
              {loading ? 'Scanning...' : 'Scan'}
            </Button>
          </Grid>
        </Grid>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>

<ResultActions tool="tls-scanner" title={`TLS scan: ${hostname}:${port}`} result={result} />
      {result && !result.reachable && <Alert severity="warning">{result.error}</Alert>}

      {result && result.reachable && (
        <Stack spacing={2}>
          <Paper sx={{ p: 3 }}>
            <Stack direction="row" spacing={2} alignItems="center">
              <Chip label={`Grade ${result.grade}`} color={gradeColor(result.grade)} sx={{ fontSize: 20, p: 2.5 }} />
              <Typography>
                {result.hostname}:{result.port} — certificate {result.certificate_trusted ? 'trusted' : 'NOT trusted'}
              </Typography>
            </Stack>
            {result.findings.length > 0 && (
              <Stack spacing={1} sx={{ mt: 2 }}>
                {result.findings.map((f, i) => (
                  <Alert key={i} severity={severityColor[f.severity] === 'error' ? 'error' : severityColor[f.severity] || 'info'}>
                    {f.message}
                  </Alert>
                ))}
              </Stack>
            )}
          </Paper>

          <Grid container spacing={2}>
            {Object.entries(result.protocols).map(([name, data]) => (
              <Grid item xs={12} md={6} key={name}>
                <Paper variant="outlined" sx={{ p: 2, height: '100%' }}>
                  <Stack direction="row" justifyContent="space-between" alignItems="center">
                    <Typography variant="h6">{name}</Typography>
                    <Chip size="small" label={data.supported ? 'Supported' : 'Not supported'}
                      color={data.supported ? (name === 'TLSv1.0' || name === 'TLSv1.1' ? 'warning' : 'success') : 'default'} />
                  </Stack>
                  {data.supported && (
                    <Box component="ul" sx={{ pl: 3, mb: 0 }}>
                      {data.ciphers.map((c) => (
                        <li key={c.name}>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {c.name}{' '}
                            {c.forward_secrecy && <Chip size="small" label="PFS" color="success" variant="outlined" />}{' '}
                            {c.weakness && <Chip size="small" label={c.weakness.reason} color="error" variant="outlined" />}
                          </Typography>
                        </li>
                      ))}
                    </Box>
                  )}
                </Paper>
              </Grid>
            ))}
          </Grid>
        </Stack>
      )}
    </Box>
  );
}

export default TLSScanner;
