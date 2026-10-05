import React, { useState } from 'react';
import {
  Alert, Box, Button, Chip, Grid, Paper, Stack, TextField, Typography,
} from '@mui/material';
import { Http as HttpIcon } from '@mui/icons-material';
import { sslCheckAPI } from '../services/api';
import ResultActions from './ResultActions';

const statusColor = { pass: 'success', warn: 'warning', fail: 'error' };
const gradeColor = (grade) => (grade.startsWith('A') ? 'success' : grade === 'B' ? 'info' : grade === 'C' ? 'warning' : 'error');

function SecurityHeaders() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleCheck = async () => {
    if (!url.trim()) {
      setError('URL or hostname is required');
      return;
    }
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const response = await sslCheckAPI.checkHeaders({ url: url.trim() });
      setResult(response.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Header check failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <HttpIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Security Headers
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Audit HSTS, CSP, framing, referrer and cookie settings of a website and get a score out of 100.
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={9}>
            <TextField label="URL or hostname" fullWidth value={url}
              onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com"
              onKeyDown={(e) => e.key === 'Enter' && handleCheck()} />
          </Grid>
          <Grid item xs={12} md={3}>
            <Button variant="contained" fullWidth onClick={handleCheck} disabled={loading}>
              {loading ? 'Checking...' : 'Check'}
            </Button>
          </Grid>
        </Grid>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>

<ResultActions tool="security-headers" title={`Security headers: ${url}`} result={result} />
      {result && (
        <Stack spacing={2}>
          <Paper sx={{ p: 3 }}>
            <Stack direction="row" spacing={2} alignItems="center">
              <Chip label={`${result.grade} · ${result.score}/100`} color={gradeColor(result.grade)} sx={{ fontSize: 20, p: 2.5 }} />
              <Typography>
                {result.final_url} (HTTP {result.status_code})
              </Typography>
            </Stack>
          </Paper>
          {result.checks.map((c) => (
            <Paper key={c.header} variant="outlined" sx={{ p: 2 }}>
              <Stack direction="row" justifyContent="space-between" alignItems="center">
                <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{c.header}</Typography>
                <Chip size="small" color={statusColor[c.status]} label={`${c.points}/${c.max_points}`} />
              </Stack>
              <Typography variant="body2" color="text.secondary">{c.detail}</Typography>
              {c.value && (
                <Typography variant="caption" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{c.value}</Typography>
              )}
            </Paper>
          ))}
        </Stack>
      )}
    </Box>
  );
}

export default SecurityHeaders;
