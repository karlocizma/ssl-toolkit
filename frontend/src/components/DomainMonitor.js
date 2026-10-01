import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert, Box, Button, Chip, Grid, IconButton, Paper, Stack, TextField, Tooltip, Typography,
} from '@mui/material';
import { Delete as DeleteIcon, Refresh as RefreshIcon, Visibility as VisibilityIcon } from '@mui/icons-material';
import { accessToken, monitorAPI } from '../services/api';

const statusChip = (d) => {
  if (d.status === 'error') return <Chip size="small" color="error" label="Unreachable" />;
  if (d.status === 'pending') return <Chip size="small" label="Pending" />;
  const days = d.days_until_expiry;
  if (days < 0) return <Chip size="small" color="error" label="Expired" />;
  if (days <= 7) return <Chip size="small" color="error" label={`${days} days left`} />;
  if (days <= 30) return <Chip size="small" color="warning" label={`${days} days left`} />;
  return <Chip size="small" color="success" label={`${days} days left`} />;
};

function DomainMonitor() {
  const [domains, setDomains] = useState([]);
  const [hostname, setHostname] = useState('');
  const [port, setPort] = useState(443);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [token, setToken] = useState(accessToken.get());

  const load = useCallback(async () => {
    try {
      const response = await monitorAPI.listDomains();
      setDomains(response.data.domains);
    } catch (err) {
      setError(err.response?.data?.error || 'Unable to load monitored domains.');
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const saveToken = () => {
    accessToken.set(token.trim());
    setError('');
    load();
  };

  const run = async (fn) => {
    setError('');
    setBusy(true);
    try {
      await fn();
      await load();
    } catch (err) {
      setError(err.response?.data?.message || err.response?.data?.error || 'Request failed.');
    } finally {
      setBusy(false);
    }
  };

  const handleAdd = () => {
    if (!hostname.trim()) {
      setError('Hostname is required');
      return;
    }
    run(async () => {
      await monitorAPI.addDomain({ hostname: hostname.trim(), port: Number(port) });
      setHostname('');
    });
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <VisibilityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Domain Monitor
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Domains are re-checked automatically. Expiry warnings and certificate changes (renewals, issuer changes) are sent through the configured email or webhook channels.
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2} alignItems="center" sx={{ mb: 2 }}>
          <Grid item xs={12} md={9}>
            <TextField label="Access token (API key or admin token)" type="password" fullWidth value={token}
              onChange={(e) => setToken(e.target.value)} helperText="Required unless the server sets MONITOR_PUBLIC=true. Kept for this browser tab only." />
          </Grid>
          <Grid item xs={12} md={3}>
            <Button variant="outlined" fullWidth onClick={saveToken}>Use token</Button>
          </Grid>
        </Grid>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={6}>
            <TextField label="Hostname" fullWidth value={hostname} placeholder="example.com"
              onChange={(e) => setHostname(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && handleAdd()} />
          </Grid>
          <Grid item xs={6} md={3}>
            <TextField label="Port" type="number" fullWidth value={port} onChange={(e) => setPort(e.target.value)} />
          </Grid>
          <Grid item xs={6} md={3}>
            <Button variant="contained" fullWidth onClick={handleAdd} disabled={busy}>Add domain</Button>
          </Grid>
        </Grid>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>

      <Stack spacing={1.5}>
        {domains.length === 0 && <Typography color="text.secondary">No domains monitored yet.</Typography>}
        {domains.map((d) => (
          <Paper key={d.id} variant="outlined" sx={{ p: 2 }}>
            <Stack direction="row" alignItems="center" justifyContent="space-between" spacing={2}>
              <Box sx={{ minWidth: 0 }}>
                <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
                  {d.hostname}{d.port !== 443 ? `:${d.port}` : ''}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {d.status === 'error'
                    ? d.last_error
                    : d.issuer
                      ? `Issuer: ${d.issuer} · expires ${new Date(d.not_after).toLocaleDateString()}`
                      : 'Not checked yet'}
                  {d.last_check ? ` · checked ${new Date(d.last_check).toLocaleString()}` : ''}
                </Typography>
                {d.changes?.length > 0 && (
                  <Typography variant="caption" color="text.secondary">
                    Last certificate change: {new Date(d.changes[d.changes.length - 1].detected_at).toLocaleString()}
                  </Typography>
                )}
              </Box>
              <Stack direction="row" alignItems="center" spacing={1}>
                {statusChip(d)}
                <Tooltip title="Check now">
                  <span>
                    <IconButton disabled={busy} onClick={() => run(() => monitorAPI.checkDomain(d.id))}>
                      <RefreshIcon />
                    </IconButton>
                  </span>
                </Tooltip>
                <Tooltip title="Remove">
                  <span>
                    <IconButton disabled={busy} onClick={() => run(() => monitorAPI.removeDomain(d.id))}>
                      <DeleteIcon />
                    </IconButton>
                  </span>
                </Tooltip>
              </Stack>
            </Stack>
          </Paper>
        ))}
      </Stack>
    </Box>
  );
}

export default DomainMonitor;
