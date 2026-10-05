import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert, Box, Button, Checkbox, Chip, Collapse, FormControlLabel, Grid, IconButton, Paper, Stack, TextField, Tooltip, Typography,
} from '@mui/material';
import {
  Delete as DeleteIcon, Refresh as RefreshIcon, Visibility as VisibilityIcon, Timeline as TimelineIcon,
} from '@mui/icons-material';
import { monitorAPI } from '../services/api';
import TokenField from './TokenField';
import ExpiryHistoryChart from './ExpiryHistoryChart';

const saveBlob = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

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
  const [openHistory, setOpenHistory] = useState({});
  const [histories, setHistories] = useState({});
  const [importText, setImportText] = useState('');
  const [notice, setNotice] = useState('');
  const [channels, setChannels] = useState(null);
  const [alertMessage, setAlertMessage] = useState('');

  const load = useCallback(async () => {
    try {
      const response = await monitorAPI.listDomains();
      setDomains(response.data.domains);
    } catch (err) {
      setError(err.response?.data?.error || 'Unable to load monitored domains.');
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const useToken = () => {
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

  const toggleHistory = async (id) => {
    const opening = !openHistory[id];
    setOpenHistory({ ...openHistory, [id]: opening });
    if (opening) {
      try {
        const { data } = await monitorAPI.getDomain(id);
        setHistories((h) => ({ ...h, [id]: data.domain }));
      } catch (err) {
        setError(err.response?.data?.message || 'Could not load the history.');
      }
    }
  };

  const loadChannels = async () => {
    setAlertMessage('');
    try {
      const { data } = await monitorAPI.alertsConfig();
      setChannels(data.config);
    } catch (err) {
      setChannels(null);
      setAlertMessage(err.response?.status === 401 || err.response?.status === 403
        ? 'Alert settings need the admin token.' : (err.response?.data?.message || 'Could not load the alert settings.'));
    }
  };

  const sendTestAlert = async () => {
    setAlertMessage('');
    try {
      const { data } = await monitorAPI.alertsTest();
      const sent = data.deliveries.filter((x) => x.sent).map((x) => x.channel);
      setAlertMessage(sent.length ? `Test alert sent via ${sent.join(', ')}.` : 'No channel is configured, nothing was sent.');
    } catch (err) {
      setAlertMessage(err.response?.status === 401 || err.response?.status === 403
        ? 'Sending a test alert needs the admin token.' : 'Could not send the test alert.');
    }
  };

  const togglePublic = (d) => run(() => monitorAPI.setPublic(d.id, { public: !d.public }));

  const exportAs = (format) => run(async () => {
    const { data } = await monitorAPI.exportData(format);
    saveBlob(data, `monitor-export.${format}`);
  });

  const importHosts = () => run(async () => {
    const { data } = await monitorAPI.importCsv(importText);
    const skipped = data.results.filter((r) => r.status !== 'added');
    setNotice(`Imported ${data.added} host(s).${skipped.length ? ` Skipped: ${skipped.map((r) => `${r.hostname} (${r.message})`).join('; ')}` : ''}`);
    setImportText('');
  });

  const onImportFile = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setImportText(String(reader.result));
    reader.readAsText(file);
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
        Tick &quot;Public&quot; on a host to show its certificate expiry on the <a href="/status">public status page</a> (nothing else about it is shown).
        Domains are re-checked automatically. Expiry warnings and certificate changes (renewals, issuer changes) are sent through the configured email, Microsoft Teams or webhook channels.
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <TokenField label="Access token (API key or admin token)" onUse={useToken}
          helperText="Required unless the server sets MONITOR_PUBLIC=true. Kept for this browser tab unless you tick the box below." />
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

      <Paper sx={{ p: 3, mb: 3 }}>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
          <Typography variant="subtitle1" sx={{ fontWeight: 600, mr: 1 }}>Alert channels</Typography>
          <Button size="small" variant="outlined" onClick={loadChannels}>Show</Button>
          <Button size="small" variant="outlined" onClick={sendTestAlert}>Send test alert</Button>
          {channels && (
            <>
              <Chip size="small" label="Email" color={channels.email_configured ? 'success' : 'default'} />
              <Chip size="small" label="Teams" color={channels.teams_configured ? 'success' : 'default'} />
              <Chip size="small" label="Webhook" color={channels.webhook_configured ? 'success' : 'default'} />
              <Typography variant="caption" color="text.secondary">
                thresholds: {channels.thresholds.join(', ')} days
              </Typography>
            </>
          )}
        </Stack>
        {alertMessage && <Alert severity="info" sx={{ mt: 2 }}>{alertMessage}</Alert>}
      </Paper>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" sx={{ mb: 2 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 600, mr: 1 }}>Import / export</Typography>
          <Button size="small" variant="outlined" disabled={busy} onClick={() => exportAs('csv')}>Export CSV</Button>
          <Button size="small" variant="outlined" disabled={busy} onClick={() => exportAs('json')}>Export JSON</Button>
          <Button size="small" component="label">Load CSV file<input hidden type="file" accept=".csv,text/csv,text/plain" onChange={onImportFile} /></Button>
        </Stack>
        <TextField label="Import hosts: one per line as hostname[,port[,label[,tags]]] (max 100)" multiline minRows={3} maxRows={8}
          fullWidth value={importText} onChange={(e) => setImportText(e.target.value)}
          placeholder={'example.com\nmail.example.com,993,Mail server,prod'} sx={{ '& textarea': { fontFamily: 'monospace', fontSize: 12 } }} />
        <Button variant="contained" sx={{ mt: 1 }} disabled={busy || !importText.trim()} onClick={importHosts}>Import hosts</Button>
        {notice && <Alert severity="success" sx={{ mt: 2 }}>{notice}</Alert>}
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
                {d.registration?.expires && (
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                    Domain {d.registration.domain} registered until {new Date(d.registration.expires).toLocaleDateString()}
                    {d.registration.registrar ? ` (${d.registration.registrar})` : ''}
                  </Typography>
                )}
                {d.changes?.length > 0 && (
                  <Typography variant="caption" color="text.secondary">
                    Last certificate change: {new Date(d.changes[d.changes.length - 1].detected_at).toLocaleString()}
                  </Typography>
                )}
              </Box>
              <Stack direction="row" alignItems="center" spacing={1}>
                {statusChip(d)}
                <Tooltip title="Show this host's certificate expiry on the public status page">
                  <FormControlLabel sx={{ mr: 0 }} control={<Checkbox size="small" checked={!!d.public} disabled={busy} onChange={() => togglePublic(d)} />}
                    label={<Typography variant="caption">Public</Typography>} />
                </Tooltip>
                <Tooltip title="Expiry history">
                  <IconButton aria-label={`History for ${d.hostname}`} onClick={() => toggleHistory(d.id)}><TimelineIcon /></IconButton>
                </Tooltip>
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
            <Collapse in={!!openHistory[d.id]} unmountOnExit>
              <Box sx={{ mt: 2 }}>
                {histories[d.id]
                  ? <ExpiryHistoryChart history={histories[d.id].history} changes={histories[d.id].changes} />
                  : <Typography variant="caption">Loading…</Typography>}
              </Box>
            </Collapse>
          </Paper>
        ))}
      </Stack>
    </Box>
  );
}

export default DomainMonitor;
