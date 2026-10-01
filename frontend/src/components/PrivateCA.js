import React, { useState } from 'react';
import {
  Alert, Box, Button, FormControl, Grid, InputLabel, MenuItem, Paper, Select, Stack, TextField, Typography,
} from '@mui/material';
import { AccountBalance as AccountBalanceIcon } from '@mui/icons-material';
import { caAPI } from '../services/api';

const monoField = { sx: { '& textarea': { fontFamily: 'monospace', fontSize: 12 } } };

const download = (filename, content, base64 = false) => {
  const data = base64 ? Uint8Array.from(atob(content), (c) => c.charCodeAt(0)) : content;
  const url = URL.createObjectURL(new Blob([data]));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

function PemOutput({ label, value, filename }) {
  return (
    <Box>
      <TextField label={label} value={value} multiline minRows={4} maxRows={8} fullWidth InputProps={{ readOnly: true }} {...monoField} />
      <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
        <Button size="small" onClick={() => navigator.clipboard?.writeText(value)}>Copy</Button>
        <Button size="small" onClick={() => download(filename, value)}>Download</Button>
      </Stack>
    </Box>
  );
}

function PrivateCA() {
  const [caForm, setCaForm] = useState({ common_name: '', organization: '', validity_days: 3650 });
  const [ca, setCa] = useState({ certificate: '', key: '', password: '' });
  const [issueForm, setIssueForm] = useState({ common_name: '', sans: '', usage: 'server', validity_days: 365, pkcs12_password: '' });
  const [created, setCreated] = useState(null);
  const [issued, setIssued] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const call = async (fn) => {
    setError('');
    setLoading(true);
    try {
      await fn();
    } catch (err) {
      setError(err.response?.data?.error || 'Request failed.');
    } finally {
      setLoading(false);
    }
  };

  const createCA = () => call(async () => {
    const { data } = await caAPI.create({ ...caForm, validity_days: Number(caForm.validity_days) });
    setCreated(data.result);
    setCa({ certificate: data.result.ca_certificate_pem, key: data.result.ca_private_key_pem, password: '' });
  });

  const issue = () => call(async () => {
    const { data } = await caAPI.issue({
      ca_certificate: ca.certificate,
      ca_private_key: ca.key,
      ca_key_password: ca.password || undefined,
      common_name: issueForm.common_name,
      sans: issueForm.sans.split(',').map((s) => s.trim()).filter(Boolean),
      usage: issueForm.usage,
      validity_days: Number(issueForm.validity_days),
      pkcs12_password: issueForm.pkcs12_password || undefined,
    });
    setIssued(data.result);
  });

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <AccountBalanceIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Private CA
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Create an internal root CA and issue server or client (mTLS) certificates from it. Nothing is stored on the server: keep the CA key safe and offline.
      </Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>1. Create a root CA</Typography>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={4}>
            <TextField label="CA common name" fullWidth value={caForm.common_name}
              onChange={(e) => setCaForm({ ...caForm, common_name: e.target.value })} placeholder="Acme Internal Root CA" />
          </Grid>
          <Grid item xs={12} md={3}>
            <TextField label="Organization" fullWidth value={caForm.organization}
              onChange={(e) => setCaForm({ ...caForm, organization: e.target.value })} />
          </Grid>
          <Grid item xs={6} md={2}>
            <TextField label="Validity (days)" type="number" fullWidth value={caForm.validity_days}
              onChange={(e) => setCaForm({ ...caForm, validity_days: e.target.value })} />
          </Grid>
          <Grid item xs={6} md={3}>
            <Button variant="contained" fullWidth disabled={loading || !caForm.common_name.trim()} onClick={createCA}>Create CA</Button>
          </Grid>
        </Grid>
        {created && (
          <Stack spacing={2} sx={{ mt: 2 }}>
            <Alert severity="warning">{created.warning}</Alert>
            <PemOutput label="CA certificate (distribute to clients)" value={created.ca_certificate_pem} filename="ca.crt" />
            <PemOutput label="CA private key (keep secret)" value={created.ca_private_key_pem} filename="ca.key" />
          </Stack>
        )}
      </Paper>

      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" gutterBottom>2. Issue a certificate</Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} md={6}>
            <TextField label="CA certificate (PEM)" multiline minRows={4} maxRows={8} fullWidth value={ca.certificate}
              onChange={(e) => setCa({ ...ca, certificate: e.target.value })} {...monoField} />
          </Grid>
          <Grid item xs={12} md={6}>
            <TextField label="CA private key (PEM)" multiline minRows={4} maxRows={8} fullWidth value={ca.key}
              onChange={(e) => setCa({ ...ca, key: e.target.value })} {...monoField} />
          </Grid>
          <Grid item xs={12} md={4}>
            <TextField label="Common name" fullWidth value={issueForm.common_name}
              onChange={(e) => setIssueForm({ ...issueForm, common_name: e.target.value })} placeholder="app.internal" />
          </Grid>
          <Grid item xs={12} md={5}>
            <TextField label="Subject alternative names (comma separated)" fullWidth value={issueForm.sans}
              onChange={(e) => setIssueForm({ ...issueForm, sans: e.target.value })} placeholder="www.internal, 10.0.0.5" />
          </Grid>
          <Grid item xs={6} md={3}>
            <FormControl fullWidth>
              <InputLabel id="usage-label">Usage</InputLabel>
              <Select labelId="usage-label" label="Usage" value={issueForm.usage}
                onChange={(e) => setIssueForm({ ...issueForm, usage: e.target.value })}>
                <MenuItem value="server">Server (TLS)</MenuItem>
                <MenuItem value="client">Client (mTLS)</MenuItem>
                <MenuItem value="both">Both</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={6} md={3}>
            <TextField label="Validity (days, max 825)" type="number" fullWidth value={issueForm.validity_days}
              onChange={(e) => setIssueForm({ ...issueForm, validity_days: e.target.value })} />
          </Grid>
          <Grid item xs={12} md={3}>
            <TextField label="PKCS#12 password (optional)" type="password" fullWidth value={issueForm.pkcs12_password}
              onChange={(e) => setIssueForm({ ...issueForm, pkcs12_password: e.target.value })} />
          </Grid>
          <Grid item xs={12} md={3}>
            <TextField label="CA key password (if encrypted)" type="password" fullWidth value={ca.password}
              onChange={(e) => setCa({ ...ca, password: e.target.value })} />
          </Grid>
          <Grid item xs={12} md={3}>
            <Button variant="contained" fullWidth sx={{ height: '100%' }} onClick={issue}
              disabled={loading || !ca.certificate || !ca.key || !issueForm.common_name.trim()}>
              Issue certificate
            </Button>
          </Grid>
        </Grid>
        {issued && (
          <Stack spacing={2} sx={{ mt: 3 }}>
            <PemOutput label="Certificate" value={issued.certificate_pem} filename="server.crt" />
            <PemOutput label="Full chain" value={issued.fullchain_pem} filename="fullchain.pem" />
            {issued.private_key_pem && <PemOutput label="Private key" value={issued.private_key_pem} filename="server.key" />}
            {issued.pkcs12_base64 && (
              <Button variant="outlined" onClick={() => download('certificate.p12', issued.pkcs12_base64, true)}>
                Download PKCS#12 bundle
              </Button>
            )}
          </Stack>
        )}
      </Paper>
    </Box>
  );
}

export default PrivateCA;
