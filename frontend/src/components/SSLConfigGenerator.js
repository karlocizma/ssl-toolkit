import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  TextField,
  Button,
  MenuItem,
  Switch,
  FormControlLabel,
  Stack,
  Divider,
  Alert,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import { Code as CodeIcon } from '@mui/icons-material';
import { sysAdminAPI } from '../services/api';

const serverOptions = [
  { label: 'Nginx', value: 'nginx' },
  { label: 'Apache', value: 'apache' },
  { label: 'HAProxy', value: 'haproxy' },
];

const tlsOptions = [
  { label: 'TLS 1.2 + 1.3 (recommended)', value: 'TLSv1.2' },
  { label: 'TLS 1.3 only (strictest)', value: 'TLSv1.3' },
];

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <Button size="small" variant="outlined" onClick={handleCopy}>
      {copied ? 'Copied!' : 'Copy'}
    </Button>
  );
}

function SSLConfigGenerator() {
  const [form, setForm] = useState({
    server: 'nginx',
    domain: '',
    cert_path: '/etc/ssl/certs/server.crt',
    key_path: '/etc/ssl/private/server.key',
    chain_path: '',
    min_tls: 'TLSv1.2',
    hsts: true,
    ocsp_stapling: true,
  });
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });
  const handleToggle = (name) => setForm({ ...form, [name]: !form[name] });

  const handleGenerate = async () => {
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const response = await sysAdminAPI.generateSSLConfig(form);
      setResult(response.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Generation failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box sx={{ maxWidth: 900, mx: 'auto', p: 3 }}>
      <Stack direction="row" alignItems="center" spacing={1} mb={3}>
        <CodeIcon color="primary" />
        <Typography variant="h4" fontWeight={700}>SSL Config Generator</Typography>
      </Stack>

      <Paper sx={{ p: 3, mb: 4 }}>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={4}>
            <TextField
              select
              label="Web Server"
              name="server"
              value={form.server}
              onChange={handleChange}
              fullWidth
            >
              {serverOptions.map((o) => (
                <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
              ))}
            </TextField>
          </Grid>
          <Grid item xs={12} sm={8}>
            <TextField
              label="Domain"
              name="domain"
              value={form.domain}
              onChange={handleChange}
              fullWidth
              placeholder="example.com"
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Certificate Path"
              name="cert_path"
              value={form.cert_path}
              onChange={handleChange}
              fullWidth
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Private Key Path"
              name="key_path"
              value={form.key_path}
              onChange={handleChange}
              fullWidth
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Chain / CA Bundle Path (optional)"
              name="chain_path"
              value={form.chain_path}
              onChange={handleChange}
              fullWidth
              placeholder="/etc/ssl/certs/chain.pem"
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              select
              label="Minimum TLS Version"
              name="min_tls"
              value={form.min_tls}
              onChange={handleChange}
              fullWidth
            >
              {tlsOptions.map((o) => (
                <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
              ))}
            </TextField>
          </Grid>
          <Grid item xs={12} sm={6}>
            <FormControlLabel
              control={
                <Switch
                  checked={form.hsts}
                  onChange={() => handleToggle('hsts')}
                  color="primary"
                />
              }
              label="Enable HSTS"
            />
          </Grid>
          {form.server !== 'haproxy' && (
            <Grid item xs={12} sm={6}>
              <FormControlLabel
                control={
                  <Switch
                    checked={form.ocsp_stapling}
                    onChange={() => handleToggle('ocsp_stapling')}
                    color="primary"
                  />
                }
                label="Enable OCSP Stapling"
              />
            </Grid>
          )}
          <Grid item xs={12}>
            <Button
              variant="contained"
              size="large"
              onClick={handleGenerate}
              disabled={loading || !form.domain || !form.cert_path || !form.key_path}
            >
              {loading ? 'Generating…' : 'Generate Config'}
            </Button>
          </Grid>
        </Grid>
      </Paper>

      {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

      {result && (
        <Paper sx={{ p: 3 }}>
          <Stack direction="row" alignItems="center" justifyContent="space-between" mb={2}>
            <Typography variant="h6">
              {result.server.charAt(0).toUpperCase() + result.server.slice(1)} Config — {result.domain}
            </Typography>
            <CopyButton text={result.config_snippet} />
          </Stack>
          <Paper
            variant="outlined"
            sx={{ p: 2, bgcolor: 'action.hover', overflow: 'auto' }}
          >
            <Typography
              component="pre"
              sx={{ fontFamily: 'monospace', fontSize: '0.78rem', margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
            >
              {result.config_snippet}
            </Typography>
          </Paper>

          {result.notes?.length > 0 && (
            <Box mt={2}>
              <Divider sx={{ mb: 2 }} />
              <Typography variant="subtitle2" gutterBottom>Notes</Typography>
              <List dense disablePadding>
                {result.notes.map((note, i) => (
                  <ListItem key={i} disableGutters>
                    <ListItemText primary={note} />
                  </ListItem>
                ))}
              </List>
            </Box>
          )}
        </Paper>
      )}
    </Box>
  );
}

export default SSLConfigGenerator;
