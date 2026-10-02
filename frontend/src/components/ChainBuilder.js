import React, { useState } from 'react';
import {
  Alert, Box, Button, Checkbox, Chip, FormControlLabel, Grid, Paper, Stack, Tab, Tabs, TextField, Typography,
} from '@mui/material';
import { Layers as LayersIcon } from '@mui/icons-material';
import { chainAPI } from '../services/api';

const mono = { sx: { '& textarea': { fontFamily: 'monospace', fontSize: 12 } } };
const roleColor = { leaf: 'primary', intermediate: 'info', root: 'default' };

const download = (filename, content) => {
  const url = URL.createObjectURL(new Blob([content]));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

function Pem({ label, value, filename }) {
  return (
    <Box>
      <TextField label={label} value={value} multiline minRows={3} maxRows={8} fullWidth InputProps={{ readOnly: true }} {...mono} />
      <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
        <Button size="small" onClick={() => navigator.clipboard?.writeText(value)}>Copy</Button>
        <Button size="small" onClick={() => download(filename, value)}>Download</Button>
      </Stack>
    </Box>
  );
}

function ChainBuilder() {
  const [tab, setTab] = useState(0);
  const [certificate, setCertificate] = useState('');
  const [hostname, setHostname] = useState('');
  const [includeRoot, setIncludeRoot] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const build = async () => {
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const payload = tab === 0 ? { certificate, include_root: includeRoot } : { hostname: hostname.trim(), include_root: includeRoot };
      const { data } = await chainAPI.build(payload);
      setResult(data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Could not build the chain.');
    } finally {
      setLoading(false);
    }
  };

  const ready = tab === 0 ? certificate.trim().length > 0 : hostname.trim().length > 0;

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <LayersIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Chain Builder
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Missing or mis-ordered intermediate certificates are one of the most common deployment errors: browsers may cope, but many clients and APIs fail. Paste a leaf (or a messy bundle), or point at a server, and get a correct <code>fullchain.pem</code>.
      </Typography>
      <Paper sx={{ p: 3, mb: 3 }}>
        <Tabs value={tab} onChange={(_, v) => { setTab(v); setResult(null); setError(''); }} sx={{ mb: 2 }}>
          <Tab label="Paste certificate(s)" />
          <Tab label="Check a server" />
        </Tabs>
        {tab === 0 ? (
          <TextField label="Leaf certificate or PEM bundle" multiline minRows={6} maxRows={14} fullWidth value={certificate}
            onChange={(e) => setCertificate(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" {...mono} />
        ) : (
          <TextField label="Hostname" fullWidth value={hostname} placeholder="example.com"
            onChange={(e) => setHostname(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && ready && build()} />
        )}
        <Grid container spacing={2} alignItems="center" sx={{ mt: 0.5 }}>
          <Grid item>
            <FormControlLabel control={<Checkbox checked={includeRoot} onChange={(e) => setIncludeRoot(e.target.checked)} />}
              label="Include the root certificate in the output" />
          </Grid>
          <Grid item>
            <Button variant="contained" disabled={loading || !ready} onClick={build}>{loading ? 'Building...' : 'Build chain'}</Button>
          </Grid>
        </Grid>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>

      {result && (
        <Stack spacing={2}>
          <Paper sx={{ p: 3 }}>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" sx={{ mb: 1 }}>
              <Chip color={result.complete ? 'success' : 'error'} label={result.complete ? 'Chain complete' : 'Chain incomplete'} />
              <Chip color={result.trusted ? 'success' : 'warning'} label={result.trusted ? 'Trusted root' : 'Root not in the Mozilla store'} />
              <Typography variant="body2">for {result.leaf}</Typography>
            </Stack>
            <Stack spacing={1}>
              {result.findings.map((f, i) => (
                <Alert key={i} severity={f.severity === 'error' ? 'error' : f.severity === 'warning' ? 'warning' : 'info'}>{f.message}</Alert>
              ))}
            </Stack>
          </Paper>

          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>Chain (leaf first)</Typography>
            <Stack spacing={1}>
              {result.chain.map((c) => (
                <Paper key={c.sha256} variant="outlined" sx={{ p: 1.5 }}>
                  <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                    <Chip size="small" color={roleColor[c.role]} label={c.role} />
                    <Typography sx={{ fontWeight: 600 }}>{c.subject}</Typography>
                    {c.expired && <Chip size="small" color="error" label="expired" />}
                  </Stack>
                  <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                    issued by {c.issuer} · valid until {new Date(c.not_after).toLocaleDateString()} · {c.signature_hash} · {c.source}
                  </Typography>
                </Paper>
              ))}
            </Stack>
          </Paper>

          <Pem label="fullchain.pem (use this on the server)" value={result.fullchain_pem} filename="fullchain.pem" />
          {result.chain_pem && <Pem label="chain.pem (intermediates only)" value={result.chain_pem} filename="chain.pem" />}
        </Stack>
      )}
    </Box>
  );
}

export default ChainBuilder;
