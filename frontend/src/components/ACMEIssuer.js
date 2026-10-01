import React, { useState } from 'react';
import {
  Alert, Box, Button, FormControl, Grid, InputLabel, MenuItem, Paper, Select, Stack, Tab, Table, TableBody,
  TableCell, TableHead, TableRow, Tabs, TextField, Typography,
} from '@mui/material';
import { WorkspacePremium as WorkspacePremiumIcon } from '@mui/icons-material';
import { acmeAPI } from '../services/api';

const monoField = { sx: { '& textarea': { fontFamily: 'monospace', fontSize: 12 } } };

const download = (filename, content) => {
  const url = URL.createObjectURL(new Blob([content]));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

function PemOutput({ label, value, filename }) {
  return (
    <Box>
      <TextField label={label} value={value} multiline minRows={3} maxRows={8} fullWidth InputProps={{ readOnly: true }} {...monoField} />
      <Stack direction="row" spacing={1} sx={{ mt: 0.5 }}>
        <Button size="small" onClick={() => navigator.clipboard?.writeText(value)}>Copy</Button>
        <Button size="small" onClick={() => download(filename, value)}>Download</Button>
      </Stack>
    </Box>
  );
}

function CertificateResult({ result, privateKey, accountKey }) {
  return (
    <Stack spacing={2} sx={{ mt: 3 }}>
      <Alert severity="success">
        Certificate issued{result.certificate_info?.validity ? `, valid until ${new Date(result.certificate_info.validity.not_after).toLocaleDateString()}` : ''}.
        Nothing was stored on the server, so download your files now.
      </Alert>
      <PemOutput label="Full chain (certificate + intermediates)" value={result.fullchain_pem} filename="fullchain.pem" />
      <PemOutput label="Certificate" value={result.certificate_pem} filename="cert.pem" />
      {privateKey && <PemOutput label="Private key (keep secret)" value={privateKey} filename="privkey.pem" />}
      {accountKey && <PemOutput label="ACME account key (reuse it for renewals)" value={accountKey} filename="account.key" />}
    </Stack>
  );
}

function CommonFields({ form, setForm }) {
  return (
    <Grid container spacing={2}>
      <Grid item xs={12} md={6}>
        <TextField label="Domains (one per line; *.example.com for wildcards)" multiline minRows={3} fullWidth value={form.domains}
          onChange={(e) => setForm({ ...form, domains: e.target.value })} placeholder={'example.com\n*.example.com'} />
      </Grid>
      <Grid item xs={12} md={6}>
        <Stack spacing={2}>
          <TextField label="Contact email (optional)" fullWidth value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
          <FormControl fullWidth>
            <InputLabel id="dir-label">Certificate authority</InputLabel>
            <Select labelId="dir-label" label="Certificate authority" value={form.directory}
              onChange={(e) => setForm({ ...form, directory: e.target.value })}>
              <MenuItem value="letsencrypt-staging">Let's Encrypt staging (untrusted test certificates)</MenuItem>
              <MenuItem value="letsencrypt">Let's Encrypt production</MenuItem>
            </Select>
          </FormControl>
        </Stack>
      </Grid>
    </Grid>
  );
}

const parseDomains = (text) => text.split(/[\s,]+/).map((d) => d.trim()).filter(Boolean);

function ManualFlow() {
  const [form, setForm] = useState({ domains: '', email: '', directory: 'letsencrypt-staging', challenge_type: 'dns-01' });
  const [order, setOrder] = useState(null);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const run = async (fn) => {
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

  const start = () => run(async () => {
    setResult(null);
    const { data } = await acmeAPI.order({
      domains: parseDomains(form.domains), email: form.email || undefined,
      directory: form.directory, challenge_type: form.challenge_type,
    });
    setOrder(data.result);
  });

  const complete = () => run(async () => {
    const { data } = await acmeAPI.complete({
      directory: order.directory, order_url: order.order_url, account_key_pem: order.account_key_pem,
      csr_pem: order.csr_pem, challenge_type: order.challenge_type,
    });
    setResult(data.result);
  });

  return (
    <Box>
      <Typography color="text.secondary" paragraph>
        Step 1 creates the order and shows what to publish. Step 2, after you have published it, validates and issues the certificate.
      </Typography>
      <CommonFields form={form} setForm={setForm} />
      <Stack direction="row" spacing={2} sx={{ mt: 2 }} alignItems="center">
        <FormControl sx={{ minWidth: 220 }}>
          <InputLabel id="ct-label">Challenge</InputLabel>
          <Select labelId="ct-label" label="Challenge" value={form.challenge_type}
            onChange={(e) => setForm({ ...form, challenge_type: e.target.value })}>
            <MenuItem value="dns-01">DNS TXT record (dns-01)</MenuItem>
            <MenuItem value="http-01">File on port 80 (http-01)</MenuItem>
          </Select>
        </FormControl>
        <Button variant="contained" disabled={loading || !parseDomains(form.domains).length} onClick={start}>
          1. Create order
        </Button>
      </Stack>
      {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}

      {order && (
        <Paper variant="outlined" sx={{ p: 2, mt: 3 }}>
          <Typography variant="h6" gutterBottom>Publish these challenges</Typography>
          <Alert severity="info" sx={{ mb: 2 }}>{order.instructions}</Alert>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Domain</TableCell>
                <TableCell>{order.challenge_type === 'dns-01' ? 'TXT record name' : 'URL'}</TableCell>
                <TableCell>{order.challenge_type === 'dns-01' ? 'TXT value' : 'File content'}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {order.challenges.map((c, i) => (
                <TableRow key={i}>
                  <TableCell>{c.domain}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{c.dns_name || c.http_url}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{c.dns_value || c.http_content}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Button variant="contained" sx={{ mt: 2 }} disabled={loading} onClick={complete}>
            {loading ? 'Validating...' : "2. I've published them — validate and issue"}
          </Button>
        </Paper>
      )}
      {result && <CertificateResult result={result} privateKey={order?.private_key_pem} accountKey={order?.account_key_pem} />}
    </Box>
  );
}

function AutomaticFlow() {
  const [form, setForm] = useState({ domains: '', email: '', directory: 'letsencrypt-staging' });
  const [provider, setProvider] = useState({ type: 'cloudflare', api_token: '', zone_id: '', server: '', port: 53, zone: '', tsig_name: '', tsig_secret: '', tsig_algorithm: 'hmac-sha256' });
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const issue = async () => {
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const dns_provider = provider.type === 'cloudflare'
        ? { type: 'cloudflare', api_token: provider.api_token, zone_id: provider.zone_id || undefined }
        : { type: 'rfc2136', server: provider.server, port: Number(provider.port), zone: provider.zone,
            tsig_name: provider.tsig_name, tsig_secret: provider.tsig_secret, tsig_algorithm: provider.tsig_algorithm };
      const { data } = await acmeAPI.issue({
        domains: parseDomains(form.domains), email: form.email || undefined, directory: form.directory, dns_provider,
      });
      setResult(data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Issuance failed.');
    } finally {
      setLoading(false);
    }
  };

  const set = (k) => (e) => setProvider({ ...provider, [k]: e.target.value });

  return (
    <Box>
      <Typography color="text.secondary" paragraph>
        The toolkit publishes the DNS challenge records through your DNS provider, validates, issues and removes the records again. Provider credentials are used for this request only and never stored.
      </Typography>
      <CommonFields form={form} setForm={setForm} />
      <Paper variant="outlined" sx={{ p: 2, mt: 2 }}>
        <Grid container spacing={2}>
          <Grid item xs={12} md={4}>
            <FormControl fullWidth>
              <InputLabel id="prov-label">DNS provider</InputLabel>
              <Select labelId="prov-label" label="DNS provider" value={provider.type} onChange={set('type')}>
                <MenuItem value="cloudflare">Cloudflare</MenuItem>
                <MenuItem value="rfc2136">RFC 2136 (BIND, Knot, PowerDNS…)</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          {provider.type === 'cloudflare' ? (
            <>
              <Grid item xs={12} md={5}>
                <TextField label="API token (Zone:DNS:Edit)" type="password" fullWidth value={provider.api_token} onChange={set('api_token')} />
              </Grid>
              <Grid item xs={12} md={3}>
                <TextField label="Zone ID (optional)" fullWidth value={provider.zone_id} onChange={set('zone_id')} />
              </Grid>
            </>
          ) : (
            <>
              <Grid item xs={8} md={5}><TextField label="DNS server" fullWidth value={provider.server} onChange={set('server')} /></Grid>
              <Grid item xs={4} md={3}><TextField label="Port" type="number" fullWidth value={provider.port} onChange={set('port')} /></Grid>
              <Grid item xs={12} md={4}><TextField label="Zone" fullWidth value={provider.zone} onChange={set('zone')} placeholder="example.com" /></Grid>
              <Grid item xs={12} md={4}><TextField label="TSIG key name" fullWidth value={provider.tsig_name} onChange={set('tsig_name')} /></Grid>
              <Grid item xs={12} md={5}><TextField label="TSIG secret (base64)" type="password" fullWidth value={provider.tsig_secret} onChange={set('tsig_secret')} /></Grid>
              <Grid item xs={12} md={3}><TextField label="TSIG algorithm" fullWidth value={provider.tsig_algorithm} onChange={set('tsig_algorithm')} /></Grid>
            </>
          )}
        </Grid>
      </Paper>
      <Button variant="contained" sx={{ mt: 2 }} onClick={issue} disabled={loading || !parseDomains(form.domains).length}>
        {loading ? 'Issuing (can take a minute)...' : 'Issue certificate'}
      </Button>
      {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      {result && <CertificateResult result={result} privateKey={result.private_key_pem} accountKey={result.account_key_pem} />}
    </Box>
  );
}

function ACMEIssuer() {
  const [tab, setTab] = useState(0);
  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <WorkspacePremiumIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        ACME / Let's Encrypt
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Get free, publicly trusted certificates. Start with the staging CA to avoid rate limits. Certificates and keys are returned to you and never stored on the server.
      </Typography>
      <Paper sx={{ p: 3 }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)} sx={{ mb: 2 }}>
          <Tab label="Manual" />
          <Tab label="Automatic (DNS provider)" />
        </Tabs>
        {tab === 0 ? <ManualFlow /> : <AutomaticFlow />}
      </Paper>
    </Box>
  );
}

export default ACMEIssuer;
