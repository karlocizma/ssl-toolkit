import React, { useState } from 'react';
import {
  Alert, Box, Button, Checkbox, Chip, Grid, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow,
  TextField, Typography,
} from '@mui/material';
import { TravelExplore as TravelExploreIcon } from '@mui/icons-material';
import { ctAPI, monitorAPI } from '../services/api';

const fmt = (iso) => (iso ? new Date(iso.endsWith('Z') || iso.includes('+') ? iso : `${iso}Z`).toLocaleDateString() : '');

function CTLookup() {
  const [domain, setDomain] = useState('');
  const [expected, setExpected] = useState('');
  const [result, setResult] = useState(null);
  const [selected, setSelected] = useState({});
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [loading, setLoading] = useState(false);
  const [adding, setAdding] = useState(false);

  const search = async () => {
    if (!domain.trim()) {
      setError('Enter a domain');
      return;
    }
    setError('');
    setNotice('');
    setResult(null);
    setLoading(true);
    try {
      const { data } = await ctAPI.lookup({
        domain: domain.trim(),
        expected_issuers: expected.split(',').map((s) => s.trim()).filter(Boolean),
      });
      setResult(data.result);
      setSelected(Object.fromEntries(data.result.subdomains.filter((s) => s.active).map((s) => [s.name, true])));
    } catch (err) {
      setError(err.response?.data?.error || 'Lookup failed.');
    } finally {
      setLoading(false);
    }
  };

  const chosen = Object.keys(selected).filter((k) => selected[k]);

  const addToMonitor = async () => {
    setError('');
    setNotice('');
    setAdding(true);
    try {
      const { data } = await monitorAPI.addDomains({ hostnames: chosen.slice(0, 50) });
      const skipped = data.results.filter((r) => r.status !== 'added');
      setNotice(`Added ${data.added} host(s) to the Domain Monitor.${skipped.length ? ` Skipped: ${skipped.map((r) => `${r.hostname} (${r.message})`).join('; ')}` : ''}`);
    } catch (err) {
      setError(err.response?.data?.error || 'Could not add hosts.');
    } finally {
      setAdding(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <TravelExploreIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        CT Lookup
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Lists every certificate ever logged in public Certificate Transparency logs for a domain, which reveals forgotten subdomains and certificates from CAs you don't use.
      </Typography>
      <Alert severity="info" sx={{ mb: 2 }}>
        Privacy: the domain name you enter is sent to crt.sh, a public CT search service. Everything it returns is public.
      </Alert>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={4}>
            <TextField label="Domain" fullWidth value={domain} placeholder="example.com"
              onChange={(e) => setDomain(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && search()} />
          </Grid>
          <Grid item xs={12} md={5}>
            <TextField label="Expected CAs (optional, comma separated)" fullWidth value={expected}
              placeholder="Let's Encrypt, DigiCert" onChange={(e) => setExpected(e.target.value)} />
          </Grid>
          <Grid item xs={12} md={3}>
            <Button variant="contained" fullWidth onClick={search} disabled={loading}>
              {loading ? 'Searching (can take 30s)...' : 'Search'}
            </Button>
          </Grid>
        </Grid>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
        {notice && <Alert severity="success" sx={{ mt: 2 }}>{notice}</Alert>}
      </Paper>

      {result && (
        <Stack spacing={2}>
          <Paper sx={{ p: 3 }}>
            <Stack direction="row" spacing={1} flexWrap="wrap" alignItems="center">
              <Chip label={`${result.total_certificates} certificates`} />
              <Chip label={`${result.active_certificates} active`} color="success" />
              <Chip label={`${result.subdomains.length} hostnames`} color="info" />
              {result.issuers.map((i) => <Chip key={i.issuer} variant="outlined" label={`${i.count} × ${i.issuer}`} />)}
            </Stack>
            <Stack spacing={1} sx={{ mt: 2 }}>
              {result.findings.map((f, i) => <Alert key={i} severity={f.severity === 'warning' ? 'warning' : 'info'}>{f.message}</Alert>)}
              {result.truncated && <Alert severity="info">Showing the 200 newest certificates; the hostname list covers all of them.</Alert>}
            </Stack>
          </Paper>

          <Paper sx={{ p: 2 }}>
            <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
              <Typography variant="h6">Hostnames</Typography>
              <Button variant="contained" disabled={adding || chosen.length === 0} onClick={addToMonitor}>
                {adding ? 'Adding...' : `Add ${Math.min(chosen.length, 50)} to Domain Monitor`}
              </Button>
            </Stack>
            <Table size="small">
              <TableHead>
                <TableRow><TableCell /><TableCell>Name</TableCell><TableCell>Certificates</TableCell><TableCell>First seen</TableCell><TableCell>Last seen</TableCell><TableCell>Status</TableCell></TableRow>
              </TableHead>
              <TableBody>
                {result.subdomains.map((s) => (
                  <TableRow key={s.name}>
                    <TableCell padding="checkbox">
                      <Checkbox checked={!!selected[s.name]} onChange={(e) => setSelected({ ...selected, [s.name]: e.target.checked })} />
                    </TableCell>
                    <TableCell sx={{ fontFamily: 'monospace' }}>{s.name}</TableCell>
                    <TableCell>{s.certificates}</TableCell>
                    <TableCell>{fmt(s.first_seen)}</TableCell>
                    <TableCell>{fmt(s.last_seen)}</TableCell>
                    <TableCell><Chip size="small" color={s.active ? 'success' : 'default'} label={s.active ? 'Active' : 'Expired'} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Paper>

          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>Certificates</Typography>
            <Table size="small">
              <TableHead>
                <TableRow><TableCell>Issuer</TableCell><TableCell>Names</TableCell><TableCell>Valid from</TableCell><TableCell>Valid until</TableCell><TableCell /></TableRow>
              </TableHead>
              <TableBody>
                {result.certificates.slice(0, 50).map((c) => (
                  <TableRow key={`${c.serial_number}-${c.id}`}>
                    <TableCell sx={{ maxWidth: 240, wordBreak: 'break-word' }}>{c.issuer}</TableCell>
                    <TableCell sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{c.names.slice(0, 4).join(', ')}{c.names.length > 4 ? ` +${c.names.length - 4}` : ''}</TableCell>
                    <TableCell>{fmt(c.not_before)}</TableCell>
                    <TableCell>{fmt(c.not_after)}{c.expired ? ' (expired)' : ''}</TableCell>
                    <TableCell>{c.link && <a href={c.link} target="_blank" rel="noreferrer">crt.sh</a>}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Paper>
        </Stack>
      )}
    </Box>
  );
}

export default CTLookup;
