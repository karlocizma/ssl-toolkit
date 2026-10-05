import React, { useState } from 'react';
import {
  Alert, Box, Button, Checkbox, Chip, FormControlLabel, LinearProgress, Stack, Table, TableBody, TableCell, TableHead,
  TableRow, Typography,
} from '@mui/material';
import { deliverabilityAPI } from '../services/api';

const sev = (s) => (s === 'error' ? 'error' : s === 'warning' ? 'warning' : 'info');
const statusColor = { authenticated: 'success', partial: 'warning', failing: 'error' };
const rateColor = (rate) => (rate >= 98 ? 'success' : rate >= 90 ? 'warning' : 'error');

const readFile = (file) => new Promise((resolve, reject) => {
  const reader = new FileReader();
  reader.onload = () => resolve({ name: file.name, file_base64: String(reader.result).split(',')[1] || '' });
  reader.onerror = () => reject(new Error(`Could not read ${file.name}`));
  reader.readAsDataURL(file);
});

function DmarcReports() {
  const [files, setFiles] = useState([]);
  const [lookupPtr, setLookupPtr] = useState(true);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const onFiles = async (e) => {
    const chosen = Array.from(e.target.files || []);
    e.target.value = '';
    try {
      const loaded = await Promise.all(chosen.map(readFile));
      setFiles((prev) => [...prev, ...loaded].slice(0, 100));
      setError('');
    } catch (err) {
      setError(err.message);
    }
  };

  const analyze = async () => {
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const { data } = await deliverabilityAPI.dmarcReports({ files, lookup_ptr: lookupPtr });
      setResult(data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Could not analyse the reports.');
    } finally {
      setLoading(false);
    }
  };

  const maxDay = result ? Math.max(1, ...result.daily.map((d) => d.total)) : 1;

  return (
    <Box>
      <Typography variant="body2" color="text.secondary" paragraph>
        Select many DMARC aggregate reports at once (.xml, .gz or .zip, up to 100). They are merged into one view: who sends mail as your
        domain, whether it authenticates, and how that develops over time. Reports are analysed in memory and not stored.
      </Typography>
      <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" sx={{ mb: 1 }}>
        <Button variant="outlined" component="label">Add report files<input hidden multiple type="file" onChange={onFiles} /></Button>
        {files.length > 0 && <Chip label={`${files.length} file(s) selected`} onDelete={() => { setFiles([]); setResult(null); }} />}
        <FormControlLabel control={<Checkbox checked={lookupPtr} onChange={(e) => setLookupPtr(e.target.checked)} />}
          label="Look up host names of the biggest senders" />
        <Button variant="contained" disabled={loading || files.length === 0} onClick={analyze}>Analyze</Button>
      </Stack>
      {loading && <LinearProgress sx={{ my: 2 }} />}
      {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}

      {result && (
        <Stack spacing={2} sx={{ mt: 2 }}>
          <Stack direction="row" spacing={1} flexWrap="wrap">
            <Chip label={`${result.reports} report(s)`} />
            <Chip label={`${result.total_messages} messages`} />
            <Chip color={rateColor(result.pass_rate)} label={`${result.pass_rate}% pass DMARC`} />
            {result.domains.map((d) => (
              <Chip key={d} variant="outlined" label={`${d}: p=${result.policies[d].p || '?'}${result.policies[d].pct && result.policies[d].pct !== '100' ? ` pct=${result.policies[d].pct}` : ''}`} />
            ))}
            {result.duplicates_skipped > 0 && <Chip variant="outlined" label={`${result.duplicates_skipped} duplicate(s) skipped`} />}
          </Stack>
          {result.period.start && (
            <Typography variant="caption" color="text.secondary">
              {new Date(result.period.start).toLocaleDateString()} – {new Date(result.period.end).toLocaleDateString()}
            </Typography>
          )}
          {result.errors.length > 0 && (
            <Alert severity="warning">
              {result.errors.length} file(s) could not be read: {result.errors.map((e) => `${e.file} (${e.error})`).join('; ')}
            </Alert>
          )}
          {result.findings.map((f, i) => <Alert key={i} severity={sev(f.severity)}>{f.message}</Alert>)}

          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Per day</Typography>
            {result.daily.map((d) => (
              <Stack key={d.date} direction="row" spacing={1} alignItems="center" sx={{ py: 0.25 }}>
                <Typography variant="caption" sx={{ width: 80, fontFamily: 'monospace' }}>{d.date}</Typography>
                <Box sx={{ flex: 1, height: 10, bgcolor: 'action.hover', borderRadius: 1, overflow: 'hidden' }}>
                  <Box sx={{ width: `${(100 * d.total) / maxDay}%`, height: '100%', display: 'flex' }}>
                    <Box sx={{ width: `${d.pass_rate}%`, bgcolor: 'success.main' }} />
                    <Box sx={{ flex: 1, bgcolor: 'error.main' }} />
                  </Box>
                </Box>
                <Typography variant="caption" sx={{ width: 110 }}>{d.total} msgs, {d.pass_rate}%</Typography>
              </Stack>
            ))}
          </Box>

          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Sending sources</Typography>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Source</TableCell><TableCell>Messages</TableCell><TableCell>Pass</TableCell>
                  <TableCell>DKIM / SPF aligned</TableCell><TableCell>Status</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {result.sources.map((s) => (
                  <TableRow key={s.source_ip}>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>{s.source_ip}</Typography>
                      {s.ptr && <Typography variant="caption" color="text.secondary">{s.ptr}</Typography>}
                    </TableCell>
                    <TableCell>{s.count}</TableCell>
                    <TableCell>{s.pass_rate}%</TableCell>
                    <TableCell>{s.dkim_pass} / {s.spf_pass}</TableCell>
                    <TableCell><Chip size="small" color={statusColor[s.status]} label={s.status} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </Box>

          <Box>
            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Reporting providers</Typography>
            <Stack direction="row" spacing={1} flexWrap="wrap" sx={{ mt: 1 }}>
              {result.reporters.map((r) => <Chip key={r.name} variant="outlined" label={`${r.name}: ${r.reports} report(s), ${r.messages} msgs`} />)}
            </Stack>
          </Box>
        </Stack>
      )}
    </Box>
  );
}

export default DmarcReports;
