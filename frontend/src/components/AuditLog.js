import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert, Box, Button, Chip, Grid, MenuItem, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow,
  TextField, Typography,
} from '@mui/material';
import { History as HistoryIcon } from '@mui/icons-material';
import { auditAPI } from '../services/api';
import TokenField from './TokenField';

const ACTION_GROUPS = [
  { value: '', label: 'All actions' },
  { value: 'auth.denied', label: 'Refused logins' },
  { value: 'monitor.domain', label: 'Monitored domains' },
  { value: 'monitor.certificate', label: 'Monitored certificates' },
  { value: 'monitor.export', label: 'Exports' },
  { value: 'apikey', label: 'API keys' },
  { value: 'alerts', label: 'Alerts' },
];
const resultColor = { success: 'success', failed: 'warning', denied: 'error' };
const PAGE = 50;

const saveBlob = (blob, filename) => {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

const actorText = (actor) => (actor.id ? `${actor.type}: ${actor.id}` : actor.type);

function AuditLog() {
  const [action, setAction] = useState('');
  const [result, setResult] = useState('');
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const [data, setData] = useState(null);
  const [integrity, setIntegrity] = useState(null);
  const [error, setError] = useState('');

  const params = useCallback(() => {
    const p = {};
    if (action) p.action = action;
    if (result) p.result = result;
    if (query.trim()) p.q = query.trim();
    return p;
  }, [action, result, query]);

  const load = useCallback(async (nextPage = 0) => {
    setError('');
    try {
      const response = await auditAPI.list({ ...params(), limit: PAGE, offset: nextPage * PAGE });
      setData(response.data);
      setPage(nextPage);
    } catch (err) {
      setData(null);
      setError(err.response?.status === 401 || err.response?.status === 403
        ? 'The audit log needs the admin token (ADMIN_TOKEN).' : (err.response?.data?.error || 'Could not load the audit log.'));
    }
  }, [params]);

  // Load once on mount; later loads follow the Apply button and paging, not every keystroke in a filter.
  useEffect(() => {
    load(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);


  const verify = async () => {
    setError('');
    try {
      setIntegrity((await auditAPI.verify()).data);
    } catch (err) {
      setError(err.response?.data?.error || 'Could not verify the log.');
    }
  };

  const exportAs = async (format) => {
    try {
      const response = await auditAPI.exportData(format, params());
      saveBlob(response.data, `audit-log.${format}`);
    } catch (err) {
      setError('Export failed.');
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <HistoryIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Audit Log
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Who added, changed or removed monitored hosts, certificates, API keys and alert settings, and who was refused. Entries are chained by
        hash, so a deleted or edited line shows up under "Verify integrity". Tokens, keys and certificates are never logged.
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <TokenField label="Admin token" onUse={() => load(0)}
          helperText="The ADMIN_TOKEN of the server. Kept for this browser tab unless you tick the box below." />
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={3}>
            <TextField select label="Action" fullWidth value={action} onChange={(e) => setAction(e.target.value)}>
              {ACTION_GROUPS.map((g) => <MenuItem key={g.value} value={g.value}>{g.label}</MenuItem>)}
            </TextField>
          </Grid>
          <Grid item xs={6} md={2}>
            <TextField select label="Result" fullWidth value={result} onChange={(e) => setResult(e.target.value)}>
              <MenuItem value="">Any</MenuItem>
              <MenuItem value="success">Success</MenuItem>
              <MenuItem value="failed">Failed</MenuItem>
              <MenuItem value="denied">Denied</MenuItem>
            </TextField>
          </Grid>
          <Grid item xs={6} md={4}>
            <TextField label="Search (actor, target, IP…)" fullWidth value={query} onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && load(0)} />
          </Grid>
          <Grid item xs={12} md={3}>
            <Button variant="contained" fullWidth onClick={() => load(0)}>Apply</Button>
          </Grid>
        </Grid>
        {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      </Paper>

      {data && (
        <Paper sx={{ p: 3 }}>
          <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" sx={{ mb: 2 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 600, mr: 1 }}>{data.total} entr{data.total === 1 ? 'y' : 'ies'}</Typography>
            <Button size="small" variant="outlined" onClick={verify}>Verify integrity</Button>
            <Button size="small" variant="outlined" onClick={() => exportAs('csv')}>Export CSV</Button>
            <Button size="small" variant="outlined" onClick={() => exportAs('json')}>Export JSON</Button>
            {integrity && (
              <Chip color={integrity.valid ? 'success' : 'error'}
                label={integrity.valid ? `Chain intact (${integrity.entries} entries)`
                  : `Broken at ${integrity.problem.file} line ${integrity.problem.line}: ${integrity.problem.reason}`} />
            )}
          </Stack>
          <Table size="small">
            <TableHead>
              <TableRow><TableCell>Time</TableCell><TableCell>Action</TableCell><TableCell>Who</TableCell><TableCell>Target</TableCell><TableCell>Result</TableCell><TableCell>IP</TableCell></TableRow>
            </TableHead>
            <TableBody>
              {data.entries.map((e) => (
                <TableRow key={e.hash}>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{new Date(e.ts).toLocaleString()}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{e.action}</TableCell>
                  <TableCell>{actorText(e.actor)}</TableCell>
                  <TableCell sx={{ wordBreak: 'break-all' }}>
                    {e.target || '—'}
                    {Object.keys(e.detail || {}).length > 0 && (
                      <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>{JSON.stringify(e.detail)}</Typography>
                    )}
                  </TableCell>
                  <TableCell><Chip size="small" color={resultColor[e.result] || 'default'} label={e.status ? `${e.result} (${e.status})` : e.result} /></TableCell>
                  <TableCell>{e.ip || '—'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
            <Button size="small" disabled={page === 0} onClick={() => load(page - 1)}>Newer</Button>
            <Button size="small" disabled={(page + 1) * PAGE >= data.total} onClick={() => load(page + 1)}>Older</Button>
          </Stack>
        </Paper>
      )}
    </Box>
  );
}

export default AuditLog;
