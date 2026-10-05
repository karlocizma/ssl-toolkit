import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Alert, Box, Chip, CircularProgress, Container, Paper, Stack, Typography, Button, Table, TableBody, TableRow, TableCell } from '@mui/material';
import { shareAPI } from '../services/api';
import { exportJson, exportHtml, findingsOf, topFacts } from '../utils/report';

const CHIPS = ['grade', 'score', 'status', 'overall', 'verdict'];

/** Public, read-only view of a shared result. No navigation, no login. */
export default function SharedReport() {
  const { token } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    shareAPI.get(token)
      .then((r) => setData(r.data))
      .catch((e) => setError(e.response?.status === 404 ? 'This link does not exist or has expired.' : 'Could not load the shared result.'));
  }, [token]);

  if (error) return <Container sx={{ py: 6 }}><Alert severity="info">{error}</Alert></Container>;
  if (!data) return <Box sx={{ textAlign: 'center', py: 8 }}><CircularProgress /></Box>;

  const { title, tool, result, expires_at: expires, created_at: created } = data;
  const facts = topFacts(result);
  const findings = findingsOf(result);
  const chips = facts.filter(([k]) => CHIPS.includes(k));

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Typography variant="h4" component="h1" gutterBottom>{title}</Typography>
      <Typography color="text.secondary" gutterBottom>
        {tool} · shared {new Date(created).toLocaleString()} · expires {new Date(expires).toLocaleString()}
      </Typography>
      <Alert severity="info" sx={{ my: 2 }}>This is a read-only snapshot, not a live check. The result may be out of date.</Alert>
      {chips.length > 0 && (
        <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
          {chips.map(([k, v]) => <Chip key={k} label={`${k}: ${v}`} color="primary" />)}
        </Stack>
      )}
      {facts.length > 0 && (
        <Paper sx={{ mb: 2 }}><Table size="small"><TableBody>
          {facts.map(([k, v]) => (
            <TableRow key={k}><TableCell component="th" sx={{ width: '30%' }}>{k}</TableCell><TableCell>{String(v)}</TableCell></TableRow>
          ))}
        </TableBody></Table></Paper>
      )}
      {findings.length > 0 && (
        <Box sx={{ mb: 2 }}>
          <Typography variant="h6">Findings</Typography>
          {findings.map((f, i) => (
            <Alert key={i} severity={['error', 'critical'].includes(f.severity) ? 'error' : f.severity === 'warning' ? 'warning' : 'info'} sx={{ mt: 1 }}>
              {f.message || f.title || JSON.stringify(f)}
            </Alert>
          ))}
        </Box>
      )}
      <Typography variant="h6">Full result</Typography>
      <Paper sx={{ p: 2, overflow: 'auto' }}>
        <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{JSON.stringify(result, null, 2)}</pre>
      </Paper>
      <Stack direction="row" spacing={1} sx={{ mt: 2 }}>
        <Button onClick={() => exportJson(title, result)}>Download JSON</Button>
        <Button onClick={() => exportHtml({ title, tool, result })}>Download HTML report</Button>
      </Stack>
    </Container>
  );
}
