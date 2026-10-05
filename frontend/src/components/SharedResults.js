import React, { useCallback, useEffect, useState } from 'react';
import { Alert, Box, Button, Container, Paper, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';
import { shareAPI } from '../services/api';

/** Manage active share links: see what is shared and revoke it. */
export default function SharedResults() {
  const [shares, setShares] = useState(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      setShares((await shareAPI.list()).data.shares);
      setError('');
    } catch (e) {
      setError(e.response?.status === 401 ? 'Managing shared results needs the access token. Set it on the Domain Monitor page.' : 'Could not load shared results.');
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const revoke = async (id) => {
    try { await shareAPI.revoke(id); await load(); } catch (e) { setError('Could not revoke the link.'); }
  };

  return (
    <Container maxWidth="lg">
      <Typography variant="h4" gutterBottom>Shared results</Typography>
      <Typography color="text.secondary" paragraph>
        Links created with “Share link” on a result. Revoking a link makes it stop working immediately. Links are shown only once, when created.
      </Typography>
      {error && <Alert severity="warning" sx={{ mb: 2 }}>{error}</Alert>}
      {shares && shares.length === 0 && <Alert severity="info">No active shared results.</Alert>}
      {shares && shares.length > 0 && (
        <Paper><Box sx={{ overflowX: 'auto' }}><Table size="small">
          <TableHead><TableRow>
            <TableCell>Title</TableCell><TableCell>Tool</TableCell><TableCell>Created</TableCell><TableCell>Expires</TableCell><TableCell>Views</TableCell><TableCell />
          </TableRow></TableHead>
          <TableBody>
            {shares.map((s) => (
              <TableRow key={s.id}>
                <TableCell>{s.title}</TableCell><TableCell>{s.tool}</TableCell>
                <TableCell>{new Date(s.created_at).toLocaleString()}</TableCell>
                <TableCell>{new Date(s.expires_at).toLocaleString()}</TableCell>
                <TableCell>{s.views}</TableCell>
                <TableCell><Button size="small" color="error" onClick={() => revoke(s.id)} aria-label={`revoke ${s.title}`}>Revoke</Button></TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table></Box></Paper>
      )}
    </Container>
  );
}
