import React, { useCallback, useEffect, useState } from 'react';
import { Alert, Box, Chip, Container, LinearProgress, Paper, Stack, Typography } from '@mui/material';
import { statusAPI } from '../services/api';

const OVERALL = {
  ok: { severity: 'success', text: 'All certificates are valid' },
  attention: { severity: 'warning', text: 'Some certificates expire soon' },
  problem: { severity: 'error', text: 'Some certificates need attention' },
};
const HOST = {
  ok: { color: 'success', label: 'Valid' },
  expiring: { color: 'warning', label: 'Expires soon' },
  critical: { color: 'error', label: 'Expires very soon' },
  expired: { color: 'error', label: 'Expired' },
  unreachable: { color: 'error', label: 'Not reachable' },
  pending: { color: 'default', label: 'Not checked yet' },
};
const REFRESH_MS = 60000;

const dayText = (days) => {
  if (days === null || days === undefined) return null;
  if (days < 0) return `expired ${-days} day${days === -1 ? '' : 's'} ago`;
  if (days === 0) return 'expires today';
  return `expires in ${days} day${days === 1 ? '' : 's'}`;
};

function StatusPage() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const response = await statusAPI.get();
      setData(response.data);
      setError('');
    } catch (err) {
      setError(err.response?.status === 404 ? 'The status page is not available.' : 'The status could not be loaded.');
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, REFRESH_MS);
    return () => clearInterval(timer);
  }, [load]);

  return (
    <Container maxWidth="md" sx={{ py: 5 }}>
      <Typography variant="h4" component="h1" gutterBottom>{data?.title || 'Certificate status'}</Typography>
      {error && <Alert severity="error">{error}</Alert>}
      {!data && !error && <LinearProgress />}
      {data && (
        <Stack spacing={2}>
          <Alert severity={OVERALL[data.overall].severity} sx={{ fontSize: 18 }}>
            {data.hosts.length === 0 ? 'No certificates are published yet' : OVERALL[data.overall].text}
          </Alert>
          {data.hosts.map((h) => {
            const info = HOST[h.status] || HOST.pending;
            return (
              <Paper key={h.id} variant="outlined" sx={{ p: 2 }}>
                <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={2}>
                  <Box sx={{ minWidth: 0 }}>
                    <Typography variant="subtitle1" sx={{ fontWeight: 600, wordBreak: 'break-word' }}>{h.name}</Typography>
                    <Typography variant="body2" color="text.secondary">
                      {h.not_after && `${h.status === 'unreachable' ? 'Last known certificate valid until' : 'Certificate valid until'} ${new Date(h.not_after).toLocaleDateString()}`}
                      {h.days_until_expiry !== null && ` (${dayText(h.days_until_expiry)})`}
                    </Typography>
                    {h.domain_expires && (
                      <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                        Domain registered until {new Date(h.domain_expires).toLocaleDateString()}
                      </Typography>
                    )}
                  </Box>
                  <Chip color={info.color} label={info.label} />
                </Stack>
              </Paper>
            );
          })}
          <Typography variant="caption" color="text.secondary">
            Updated {data.generated_at ? new Date(data.generated_at).toLocaleString() : ''}; refreshes every minute.
            Certificates are checked regularly in the background.
          </Typography>
        </Stack>
      )}
    </Container>
  );
}

export default StatusPage;
