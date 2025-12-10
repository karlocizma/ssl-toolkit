import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  TextField,
  Button,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Chip,
  Alert,
  Stack,
  Divider,
} from '@mui/material';
import { Dns as DnsIcon } from '@mui/icons-material';
import { sysAdminAPI } from '../services/api';

const recordOptions = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'];

function DNSDiagnostics() {
  const [domain, setDomain] = useState('');
  const [recordTypes, setRecordTypes] = useState(['A', 'AAAA', 'MX', 'TXT']);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLookup = async () => {
    if (!domain.trim()) {
      setError('Domain is required');
      return;
    }

    setError('');
    setResult(null);
    setLoading(true);

    try {
      const response = await sysAdminAPI.lookupDNS({
        domain: domain.trim(),
        record_types: recordTypes,
      });
      setResult(response.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Unable to fetch DNS records.');
    } finally {
      setLoading(false);
    }
  };

  const renderRecordSection = (type, data) => (
    <Paper key={type} variant="outlined" sx={{ p: 2 }}>
      <Stack direction="row" spacing={1} alignItems="center" justifyContent="space-between">
        <Typography variant="h6">{type}</Typography>
        {data.ttl != null && <Chip label={`TTL: ${data.ttl}s`} size="small" />}
      </Stack>
      <Divider sx={{ my: 1 }} />
      {data.error ? (
        <Alert severity="warning">{data.error}</Alert>
      ) : data.records?.length > 0 ? (
        <Box component="ul" sx={{ pl: 3 }}>
          {data.records.map((record, index) => (
            <li key={index}>
              {typeof record === 'string' ? (
                <Typography sx={{ fontFamily: 'monospace' }}>{record}</Typography>
              ) : type === 'MX' ? (
                <Typography sx={{ fontFamily: 'monospace' }}>
                  {record.priority} → {record.host}
                </Typography>
              ) : (
                <Typography sx={{ fontFamily: 'monospace' }}>{JSON.stringify(record)}</Typography>
              )}
            </li>
          ))}
        </Box>
      ) : (
        <Typography color="text.secondary">No records returned.</Typography>
      )}
    </Paper>
  );

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <DnsIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        DNS Diagnostics
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Quickly inspect common DNS records to troubleshoot email delivery, certificate issuance, or general connectivity issues.
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Grid container spacing={2} alignItems="center">
          <Grid item xs={12} md={4}>
            <TextField
              label="Domain"
              fullWidth
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="example.com"
            />
          </Grid>
          <Grid item xs={12} md={6}>
            <FormControl fullWidth>
              <InputLabel id="record-types-label">Record Types</InputLabel>
              <Select
                labelId="record-types-label"
                multiple
                value={recordTypes}
                label="Record Types"
                onChange={(e) =>
                  setRecordTypes(
                    typeof e.target.value === 'string' ? e.target.value.split(',') : e.target.value
                  )
                }
                renderValue={(selected) => selected.join(', ')}
              >
                {recordOptions.map((option) => (
                  <MenuItem key={option} value={option}>
                    <Chip label={option} size="small" sx={{ mr: 1 }} />
                    {option}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} md={2}>
            <Button
              variant="contained"
              onClick={handleLookup}
              disabled={loading}
              fullWidth
            >
              {loading ? 'Checking...' : 'Lookup'}
            </Button>
          </Grid>
        </Grid>
        {error && (
          <Alert severity="error" sx={{ mt: 2 }}>
            {error}
          </Alert>
        )}
      </Paper>

      {result && (
        <Box>
          <Typography variant="h6" gutterBottom>
            Results for <strong>{result.domain}</strong> (queried {result.queried_at ? new Date(result.queried_at).toLocaleString() : 'just now'})
          </Typography>
          <Grid container spacing={2}>
            {Object.entries(result.results || {}).map(([type, data]) => (
              <Grid item xs={12} md={6} key={type}>
                {renderRecordSection(type, data)}
              </Grid>
            ))}
          </Grid>
        </Box>
      )}
    </Box>
  );
}

export default DNSDiagnostics;
