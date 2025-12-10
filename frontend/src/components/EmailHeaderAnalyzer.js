import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  TextField,
  Button,
  Grid,
  Chip,
  Divider,
  Alert,
  Stack,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import {
  MarkEmailRead as MarkEmailReadIcon,
  Timeline as TimelineIcon,
  Verified as VerifiedIcon,
} from '@mui/icons-material';
import { sysAdminAPI } from '../services/api';

function EmailHeaderAnalyzer() {
  const [rawHeaders, setRawHeaders] = useState('');
  const [analysis, setAnalysis] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleAnalyze = async () => {
    if (!rawHeaders.trim()) {
      setError('Paste raw email headers to analyze.');
      return;
    }

    setError('');
    setAnalysis(null);
    setLoading(true);

    try {
      const response = await sysAdminAPI.analyzeEmailHeaders({ headers: rawHeaders });
      setAnalysis(response.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Unable to analyze email headers.');
    } finally {
      setLoading(false);
    }
  };

  const renderMetadata = (metadata = {}) => (
    <Grid container spacing={2}>
      {['subject', 'from', 'to', 'date', 'message_id'].map((field) => (
        <Grid item xs={12} sm={field === 'subject' ? 12 : 6} key={field}>
          <Typography variant="subtitle2" color="text.secondary" gutterBottom>
            {field.replace('_', ' ').toUpperCase()}
          </Typography>
          <Typography variant="body1" sx={{ wordBreak: 'break-word' }}>
            {metadata[field] || '—'}
          </Typography>
        </Grid>
      ))}
    </Grid>
  );

  const renderReceivedChain = (received = []) => (
    <Stack spacing={2}>
      {received.map((hop, index) => (
        <Paper key={index} variant="outlined" sx={{ p: 2 }}>
          <Typography variant="subtitle2" gutterBottom>
            Hop #{index + 1}
          </Typography>
          <List dense>
            {['from', 'by', 'with', 'ip', 'timestamp'].map((field) => (
              hop[field] && (
                <ListItem key={field} disablePadding>
                  <ListItemText primary={field.toUpperCase()} secondary={hop[field]} />
                </ListItem>
              )
            ))}
          </List>
          {hop.raw && (
            <Typography variant="caption" color="text.secondary" sx={{ wordBreak: 'break-word' }}>
              {hop.raw}
            </Typography>
          )}
        </Paper>
      ))}
    </Stack>
  );

  const renderAuthChips = (authentication = {}) => (
    <Stack direction="row" spacing={1} flexWrap="wrap">
      {['spf', 'dkim', 'dmarc'].map((mechanism) => (
        <Chip
          key={mechanism}
          icon={<VerifiedIcon fontSize="small" />}
          label={`${mechanism.toUpperCase()}: ${authentication[mechanism] || 'unknown'}`}
          variant="outlined"
        />
      ))}
    </Stack>
  );

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <MarkEmailReadIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Email Header Analyzer
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Paste full email headers to trace the delivery path, authentication results, and potential anomalies.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              Header Input
            </Typography>
            <TextField
              multiline
              minRows={16}
              value={rawHeaders}
              onChange={(e) => setRawHeaders(e.target.value)}
              placeholder="Received: from ..."
              fullWidth
            />
            <Button
              variant="contained"
              sx={{ mt: 2 }}
              onClick={handleAnalyze}
              disabled={loading}
            >
              {loading ? 'Analyzing...' : 'Analyze Headers'}
            </Button>
            {error && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {error}
              </Alert>
            )}
          </Paper>
        </Grid>

        <Grid item xs={12} md={8}>
          {analysis ? (
            <Stack spacing={3}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Message Summary
                </Typography>
                {renderMetadata(analysis.metadata)}
              </Paper>

              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  <VerifiedIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                  Authentication Results
                </Typography>
                {renderAuthChips(analysis.authentication)}
                {analysis.authentication?.details?.length > 0 && (
                  <List dense sx={{ mt: 2 }}>
                    {analysis.authentication.details.map((detail, index) => (
                      <ListItem key={index}>
                        <ListItemText
                          primary={`${detail.mechanism.toUpperCase()} => ${detail.result}`}
                          secondary={detail.detail || '—'}
                        />
                      </ListItem>
                    ))}
                  </List>
                )}
              </Paper>

              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  <TimelineIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
                  Delivery Timeline
                </Typography>
                <Stack direction="row" spacing={1} mb={2}>
                  <Chip label={`Hops: ${analysis.hop_summary?.hop_count ?? 0}`} />
                  {analysis.hop_summary?.duration_seconds != null && (
                    <Chip label={`Transit: ${Math.round(analysis.hop_summary.duration_seconds)}s`} />
                  )}
                </Stack>
                {analysis.received_chain?.length > 0 ? (
                  renderReceivedChain(analysis.received_chain)
                ) : (
                  <Typography color="text.secondary">No Received headers were found.</Typography>
                )}
              </Paper>

              {analysis.warnings?.length > 0 && (
                <Alert severity="warning">
                  <Typography variant="subtitle2">Potential Issues</Typography>
                  <ul>
                    {analysis.warnings.map((warning, index) => (
                      <li key={index}>{warning}</li>
                    ))}
                  </ul>
                </Alert>
              )}

              {analysis.header_map && (
                <Paper sx={{ p: 3 }}>
                  <Typography variant="h6" gutterBottom>
                    All Headers
                  </Typography>
                  <List dense>
                    {Object.entries(analysis.header_map).map(([key, value]) => (
                      <ListItem key={key}>
                        <ListItemText
                          primary={key}
                          secondary={value}
                          primaryTypographyProps={{ fontWeight: 600 }}
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              )}
            </Stack>
          ) : (
            <Paper sx={{ p: 4, textAlign: 'center', color: 'text.secondary' }}>
              <Typography variant="h6" gutterBottom>
                Awaiting Headers
              </Typography>
              <Typography>
                Paste the raw headers on the left and click analyze to view the delivery path and authentication story for your email.
              </Typography>
            </Paper>
          )}
        </Grid>
      </Grid>
    </Box>
  );
}

export default EmailHeaderAnalyzer;
