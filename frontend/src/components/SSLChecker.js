import React, { useState } from 'react';
import {
  Typography,
  TextField,
  Button,
  Box,
  Paper,
  Grid,
  Alert,
  CircularProgress,
  Chip,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material';
import {
  Search as SearchIcon,
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
} from '@mui/icons-material';
import { sslCheckAPI } from '../services/api';
import moment from 'moment';

function SSLChecker() {
  const [hostname, setHostname] = useState('');
  const [port, setPort] = useState(443);
  const [timeout, setTimeout] = useState(10);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleCheck = async () => {
    if (!hostname.trim()) {
      setError('Hostname is required');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await sslCheckAPI.checkDomain({
        hostname: hostname.trim(),
        port: parseInt(port),
        timeout: parseInt(timeout)
      });
      setResult(response.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to check SSL certificate');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    return moment(dateString).format('YYYY-MM-DD HH:mm:ss UTC');
  };

  const getExpiryStatus = (expiryDate, isExpired) => {
    if (isExpired) {
      return { color: 'error', label: 'Expired', icon: <ErrorIcon /> };
    }
    const daysUntilExpiry = moment(expiryDate).diff(moment(), 'days');
    if (daysUntilExpiry <= 30) {
      return { color: 'warning', label: `Expires in ${daysUntilExpiry} days`, icon: <WarningIcon /> };
    }
    return { color: 'success', label: `Valid for ${daysUntilExpiry} days`, icon: <CheckCircleIcon /> };
  };

  const getConnectionStatus = () => {
    if (!result) return null;
    if (result.connection_secure) {
      return { color: 'success', label: 'Secure Connection', icon: <CheckCircleIcon /> };
    }
    return { color: 'error', label: 'Connection Failed', icon: <ErrorIcon /> };
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <SearchIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        SSL Certificate Checker
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Check SSL certificates for any domain or IP address. Verify certificate validity, expiration, and security configuration.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              SSL Certificate Check
            </Typography>
            
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Hostname or IP Address"
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                  placeholder="example.com"
                  required
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="Port"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  InputProps={{ inputProps: { min: 1, max: 65535 } }}
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="Timeout (seconds)"
                  value={timeout}
                  onChange={(e) => setTimeout(e.target.value)}
                  InputProps={{ inputProps: { min: 1, max: 60 } }}
                />
              </Grid>
            </Grid>

            <Button
              variant="contained"
              onClick={handleCheck}
              disabled={loading || !hostname.trim()}
              startIcon={loading ? <CircularProgress size={20} /> : <SearchIcon />}
              fullWidth
              size="large"
              sx={{ mt: 3 }}
            >
              {loading ? 'Checking...' : 'Check SSL Certificate'}
            </Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          {result && (
            <Paper sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                SSL Check Results
              </Typography>

              <Box sx={{ mb: 3 }}>
                <Grid container spacing={2}>
                  <Grid item xs={12}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography variant="subtitle2">Connection Status:</Typography>
                      <Chip 
                        icon={getConnectionStatus()?.icon}
                        label={getConnectionStatus()?.label}
                        color={getConnectionStatus()?.color}
                        size="small"
                      />
                    </Box>
                  </Grid>
                  <Grid item xs={12}>
                    <Typography variant="body2" color="text.secondary">Target: {result.hostname}:{result.port}</Typography>
                  </Grid>
                  {result.ssl_version && (
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">SSL/TLS Version: {result.ssl_version}</Typography>
                    </Grid>
                  )}
                  {result.cipher && result.cipher.name && (
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">
                        Cipher: {result.cipher.name} ({result.cipher.bits} bits)
                      </Typography>
                    </Grid>
                  )}
                </Grid>
              </Box>

              {result.certificate && (
                <>
                  <Accordion defaultExpanded>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">Certificate Information</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Common Name</Typography>
                          <Typography variant="body1">{result.certificate.subject?.common_name || 'N/A'}</Typography>
                        </Grid>
                        {result.certificate.subject?.organization && (
                          <Grid item xs={12}>
                            <Typography variant="body2" color="text.secondary">Organization</Typography>
                            <Typography variant="body1">{result.certificate.subject.organization}</Typography>
                          </Grid>
                        )}
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Issuer</Typography>
                          <Typography variant="body1">{result.certificate.issuer?.common_name || 'N/A'}</Typography>
                        </Grid>
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Valid for Hostname</Typography>
                          <Chip 
                            label={result.valid_for_hostname ? 'Yes' : 'No'}
                            color={result.valid_for_hostname ? 'success' : 'error'}
                            size="small"
                          />
                        </Grid>
                      </Grid>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">Validity Period</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Valid From</Typography>
                          <Typography variant="body1">{formatDate(result.certificate.validity?.not_before)}</Typography>
                        </Grid>
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Valid Until</Typography>
                          <Typography variant="body1">{formatDate(result.certificate.validity?.not_after)}</Typography>
                        </Grid>
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Status</Typography>
                          <Chip 
                            icon={getExpiryStatus(result.certificate.validity?.not_after, result.certificate.validity?.is_expired)?.icon}
                            label={getExpiryStatus(result.certificate.validity?.not_after, result.certificate.validity?.is_expired)?.label}
                            color={getExpiryStatus(result.certificate.validity?.not_after, result.certificate.validity?.is_expired)?.color}
                            size="small"
                          />
                        </Grid>
                      </Grid>
                    </AccordionDetails>
                  </Accordion>

                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">Technical Details</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Serial Number</Typography>
                          <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                            {result.certificate.serial_number}
                          </Typography>
                        </Grid>
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Signature Algorithm</Typography>
                          <Typography variant="body1">{result.certificate.signature_algorithm}</Typography>
                        </Grid>
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">Public Key</Typography>
                          <Typography variant="body1">
                            {result.certificate.public_key?.algorithm} ({result.certificate.public_key?.key_size} bits)
                          </Typography>
                        </Grid>
                      </Grid>
                    </AccordionDetails>
                  </Accordion>

                  {result.certificate.subject_alternative_names && result.certificate.subject_alternative_names.length > 0 && (
                    <Accordion>
                      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                        <Typography variant="subtitle1">Subject Alternative Names</Typography>
                      </AccordionSummary>
                      <AccordionDetails>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                          {result.certificate.subject_alternative_names.map((san, index) => (
                            <Chip key={index} label={san} variant="outlined" size="small" />
                          ))}
                        </Box>
                      </AccordionDetails>
                    </Accordion>
                  )}

                  <Accordion>
                    <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                      <Typography variant="subtitle1">Fingerprints</Typography>
                    </AccordionSummary>
                    <AccordionDetails>
                      <Grid container spacing={2}>
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">SHA-1</Typography>
                          <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all' }}>
                            {result.certificate.fingerprints?.sha1}
                          </Typography>
                        </Grid>
                        <Grid item xs={12}>
                          <Typography variant="body2" color="text.secondary">SHA-256</Typography>
                          <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: '0.875rem', wordBreak: 'break-all' }}>
                            {result.certificate.fingerprints?.sha256}
                          </Typography>
                        </Grid>
                      </Grid>
                    </AccordionDetails>
                  </Accordion>
                </>
              )}

              {result.errors && result.errors.length > 0 && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  <Typography variant="subtitle2">Errors:</Typography>
                  <ul style={{ margin: '8px 0 0 0', paddingLeft: '20px' }}>
                    {result.errors.map((err, index) => (
                      <li key={index}>
                        <Typography variant="body2">{err}</Typography>
                      </li>
                    ))}
                  </ul>
                </Alert>
              )}
            </Paper>
          )}
        </Grid>
      </Grid>
    </Box>
  );
}

export default SSLChecker;
