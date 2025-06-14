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
  Card,
  CardContent,
  CardHeader,
  List,
  ListItem,
  ListItemText,
  Divider,
  useTheme,
} from '@mui/material';
import {
  Link as LinkIcon,
  Security as SecurityIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Timeline as TimelineIcon,
} from '@mui/icons-material';
import { sslCheckAPI } from '../services/api';

function CertificateChainChecker() {
  const [hostname, setHostname] = useState('');
  const [port, setPort] = useState(443);
  const [timeout, setTimeout] = useState(10);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const theme = useTheme();

  const handleCheckChain = async () => {
    if (!hostname.trim()) {
      setError('Please enter a hostname');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await sslCheckAPI.checkChain({
        hostname: hostname.trim(),
        port: parseInt(port),
        timeout: parseInt(timeout)
      });
      setResult(response.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to check certificate chain');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    try {
      return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    } catch {
      return dateString;
    }
  };

  const getCertificateTypeIcon = (cert) => {
    if (cert.is_leaf) return <SecurityIcon color="primary" />;
    if (cert.is_intermediate) return <LinkIcon color="secondary" />;
    if (cert.is_root) return <CheckCircleIcon color="success" />;
    return <SecurityIcon />;
  };

  const getCertificateTypeLabel = (cert) => {
    if (cert.is_leaf) return 'Leaf Certificate';
    if (cert.is_intermediate) return 'Intermediate CA';
    if (cert.is_root) return 'Root CA';
    return 'Certificate';
  };

  const getCertificateStatus = (cert) => {
    const now = new Date();
    const notAfter = new Date(cert.validity.not_after);
    const notBefore = new Date(cert.validity.not_before);
    
    if (now < notBefore) {
      return { status: 'not-yet-valid', color: 'warning', text: 'Not Yet Valid' };
    } else if (now > notAfter) {
      return { status: 'expired', color: 'error', text: 'Expired' };
    } else {
      const daysLeft = Math.ceil((notAfter - now) / (1000 * 60 * 60 * 24));
      if (daysLeft <= 30) {
        return { status: 'expiring-soon', color: 'warning', text: `Expires in ${daysLeft} days` };
      } else {
        return { status: 'valid', color: 'success', text: 'Valid' };
      }
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <TimelineIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Certificate Chain Checker
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Analyze the complete SSL certificate chain for any domain. This tool examines each certificate in the chain, 
        validates the trust path, and provides detailed information about each certificate's validity and properties.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={4}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Domain Configuration
            </Typography>
            
            <TextField
              fullWidth
              label="Hostname"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="example.com"
              sx={{ mb: 2 }}
              helperText="Enter the domain name to check"
            />
            
            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="Port"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  inputProps={{ min: 1, max: 65535 }}
                />
              </Grid>
              <Grid item xs={6}>
                <TextField
                  fullWidth
                  type="number"
                  label="Timeout (seconds)"
                  value={timeout}
                  onChange={(e) => setTimeout(e.target.value)}
                  inputProps={{ min: 1, max: 60 }}
                />
              </Grid>
            </Grid>
            
            <Button
              variant="contained"
              onClick={handleCheckChain}
              disabled={loading || !hostname.trim()}
              startIcon={loading ? <CircularProgress size={20} /> : <TimelineIcon />}
              fullWidth
              size="large"
            >
              {loading ? 'Checking Chain...' : 'Check Certificate Chain'}
            </Button>
          </Paper>
        </Grid>

        <Grid item xs={12} md={8}>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          {result && (
            <Box>
              <Paper sx={{ p: 3, mb: 2 }}>
                <Typography variant="h6" gutterBottom>
                  Chain Summary
                </Typography>
                <Grid container spacing={2}>
                  <Grid item xs={6} sm={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" color="primary">
                        {result.chain_length || 0}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Certificates
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={6} sm={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Chip
                        icon={result.chain_valid ? <CheckCircleIcon /> : <ErrorIcon />}
                        label={result.chain_valid ? 'Valid Chain' : 'Invalid Chain'}
                        color={result.chain_valid ? 'success' : 'error'}
                        variant="outlined"
                      />
                    </Box>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary">
                      <strong>Domain:</strong> {result.hostname}:{result.port}
                    </Typography>
                  </Grid>
                </Grid>
              </Paper>

              {result.certificates && result.certificates.length > 0 ? (
                <Box>
                  <Typography variant="h6" gutterBottom>
                    Certificate Chain Details
                  </Typography>
                  {result.certificates.map((cert, index) => {
                    const status = getCertificateStatus(cert);
                    return (
                      <Card key={index} sx={{ mb: 2 }}>
                        <CardHeader
                          avatar={getCertificateTypeIcon(cert)}
                          title={
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                              <Typography variant="h6">
                                {getCertificateTypeLabel(cert)}
                              </Typography>
                              <Chip
                                size="small"
                                label={status.text}
                                color={status.color}
                                variant="outlined"
                              />
                            </Box>
                          }
                          subheader={`Position ${cert.position + 1} in chain`}
                        />
                        <CardContent>
                          <Grid container spacing={2}>
                            <Grid item xs={12} md={6}>
                              <Typography variant="subtitle2" gutterBottom>
                                Subject Information
                              </Typography>
                              <List dense>
                                <ListItem>
                                  <ListItemText
                                    primary="Common Name"
                                    secondary={cert.subject.common_name || 'N/A'}
                                  />
                                </ListItem>
                                <ListItem>
                                  <ListItemText
                                    primary="Organization"
                                    secondary={cert.subject.organization || 'N/A'}
                                  />
                                </ListItem>
                                <ListItem>
                                  <ListItemText
                                    primary="Country"
                                    secondary={cert.subject.country || 'N/A'}
                                  />
                                </ListItem>
                              </List>
                            </Grid>
                            
                            <Grid item xs={12} md={6}>
                              <Typography variant="subtitle2" gutterBottom>
                                Issuer Information
                              </Typography>
                              <List dense>
                                <ListItem>
                                  <ListItemText
                                    primary="Common Name"
                                    secondary={cert.issuer.common_name || 'N/A'}
                                  />
                                </ListItem>
                                <ListItem>
                                  <ListItemText
                                    primary="Organization"
                                    secondary={cert.issuer.organization || 'N/A'}
                                  />
                                </ListItem>
                                <ListItem>
                                  <ListItemText
                                    primary="Country"
                                    secondary={cert.issuer.country || 'N/A'}
                                  />
                                </ListItem>
                              </List>
                            </Grid>
                            
                            <Grid item xs={12}>
                              <Divider sx={{ my: 1 }} />
                              <Grid container spacing={2}>
                                <Grid item xs={12} sm={6} md={3}>
                                  <Typography variant="body2" color="text.secondary">
                                    <strong>Valid From:</strong><br />
                                    {formatDate(cert.validity.not_before)}
                                  </Typography>
                                </Grid>
                                <Grid item xs={12} sm={6} md={3}>
                                  <Typography variant="body2" color="text.secondary">
                                    <strong>Valid Until:</strong><br />
                                    {formatDate(cert.validity.not_after)}
                                  </Typography>
                                </Grid>
                                <Grid item xs={12} sm={6} md={3}>
                                  <Typography variant="body2" color="text.secondary">
                                    <strong>Key Algorithm:</strong><br />
                                    {cert.public_key.algorithm} ({cert.public_key.key_size} bits)
                                  </Typography>
                                </Grid>
                                <Grid item xs={12} sm={6} md={3}>
                                  <Typography variant="body2" color="text.secondary">
                                    <strong>Signature:</strong><br />
                                    {cert.signature_algorithm}
                                  </Typography>
                                </Grid>
                              </Grid>
                            </Grid>
                            
                            {cert.subject_alternative_names && cert.subject_alternative_names.length > 0 && (
                              <Grid item xs={12}>
                                <Typography variant="subtitle2" gutterBottom>
                                  Subject Alternative Names
                                </Typography>
                                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                                  {cert.subject_alternative_names.map((san, sanIndex) => (
                                    <Chip
                                      key={sanIndex}
                                      label={san}
                                      size="small"
                                      variant="outlined"
                                    />
                                  ))}
                                </Box>
                              </Grid>
                            )}
                          </Grid>
                        </CardContent>
                      </Card>
                    );
                  })}
                </Box>
              ) : (
                <Alert severity="warning">
                  No certificate information available in the chain response.
                </Alert>
              )}
            </Box>
          )}
        </Grid>
      </Grid>
    </Box>
  );
}

export default CertificateChainChecker;
