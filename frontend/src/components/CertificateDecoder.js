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
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip,
  useTheme,
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon,
  Upload as UploadIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';
import { useDropzone } from 'react-dropzone';
import { certificateAPI } from '../services/api';
import moment from 'moment';

function CertificateDecoder() {
  const [certificateData, setCertificateData] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const theme = useTheme();

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: {
      'text/plain': ['.pem', '.crt', '.cer'],
      'application/x-x509-ca-cert': ['.crt', '.cer']
    },
    maxFiles: 1,
    onDrop: (acceptedFiles) => {
      const file = acceptedFiles[0];
      const reader = new FileReader();
      reader.onload = (e) => {
        setCertificateData(e.target.result);
      };
      reader.readAsText(file);
    }
  });

  const handleDecode = async () => {
    if (!certificateData.trim()) {
      setError('Please provide certificate data');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await certificateAPI.decode(certificateData);
      setResult(response.data.certificate_info);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to decode certificate');
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString) => {
    return moment(dateString).format('YYYY-MM-DD HH:mm:ss UTC');
  };

  const getExpiryStatus = (expiryDate, isExpired) => {
    if (isExpired) {
      return { color: 'error', label: 'Expired' };
    }
    const daysUntilExpiry = moment(expiryDate).diff(moment(), 'days');
    if (daysUntilExpiry <= 30) {
      return { color: 'warning', label: `Expires in ${daysUntilExpiry} days` };
    }
    return { color: 'success', label: `Valid for ${daysUntilExpiry} days` };
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <SecurityIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Certificate Decoder
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Decode and analyze SSL/TLS certificates. Paste your certificate in PEM format or upload a certificate file.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Certificate Input
            </Typography>
            
            <Box
              {...getRootProps()}
              sx={{
                border: `2px dashed ${isDragActive ? theme.palette.primary.main : theme.palette.grey[300]}`,
                borderRadius: 2,
                p: 3,
                mb: 2,
                textAlign: 'center',
                cursor: 'pointer',
                backgroundColor: isDragActive ? theme.palette.action.hover : 'transparent'
              }}
            >
              <input {...getInputProps()} />
              <UploadIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 1 }} />
              <Typography variant="body2" color="text.secondary">
                {isDragActive
                  ? 'Drop the certificate file here...'
                  : 'Drag and drop a certificate file here, or click to select'}
              </Typography>
            </Box>

            <TextField
              fullWidth
              multiline
              rows={12}
              value={certificateData}
              onChange={(e) => setCertificateData(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----
Paste your PEM certificate here...
-----END CERTIFICATE-----"
              variant="outlined"
              sx={{ mb: 2 }}
            />
            
            <Button
              variant="contained"
              onClick={handleDecode}
              disabled={loading || !certificateData.trim()}
              startIcon={loading ? <CircularProgress size={20} /> : <SecurityIcon />}
              fullWidth
            >
              {loading ? 'Decoding...' : 'Decode Certificate'}
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
                Certificate Information
              </Typography>

              <Accordion defaultExpanded>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1">Subject Information</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">Common Name (CN)</Typography>
                      <Typography variant="body1">{result.subject.common_name || 'N/A'}</Typography>
                    </Grid>
                    {result.subject.organization && (
                      <Grid item xs={12}>
                        <Typography variant="body2" color="text.secondary">Organization (O)</Typography>
                        <Typography variant="body1">{result.subject.organization}</Typography>
                      </Grid>
                    )}
                    {result.subject.country && (
                      <Grid item xs={12}>
                        <Typography variant="body2" color="text.secondary">Country (C)</Typography>
                        <Typography variant="body1">{result.subject.country}</Typography>
                      </Grid>
                    )}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1">Validity</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">Valid From</Typography>
                      <Typography variant="body1">{formatDate(result.validity.not_before)}</Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">Valid Until</Typography>
                      <Typography variant="body1">{formatDate(result.validity.not_after)}</Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">Status</Typography>
                      <Chip 
                        label={getExpiryStatus(result.validity.not_after, result.validity.is_expired).label}
                        color={getExpiryStatus(result.validity.not_after, result.validity.is_expired).color}
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
                      <Typography variant="body1" sx={{ fontFamily: 'monospace' }}>{result.serial_number}</Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">Signature Algorithm</Typography>
                      <Typography variant="body1">{result.signature_algorithm}</Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">Public Key</Typography>
                      <Typography variant="body1">{result.public_key.algorithm} ({result.public_key.key_size} bits)</Typography>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1">Fingerprints</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">SHA-1</Typography>
                      <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                        {result.fingerprints.sha1}
                      </Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">SHA-256</Typography>
                      <Typography variant="body1" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                        {result.fingerprints.sha256}
                      </Typography>
                    </Grid>
                  </Grid>
                </AccordionDetails>
              </Accordion>

              {result.subject_alternative_names && result.subject_alternative_names.length > 0 && (
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="subtitle1">Subject Alternative Names</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                      {result.subject_alternative_names.map((san, index) => (
                        <Chip key={index} label={san} variant="outlined" size="small" />
                      ))}
                    </Box>
                  </AccordionDetails>
                </Accordion>
              )}
            </Paper>
          )}
        </Grid>
      </Grid>
    </Box>
  );
}

export default CertificateDecoder;

