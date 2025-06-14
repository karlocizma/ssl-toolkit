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
  Description as DescriptionIcon,
} from '@mui/icons-material';
import { useDropzone } from 'react-dropzone';
import { csrAPI } from '../services/api';

function CSRDecoder() {
  const [csrData, setCsrData] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const theme = useTheme();

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: {
      'text/plain': ['.pem', '.csr'],
      'application/pkcs10': ['.csr']
    },
    maxFiles: 1,
    onDrop: (acceptedFiles) => {
      const file = acceptedFiles[0];
      const reader = new FileReader();
      reader.onload = (e) => {
        setCsrData(e.target.result);
      };
      reader.readAsText(file);
    }
  });

  const handleDecode = async () => {
    if (!csrData.trim()) {
      setError('Please provide CSR data');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await csrAPI.decode(csrData);
      setResult(response.data.csr_info);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to decode CSR');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <DescriptionIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        CSR Decoder
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Decode and analyze Certificate Signing Requests (CSR). View subject information, public key details, and extensions.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              CSR Input
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
                  ? 'Drop the CSR file here...'
                  : 'Drag and drop a CSR file here, or click to select'}
              </Typography>
            </Box>

            <TextField
              fullWidth
              multiline
              rows={12}
              value={csrData}
              onChange={(e) => setCsrData(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE REQUEST-----
Paste your CSR here...
-----END CERTIFICATE REQUEST-----"
              variant="outlined"
              sx={{ mb: 2 }}
            />
            
            <Button
              variant="contained"
              onClick={handleDecode}
              disabled={loading || !csrData.trim()}
              startIcon={loading ? <CircularProgress size={20} /> : <DescriptionIcon />}
              fullWidth
            >
              {loading ? 'Decoding...' : 'Decode CSR'}
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
                CSR Information
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
                    {result.subject.organizational_unit && (
                      <Grid item xs={12}>
                        <Typography variant="body2" color="text.secondary">Organizational Unit (OU)</Typography>
                        <Typography variant="body1">{result.subject.organizational_unit}</Typography>
                      </Grid>
                    )}
                    {result.subject.country && (
                      <Grid item xs={12}>
                        <Typography variant="body2" color="text.secondary">Country (C)</Typography>
                        <Typography variant="body1">{result.subject.country}</Typography>
                      </Grid>
                    )}
                    {result.subject.state && (
                      <Grid item xs={12}>
                        <Typography variant="body2" color="text.secondary">State/Province (ST)</Typography>
                        <Typography variant="body1">{result.subject.state}</Typography>
                      </Grid>
                    )}
                    {result.subject.locality && (
                      <Grid item xs={12}>
                        <Typography variant="body2" color="text.secondary">City/Locality (L)</Typography>
                        <Typography variant="body1">{result.subject.locality}</Typography>
                      </Grid>
                    )}
                    {result.subject.email && (
                      <Grid item xs={12}>
                        <Typography variant="body2" color="text.secondary">Email Address</Typography>
                        <Typography variant="body1">{result.subject.email}</Typography>
                      </Grid>
                    )}
                  </Grid>
                </AccordionDetails>
              </Accordion>

              <Accordion>
                <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                  <Typography variant="subtitle1">Public Key Information</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <Grid container spacing={2}>
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">Algorithm</Typography>
                      <Typography variant="body1">{result.public_key.algorithm}</Typography>
                    </Grid>
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">Key Size</Typography>
                      <Typography variant="body1">{result.public_key.key_size} bits</Typography>
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
                      <Typography variant="body2" color="text.secondary">Signature Algorithm</Typography>
                      <Typography variant="body1">{result.signature_algorithm}</Typography>
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

export default CSRDecoder;
