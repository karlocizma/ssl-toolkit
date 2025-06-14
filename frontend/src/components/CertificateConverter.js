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
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  useTheme,
} from '@mui/material';
import {
  Transform as TransformIcon,
  Upload as UploadIcon,
  Download as DownloadIcon,
} from '@mui/icons-material';
import { useDropzone } from 'react-dropzone';
import { conversionAPI } from '../services/api';

function CertificateConverter() {
  const [certificateData, setCertificateData] = useState('');
  const [privateKeyData, setPrivateKeyData] = useState('');
  const [inputFormat, setInputFormat] = useState('PEM');
  const [outputFormat, setOutputFormat] = useState('DER');
  const [password, setPassword] = useState('');
  const [pfxPassword, setPfxPassword] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const theme = useTheme();

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    accept: {
      'text/plain': ['.pem', '.crt', '.cer'],
      'application/x-x509-ca-cert': ['.crt', '.cer'],
      'application/x-pkcs12': ['.pfx', '.p12'],
      'application/octet-stream': ['.der']
    },
    maxFiles: 1,
    onDrop: (acceptedFiles) => {
      const file = acceptedFiles[0];
      const reader = new FileReader();
      
      // Detect format based on file extension
      const extension = file.name.split('.').pop().toLowerCase();
      if (['pfx', 'p12'].includes(extension)) {
        setInputFormat('PFX');
        reader.readAsArrayBuffer(file);
        reader.onload = (e) => {
          const arrayBuffer = e.target.result;
          const base64String = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
          setCertificateData(base64String);
        };
      } else if (extension === 'der') {
        setInputFormat('DER');
        reader.readAsArrayBuffer(file);
        reader.onload = (e) => {
          const arrayBuffer = e.target.result;
          const base64String = btoa(String.fromCharCode(...new Uint8Array(arrayBuffer)));
          setCertificateData(base64String);
        };
      } else {
        setInputFormat('PEM');
        reader.readAsText(file);
        reader.onload = (e) => {
          setCertificateData(e.target.result);
        };
      }
    }
  });

  const handleConvert = async () => {
    if (!certificateData.trim()) {
      setError('Please provide certificate data');
      return;
    }
    
    if (outputFormat === 'PFX' && !privateKeyData.trim()) {
      setError('Private key is required for PFX conversion');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const payload = {
        certificate_data: certificateData,
        input_format: inputFormat,
        output_format: outputFormat,
        password: password || undefined,
        private_key_data: outputFormat === 'PFX' ? privateKeyData : undefined,
        is_base64: inputFormat === 'DER' || inputFormat === 'PFX'
      };
      
      // Use PFX password for PFX output
      if (outputFormat === 'PFX' && pfxPassword) {
        payload.password = pfxPassword;
      }

      const response = await conversionAPI.convert(payload);
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to convert certificate');
    } finally {
      setLoading(false);
    }
  };

  const downloadConverted = () => {
    if (!result) return;
    
    let content = result.converted_data;
    let mimeType = 'text/plain';
    let extension = outputFormat.toLowerCase();
    
    if (result.is_base64) {
      // Convert base64 to binary for download
      const binaryString = atob(content);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
      
      const blob = new Blob([bytes], { type: 'application/octet-stream' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `converted_certificate.${extension}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } else {
      // Text-based download
      const blob = new Blob([content], { type: mimeType });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `converted_certificate.${extension}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <TransformIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Certificate Converter
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Convert certificates between different formats: PEM, DER, PFX (PKCS#12). Supports both certificate files and certificate bundles.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Certificate Input
            </Typography>
            
            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Input Format</InputLabel>
                  <Select
                    value={inputFormat}
                    label="Input Format"
                    onChange={(e) => setInputFormat(e.target.value)}
                  >
                    <MenuItem value="PEM">PEM (.pem, .crt, .cer)</MenuItem>
                    <MenuItem value="DER">DER (.der)</MenuItem>
                    <MenuItem value="PFX">PFX/PKCS#12 (.pfx, .p12)</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              <Grid item xs={6}>
                <FormControl fullWidth>
                  <InputLabel>Output Format</InputLabel>
                  <Select
                    value={outputFormat}
                    label="Output Format"
                    onChange={(e) => setOutputFormat(e.target.value)}
                  >
                    <MenuItem value="PEM">PEM</MenuItem>
                    <MenuItem value="DER">DER</MenuItem>
                    <MenuItem value="PFX">PFX/PKCS#12</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
            </Grid>

            {inputFormat === 'PFX' && (
              <TextField
                fullWidth
                type="password"
                label="PFX Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter PFX password"
                sx={{ mb: 2 }}
              />
            )}
            
            {outputFormat === 'PFX' && (
              <>
                <TextField
                  fullWidth
                  multiline
                  rows={6}
                  label="Private Key (Required for PFX)"
                  value={privateKeyData}
                  onChange={(e) => setPrivateKeyData(e.target.value)}
                  placeholder="-----BEGIN PRIVATE KEY-----
Paste your private key here...
-----END PRIVATE KEY-----"
                  variant="outlined"
                  sx={{ mb: 2 }}
                  helperText="A private key is required to create a PFX file"
                />
                <TextField
                  fullWidth
                  type="password"
                  label="PFX Password (Optional)"
                  value={pfxPassword}
                  onChange={(e) => setPfxPassword(e.target.value)}
                  placeholder="Enter password for the PFX file"
                  sx={{ mb: 2 }}
                  helperText="Leave empty for unprotected PFX file"
                />
              </>
            )}
            
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
              <Typography variant="caption" color="text.secondary">
                Supports: .pem, .crt, .cer, .der, .pfx, .p12
              </Typography>
            </Box>

            {inputFormat === 'PEM' && (
              <TextField
                fullWidth
                multiline
                rows={8}
                value={certificateData}
                onChange={(e) => setCertificateData(e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----
Paste your certificate here...
-----END CERTIFICATE-----"
                variant="outlined"
                sx={{ mb: 2 }}
              />
            )}

            {(inputFormat === 'DER' || inputFormat === 'PFX') && certificateData && (
              <Alert severity="info" sx={{ mb: 2 }}>
                Binary file loaded successfully. File size: {Math.round(certificateData.length * 0.75)} bytes
              </Alert>
            )}
            
            <Button
              variant="contained"
              onClick={handleConvert}
              disabled={loading || !certificateData.trim()}
              startIcon={loading ? <CircularProgress size={20} /> : <TransformIcon />}
              fullWidth
            >
              {loading ? 'Converting...' : `Convert ${inputFormat} to ${outputFormat}`}
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
                Conversion Result
              </Typography>

              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" color="text.secondary">
                  Converted from {result.input_format} to {result.output_format}
                </Typography>
              </Box>

              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                  <Typography variant="subtitle1">Converted Certificate</Typography>
                  <Button
                    size="small"
                    startIcon={<DownloadIcon />}
                    onClick={downloadConverted}
                  >
                    Download
                  </Button>
                </Box>
                
                {result.is_base64 ? (
                  <Alert severity="info">
                    <Typography variant="body2">
                      Binary format file converted successfully. Click Download to save the file.
                      File size: {Math.round(result.converted_data.length * 0.75)} bytes
                    </Typography>
                  </Alert>
                ) : (
                  <TextField
                    fullWidth
                    multiline
                    rows={12}
                    value={result.converted_data}
                    variant="outlined"
                    InputProps={{
                      readOnly: true,
                      sx: { fontFamily: 'monospace', fontSize: '0.875rem' }
                    }}
                  />
                )}
              </Box>

              <Alert severity="success">
                <Typography variant="body2">
                  Certificate successfully converted from {result.input_format} to {result.output_format} format.
                </Typography>
              </Alert>
            </Paper>
          )}
        </Grid>
      </Grid>
    </Box>
  );
}

export default CertificateConverter;
