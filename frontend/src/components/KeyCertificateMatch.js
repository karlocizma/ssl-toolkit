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
  useTheme,
} from '@mui/material';
import {
  Link as LinkIcon,
  Upload as UploadIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
} from '@mui/icons-material';
import { useDropzone } from 'react-dropzone';
import { keyAPI } from '../services/api';

function KeyCertificateMatch() {
  const [privateKey, setPrivateKey] = useState('');
  const [certificate, setCertificate] = useState('');
  const [keyPassword, setKeyPassword] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const theme = useTheme();

  const { getRootProps: getKeyRootProps, getInputProps: getKeyInputProps, isDragActive: isKeyDragActive } = useDropzone({
    accept: {
      'text/plain': ['.pem', '.key'],
    },
    maxFiles: 1,
    onDrop: (acceptedFiles) => {
      const file = acceptedFiles[0];
      const reader = new FileReader();
      reader.onload = (e) => {
        setPrivateKey(e.target.result);
      };
      reader.readAsText(file);
    }
  });

  const { getRootProps: getCertRootProps, getInputProps: getCertInputProps, isDragActive: isCertDragActive } = useDropzone({
    accept: {
      'text/plain': ['.pem', '.crt', '.cer'],
      'application/x-x509-ca-cert': ['.crt', '.cer']
    },
    maxFiles: 1,
    onDrop: (acceptedFiles) => {
      const file = acceptedFiles[0];
      const reader = new FileReader();
      reader.onload = (e) => {
        setCertificate(e.target.result);
      };
      reader.readAsText(file);
    }
  });

  const handleMatch = async () => {
    if (!privateKey.trim() || !certificate.trim()) {
      setError('Please provide both private key and certificate');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await keyAPI.matchCertificate({
        private_key: privateKey,
        certificate: certificate,
        key_password: keyPassword || undefined
      });
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to check key-certificate match');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <LinkIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Key-Certificate Matcher
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Verify if a private key matches a certificate by comparing their public key components. Essential for ensuring key-certificate pairs are correctly matched.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Private Key
            </Typography>
            
            <Box
              {...getKeyRootProps()}
              sx={{
                border: `2px dashed ${isKeyDragActive ? theme.palette.primary.main : theme.palette.grey[300]}`,
                borderRadius: 2,
                p: 3,
                mb: 2,
                textAlign: 'center',
                cursor: 'pointer',
                backgroundColor: isKeyDragActive ? theme.palette.action.hover : 'transparent'
              }}
            >
              <input {...getKeyInputProps()} />
              <UploadIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 1 }} />
              <Typography variant="body2" color="text.secondary">
                {isKeyDragActive
                  ? 'Drop the private key file here...'
                  : 'Drag and drop a private key file here, or click to select'}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Supports: .pem, .key files
              </Typography>
            </Box>

            <TextField
              fullWidth
              multiline
              rows={8}
              value={privateKey}
              onChange={(e) => setPrivateKey(e.target.value)}
              placeholder="-----BEGIN PRIVATE KEY-----
Paste your private key here...
-----END PRIVATE KEY-----"
              variant="outlined"
              sx={{ mb: 2 }}
            />
            
            <TextField
              fullWidth
              type="password"
              label="Private Key Password (if encrypted)"
              value={keyPassword}
              onChange={(e) => setKeyPassword(e.target.value)}
              placeholder="Enter password for encrypted keys"
              variant="outlined"
              sx={{ mb: 2 }}
            />
          </Paper>
          
          <Paper sx={{ p: 3, mt: 2 }}>
            <Typography variant="h6" gutterBottom>
              Certificate
            </Typography>
            
            <Box
              {...getCertRootProps()}
              sx={{
                border: `2px dashed ${isCertDragActive ? theme.palette.primary.main : theme.palette.grey[300]}`,
                borderRadius: 2,
                p: 3,
                mb: 2,
                textAlign: 'center',
                cursor: 'pointer',
                backgroundColor: isCertDragActive ? theme.palette.action.hover : 'transparent'
              }}
            >
              <input {...getCertInputProps()} />
              <UploadIcon sx={{ fontSize: 48, color: 'text.secondary', mb: 1 }} />
              <Typography variant="body2" color="text.secondary">
                {isCertDragActive
                  ? 'Drop the certificate file here...'
                  : 'Drag and drop a certificate file here, or click to select'}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Supports: .pem, .crt, .cer files
              </Typography>
            </Box>

            <TextField
              fullWidth
              multiline
              rows={8}
              value={certificate}
              onChange={(e) => setCertificate(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----
Paste your certificate here...
-----END CERTIFICATE-----"
              variant="outlined"
              sx={{ mb: 2 }}
            />
          </Paper>
          
          <Button
            variant="contained"
            onClick={handleMatch}
            disabled={loading || !privateKey.trim() || !certificate.trim()}
            startIcon={loading ? <CircularProgress size={20} /> : <LinkIcon />}
            fullWidth
            size="large"
            sx={{ mt: 2 }}
          >
            {loading ? 'Checking Match...' : 'Check Key-Certificate Match'}
          </Button>
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
                Match Results
              </Typography>

              <Box sx={{ mb: 3, textAlign: 'center' }}>
                <Chip 
                  icon={result.matches ? <CheckCircleIcon /> : <ErrorIcon />}
                  label={result.matches ? 'Keys Match!' : 'Keys Do Not Match'}
                  color={result.matches ? 'success' : 'error'}
                  size="large"
                  sx={{ 
                    fontSize: '1.1rem',
                    py: 2,
                    px: 3,
                    height: 'auto'
                  }}
                />
              </Box>

              {result.matches ? (
                <Alert severity="success">
                  <Typography variant="body2">
                    <strong>✓ Perfect Match!</strong><br/>
                    The private key and certificate are a valid pair. The public key derived from the private key 
                    matches the public key in the certificate. This key-certificate pair can be safely used together 
                    for SSL/TLS configurations.
                  </Typography>
                </Alert>
              ) : (
                <Alert severity="error">
                  <Typography variant="body2">
                    <strong>✗ No Match</strong><br/>
                    The private key and certificate do not match. The public key derived from the private key 
                    does not match the public key in the certificate. These cannot be used together as a 
                    key-certificate pair.
                  </Typography>
                </Alert>
              )}

              <Box sx={{ mt: 3 }}>
                <Typography variant="subtitle2" gutterBottom>
                  What this means:
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  {result.matches ? (
                    <>This verification confirms that the certificate was issued for the corresponding public key, 
                    making it cryptographically valid for use with the provided private key. You can confidently 
                    use these together in your SSL/TLS configuration.</>
                  ) : (
                    <>The public key embedded in the certificate was not derived from the provided private key. 
                    This means either the wrong private key was provided, or the certificate belongs to a different 
                    key pair. You'll need to find the correct matching private key for this certificate.</>
                  )}
                </Typography>
              </Box>
            </Paper>
          )}
        </Grid>
      </Grid>
    </Box>
  );
}

export default KeyCertificateMatch;
