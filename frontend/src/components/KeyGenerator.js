import React, { useState } from 'react';
import {
  Typography,
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
  TextField,
} from '@mui/material';
import {
  VpnKey as VpnKeyIcon,
  Download as DownloadIcon,
} from '@mui/icons-material';
import { keyAPI } from '../services/api';

function KeyGenerator() {
  const [keyType, setKeyType] = useState('RSA');
  const [keySize, setKeySize] = useState(2048);
  const [curveName, setCurveName] = useState('secp256r1');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleGenerate = async () => {
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const payload = {
        key_type: keyType,
        key_size: keyType === 'RSA' ? parseInt(keySize) : undefined,
        curve_name: keyType === 'EC' ? curveName : undefined
      };

      const response = await keyAPI.generate(payload);
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to generate private key');
    } finally {
      setLoading(false);
    }
  };

  const downloadKey = (content, filename) => {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none';
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <VpnKeyIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Private Key Generator
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Generate RSA or Elliptic Curve (EC) private keys for SSL certificates and other cryptographic purposes.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Key Configuration
            </Typography>
            
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <FormControl fullWidth>
                  <InputLabel>Key Type</InputLabel>
                  <Select
                    value={keyType}
                    label="Key Type"
                    onChange={(e) => setKeyType(e.target.value)}
                  >
                    <MenuItem value="RSA">RSA</MenuItem>
                    <MenuItem value="EC">Elliptic Curve (EC)</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              
              {keyType === 'RSA' && (
                <Grid item xs={12}>
                  <FormControl fullWidth>
                    <InputLabel>Key Size</InputLabel>
                    <Select
                      value={keySize}
                      label="Key Size"
                      onChange={(e) => setKeySize(e.target.value)}
                    >
                      <MenuItem value={2048}>2048 bits (Recommended)</MenuItem>
                      <MenuItem value={3072}>3072 bits</MenuItem>
                      <MenuItem value={4096}>4096 bits (High Security)</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              )}
              
              {keyType === 'EC' && (
                <Grid item xs={12}>
                  <FormControl fullWidth>
                    <InputLabel>Curve</InputLabel>
                    <Select
                      value={curveName}
                      label="Curve"
                      onChange={(e) => setCurveName(e.target.value)}
                    >
                      <MenuItem value="secp256r1">secp256r1 (P-256) - Recommended</MenuItem>
                      <MenuItem value="secp384r1">secp384r1 (P-384)</MenuItem>
                      <MenuItem value="secp521r1">secp521r1 (P-521)</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              )}
            </Grid>

            <Button
              variant="contained"
              onClick={handleGenerate}
              disabled={loading}
              startIcon={loading ? <CircularProgress size={20} /> : <VpnKeyIcon />}
              fullWidth
              size="large"
              sx={{ mt: 3 }}
            >
              {loading ? 'Generating...' : 'Generate Private Key'}
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
                Generated Private Key
              </Typography>

              <Box sx={{ mb: 2 }}>
                <Typography variant="body2" color="text.secondary" gutterBottom>
                  Key Type: {result.key_type} {result.key_size ? `(${result.key_size} bits)` : `(${result.curve})`}
                </Typography>
              </Box>

              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                  <Typography variant="subtitle1">Private Key (PEM Format)</Typography>
                  <Button
                    size="small"
                    startIcon={<DownloadIcon />}
                    onClick={() => downloadKey(result.private_key, `private_key_${keyType.toLowerCase()}.pem`)}
                  >
                    Download
                  </Button>
                </Box>
                <TextField
                  fullWidth
                  multiline
                  rows={12}
                  value={result.private_key}
                  variant="outlined"
                  InputProps={{
                    readOnly: true,
                    sx: { fontFamily: 'monospace', fontSize: '0.875rem' }
                  }}
                />
              </Box>

              <Alert severity="warning">
                <Typography variant="body2">
                  <strong>Important:</strong> Store your private key securely! Anyone with access to this key can impersonate your identity. 
                  Never share private keys or store them in unsecured locations.
                </Typography>
              </Alert>
            </Paper>
          )}
        </Grid>
      </Grid>
    </Box>
  );
}

export default KeyGenerator;
