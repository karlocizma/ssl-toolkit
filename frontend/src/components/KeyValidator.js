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
} from '@mui/material';
import {
  VerifiedUser as VerifiedUserIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
} from '@mui/icons-material';
import { keyAPI } from '../services/api';

function KeyValidator() {
  const [keyData, setKeyData] = useState('');
  const [password, setPassword] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [isValid, setIsValid] = useState(false);

  const handleValidate = async () => {
    if (!keyData.trim()) {
      setError('Please provide private key data');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);
    setIsValid(false);

    try {
      const response = await keyAPI.validate({
        private_key: keyData,
        password: password || undefined
      });
      setResult(response.data.key_info);
      setIsValid(true);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to validate private key');
      setIsValid(false);
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <VerifiedUserIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Private Key Validator
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Validate private keys and view their properties. Supports both encrypted and unencrypted keys in PEM format.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Private Key Input
            </Typography>
            
            <TextField
              fullWidth
              multiline
              rows={12}
              value={keyData}
              onChange={(e) => setKeyData(e.target.value)}
              placeholder="-----BEGIN PRIVATE KEY-----
Paste your private key here...
-----END PRIVATE KEY-----"
              variant="outlined"
              sx={{ mb: 2 }}
            />
            
            <TextField
              fullWidth
              type="password"
              label="Password (if encrypted)"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password for encrypted keys"
              variant="outlined"
              sx={{ mb: 2 }}
            />
            
            <Button
              variant="contained"
              onClick={handleValidate}
              disabled={loading || !keyData.trim()}
              startIcon={loading ? <CircularProgress size={20} /> : <VerifiedUserIcon />}
              fullWidth
            >
              {loading ? 'Validating...' : 'Validate Private Key'}
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
                Key Validation Results
              </Typography>

              <Box sx={{ mb: 3 }}>
                <Chip 
                  icon={isValid ? <CheckCircleIcon /> : <ErrorIcon />}
                  label={isValid ? 'Valid Private Key' : 'Invalid Private Key'}
                  color={isValid ? 'success' : 'error'}
                  sx={{ mb: 2 }}
                />
              </Box>

              {isValid && result && (
                <Grid container spacing={2}>
                  <Grid item xs={12}>
                    <Typography variant="body2" color="text.secondary">Algorithm</Typography>
                    <Typography variant="body1">{result.algorithm}</Typography>
                  </Grid>
                  
                  {result.key_size && (
                    <Grid item xs={12}>
                      <Typography variant="body2" color="text.secondary">Key Size</Typography>
                      <Typography variant="body1">{result.key_size} bits</Typography>
                    </Grid>
                  )}
                  
                  <Grid item xs={12}>
                    <Typography variant="body2" color="text.secondary">Encryption Status</Typography>
                    <Chip 
                      label={result.is_encrypted ? 'Encrypted' : 'Not Encrypted'}
                      color={result.is_encrypted ? 'warning' : 'info'}
                      size="small"
                    />
                  </Grid>
                  
                  <Grid item xs={12}>
                    <Alert severity="info">
                      <Typography variant="body2">
                        This private key is valid and can be used for cryptographic operations.
                        {result.is_encrypted 
                          ? ' The key is password-protected, which provides additional security.' 
                          : ' Consider encrypting your private key for better security.'}
                      </Typography>
                    </Alert>
                  </Grid>
                </Grid>
              )}
            </Paper>
          )}
        </Grid>
      </Grid>
    </Box>
  );
}

export default KeyValidator;
