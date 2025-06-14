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
  Chip,
  IconButton,
} from '@mui/material';
import {
  Description as DescriptionIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Download as DownloadIcon,
} from '@mui/icons-material';
import { csrAPI } from '../services/api';

function CSRGenerator() {
  const [formData, setFormData] = useState({
    common_name: '',
    country: '',
    state: '',
    locality: '',
    organization: '',
    organizational_unit: '',
    email: '',
    key_type: 'RSA',
    key_size: 2048,
    curve_name: 'secp256r1'
  });
  const [sanList, setSanList] = useState(['']);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleInputChange = (field, value) => {
    setFormData(prev => ({ ...prev, [field]: value }));
  };

  const handleSanChange = (index, value) => {
    const newSanList = [...sanList];
    newSanList[index] = value;
    setSanList(newSanList);
  };

  const addSan = () => {
    setSanList([...sanList, '']);
  };

  const removeSan = (index) => {
    const newSanList = sanList.filter((_, i) => i !== index);
    setSanList(newSanList);
  };

  const handleGenerate = async () => {
    if (!formData.common_name.trim()) {
      setError('Common Name is required');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const filteredSans = sanList.filter(san => san.trim() !== '');
      const payload = {
        subject: {
          common_name: formData.common_name,
          country: formData.country || undefined,
          state: formData.state || undefined,
          locality: formData.locality || undefined,
          organization: formData.organization || undefined,
          organizational_unit: formData.organizational_unit || undefined,
          email: formData.email || undefined
        },
        key_type: formData.key_type,
        key_size: formData.key_type === 'RSA' ? parseInt(formData.key_size) : undefined,
        curve_name: formData.key_type === 'EC' ? formData.curve_name : undefined,
        subject_alternative_names: filteredSans.length > 0 ? filteredSans : undefined
      };

      const response = await csrAPI.generate(payload);
      setResult(response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to generate CSR');
    } finally {
      setLoading(false);
    }
  };

  const downloadFile = (content, filename) => {
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
        <DescriptionIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        CSR Generator
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Generate Certificate Signing Requests (CSR) with private keys. Specify subject information and optional Subject Alternative Names.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Certificate Subject Information
            </Typography>
            
            <Grid container spacing={2}>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Common Name (CN) *"
                  value={formData.common_name}
                  onChange={(e) => handleInputChange('common_name', e.target.value)}
                  placeholder="example.com"
                  required
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="Country (C)"
                  value={formData.country}
                  onChange={(e) => handleInputChange('country', e.target.value)}
                  placeholder="US"
                  inputProps={{ maxLength: 2 }}
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="State/Province (ST)"
                  value={formData.state}
                  onChange={(e) => handleInputChange('state', e.target.value)}
                  placeholder="California"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="City/Locality (L)"
                  value={formData.locality}
                  onChange={(e) => handleInputChange('locality', e.target.value)}
                  placeholder="San Francisco"
                />
              </Grid>
              <Grid item xs={12} sm={6}>
                <TextField
                  fullWidth
                  label="Organization (O)"
                  value={formData.organization}
                  onChange={(e) => handleInputChange('organization', e.target.value)}
                  placeholder="Example Corp"
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Organizational Unit (OU)"
                  value={formData.organizational_unit}
                  onChange={(e) => handleInputChange('organizational_unit', e.target.value)}
                  placeholder="IT Department"
                />
              </Grid>
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label="Email Address"
                  type="email"
                  value={formData.email}
                  onChange={(e) => handleInputChange('email', e.target.value)}
                  placeholder="admin@example.com"
                />
              </Grid>
            </Grid>

            <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
              Key Configuration
            </Typography>
            
            <Grid container spacing={2}>
              <Grid item xs={12} sm={6}>
                <FormControl fullWidth>
                  <InputLabel>Key Type</InputLabel>
                  <Select
                    value={formData.key_type}
                    label="Key Type"
                    onChange={(e) => handleInputChange('key_type', e.target.value)}
                  >
                    <MenuItem value="RSA">RSA</MenuItem>
                    <MenuItem value="EC">Elliptic Curve (EC)</MenuItem>
                  </Select>
                </FormControl>
              </Grid>
              {formData.key_type === 'RSA' && (
                <Grid item xs={12} sm={6}>
                  <FormControl fullWidth>
                    <InputLabel>Key Size</InputLabel>
                    <Select
                      value={formData.key_size}
                      label="Key Size"
                      onChange={(e) => handleInputChange('key_size', e.target.value)}
                    >
                      <MenuItem value={2048}>2048 bits</MenuItem>
                      <MenuItem value={3072}>3072 bits</MenuItem>
                      <MenuItem value={4096}>4096 bits</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              )}
              {formData.key_type === 'EC' && (
                <Grid item xs={12} sm={6}>
                  <FormControl fullWidth>
                    <InputLabel>Curve</InputLabel>
                    <Select
                      value={formData.curve_name}
                      label="Curve"
                      onChange={(e) => handleInputChange('curve_name', e.target.value)}
                    >
                      <MenuItem value="secp256r1">secp256r1 (P-256)</MenuItem>
                      <MenuItem value="secp384r1">secp384r1 (P-384)</MenuItem>
                      <MenuItem value="secp521r1">secp521r1 (P-521)</MenuItem>
                    </Select>
                  </FormControl>
                </Grid>
              )}
            </Grid>

            <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
              Subject Alternative Names (SAN)
            </Typography>
            
            {sanList.map((san, index) => (
              <Box key={index} sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <TextField
                  fullWidth
                  label={`SAN ${index + 1}`}
                  value={san}
                  onChange={(e) => handleSanChange(index, e.target.value)}
                  placeholder="www.example.com"
                  sx={{ mr: 1 }}
                />
                <IconButton
                  onClick={() => removeSan(index)}
                  disabled={sanList.length === 1}
                  color="error"
                >
                  <DeleteIcon />
                </IconButton>
              </Box>
            ))}
            
            <Button
              startIcon={<AddIcon />}
              onClick={addSan}
              variant="outlined"
              size="small"
              sx={{ mt: 1, mb: 3 }}
            >
              Add SAN
            </Button>

            <Button
              variant="contained"
              onClick={handleGenerate}
              disabled={loading || !formData.common_name.trim()}
              startIcon={loading ? <CircularProgress size={20} /> : <DescriptionIcon />}
              fullWidth
              size="large"
            >
              {loading ? 'Generating...' : 'Generate CSR & Private Key'}
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
                Generated CSR & Private Key
              </Typography>

              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                  <Typography variant="subtitle1">Certificate Signing Request</Typography>
                  <Button
                    size="small"
                    startIcon={<DownloadIcon />}
                    onClick={() => downloadFile(result.csr, `${formData.common_name}.csr`)}
                  >
                    Download CSR
                  </Button>
                </Box>
                <TextField
                  fullWidth
                  multiline
                  rows={8}
                  value={result.csr}
                  variant="outlined"
                  InputProps={{
                    readOnly: true,
                    sx: { fontFamily: 'monospace', fontSize: '0.875rem' }
                  }}
                />
              </Box>

              <Box sx={{ mb: 3 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                  <Typography variant="subtitle1">Private Key</Typography>
                  <Button
                    size="small"
                    startIcon={<DownloadIcon />}
                    onClick={() => downloadFile(result.private_key, `${formData.common_name}.key`)}
                  >
                    Download Key
                  </Button>
                </Box>
                <TextField
                  fullWidth
                  multiline
                  rows={8}
                  value={result.private_key}
                  variant="outlined"
                  InputProps={{
                    readOnly: true,
                    sx: { fontFamily: 'monospace', fontSize: '0.875rem' }
                  }}
                />
              </Box>

              <Alert severity="info">
                <Typography variant="body2">
                  <strong>Important:</strong> Save your private key securely! It cannot be recovered if lost.
                  The CSR can be submitted to a Certificate Authority to obtain a signed certificate.
                </Typography>
              </Alert>
            </Paper>
          )}
        </Grid>
      </Grid>
    </Box>
  );
}

export default CSRGenerator;

