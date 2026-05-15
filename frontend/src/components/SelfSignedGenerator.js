import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  TextField,
  Button,
  MenuItem,
  Stack,
  Divider,
  Alert,
  Chip,
} from '@mui/material';
import { Badge as BadgeIcon } from '@mui/icons-material';
import { certificateAPI } from '../services/api';

const keyTypeOptions = [
  { label: 'RSA', value: 'RSA' },
  { label: 'EC (Elliptic Curve)', value: 'EC' },
];

const rsaSizeOptions = [
  { label: '2048-bit (recommended)', value: 2048 },
  { label: '4096-bit', value: 4096 },
];

const ecCurveOptions = [
  { label: 'P-256 / secp256r1 (recommended)', value: 'secp256r1' },
  { label: 'P-384 / secp384r1', value: 'secp384r1' },
  { label: 'P-521 / secp521r1', value: 'secp521r1' },
];

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <Button size="small" variant="outlined" onClick={handleCopy}>
      {copied ? 'Copied!' : 'Copy'}
    </Button>
  );
}

function DownloadButton({ content, filename, label }) {
  const handleDownload = () => {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <Button size="small" variant="outlined" onClick={handleDownload}>
      {label}
    </Button>
  );
}

function SelfSignedGenerator() {
  const [form, setForm] = useState({
    common_name: '',
    organization: '',
    organizational_unit: '',
    country: '',
    state: '',
    locality: '',
    validity_days: 365,
    key_type: 'RSA',
    key_size: 2048,
    curve_name: 'secp256r1',
    sans: '',
  });
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

  const handleGenerate = async () => {
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const payload = {
        ...form,
        validity_days: parseInt(form.validity_days, 10),
        key_size: parseInt(form.key_size, 10),
        sans: form.sans
          ? form.sans.split(',').map((s) => s.trim()).filter(Boolean)
          : [],
      };
      const response = await certificateAPI.generateSelfSigned(payload);
      setResult(response.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Generation failed');
    } finally {
      setLoading(false);
    }
  };

  const info = result?.certificate_info;

  return (
    <Box sx={{ maxWidth: 900, mx: 'auto', p: 3 }}>
      <Stack direction="row" alignItems="center" spacing={1} mb={3}>
        <BadgeIcon color="primary" />
        <Typography variant="h4" fontWeight={700}>Self-Signed Certificate Generator</Typography>
      </Stack>

      <Paper sx={{ p: 3, mb: 4 }}>
        <Typography variant="h6" gutterBottom>Subject Information</Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={6}>
            <TextField
              required
              label="Common Name (CN)"
              name="common_name"
              value={form.common_name}
              onChange={handleChange}
              fullWidth
              placeholder="localhost or example.com"
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Organization (O)"
              name="organization"
              value={form.organization}
              onChange={handleChange}
              fullWidth
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Organizational Unit (OU)"
              name="organizational_unit"
              value={form.organizational_unit}
              onChange={handleChange}
              fullWidth
            />
          </Grid>
          <Grid item xs={12} sm={2}>
            <TextField
              label="Country (C)"
              name="country"
              value={form.country}
              onChange={handleChange}
              fullWidth
              inputProps={{ maxLength: 2 }}
              placeholder="US"
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <TextField
              label="State / Province"
              name="state"
              value={form.state}
              onChange={handleChange}
              fullWidth
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              label="Locality / City"
              name="locality"
              value={form.locality}
              onChange={handleChange}
              fullWidth
            />
          </Grid>
        </Grid>

        <Divider sx={{ my: 3 }} />
        <Typography variant="h6" gutterBottom>Key &amp; Validity</Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={4}>
            <TextField
              select
              label="Key Type"
              name="key_type"
              value={form.key_type}
              onChange={handleChange}
              fullWidth
            >
              {keyTypeOptions.map((o) => (
                <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
              ))}
            </TextField>
          </Grid>
          {form.key_type === 'RSA' ? (
            <Grid item xs={12} sm={4}>
              <TextField
                select
                label="Key Size"
                name="key_size"
                value={form.key_size}
                onChange={handleChange}
                fullWidth
              >
                {rsaSizeOptions.map((o) => (
                  <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
                ))}
              </TextField>
            </Grid>
          ) : (
            <Grid item xs={12} sm={4}>
              <TextField
                select
                label="Curve"
                name="curve_name"
                value={form.curve_name}
                onChange={handleChange}
                fullWidth
              >
                {ecCurveOptions.map((o) => (
                  <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
                ))}
              </TextField>
            </Grid>
          )}
          <Grid item xs={12} sm={4}>
            <TextField
              label="Validity (days)"
              name="validity_days"
              type="number"
              value={form.validity_days}
              onChange={handleChange}
              fullWidth
              inputProps={{ min: 1, max: 3650 }}
            />
          </Grid>
          <Grid item xs={12}>
            <TextField
              label="Subject Alternative Names (SANs)"
              name="sans"
              value={form.sans}
              onChange={handleChange}
              fullWidth
              placeholder="localhost, 127.0.0.1, example.com (comma-separated)"
              helperText="Comma-separated DNS names or IP addresses"
            />
          </Grid>
        </Grid>

        <Box mt={3}>
          <Button
            variant="contained"
            size="large"
            onClick={handleGenerate}
            disabled={loading || !form.common_name}
          >
            {loading ? 'Generating…' : 'Generate Certificate'}
          </Button>
        </Box>
      </Paper>

      {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

      {result && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>Generated Certificate</Typography>
          {info && (
            <Grid container spacing={1} mb={2}>
              <Grid item xs={12} sm={6}>
                <Typography variant="body2"><strong>CN:</strong> {info.subject?.common_name}</Typography>
                <Typography variant="body2"><strong>Valid until:</strong> {new Date(info.validity?.not_after).toLocaleDateString()}</Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="body2"><strong>Days valid:</strong> {info.validity?.days_until_expiry}</Typography>
                <Typography variant="body2"><strong>Key:</strong> {info.public_key?.algorithm} {info.public_key?.key_size}-bit</Typography>
              </Grid>
              {info.subject_alternative_names?.length > 0 && (
                <Grid item xs={12}>
                  <Stack direction="row" flexWrap="wrap" gap={0.5} mt={1}>
                    {info.subject_alternative_names.map((san, i) => (
                      <Chip key={i} label={san} size="small" variant="outlined" />
                    ))}
                  </Stack>
                </Grid>
              )}
            </Grid>
          )}

          <Divider sx={{ my: 2 }} />

          <Typography variant="subtitle2" gutterBottom>Certificate PEM</Typography>
          <Paper variant="outlined" sx={{ p: 2, mb: 2, bgcolor: 'action.hover' }}>
            <Stack direction="row" justifyContent="flex-end" gap={1} mb={1}>
              <CopyButton text={result.certificate_pem} />
              <DownloadButton content={result.certificate_pem} filename="certificate.pem" label="Download" />
            </Stack>
            <Typography variant="body2" sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap', fontSize: '0.7rem' }}>
              {result.certificate_pem}
            </Typography>
          </Paper>

          <Typography variant="subtitle2" gutterBottom>Private Key PEM</Typography>
          <Paper variant="outlined" sx={{ p: 2, bgcolor: 'action.hover' }}>
            <Stack direction="row" justifyContent="flex-end" gap={1} mb={1}>
              <CopyButton text={result.private_key_pem} />
              <DownloadButton content={result.private_key_pem} filename="private_key.pem" label="Download" />
            </Stack>
            <Typography variant="body2" sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap', fontSize: '0.7rem' }}>
              {result.private_key_pem}
            </Typography>
          </Paper>
        </Paper>
      )}
    </Box>
  );
}

export default SelfSignedGenerator;
