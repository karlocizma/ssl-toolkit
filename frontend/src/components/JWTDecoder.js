import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  TextField,
  Button,
  Stack,
  Divider,
  Chip,
  Alert,
  Grid,
} from '@mui/material';
import { Token as TokenIcon } from '@mui/icons-material';

function base64urlDecode(str) {
  let b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  return atob(b64);
}

function decodeSection(b64url) {
  try {
    const json = base64urlDecode(b64url);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function formatDate(ts) {
  if (!ts) return null;
  return new Date(ts * 1000).toLocaleString();
}

function expiryStatus(payload) {
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp !== undefined && now > payload.exp) {
    return { label: 'Expired', color: 'error' };
  }
  if (payload.nbf !== undefined && now < payload.nbf) {
    return { label: 'Not Yet Valid', color: 'warning' };
  }
  return { label: 'Valid', color: 'success' };
}

const DATE_CLAIMS = ['exp', 'iat', 'nbf'];

function ClaimsTable({ claims }) {
  return (
    <Box>
      {Object.entries(claims).map(([key, value]) => {
        const isDate = DATE_CLAIMS.includes(key) && typeof value === 'number';
        return (
          <Box key={key} sx={{ display: 'flex', gap: 2, py: 0.5, borderBottom: '1px solid', borderColor: 'divider' }}>
            <Typography variant="body2" sx={{ fontFamily: 'monospace', minWidth: 120, color: 'primary.main', flexShrink: 0 }}>
              {key}
            </Typography>
            <Box>
              <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                {typeof value === 'object' ? JSON.stringify(value) : String(value)}
              </Typography>
              {isDate && (
                <Typography variant="caption" color="text.secondary">
                  {formatDate(value)}
                </Typography>
              )}
            </Box>
          </Box>
        );
      })}
    </Box>
  );
}

function JWTDecoder() {
  const [input, setInput] = useState('');
  const [decoded, setDecoded] = useState(null);
  const [error, setError] = useState('');

  const handleDecode = () => {
    setError('');
    setDecoded(null);
    const token = input.trim();
    if (!token) {
      setError('Paste a JWT token to decode.');
      return;
    }
    const parts = token.split('.');
    if (parts.length !== 3) {
      setError('Invalid JWT: expected 3 dot-separated parts.');
      return;
    }
    const header = decodeSection(parts[0]);
    const payload = decodeSection(parts[1]);
    if (!header || !payload) {
      setError('Could not decode JWT — check that it is a valid base64url-encoded JWT.');
      return;
    }
    setDecoded({ header, payload, signature: parts[2] });
  };

  const status = decoded ? expiryStatus(decoded.payload) : null;

  return (
    <Box sx={{ maxWidth: 900, mx: 'auto', p: 3 }}>
      <Stack direction="row" alignItems="center" spacing={1} mb={3}>
        <TokenIcon color="primary" />
        <Typography variant="h4" fontWeight={700}>JWT Decoder</Typography>
      </Stack>

      <Paper sx={{ p: 3, mb: 3 }}>
        <TextField
          label="JWT Token"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          fullWidth
          multiline
          rows={4}
          placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
          sx={{ mb: 2 }}
        />
        <Button variant="contained" size="large" onClick={handleDecode} disabled={!input.trim()}>
          Decode JWT
        </Button>
      </Paper>

      {error && <Alert severity="error" sx={{ mb: 3 }}>{error}</Alert>}

      {decoded && (
        <>
          <Stack direction="row" alignItems="center" spacing={1} mb={2}>
            <Chip label={status.label} color={status.color} />
            <Chip label={`alg: ${decoded.header.alg || '?'}`} variant="outlined" size="small" />
            <Chip label={`typ: ${decoded.header.typ || '?'}`} variant="outlined" size="small" />
          </Stack>

          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="subtitle1" fontWeight={600} gutterBottom>Header</Typography>
                <Divider sx={{ mb: 1 }} />
                <ClaimsTable claims={decoded.header} />
              </Paper>
            </Grid>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="subtitle1" fontWeight={600} gutterBottom>Payload</Typography>
                <Divider sx={{ mb: 1 }} />
                <ClaimsTable claims={decoded.payload} />
              </Paper>
            </Grid>
            <Grid item xs={12}>
              <Paper sx={{ p: 2 }}>
                <Typography variant="subtitle1" fontWeight={600} gutterBottom>Signature</Typography>
                <Typography
                  variant="body2"
                  sx={{ fontFamily: 'monospace', wordBreak: 'break-all', color: 'text.secondary' }}
                >
                  {decoded.signature}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                  Signature verification requires the secret or public key — this tool only decodes the payload.
                </Typography>
              </Paper>
            </Grid>
          </Grid>
        </>
      )}
    </Box>
  );
}

export default JWTDecoder;
