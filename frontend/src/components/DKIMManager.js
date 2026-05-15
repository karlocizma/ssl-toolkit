import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  TextField,
  Button,
  MenuItem,
  Chip,
  Stack,
  Divider,
  Alert,
  List,
  ListItem,
  ListItemText,
} from '@mui/material';
import {
  VpnLock as VpnLockIcon,
  Key as KeyIcon,
  FactCheck as FactCheckIcon,
} from '@mui/icons-material';
import { sysAdminAPI } from '../services/api';

const keySizeOptions = [
  { label: '1024-bit (legacy)', value: 1024 },
  { label: '2048-bit (recommended)', value: 2048 },
  { label: '4096-bit (maximum)', value: 4096 },
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
    <Button size="small" variant="outlined" onClick={handleCopy} sx={{ ml: 1 }}>
      {copied ? 'Copied!' : 'Copy'}
    </Button>
  );
}

function DKIMManager() {
  const [genForm, setGenForm] = useState({ domain: '', selector: 'default', key_size: 2048 });
  const [genResult, setGenResult] = useState(null);
  const [genError, setGenError] = useState('');
  const [loadingGen, setLoadingGen] = useState(false);

  const [valForm, setValForm] = useState({ domain: '', selector: '', record: '' });
  const [valResult, setValResult] = useState(null);
  const [valError, setValError] = useState('');
  const [loadingVal, setLoadingVal] = useState(false);

  const handleGenChange = (e) => setGenForm({ ...genForm, [e.target.name]: e.target.value });
  const handleValChange = (e) => setValForm({ ...valForm, [e.target.name]: e.target.value });

  const handleGenerate = async () => {
    setLoadingGen(true);
    setGenError('');
    setGenResult(null);
    try {
      const response = await sysAdminAPI.generateDKIM(genForm);
      setGenResult(response.data.result);
    } catch (err) {
      setGenError(err.response?.data?.error || 'Generation failed');
    } finally {
      setLoadingGen(false);
    }
  };

  const handleValidate = async () => {
    setLoadingVal(true);
    setValError('');
    setValResult(null);
    try {
      const response = await sysAdminAPI.validateDKIM(valForm);
      setValResult(response.data.result);
    } catch (err) {
      setValError(err.response?.data?.error || 'Validation failed');
    } finally {
      setLoadingVal(false);
    }
  };

  return (
    <Box sx={{ maxWidth: 900, mx: 'auto', p: 3 }}>
      <Stack direction="row" alignItems="center" spacing={1} mb={3}>
        <VpnLockIcon color="primary" />
        <Typography variant="h4" fontWeight={700}>DKIM Manager</Typography>
      </Stack>

      {/* Generator */}
      <Paper sx={{ p: 3, mb: 4 }}>
        <Stack direction="row" alignItems="center" spacing={1} mb={2}>
          <KeyIcon color="action" />
          <Typography variant="h6">Generate DKIM Key Pair</Typography>
        </Stack>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={5}>
            <TextField
              label="Domain"
              name="domain"
              value={genForm.domain}
              onChange={handleGenChange}
              fullWidth
              placeholder="example.com"
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <TextField
              label="Selector"
              name="selector"
              value={genForm.selector}
              onChange={handleGenChange}
              fullWidth
              placeholder="default"
            />
          </Grid>
          <Grid item xs={12} sm={3}>
            <TextField
              select
              label="Key Size"
              name="key_size"
              value={genForm.key_size}
              onChange={handleGenChange}
              fullWidth
            >
              {keySizeOptions.map((o) => (
                <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
              ))}
            </TextField>
          </Grid>
          <Grid item xs={12}>
            <Button
              variant="contained"
              onClick={handleGenerate}
              disabled={loadingGen || !genForm.domain || !genForm.selector}
            >
              {loadingGen ? 'Generating…' : 'Generate DKIM Record'}
            </Button>
          </Grid>
        </Grid>

        {genError && <Alert severity="error" sx={{ mt: 2 }}>{genError}</Alert>}

        {genResult && (
          <Box mt={3}>
            <Divider sx={{ mb: 2 }} />
            <Typography variant="subtitle1" fontWeight={600} gutterBottom>DNS Record</Typography>
            <Paper variant="outlined" sx={{ p: 2, mb: 2, bgcolor: 'action.hover' }}>
              <Stack direction="row" alignItems="center" justifyContent="space-between" mb={1}>
                <Typography variant="caption" color="text.secondary">Host / Name</Typography>
                <CopyButton text={genResult.dns_host} />
              </Stack>
              <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                {genResult.dns_host}
              </Typography>
              <Stack direction="row" alignItems="center" justifyContent="space-between" mt={2} mb={1}>
                <Typography variant="caption" color="text.secondary">TXT Value</Typography>
                <CopyButton text={genResult.dns_record} />
              </Stack>
              <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                {genResult.dns_record}
              </Typography>
            </Paper>

            <Typography variant="subtitle1" fontWeight={600} gutterBottom>Private Key (keep secret)</Typography>
            <Paper variant="outlined" sx={{ p: 2, mb: 2, bgcolor: 'action.hover' }}>
              <Stack direction="row" justifyContent="flex-end" mb={1}>
                <CopyButton text={genResult.private_key_pem} />
              </Stack>
              <Typography
                variant="body2"
                sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontSize: '0.7rem' }}
              >
                {genResult.private_key_pem}
              </Typography>
            </Paper>
          </Box>
        )}
      </Paper>

      {/* Validator */}
      <Paper sx={{ p: 3 }}>
        <Stack direction="row" alignItems="center" spacing={1} mb={2}>
          <FactCheckIcon color="action" />
          <Typography variant="h6">Validate DKIM Record</Typography>
        </Stack>
        <Typography variant="body2" color="text.secondary" mb={2}>
          Look up via DNS by providing domain + selector, or paste the raw TXT record inline.
        </Typography>
        <Grid container spacing={2}>
          <Grid item xs={12} sm={5}>
            <TextField
              label="Domain (DNS lookup)"
              name="domain"
              value={valForm.domain}
              onChange={handleValChange}
              fullWidth
              placeholder="example.com"
            />
          </Grid>
          <Grid item xs={12} sm={4}>
            <TextField
              label="Selector (DNS lookup)"
              name="selector"
              value={valForm.selector}
              onChange={handleValChange}
              fullWidth
              placeholder="default"
            />
          </Grid>
          <Grid item xs={12}>
            <TextField
              label="Inline Record (optional — overrides DNS lookup)"
              name="record"
              value={valForm.record}
              onChange={handleValChange}
              fullWidth
              multiline
              rows={2}
              placeholder="v=DKIM1; k=rsa; p=..."
            />
          </Grid>
          <Grid item xs={12}>
            <Button
              variant="contained"
              onClick={handleValidate}
              disabled={loadingVal || (!valForm.record && !(valForm.domain && valForm.selector))}
            >
              {loadingVal ? 'Validating…' : 'Validate Record'}
            </Button>
          </Grid>
        </Grid>

        {valError && <Alert severity="error" sx={{ mt: 2 }}>{valError}</Alert>}

        {valResult && (
          <Box mt={3}>
            <Divider sx={{ mb: 2 }} />
            <Stack direction="row" alignItems="center" spacing={1} mb={2}>
              <Chip
                label={valResult.valid ? 'Valid' : 'Invalid'}
                color={valResult.valid ? 'success' : 'error'}
              />
              <Chip label={`Source: ${valResult.record_source}`} variant="outlined" size="small" />
            </Stack>

            {valResult.errors.length > 0 && (
              <Alert severity="error" sx={{ mb: 2 }}>
                <List dense disablePadding>
                  {valResult.errors.map((e, i) => <ListItem key={i} disableGutters><ListItemText primary={e} /></ListItem>)}
                </List>
              </Alert>
            )}
            {valResult.warnings.length > 0 && (
              <Alert severity="warning" sx={{ mb: 2 }}>
                <List dense disablePadding>
                  {valResult.warnings.map((w, i) => <ListItem key={i} disableGutters><ListItemText primary={w} /></ListItem>)}
                </List>
              </Alert>
            )}

            {Object.keys(valResult.parsed_tags).length > 0 && (
              <>
                <Typography variant="subtitle2" gutterBottom>Parsed Tags</Typography>
                <Paper variant="outlined" sx={{ p: 2, bgcolor: 'action.hover' }}>
                  {Object.entries(valResult.parsed_tags).map(([k, v]) => (
                    <Typography key={k} variant="body2" sx={{ fontFamily: 'monospace' }}>
                      <strong>{k}=</strong>{v}
                    </Typography>
                  ))}
                </Paper>
              </>
            )}
          </Box>
        )}
      </Paper>
    </Box>
  );
}

export default DKIMManager;
