import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  TextField,
  Button,
  Checkbox,
  FormControlLabel,
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
  WbSunny as WbSunnyIcon,
  BuildCircle as BuildCircleIcon,
  PlaylistAddCheck as PlaylistAddCheckIcon,
} from '@mui/icons-material';
import { sysAdminAPI } from '../services/api';

const allOptions = ['~all', '-all', '?all', '+all'];

function SPFManager() {
  const [generatorForm, setGeneratorForm] = useState({
    domain: '',
    ipv4: '',
    ipv6: '',
    include: '',
    include_mx: true,
    include_a: false,
    redirect: '',
    exp: '',
    all: '~all',
  });
  const [generatorResult, setGeneratorResult] = useState(null);
  const [generatorError, setGeneratorError] = useState('');
  const [validatorForm, setValidatorForm] = useState({ domain: '', record: '' });
  const [validatorResult, setValidatorResult] = useState(null);
  const [validatorError, setValidatorError] = useState('');
  const [loadingGenerate, setLoadingGenerate] = useState(false);
  const [loadingValidate, setLoadingValidate] = useState(false);

  const splitList = (value) =>
    value
      .split(/[,\n]+/)
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);

  const handleGeneratorChange = (field, value) => {
    setGeneratorForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleGenerate = async () => {
    if (!generatorForm.domain.trim()) {
      setGeneratorError('Domain is required to build an SPF record.');
      return;
    }

    setGeneratorError('');
    setGeneratorResult(null);
    setLoadingGenerate(true);

    try {
      const response = await sysAdminAPI.generateSPF({
        ...generatorForm,
        domain: generatorForm.domain.trim(),
        ipv4: splitList(generatorForm.ipv4),
        ipv6: splitList(generatorForm.ipv6),
        include: splitList(generatorForm.include),
        include_mx: Boolean(generatorForm.include_mx),
        include_a: Boolean(generatorForm.include_a),
        redirect: generatorForm.redirect.trim() || undefined,
        exp: generatorForm.exp.trim() || undefined,
      });
      setGeneratorResult(response.data.result);
    } catch (error) {
      setGeneratorError(error.response?.data?.error || 'Unable to build SPF record.');
    } finally {
      setLoadingGenerate(false);
    }
  };

  const handleValidate = async () => {
    if (!validatorForm.domain.trim() && !validatorForm.record.trim()) {
      setValidatorError('Provide a domain or paste a TXT record to validate.');
      return;
    }

    setValidatorError('');
    setValidatorResult(null);
    setLoadingValidate(true);

    try {
      const response = await sysAdminAPI.validateSPF({
        domain: validatorForm.domain.trim() || undefined,
        record: validatorForm.record.trim() || undefined,
      });
      setValidatorResult(response.data.result);
    } catch (error) {
      setValidatorError(error.response?.data?.error || 'Unable to validate SPF record.');
    } finally {
      setLoadingValidate(false);
    }
  };

  const renderMechanisms = (mechanisms) => (
    <Stack direction="row" spacing={1} flexWrap="wrap">
      {mechanisms?.map((mechanism, index) => (
        <Chip key={index} label={mechanism} variant="outlined" />
      ))}
    </Stack>
  );

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <WbSunnyIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        SPF Builder & Validator
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Generate robust SPF policies and inspect DNS TXT records for misconfigurations that could cause spoofed emails or DNS lookup overruns.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              <BuildCircleIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Generate SPF Record
            </Typography>

            <Stack spacing={2}>
              <TextField
                label="Domain"
                value={generatorForm.domain}
                onChange={(e) => handleGeneratorChange('domain', e.target.value)}
                placeholder="example.com"
                required
              />

              <TextField
                label="IPv4 Addresses"
                value={generatorForm.ipv4}
                onChange={(e) => handleGeneratorChange('ipv4', e.target.value)}
                helperText="Comma or newline separated"
                multiline
                minRows={2}
              />

              <TextField
                label="IPv6 Addresses"
                value={generatorForm.ipv6}
                onChange={(e) => handleGeneratorChange('ipv6', e.target.value)}
                helperText="Comma or newline separated"
                multiline
                minRows={2}
              />

              <TextField
                label="Include Domains"
                value={generatorForm.include}
                onChange={(e) => handleGeneratorChange('include', e.target.value)}
                helperText="Domains to include, separated by commas"
              />

              <FormControlLabel
                control={(
                  <Checkbox
                    checked={generatorForm.include_mx}
                    onChange={(e) => handleGeneratorChange('include_mx', e.target.checked)}
                  />
                )}
                label="Include MX records"
              />

              <FormControlLabel
                control={(
                  <Checkbox
                    checked={generatorForm.include_a}
                    onChange={(e) => handleGeneratorChange('include_a', e.target.checked)}
                  />
                )}
                label="Include A records"
              />

              <Grid container spacing={2}>
                <Grid item xs={12} sm={6}>
                  <TextField
                    label="redirect"
                    value={generatorForm.redirect}
                    onChange={(e) => handleGeneratorChange('redirect', e.target.value)}
                    helperText="Optional redirect domain"
                  />
                </Grid>
                <Grid item xs={12} sm={6}>
                  <TextField
                    label="exp"
                    value={generatorForm.exp}
                    onChange={(e) => handleGeneratorChange('exp', e.target.value)}
                    helperText="Optional explanation"
                  />
                </Grid>
              </Grid>

              <TextField
                select
                label="Terminal All Mechanism"
                value={generatorForm.all}
                onChange={(e) => handleGeneratorChange('all', e.target.value)}
              >
                {allOptions.map((option) => (
                  <MenuItem key={option} value={option}>
                    {option}
                  </MenuItem>
                ))}
              </TextField>

              <Button variant="contained" onClick={handleGenerate} disabled={loadingGenerate}>
                {loadingGenerate ? 'Generating...' : 'Generate SPF'}
              </Button>

              {generatorError && <Alert severity="error">{generatorError}</Alert>}

              {generatorResult && (
                <Box>
                  <Divider sx={{ my: 2 }} />
                  <Typography variant="subtitle1" gutterBottom>
                    Suggested TXT Record
                  </Typography>
                  <Paper variant="outlined" sx={{ p: 2, bgcolor: 'grey.50', fontFamily: 'monospace', wordBreak: 'break-word' }}>
                    {generatorResult.record}
                  </Paper>
                  <Typography variant="subtitle2" sx={{ mt: 2 }}>
                    Mechanisms
                  </Typography>
                  {renderMechanisms(generatorResult.mechanisms)}
                  {generatorResult.notes?.length > 0 && (
                    <Alert severity="info" sx={{ mt: 2 }}>
                      <ul>
                        {generatorResult.notes.map((note, index) => (
                          <li key={index}>{note}</li>
                        ))}
                      </ul>
                    </Alert>
                  )}
                </Box>
              )}
            </Stack>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              <PlaylistAddCheckIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Validate SPF Record
            </Typography>

            <Stack spacing={2}>
              <TextField
                label="Domain"
                value={validatorForm.domain}
                onChange={(e) => setValidatorForm((prev) => ({ ...prev, domain: e.target.value }))}
                placeholder="example.com"
              />

              <TextField
                label="SPF TXT Record"
                value={validatorForm.record}
                onChange={(e) => setValidatorForm((prev) => ({ ...prev, record: e.target.value }))}
                multiline
                minRows={4}
                placeholder="v=spf1 ip4:203.0.113.2 include:_spf.example.net ~all"
              />

              <Button variant="outlined" onClick={handleValidate} disabled={loadingValidate}>
                {loadingValidate ? 'Validating...' : 'Validate SPF'}
              </Button>

              {validatorError && <Alert severity="error">{validatorError}</Alert>}

              {validatorResult && (
                <Box>
                  <Divider sx={{ my: 2 }} />
                  <Stack direction="row" spacing={1} mb={2}>
                    <Chip
                      label={validatorResult.valid ? 'Valid SPF Policy' : 'Issues detected'}
                      color={validatorResult.valid ? 'success' : 'warning'}
                    />
                    {validatorResult.record_source && (
                      <Chip label={`Source: ${validatorResult.record_source}`} variant="outlined" size="small" />
                    )}
                  </Stack>

                  <Typography variant="subtitle2" gutterBottom>
                    Mechanisms
                  </Typography>
                  {renderMechanisms(validatorResult.mechanisms)}

                  {validatorResult.errors?.length > 0 && (
                    <Alert severity="error" sx={{ mt: 2 }}>
                      <Typography variant="subtitle2">Errors</Typography>
                      <ul>
                        {validatorResult.errors.map((error, index) => (
                          <li key={index}>{error}</li>
                        ))}
                      </ul>
                    </Alert>
                  )}

                  {validatorResult.warnings?.length > 0 && (
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      <Typography variant="subtitle2">Warnings</Typography>
                      <ul>
                        {validatorResult.warnings.map((warning, index) => (
                          <li key={index}>{warning}</li>
                        ))}
                      </ul>
                    </Alert>
                  )}

                  {validatorResult.dns_records && validatorResult.dns_records.length > 0 && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="subtitle2">TXT Records from DNS</Typography>
                      <List dense>
                        {validatorResult.dns_records.map((record, index) => (
                          <ListItem key={index}>
                            <ListItemText primary={record} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}
                </Box>
              )}
            </Stack>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default SPFManager;
