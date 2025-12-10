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
  Policy as PolicyIcon,
  ShieldOutlined as ShieldOutlinedIcon,
  FactCheck as FactCheckIcon,
} from '@mui/icons-material';
import { sysAdminAPI } from '../services/api';

const policyOptions = [
  { label: 'Reject (strongest)', value: 'reject' },
  { label: 'Quarantine (flag suspicious)', value: 'quarantine' },
  { label: 'None (monitor only)', value: 'none' }
];

const alignmentOptions = [
  { label: 'Strict', value: 's' },
  { label: 'Relaxed', value: 'r' }
];

function DMARCManager() {
  const [generatorForm, setGeneratorForm] = useState({
    domain: '',
    policy: 'reject',
    subdomain_policy: 'reject',
    rua: '',
    ruf: '',
    pct: 100,
    fo: '1',
    adkim: 's',
    aspf: 's',
    report_interval: 86400,
  });
  const [generatorResult, setGeneratorResult] = useState(null);
  const [generatorError, setGeneratorError] = useState('');
  const [validatorForm, setValidatorForm] = useState({ domain: '', record: '' });
  const [validatorResult, setValidatorResult] = useState(null);
  const [validatorError, setValidatorError] = useState('');
  const [loadingGenerate, setLoadingGenerate] = useState(false);
  const [loadingValidate, setLoadingValidate] = useState(false);

  const parseList = (value) =>
    value
      .split(',')
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);

  const handleGeneratorChange = (field, value) => {
    setGeneratorForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleGenerate = async () => {
    if (!generatorForm.domain.trim()) {
      setGeneratorError('Domain is required to build a DMARC record.');
      return;
    }

    setGeneratorError('');
    setGeneratorResult(null);
    setLoadingGenerate(true);

    try {
      const payload = {
        ...generatorForm,
        rua: parseList(generatorForm.rua),
        ruf: parseList(generatorForm.ruf),
        pct: Number(generatorForm.pct),
        report_interval: Number(generatorForm.report_interval),
      };
      const response = await sysAdminAPI.generateDMARC(payload);
      setGeneratorResult(response.data.result);
    } catch (error) {
      setGeneratorError(error.response?.data?.error || 'Unable to build DMARC record.');
    } finally {
      setLoadingGenerate(false);
    }
  };

  const handleValidate = async () => {
    if (!validatorForm.domain.trim() && !validatorForm.record.trim()) {
      setValidatorError('Provide a domain to fetch from DNS or paste a DMARC record to validate.');
      return;
    }

    setValidatorError('');
    setValidatorResult(null);
    setLoadingValidate(true);

    try {
      const response = await sysAdminAPI.validateDMARC({
        domain: validatorForm.domain.trim() || undefined,
        record: validatorForm.record.trim() || undefined,
      });
      setValidatorResult(response.data.result);
    } catch (error) {
      setValidatorError(error.response?.data?.error || 'Unable to validate DMARC record.');
    } finally {
      setLoadingValidate(false);
    }
  };

  const renderTagList = (tags) => (
    <List dense>
      {Object.entries(tags || {}).map(([key, value]) => (
        <ListItem key={key} disablePadding>
          <ListItemText
            primary={key}
            secondary={value}
            primaryTypographyProps={{ fontWeight: 600 }}
          />
        </ListItem>
      ))}
    </List>
  );

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <ShieldOutlinedIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        DMARC Generator & Validator
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Build best-practice DMARC DNS records and validate existing deployments. Ensure reports reach the right inboxes and policies are enforced across subdomains.
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              <PolicyIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Generate DMARC Record
            </Typography>

            <Stack spacing={2}>
              <TextField
                label="Primary Domain"
                value={generatorForm.domain}
                onChange={(e) => handleGeneratorChange('domain', e.target.value)}
                placeholder="example.com"
                required
              />

              <TextField
                select
                label="Enforcement Policy"
                value={generatorForm.policy}
                onChange={(e) => handleGeneratorChange('policy', e.target.value)}
                helperText="Select how receiving servers should handle failures"
              >
                {policyOptions.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    {option.label}
                  </MenuItem>
                ))}
              </TextField>

              <TextField
                select
                label="Subdomain Policy"
                value={generatorForm.subdomain_policy}
                onChange={(e) => handleGeneratorChange('subdomain_policy', e.target.value)}
              >
                {policyOptions.map((option) => (
                  <MenuItem key={option.value} value={option.value}>
                    {option.label}
                  </MenuItem>
                ))}
              </TextField>

              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <TextField
                    select
                    label="DKIM Alignment"
                    value={generatorForm.adkim}
                    onChange={(e) => handleGeneratorChange('adkim', e.target.value)}
                  >
                    {alignmentOptions.map((option) => (
                      <MenuItem key={option.value} value={option.value}>
                        {option.label}
                      </MenuItem>
                    ))}
                  </TextField>
                </Grid>
                <Grid item xs={6}>
                  <TextField
                    select
                    label="SPF Alignment"
                    value={generatorForm.aspf}
                    onChange={(e) => handleGeneratorChange('aspf', e.target.value)}
                  >
                    {alignmentOptions.map((option) => (
                      <MenuItem key={option.value} value={option.value}>
                        {option.label}
                      </MenuItem>
                    ))}
                  </TextField>
                </Grid>
              </Grid>

              <TextField
                label="Aggregate Report Mailboxes (rua)"
                value={generatorForm.rua}
                onChange={(e) => handleGeneratorChange('rua', e.target.value)}
                helperText="Comma-separated emails. e.g. security@example.com"
              />

              <TextField
                label="Forensic Report Mailboxes (ruf)"
                value={generatorForm.ruf}
                onChange={(e) => handleGeneratorChange('ruf', e.target.value)}
                helperText="Optional comma-separated addresses"
              />

              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <TextField
                    type="number"
                    label="pct"
                    value={generatorForm.pct}
                    onChange={(e) => handleGeneratorChange('pct', e.target.value)}
                    helperText="Percent of mail policy applies to"
                  />
                </Grid>
                <Grid item xs={6}>
                  <TextField
                    type="number"
                    label="Report Interval (seconds)"
                    value={generatorForm.report_interval}
                    onChange={(e) => handleGeneratorChange('report_interval', e.target.value)}
                    helperText="Typically 86400"
                  />
                </Grid>
              </Grid>

              <TextField
                label="Failure Reporting Options (fo)"
                value={generatorForm.fo}
                onChange={(e) => handleGeneratorChange('fo', e.target.value)}
                helperText="Combine 0,1,d,s"
              />

              <Button
                variant="contained"
                onClick={handleGenerate}
                disabled={loadingGenerate}
              >
                {loadingGenerate ? 'Generating...' : 'Generate DMARC Record'}
              </Button>

              {generatorError && <Alert severity="error">{generatorError}</Alert>}

              {generatorResult && (
                <Box>
                  <Divider sx={{ my: 2 }} />
                  <Typography variant="subtitle1" gutterBottom>
                    Recommended TXT Record ({generatorResult.dns_host})
                  </Typography>
                  <Paper variant="outlined" sx={{ p: 2, bgcolor: 'grey.50', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                    {generatorResult.record}
                  </Paper>
                  {generatorResult.recommendations?.length > 0 && (
                    <Stack direction="row" spacing={1} flexWrap="wrap" mt={2}>
                      {generatorResult.recommendations.map((note, index) => (
                        <Chip key={index} label={note} color="info" variant="outlined" />
                      ))}
                    </Stack>
                  )}
                  <Divider sx={{ my: 2 }} />
                  <Typography variant="subtitle2" gutterBottom>
                    Tags
                  </Typography>
                  {renderTagList(generatorResult.tags)}
                </Box>
              )}
            </Stack>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3, height: '100%' }}>
            <Typography variant="h6" gutterBottom>
              <FactCheckIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
              Validate DMARC Deployment
            </Typography>

            <Stack spacing={2}>
              <TextField
                label="Domain"
                value={validatorForm.domain}
                onChange={(e) => setValidatorForm((prev) => ({ ...prev, domain: e.target.value }))}
                placeholder="example.com"
                helperText="Optional. Leave blank to validate pasted record only"
              />

              <TextField
                label="Existing DMARC Record"
                multiline
                minRows={4}
                value={validatorForm.record}
                onChange={(e) => setValidatorForm((prev) => ({ ...prev, record: e.target.value }))}
                placeholder="v=DMARC1; p=reject; rua=mailto:security@example.com"
              />

              <Button
                variant="outlined"
                onClick={handleValidate}
                disabled={loadingValidate}
              >
                {loadingValidate ? 'Validating...' : 'Validate Record'}
              </Button>

              {validatorError && <Alert severity="error">{validatorError}</Alert>}

              {validatorResult && (
                <Box>
                  <Divider sx={{ my: 2 }} />
                  <Stack direction="row" spacing={1} alignItems="center" mb={2}>
                    <Chip
                      label={validatorResult.valid ? 'Valid DMARC Record' : 'Invalid DMARC Record'}
                      color={validatorResult.valid ? 'success' : 'error'}
                    />
                    {validatorResult.record_source && (
                      <Chip label={`Source: ${validatorResult.record_source}`} variant="outlined" size="small" />
                    )}
                  </Stack>

                  <Typography variant="subtitle2" gutterBottom>
                    Parsed Tags
                  </Typography>
                  {renderTagList(validatorResult.tags)}

                  {validatorResult.errors?.length > 0 && (
                    <Alert severity="error" sx={{ mt: 2 }}>
                      <Typography variant="subtitle2">Critical issues</Typography>
                      <ul>
                        {validatorResult.errors.map((issue, index) => (
                          <li key={index}>{issue}</li>
                        ))}
                      </ul>
                    </Alert>
                  )}

                  {validatorResult.warnings?.length > 0 && (
                    <Alert severity="warning" sx={{ mt: 2 }}>
                      <Typography variant="subtitle2">Recommendations</Typography>
                      <ul>
                        {validatorResult.warnings.map((warning, index) => (
                          <li key={index}>{warning}</li>
                        ))}
                      </ul>
                    </Alert>
                  )}

                  {validatorResult.dns_records && validatorResult.dns_records.length > 0 && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="subtitle2">DNS TXT Results</Typography>
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

export default DMARCManager;
