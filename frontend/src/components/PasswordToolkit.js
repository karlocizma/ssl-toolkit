import React, { useState } from 'react';
import {
  Box,
  Typography,
  Paper,
  Grid,
  Slider,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Button,
  TextField,
  Select,
  MenuItem,
  InputLabel,
  FormControl,
  Chip,
  Alert,
  Stack,
} from '@mui/material';
import {
  Password as PasswordIcon,
  Lock as LockIcon,
  Key as KeyIcon,
} from '@mui/icons-material';
import { sysAdminAPI } from '../services/api';

const hashOptions = ['sha256', 'sha512', 'sha3_512', 'md5'];

function PasswordToolkit() {
  const [length, setLength] = useState(16);
  const [characterSets, setCharacterSets] = useState({
    upper: true,
    lower: true,
    digits: true,
    symbols: false,
  });
  const [hashAlgorithms, setHashAlgorithms] = useState(['sha256', 'sha512']);
  const [encryptionEnabled, setEncryptionEnabled] = useState(false);
  const [passphrase, setPassphrase] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleGenerate = async () => {
    if (!Object.values(characterSets).some(Boolean)) {
      setError('Select at least one character set.');
      return;
    }

    setError('');
    setResult(null);
    setLoading(true);

    try {
      const payload = {
        length,
        character_sets: characterSets,
        hash_algorithms: hashAlgorithms,
        encryption: {
          enabled: encryptionEnabled,
          passphrase: encryptionEnabled && passphrase ? passphrase : undefined,
        },
      };
      const response = await sysAdminAPI.generatePassword(payload);
      setResult(response.data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Unable to generate password.');
    } finally {
      setLoading(false);
    }
  };

  const toggleCharacterSet = (key) => {
    setCharacterSets((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <PasswordIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Password Generator & Hashing Toolkit
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Create high-entropy passwords, preview multiple hash digests, and optionally encrypt the generated secret using Fernet.
      </Typography>

      <Paper sx={{ p: 3 }}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" gutterBottom>
              Length
            </Typography>
            <Slider
              min={8}
              max={64}
              value={length}
              valueLabelDisplay="on"
              onChange={(_, value) => setLength(Array.isArray(value) ? value[0] : value)}
            />

            <Typography variant="subtitle1" gutterBottom sx={{ mt: 3 }}>
              Character Sets
            </Typography>
            <FormGroup>
              {[
                { key: 'upper', label: 'Uppercase (A-Z)' },
                { key: 'lower', label: 'Lowercase (a-z)' },
                { key: 'digits', label: 'Digits (0-9)' },
                { key: 'symbols', label: 'Symbols (!@#$...)' },
              ].map(({ key, label }) => (
                <FormControlLabel
                  key={key}
                  control={(
                    <Checkbox
                      checked={characterSets[key]}
                      onChange={() => toggleCharacterSet(key)}
                    />
                  )}
                  label={label}
                />
              ))}
            </FormGroup>

            <FormControl fullWidth sx={{ mt: 3 }}>
              <InputLabel id="hash-select-label">Hash Algorithms</InputLabel>
              <Select
                labelId="hash-select-label"
                multiple
                value={hashAlgorithms}
                label="Hash Algorithms"
                onChange={(e) =>
                  setHashAlgorithms(
                    typeof e.target.value === 'string' ? e.target.value.split(',') : e.target.value
                  )
                }
                renderValue={(selected) => selected.join(', ')}
              >
                {hashOptions.map((option) => (
                  <MenuItem key={option} value={option}>
                    <Checkbox checked={hashAlgorithms.indexOf(option) > -1} />
                    <Typography sx={{ ml: 1 }}>{option}</Typography>
                  </MenuItem>
                ))}
              </Select>
            </FormControl>

            <FormControlLabel
              sx={{ mt: 3 }}
              control={(
                <Checkbox
                  checked={encryptionEnabled}
                  onChange={(e) => setEncryptionEnabled(e.target.checked)}
                />
              )}
              label="Encrypt password with Fernet"
            />

            {encryptionEnabled && (
              <TextField
                label="Passphrase (optional)"
                fullWidth
                sx={{ mt: 2 }}
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                helperText="Leave empty to auto-generate a key"
              />
            )}

            <Button
              variant="contained"
              sx={{ mt: 3 }}
              onClick={handleGenerate}
              disabled={loading}
            >
              {loading ? 'Generating...' : 'Generate Secure Password'}
            </Button>

            {error && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {error}
              </Alert>
            )}
          </Grid>

          <Grid item xs={12} md={6}>
            {result ? (
              <Stack spacing={2}>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Generated Password
                  </Typography>
                  <Typography sx={{ fontFamily: 'monospace', fontSize: '1.1rem', wordBreak: 'break-all' }}>
                    {result.password}
                  </Typography>
                  <Stack direction="row" spacing={1} mt={2}>
                    <Chip icon={<LockIcon />} label={`Entropy: ${result.entropy_bits} bits`} />
                    {Object.entries(result.character_sets || {}).map(([key, enabled]) => (
                      enabled ? <Chip key={key} size="small" label={key.toUpperCase()} variant="outlined" /> : null
                    ))}
                  </Stack>
                </Paper>

                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Typography variant="subtitle2" gutterBottom>
                    Hash Digests
                  </Typography>
                  {Object.entries(result.hashes || {}).map(([algo, digest]) => (
                    <Box key={algo} sx={{ mb: 1 }}>
                      <Typography color="text.secondary">{algo.toUpperCase()}</Typography>
                      <Typography sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{digest}</Typography>
                    </Box>
                  ))}
                  {(!result.hashes || Object.keys(result.hashes).length === 0) && (
                    <Typography color="text.secondary">No hash output available.</Typography>
                  )}
                </Paper>

                {result.encryption?.enabled && (
                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <Typography variant="subtitle2" gutterBottom>
                      Encryption
                    </Typography>
                    <Typography sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                      {result.encryption.encrypted_password}
                    </Typography>
                    {result.encryption.key && (
                      <Alert severity="info" sx={{ mt: 2 }}>
                        <Typography variant="subtitle2">Store this key securely</Typography>
                        <Typography sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                          {result.encryption.key}
                        </Typography>
                      </Alert>
                    )}
                    <Chip
                      sx={{ mt: 2 }}
                      icon={<KeyIcon />}
                      label={`Key source: ${result.encryption.key_source}`}
                    />
                  </Paper>
                )}

                {result.warnings?.length > 0 && (
                  <Alert severity="warning">
                    <ul>
                      {result.warnings.map((warning, index) => (
                        <li key={index}>{warning}</li>
                      ))}
                    </ul>
                  </Alert>
                )}
              </Stack>
            ) : (
              <Paper variant="outlined" sx={{ p: 4, textAlign: 'center', color: 'text.secondary' }}>
                <Typography variant="h6" gutterBottom>
                  No password generated yet
                </Typography>
                <Typography>
                  Pick your requirements on the left, then click "Generate" to get a password along with hashes and optional encryption output.
                </Typography>
              </Paper>
            )}
          </Grid>
        </Grid>
      </Paper>
    </Box>
  );
}

export default PasswordToolkit;
