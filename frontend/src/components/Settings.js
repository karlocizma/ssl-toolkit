import React, { useCallback, useEffect, useState } from 'react';
import {
  Alert, Box, Button, Chip, FormControlLabel, Grid, Paper, Stack, Switch, Tab, Tabs, TextField, Typography,
} from '@mui/material';
import { Settings as SettingsIcon } from '@mui/icons-material';
import { monitorAPI, settingsAPI } from '../services/api';
import TokenField from './TokenField';

const GROUPS = {
  alerts: { title: 'Alerts', intro: 'When and where expiry and change alerts are sent for monitored certificates and domains.' },
  email: { title: 'Email', intro: 'SMTP server used for alert emails.' },
  access: { title: 'Access', intro: 'Who may use the monitor and what the scanners may reach.' },
  status: { title: 'Status page', intro: 'The public page at /status.' },
  lookups: { title: 'Lookups', intro: 'DNS resolvers and caches used by the checkers.' },
  audit: { title: 'Audit log', intro: 'Size and retention of the audit log.' },
};

const FIELDS = {
  ALERT_THRESHOLDS: { label: 'Alert at (days before expiry)', help: 'Comma-separated, e.g. 30,14,7,1' },
  ALERT_CHECK_INTERVAL_HOURS: { label: 'Check every (hours)', help: '0 turns the background checks off. Turning them on again after a start with 0 needs a restart.' },
  ALERT_WEBHOOK_URL: { label: 'Slack / generic webhook URL', help: 'Receives {"text", "events"} as JSON.' },
  ALERT_TEAMS_WEBHOOK_URL: { label: 'Microsoft Teams webhook URL', help: 'A Workflows or Incoming Webhook URL (https only).' },
  APP_URL: { label: 'Public URL of this app', help: 'Adds an "Open Domain Monitor" button to Teams alerts.' },
  SMTP_HOST: { label: 'SMTP host' },
  SMTP_PORT: { label: 'SMTP port' },
  SMTP_USER: { label: 'SMTP user' },
  SMTP_PASSWORD: { label: 'SMTP password' },
  SMTP_STARTTLS: { label: 'Use STARTTLS' },
  ALERT_EMAIL_FROM: { label: 'Sender address', help: 'Defaults to the SMTP user.' },
  ALERT_EMAIL_TO: { label: 'Recipients', help: 'Comma-separated email addresses.' },
  MONITOR_PUBLIC: { label: 'Monitor needs no login', warn: 'Anyone who can reach this server can read and change the monitor. Only for a private network.' },
  ALLOW_PRIVATE_TARGETS: { label: 'Allow checks against private / internal addresses', warn: 'Lets visitors probe your internal network through this server. Keep off on anything public.' },
  STATUS_PAGE_ENABLED: { label: 'Status page enabled' },
  STATUS_PAGE_TITLE: { label: 'Status page heading' },
  RBL_RESOLVERS: { label: 'DNS resolvers for blocklist checks', help: 'IP addresses, comma-separated. Spamhaus refuses public resolvers.' },
  RBL_LISTS: { label: 'Blocklist zones', help: 'Comma-separated DNSBL zones; empty uses the defaults.' },
  ACME_DNS_RESOLVERS: { label: 'Resolvers for dns-01 propagation checks', help: 'IP addresses, comma-separated.' },
  CT_CACHE_SECONDS: { label: 'Certificate Transparency cache (seconds)', help: '0 disables the cache.' },
  RDAP_CACHE_SECONDS: { label: 'Domain registration (RDAP) cache (seconds)', help: '0 disables the cache.' },
  AUDIT_LOG_MAX_BYTES: { label: 'Rotate audit log at (bytes)' },
  AUDIT_LOG_KEEP: { label: 'Rotated audit logs to keep' },
};

const SOURCE = { ui: ['saved here', 'primary'], env: ['from .env', 'default'], default: ['default', 'default'] };
const isOn = (value) => ['1', 'true', 'yes', 'on'].includes(String(value || '').toLowerCase());

function Settings() {
  const [settings, setSettings] = useState(null);
  const [edits, setEdits] = useState({});
  const [errors, setErrors] = useState({});
  const [message, setMessage] = useState(null);
  const [tab, setTab] = useState(0);
  const [deliveries, setDeliveries] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setMessage(null);
    try {
      const { data } = await settingsAPI.get();
      setSettings(data.settings);
      setEdits({});
      setErrors({});
    } catch (err) {
      setSettings(null);
      const status = err.response?.status;
      setMessage({
        severity: 'error',
        text: status === 401 ? 'Wrong password. Enter the ADMIN_TOKEN of this server.'
          : status === 403 ? 'No admin password is set on the server. Set ADMIN_TOKEN in .env and recreate the backend.'
            : (err.response?.data?.error || 'Could not load the settings.'),
      });
    }
  }, []);

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const edit = (name, value) => setEdits((prev) => ({ ...prev, [name]: value }));
  const dirty = Object.keys(edits).length;

  const apply = async (values, reset = []) => {
    setBusy(true);
    setMessage(null);
    setErrors({});
    try {
      const { data } = await settingsAPI.save(values, reset);
      setSettings(data.settings);
      setEdits({});
      setMessage({ severity: 'success', text: 'Saved. The change is active now.' });
    } catch (err) {
      setErrors(err.response?.data?.errors || {});
      setMessage({ severity: 'error', text: err.response?.data?.errors ? 'Some values are not valid.' : (err.response?.data?.error || 'Could not save.') });
    } finally {
      setBusy(false);
    }
  };

  const sendTest = async () => {
    setDeliveries(null);
    try {
      setDeliveries((await monitorAPI.alertsTest()).data.deliveries);
    } catch (err) {
      setDeliveries([{ channel: 'request', sent: false, reason: err.response?.data?.error || 'failed' }]);
    }
  };

  const renderField = (s) => {
    const meta = FIELDS[s.name] || { label: s.name };
    const changed = s.name in edits;
    const chip = SOURCE[s.source];
    const sourceChip = <Chip size="small" color={chip[1]} variant="outlined" label={chip[0]} />;
    const resetButton = s.source === 'ui' && (
      <Button size="small" disabled={busy} onClick={() => apply({}, [s.name])}>Back to .env / default</Button>
    );
    return (
      <Grid item xs={12} key={s.name}>
        {s.type === 'bool' ? (
          <Box>
            <FormControlLabel label={meta.label} control={(
              <Switch checked={changed ? !!edits[s.name] : isOn(s.value || s.default)} onChange={(e) => edit(s.name, e.target.checked)} />
            )} />
            {sourceChip} {resetButton}
            {meta.warn && (changed ? !!edits[s.name] : isOn(s.value)) && <Alert severity="warning" sx={{ mt: 1 }}>{meta.warn}</Alert>}
            {errors[s.name] && <Typography color="error" variant="caption">{errors[s.name]}</Typography>}
          </Box>
        ) : (
          <Stack direction="row" spacing={1} alignItems="flex-start">
            <TextField fullWidth label={meta.label} name={s.name}
              type={s.secret ? 'password' : 'text'} autoComplete="off"
              value={changed ? edits[s.name] : (s.secret ? '' : (s.value ?? ''))}
              placeholder={s.secret ? (s.is_set ? '•••••••• (set, type to replace)' : 'not set') : s.default}
              onChange={(e) => edit(s.name, e.target.value)}
              error={!!errors[s.name]} helperText={errors[s.name] || meta.help} />
            <Box sx={{ pt: 1, minWidth: 150 }}>
              {sourceChip}
              {s.secret && s.is_set && !changed && (
                <Button size="small" disabled={busy} onClick={() => apply({ [s.name]: '' })}>Clear</Button>
              )}
              {resetButton}
            </Box>
          </Stack>
        )}
      </Grid>
    );
  };

  const groups = settings ? Object.keys(GROUPS).filter((g) => settings.some((s) => s.group === g)) : [];
  const group = groups[tab];

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <SettingsIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Settings
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Change alert channels and other options here instead of editing .env. Saved values win over .env and apply immediately; "Back to .env"
        removes a saved value. Passwords and webhook URLs are write-only: they are never shown again. Secrets such as ADMIN_TOKEN and
        SECRET_KEY can only be changed in .env.
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <TokenField label="Admin password" onUse={load}
          helperText="The ADMIN_TOKEN of the server. Kept for this browser tab unless you tick the box below." />
        {message && <Alert severity={message.severity}>{message.text}</Alert>}
      </Paper>

      {settings && (
        <Paper sx={{ p: 3 }}>
          <Tabs value={tab} onChange={(e, v) => setTab(v)} variant="scrollable" sx={{ mb: 2 }}>
            {groups.map((g) => <Tab key={g} label={GROUPS[g].title} />)}
          </Tabs>
          <Typography color="text.secondary" sx={{ mb: 2 }}>{GROUPS[group].intro}</Typography>
          <Grid container spacing={2}>
            {settings.filter((s) => s.group === group).map(renderField)}
          </Grid>
          <Stack direction="row" spacing={2} alignItems="center" sx={{ mt: 3 }}>
            <Button variant="contained" disabled={!dirty || busy} onClick={() => apply(edits)}>
              {dirty ? `Save ${dirty} change${dirty === 1 ? '' : 's'}` : 'Save'}
            </Button>
            {dirty > 0 && <Button disabled={busy} onClick={() => { setEdits({}); setErrors({}); }}>Discard</Button>}
            {group === 'alerts' && <Button variant="outlined" onClick={sendTest} disabled={dirty > 0}>Send test alert</Button>}
          </Stack>
          {group === 'alerts' && dirty > 0 && (
            <Typography variant="caption" color="text.secondary">Save first, then send a test.</Typography>
          )}
          {deliveries && group === 'alerts' && (
            <Stack spacing={1} sx={{ mt: 2 }}>
              {deliveries.map((d) => (
                <Alert key={d.channel} severity={d.sent ? 'success' : (d.reason === 'not configured' ? 'info' : 'error')}>
                  {d.channel}: {d.sent ? 'sent' : d.reason}
                </Alert>
              ))}
            </Stack>
          )}
        </Paper>
      )}
    </Box>
  );
}

export default Settings;
