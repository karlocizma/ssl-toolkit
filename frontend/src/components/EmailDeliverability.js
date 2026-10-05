import React, { useState } from 'react';
import {
  Alert, Box, Button, Chip, Grid, Paper, Stack, Tab, Table, TableBody, TableCell, TableHead, TableRow, Tabs,
  TextField, Typography,
} from '@mui/material';
import { ForwardToInbox as ForwardToInboxIcon } from '@mui/icons-material';
import { deliverabilityAPI } from '../services/api';
import DmarcReports from './DmarcReports';
import ResultActions from './ResultActions';

const sev = (s) => (s === 'error' ? 'error' : s === 'warning' ? 'warning' : 'info');
const gradeColor = (g) => (g.startsWith('A') ? 'success' : g === 'B' ? 'info' : g === 'C' ? 'warning' : 'error');

function Findings({ items }) {
  if (!items?.length) return null;
  return (
    <Stack spacing={1} sx={{ mt: 2 }}>
      {items.map((f, i) => <Alert key={i} severity={sev(f.severity)}>{f.message}</Alert>)}
    </Stack>
  );
}

// Shared "enter a value, call the API, show the result" shell.
function Tool({ label, placeholder, button, call, children, extra, shareTool }) {
  const [value, setValue] = useState('');
  const [extraValue, setExtraValue] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const run = async () => {
    if (!value.trim()) {
      setError(`${label} is required`);
      return;
    }
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const { data } = await call(value.trim(), extraValue);
      setResult(data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Request failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Grid container spacing={2} alignItems="center">
        <Grid item xs={12} md={extra ? 4 : 9}>
          <TextField label={label} fullWidth value={value} placeholder={placeholder}
            onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && run()} />
        </Grid>
        {extra && (
          <Grid item xs={12} md={5}>
            <TextField label={extra} fullWidth value={extraValue} onChange={(e) => setExtraValue(e.target.value)} />
          </Grid>
        )}
        <Grid item xs={12} md={3}>
          <Button variant="contained" fullWidth onClick={run} disabled={loading}>{loading ? 'Working...' : button}</Button>
        </Grid>
      </Grid>
      {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      {shareTool && <ResultActions tool={shareTool} title={`Email deliverability: ${value.trim()}`} result={result} />}
      {result && children(result)}
    </Box>
  );
}

function SpfNode({ node, depth = 0 }) {
  return (
    <Box sx={{ ml: depth * 2.5, mt: 0.5 }}>
      <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
        {node.domain}{node.note ? ` (${node.note})` : ''}{node.error ? ` — ${node.error}` : ''}
      </Typography>
      {node.record && depth > 0 && (
        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace', wordBreak: 'break-all', display: 'block' }}>
          {node.record}
        </Typography>
      )}
      {node.children.map((c, i) => <SpfNode key={i} node={c} depth={depth + 1} />)}
    </Box>
  );
}

function Overview() {
  return (
    <Tool label="Domain" placeholder="example.com" button="Check domain" shareTool="email-deliverability" call={(v) => deliverabilityAPI.overview({ domain: v })}>
      {(r) => (
        <Stack spacing={2} sx={{ mt: 2 }}>
          <Stack direction="row" spacing={2} alignItems="center">
            <Chip label={`${r.grade} · ${r.score}/100`} color={gradeColor(r.grade)} sx={{ fontSize: 20, p: 2.5 }} />
            <Typography>{r.domain}</Typography>
          </Stack>
          <Table size="small">
            <TableHead><TableRow><TableCell>Check</TableCell><TableCell>Score</TableCell><TableCell>Detail</TableCell></TableRow></TableHead>
            <TableBody>
              {r.checks.map((c) => (
                <TableRow key={c.check}>
                  <TableCell>{c.check}</TableCell>
                  <TableCell><Chip size="small" color={c.points === c.max_points ? 'success' : c.points === 0 ? 'error' : 'warning'} label={`${c.points}/${c.max_points}`} /></TableCell>
                  <TableCell>{c.detail}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Findings items={r.findings} />
        </Stack>
      )}
    </Tool>
  );
}

function SpfFlatten() {
  return (
    <Box>
      <Typography variant="body2" color="text.secondary" paragraph>
        SPF allows at most 10 DNS lookups. Flattening replaces include, a and mx by the IP ranges behind them, so the record needs none
        (or only a few helper records). Providers change their addresses, so a flattened record is a snapshot that must be regenerated regularly.
        Nothing is published for you.
      </Typography>
      <Tool label="Domain" placeholder="example.com" button="Flatten SPF" extra="Keep these includes (comma separated, optional)"
        call={(v, keep) => deliverabilityAPI.spfFlatten({ domain: v, keep: keep.split(/[\s,]+/).filter(Boolean) })}>
        {(r) => (
          <Stack spacing={2} sx={{ mt: 2 }}>
            <Stack direction="row" spacing={1} flexWrap="wrap">
              <Chip label={`${r.original_lookups ?? '?'} lookups before`} color="warning" />
              <Chip label={`${r.lookups_after} lookups after`} color="success" />
              <Chip variant="outlined" label={`${r.network_count} address ranges`} />
              <Chip variant="outlined" label={`${r.records.length} record(s)`} />
            </Stack>
            {r.warnings.map((w, i) => <Alert key={i} severity="warning">{w}</Alert>)}
            {[...r.records].reverse().map((rec) => (
              <Box key={rec.name}>
                <Typography variant="caption" color="text.secondary">TXT record at {rec.name} ({rec.length} characters)</Typography>
                <Box component="pre" sx={{ p: 1.5, bgcolor: 'action.hover', borderRadius: 1, overflow: 'auto', fontSize: 12, m: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{rec.value}</Box>
              </Box>
            ))}
            <Typography variant="caption" color="text.secondary">Publish in the order shown: helper records first, the main record last.</Typography>
            {r.notes.map((n, i) => <Typography key={i} variant="caption" color="text.secondary" sx={{ display: 'block' }}>{n}</Typography>)}
          </Stack>
        )}
      </Tool>
    </Box>
  );
}

function Spf() {
  return (
    <Tool label="Domain" placeholder="example.com" button="Analyze SPF" call={(v) => deliverabilityAPI.spf({ domain: v })}>
      {(r) => (
        <Stack spacing={2} sx={{ mt: 2 }}>
          {r.has_spf && (
            <Stack direction="row" spacing={1} alignItems="center">
              <Chip color={r.lookups > r.lookup_limit ? 'error' : r.lookups >= 8 ? 'warning' : 'success'}
                label={`${r.lookups} / ${r.lookup_limit} DNS lookups`} />
              <Typography variant="body2" sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{r.record}</Typography>
            </Stack>
          )}
          <Findings items={r.findings} />
          <Paper variant="outlined" sx={{ p: 2 }}><SpfNode node={r.tree} /></Paper>
        </Stack>
      )}
    </Tool>
  );
}

function Dkim() {
  return (
    <Tool label="Domain" placeholder="example.com" button="Discover selectors" extra="Extra selectors (comma separated)"
      call={(v, extra) => deliverabilityAPI.dkim({ domain: v, selectors: extra.split(',').map((s) => s.trim()).filter(Boolean) })}>
      {(r) => (
        <Stack spacing={2} sx={{ mt: 2 }}>
          <Typography variant="body2" color="text.secondary">Probed {r.selectors_tried} selector names.</Typography>
          {r.found.map((f) => (
            <Paper key={f.selector} variant="outlined" sx={{ p: 2 }}>
              <Stack direction="row" spacing={1} alignItems="center">
                <Typography sx={{ fontWeight: 600 }}>{f.selector}</Typography>
                {f.key.bits && <Chip size="small" label={`${f.key.type.toUpperCase()} ${f.key.bits}`} color={f.key.bits >= 2048 ? 'success' : 'warning'} />}
                {f.key.revoked && <Chip size="small" label="revoked" />}
              </Stack>
              <Typography variant="caption" sx={{ fontFamily: 'monospace', wordBreak: 'break-all', display: 'block' }}>{f.name}</Typography>
            </Paper>
          ))}
          <Findings items={r.findings} />
        </Stack>
      )}
    </Tool>
  );
}

function DmarcReport() {
  const [text, setText] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async (payload) => {
    setError('');
    setResult(null);
    setLoading(true);
    try {
      const { data } = await deliverabilityAPI.dmarcReport(payload);
      setResult(data.result);
    } catch (err) {
      setError(err.response?.data?.error || 'Could not parse the report.');
    } finally {
      setLoading(false);
    }
  };

  const onFile = (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => submit({ file_base64: String(reader.result).split(',')[1] });
    reader.readAsDataURL(file);
  };

  return (
    <Box>
      <Typography variant="body2" color="text.secondary" paragraph>
        Upload a DMARC aggregate report (.xml, .gz or .zip, as attached to the mails from Google, Microsoft and others) or paste its XML. It is analysed in memory and not stored.
      </Typography>
      <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
        <Button variant="outlined" component="label">Choose report file<input hidden type="file" onChange={onFile} /></Button>
      </Stack>
      <TextField label="…or paste report XML" multiline minRows={4} maxRows={10} fullWidth value={text}
        onChange={(e) => setText(e.target.value)} sx={{ '& textarea': { fontFamily: 'monospace', fontSize: 12 } }} />
      <Button variant="contained" sx={{ mt: 1 }} disabled={loading || !text.trim()} onClick={() => submit({ xml: text })}>Analyze pasted XML</Button>
      {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
      {result && (
        <Stack spacing={2} sx={{ mt: 2 }}>
          <Stack direction="row" spacing={1} flexWrap="wrap">
            <Chip label={`From ${result.reporter || 'unknown'}`} />
            <Chip label={`${result.total_messages} messages`} />
            <Chip color={result.pass_rate >= 98 ? 'success' : result.pass_rate >= 90 ? 'warning' : 'error'} label={`${result.pass_rate}% pass DMARC`} />
            {result.policy.p && <Chip variant="outlined" label={`policy p=${result.policy.p}`} />}
          </Stack>
          <Findings items={result.findings} />
          <Table size="small">
            <TableHead>
              <TableRow><TableCell>Source IP</TableCell><TableCell>Messages</TableCell><TableCell>Passed</TableCell><TableCell>Failed</TableCell><TableCell>DKIM / SPF auth</TableCell></TableRow>
            </TableHead>
            <TableBody>
              {result.sources.map((s) => (
                <TableRow key={s.source_ip}>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{s.source_ip}</TableCell>
                  <TableCell>{s.count}</TableCell>
                  <TableCell>{s.pass_count}</TableCell>
                  <TableCell>{s.fail_count > 0 ? <Chip size="small" color="error" label={s.fail_count} /> : 0}</TableCell>
                  <TableCell sx={{ fontSize: 12 }}>{[...s.dkim_domains, ...s.spf_domains].join(', ')}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Stack>
      )}
    </Box>
  );
}

function Blocklists() {
  return (
    <Tool label="IPv4 address or domain" placeholder="203.0.113.5 or example.com" button="Check blocklists"
      call={(v) => deliverabilityAPI.blocklist({ target: v })}>
      {(r) => (
        <Stack spacing={2} sx={{ mt: 2 }}>
          <Stack direction="row" spacing={1} flexWrap="wrap" alignItems="center">
            <Chip color={r.status === 'clean' ? 'success' : 'error'} label={r.status === 'clean' ? 'Not listed' : `Listed on ${r.listed.length}`} />
            <Typography variant="body2">{r.checked_lists} lookups across {r.ips.length} IP(s): {r.ips.join(', ') || 'none'}</Typography>
          </Stack>
          <Findings items={r.findings} />
        </Stack>
      )}
    </Tool>
  );
}

function EmailDeliverability() {
  const [tab, setTab] = useState(0);
  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        <ForwardToInboxIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
        Email Deliverability
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Check whether mail from your domain is authenticated and trusted: an overall score, SPF lookup counting and flattening (tab &quot;SPF flatten&quot;), DKIM selector discovery, DMARC report analysis (tab &quot;DMARC reports + advisor&quot; merges many reports and tells you whether it is safe to tighten the policy) and blocklist checks.
      </Typography>
      <Paper sx={{ p: 3 }}>
        <Tabs value={tab} onChange={(_, v) => setTab(v)} variant="scrollable" sx={{ mb: 2 }}>
          <Tab label="Overview" /><Tab label="SPF" /><Tab label="SPF flatten" /><Tab label="DKIM" /><Tab label="DMARC single report" /><Tab label="DMARC reports + advisor" /><Tab label="Blocklists" />
        </Tabs>
        {tab === 0 && <Overview />}
        {tab === 1 && <Spf />}
        {tab === 2 && <SpfFlatten />}
        {tab === 3 && <Dkim />}
        {tab === 4 && <DmarcReport />}
        {tab === 5 && <DmarcReports />}
        {tab === 6 && <Blocklists />}
      </Paper>
    </Box>
  );
}

export default EmailDeliverability;
