import React, { useState } from 'react';
import {
  Box, Button, Menu, MenuItem, TextField, IconButton, Alert, Select, FormControl, InputLabel, Stack, Tooltip,
} from '@mui/material';
import DownloadIcon from '@mui/icons-material/Download';
import ShareIcon from '@mui/icons-material/Share';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { shareAPI } from '../services/api';
import { exportJson, exportHtml } from '../utils/report';

const TTLS = [[1, '1 hour'], [24, '24 hours'], [168, '7 days'], [720, '30 days']];

/** Export (JSON / HTML report) and expiring share link for a tool result. */
export default function ResultActions({ tool, title, result }) {
  const [anchor, setAnchor] = useState(null);
  const [ttl, setTtl] = useState(24);
  const [share, setShare] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  if (!result) return null;

  const link = share ? `${window.location.origin}/shared/${share.token}` : '';

  const create = async () => {
    setBusy(true);
    setError('');
    try {
      const r = await shareAPI.create({ title, tool, result, ttl_hours: ttl });
      setShare(r.data.share);
    } catch (e) {
      setError(e.response?.status === 401
        ? 'Sharing needs the access token. Set it on the Domain Monitor page first.'
        : (e.response?.data?.error || 'Could not create the link'));
    } finally {
      setBusy(false);
    }
  };

  const copy = () => navigator.clipboard?.writeText(link).catch(() => {});

  return (
    <Box sx={{ mt: 2 }}>
      <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
        <Button size="small" startIcon={<DownloadIcon />} onClick={(e) => setAnchor(e.currentTarget)}>Export</Button>
        <Menu anchorEl={anchor} open={Boolean(anchor)} onClose={() => setAnchor(null)}>
          <MenuItem onClick={() => { exportJson(title, result); setAnchor(null); }}>JSON file</MenuItem>
          <MenuItem onClick={() => { exportHtml({ title, tool, result }); setAnchor(null); }}>HTML report</MenuItem>
        </Menu>
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel id={`ttl-${tool}`}>Link valid for</InputLabel>
          <Select labelId={`ttl-${tool}`} label="Link valid for" value={ttl} onChange={(e) => setTtl(e.target.value)}>
            {TTLS.map(([h, l]) => <MenuItem key={h} value={h}>{l}</MenuItem>)}
          </Select>
        </FormControl>
        <Button size="small" variant="outlined" startIcon={<ShareIcon />} onClick={create} disabled={busy}>Share link</Button>
      </Stack>
      {error && <Alert severity="warning" sx={{ mt: 1 }}>{error}</Alert>}
      {share && (
        <Box sx={{ mt: 1, display: 'flex', gap: 1, alignItems: 'center' }}>
          <TextField size="small" fullWidth value={link} inputProps={{ readOnly: true, 'aria-label': 'Share link' }}
            helperText={`Anyone with the link can read this snapshot until ${new Date(share.expires_at).toLocaleString()}. Revoke it under Shared results.`} />
          <Tooltip title="Copy link"><IconButton aria-label="copy link" onClick={copy}><ContentCopyIcon /></IconButton></Tooltip>
        </Box>
      )}
    </Box>
  );
}
