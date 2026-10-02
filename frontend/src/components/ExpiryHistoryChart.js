import React from 'react';
import { Box, Typography } from '@mui/material';

const W = 520;
const H = 110;
const PAD = { l: 34, r: 8, t: 8, b: 20 };

// Days-until-expiry over time. Sawtooth drops mark time passing; a jump up is a renewal.
function ExpiryHistoryChart({ history, changes = [] }) {
  const points = (history || []).filter((h) => h.days_until_expiry != null && h.checked_at);
  if (points.length < 2) {
    return <Typography variant="caption" color="text.secondary">Not enough checks yet to draw a history (needs at least two).</Typography>;
  }
  const times = points.map((p) => new Date(p.checked_at).getTime());
  const vals = points.map((p) => p.days_until_expiry);
  const t0 = Math.min(...times);
  const t1 = Math.max(...times);
  const vMax = Math.max(30, ...vals);
  const vMin = Math.min(0, ...vals);
  const x = (t) => PAD.l + ((t - t0) / (t1 - t0 || 1)) * (W - PAD.l - PAD.r);
  const y = (v) => PAD.t + (1 - (v - vMin) / (vMax - vMin || 1)) * (H - PAD.t - PAD.b);
  const line = points.map((p, i) => `${x(times[i]).toFixed(1)},${y(vals[i]).toFixed(1)}`).join(' ');
  const renewals = changes.map((c) => new Date(c.detected_at).getTime()).filter((t) => t >= t0 && t <= t1);
  const warnY = y(14);

  return (
    <Box>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Days until certificate expiry over time">
        <line x1={PAD.l} x2={W - PAD.r} y1={warnY} y2={warnY} stroke="#ed6c02" strokeDasharray="4 3" strokeWidth="1" />
        <text x={PAD.l - 4} y={warnY + 3} fontSize="9" textAnchor="end" fill="#ed6c02">14d</text>
        <text x={PAD.l - 4} y={y(vMax) + 3} fontSize="9" textAnchor="end" fill="currentColor">{vMax}d</text>
        <text x={PAD.l - 4} y={y(vMin) + 3} fontSize="9" textAnchor="end" fill="currentColor">{vMin}d</text>
        <polyline points={line} fill="none" stroke="#1976d2" strokeWidth="2" />
        {renewals.map((t, i) => (
          <line key={i} x1={x(t)} x2={x(t)} y1={PAD.t} y2={H - PAD.b} stroke="#2e7d32" strokeWidth="1" strokeDasharray="2 2" />
        ))}
        <text x={PAD.l} y={H - 5} fontSize="9" fill="currentColor">{new Date(t0).toLocaleDateString()}</text>
        <text x={W - PAD.r} y={H - 5} fontSize="9" textAnchor="end" fill="currentColor">{new Date(t1).toLocaleDateString()}</text>
      </svg>
      <Typography variant="caption" color="text.secondary">
        {points.length} checks{renewals.length ? ` · green lines mark ${renewals.length} certificate replacement(s)` : ''}
      </Typography>
    </Box>
  );
}

export default ExpiryHistoryChart;
