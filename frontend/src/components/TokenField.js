import React, { useState } from 'react';
import { Button, Checkbox, FormControlLabel, Grid, TextField } from '@mui/material';
import { accessToken } from '../services/api';

/** Field for the access token. Kept for the current tab unless "remember" is ticked. */
export default function TokenField({ label, helperText, onUse }) {
  const [token, setToken] = useState(accessToken.get());
  const [remember, setRemember] = useState(!!accessToken.isRemembered());

  const use = () => {
    accessToken.set(token.trim(), remember);
    onUse();
  };

  return (
    <Grid container spacing={2} alignItems="flex-start" sx={{ mb: 2 }}>
      <Grid item xs={12} md={9}>
        <TextField label={label} type="password" fullWidth value={token} onChange={(e) => setToken(e.target.value)}
          helperText={helperText} />
        <FormControlLabel
          control={<Checkbox size="small" checked={remember} onChange={(e) => setRemember(e.target.checked)} />}
          label="Remember on this device (only on a computer you trust)" />
      </Grid>
      <Grid item xs={12} md={3}>
        <Button variant="outlined" fullWidth onClick={use} sx={{ mt: 1 }}>Use token</Button>
      </Grid>
    </Grid>
  );
}
