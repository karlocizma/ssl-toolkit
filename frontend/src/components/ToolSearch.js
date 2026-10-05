import React, { useEffect, useMemo, useRef } from 'react';
import { Autocomplete, Box, InputAdornment, ListItemIcon, TextField, Typography } from '@mui/material';
import { Search as SearchIcon } from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { getTools } from './Dashboard';

// Terms people look for that are not in a tool's title or card text (English and German).
const KEYWORDS = {
  '/email-deliverability': 'spf flatten flattening lookup limit dmarc reports aggregate rua ramp advisor policy none quarantine reject dkim selector blocklist rbl dnsbl score zustellbarkeit',
  '/dmarc-tool': 'dmarc record generator policy rua ruf',
  '/spf-tool': 'spf record generator validator',
  '/mta-sts': 'mta-sts tls-rpt tlsrpt smtp tls reporting policy mx',
  '/mail-tls': 'starttls smtp imap pop3 mail server mx tls test',
  '/domain-expiry': 'rdap whois registration registrar expiry domain ablauf',
  '/domain-monitor': 'monitor alerts alert teams webhook email status page badge public export import überwachung',
  '/audit-log': 'audit log verify hash chain protokoll',
  '/shares': 'share link shared export report snapshot teilen geteilt',
  '/ct-lookup': 'certificate transparency crt.sh subdomains',
  '/ssl-checker': 'certificate check ocsp crl expiry website https',
  '/tls-scanner': 'tls protocols ciphers grade scan',
  '/security-headers': 'hsts csp http headers',
  '/acme': "let's encrypt letsencrypt zerossl issue certificate dns-01 http-01 eab",
  '/private-ca': 'internal ca root intermediate issue sign',
  '/chain-builder': 'fullchain intermediate bundle order',
  '/jwt-decoder': 'jwt token json web token',
  '/password-toolkit': 'password generator hash encrypt',
};

const norm = (s) => String(s || '').toLowerCase();

export const filterTools = (options, query) => {
  const words = norm(query).split(/\s+/).filter(Boolean);
  if (!words.length) return options;
  const hits = options.filter((o) => words.every((w) => o.haystack.includes(w)));
  // Titles that start with what was typed come first.
  return hits.sort((a, b) => Number(norm(b.label).startsWith(words[0])) - Number(norm(a.label).startsWith(words[0])));
};

/** Search box for the tools (also: Ctrl/Cmd+K). `items` are the navigation entries {textKey, icon, path}. */
export default function ToolSearch({ items }) {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const inputRef = useRef(null);

  const options = useMemo(() => {
    const cards = Object.fromEntries(getTools(t).map((c) => [c.path, c]));
    return items.map((item) => {
      const card = cards[item.path];
      const features = card ? (card.featuresKeys || []).map((k) => t(k)).join(' ') : '';
      const description = card ? t(card.descriptionKey) : '';
      const label = t(item.textKey);
      return {
        path: item.path, icon: item.icon, label, description,
        haystack: norm([label, description, features, KEYWORDS[item.path]].join(' ')),
      };
    });
  }, [items, t]);

  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <Autocomplete
      size="small"
      options={options}
      value={null}
      blurOnSelect
      clearOnBlur
      autoHighlight
      filterOptions={(opts, state) => filterTools(opts, state.inputValue)}
      getOptionLabel={(o) => o.label}
      isOptionEqualToValue={(a, b) => a.path === b.path}
      noOptionsText={t('nav.searchNone')}
      onChange={(_, option) => option && navigate(option.path)}
      sx={{
        width: { xs: 150, sm: 300 }, mr: 1,
        '& .MuiOutlinedInput-root': { bgcolor: 'rgba(255,255,255,0.15)', color: 'inherit', '& fieldset': { borderColor: 'rgba(255,255,255,0.4)' } },
        '& .MuiSvgIcon-root': { color: 'inherit' },
        '& input::placeholder': { color: 'inherit', opacity: 0.85 },
      }}
      renderOption={(props, o) => (
        <li {...props} key={o.path}>
          <ListItemIcon sx={{ minWidth: 36 }}>{o.icon}</ListItemIcon>
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="body2">{o.label}</Typography>
            {o.description && <Typography variant="caption" color="text.secondary" noWrap sx={{ display: 'block' }}>{o.description}</Typography>}
          </Box>
        </li>
      )}
      renderInput={(params) => (
        <TextField
          {...params}
          inputRef={inputRef}
          placeholder={t('nav.search')}
          inputProps={{ ...params.inputProps, 'aria-label': t('nav.search') }}
          InputProps={{
            ...params.InputProps,
            startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" sx={{ color: 'inherit' }} /></InputAdornment>,
          }}
        />
      )}
    />
  );
}
