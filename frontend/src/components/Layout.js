import React, { useState } from 'react';
import {
  AppBar,
  Box,
  Drawer,
  IconButton,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  Typography,
  useTheme,
  Menu,
  MenuItem,
  Button,
} from '@mui/material';
import {
  Menu as MenuIcon,
  Security as SecurityIcon,
  VpnKey as VpnKeyIcon,
  Description as DescriptionIcon,
  Transform as TransformIcon,
  Search as SearchIcon,
  Dashboard as DashboardIcon,
  VerifiedUser as VerifiedUserIcon,
  Link as LinkIcon,
  AccountTree as AccountTreeIcon,
  Policy as PolicyIcon,
  WbSunny as WbSunnyIcon,
  MarkEmailRead as MarkEmailReadIcon,
  Password as PasswordIcon,
  Dns as DnsIcon,
  Language as LanguageIcon,
} from '@mui/icons-material';
import { useNavigate, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

const drawerWidth = 240;

function Layout({ children }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [langAnchorEl, setLangAnchorEl] = useState(null);
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useTheme();
  const { t, i18n } = useTranslation();

  const menuItems = [
    { textKey: 'nav.dashboard', icon: <DashboardIcon />, path: '/' },
    { textKey: 'nav.certificateDecoder', icon: <SecurityIcon />, path: '/certificate-decoder' },
    { textKey: 'nav.csrGenerator', icon: <DescriptionIcon />, path: '/csr-generator' },
    { textKey: 'nav.csrDecoder', icon: <DescriptionIcon />, path: '/csr-decoder' },
    { textKey: 'nav.sslChecker', icon: <SearchIcon />, path: '/ssl-checker' },
    { textKey: 'nav.certificateConverter', icon: <TransformIcon />, path: '/certificate-converter' },
    { textKey: 'nav.keyGenerator', icon: <VpnKeyIcon />, path: '/key-generator' },
    { textKey: 'nav.keyValidator', icon: <VerifiedUserIcon />, path: '/key-validator' },
    { textKey: 'nav.keyCertificateMatch', icon: <LinkIcon />, path: '/key-certificate-match' },
    { textKey: 'nav.certificateChainChecker', icon: <AccountTreeIcon />, path: '/certificate-chain-checker' },
    { textKey: 'nav.dmarcManager', icon: <PolicyIcon />, path: '/dmarc-tool' },
    { textKey: 'nav.spfManager', icon: <WbSunnyIcon />, path: '/spf-tool' },
    { textKey: 'nav.emailHeaderAnalyzer', icon: <MarkEmailReadIcon />, path: '/email-header-analyzer' },
    { textKey: 'nav.passwordToolkit', icon: <PasswordIcon />, path: '/password-toolkit' },
    { textKey: 'nav.dnsDiagnostics', icon: <DnsIcon />, path: '/dns-diagnostics' },
  ];

  const handleDrawerToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const handleLangMenuOpen = (event) => {
    setLangAnchorEl(event.currentTarget);
  };

  const handleLangMenuClose = () => {
    setLangAnchorEl(null);
  };

  const handleLanguageChange = (lang) => {
    i18n.changeLanguage(lang);
    handleLangMenuClose();
  };

  const drawer = (
    <div>
      <Toolbar>
        <Typography variant="h6" noWrap component="div" sx={{ fontSize: '0.95rem' }}>
          {t('app.shortName')}
        </Typography>
      </Toolbar>
      <List>
        {menuItems.map((item) => (
          <ListItem key={item.textKey} disablePadding>
            <ListItemButton
              selected={location.pathname === item.path}
              onClick={() => {
                navigate(item.path);
                setMobileOpen(false);
              }}
            >
              <ListItemIcon>{item.icon}</ListItemIcon>
              <ListItemText primary={t(item.textKey)} />
            </ListItemButton>
          </ListItem>
        ))}
      </List>
    </div>
  );

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar
        position="fixed"
        sx={{
          width: { sm: `calc(100% - ${drawerWidth}px)` },
          ml: { sm: `${drawerWidth}px` },
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2, display: { sm: 'none' } }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" noWrap component="div" sx={{ flexGrow: 1 }}>
            {t('app.name')}
          </Typography>
          <Button
            color="inherit"
            startIcon={<LanguageIcon />}
            onClick={handleLangMenuOpen}
          >
            {i18n.language.toUpperCase()}
          </Button>
          <Menu
            anchorEl={langAnchorEl}
            open={Boolean(langAnchorEl)}
            onClose={handleLangMenuClose}
          >
            <MenuItem
              onClick={() => handleLanguageChange('en')}
              selected={i18n.language === 'en'}
            >
              English
            </MenuItem>
            <MenuItem
              onClick={() => handleLanguageChange('de')}
              selected={i18n.language === 'de'}
            >
              Deutsch
            </MenuItem>
          </Menu>
        </Toolbar>
      </AppBar>
      <Box
        component="nav"
        sx={{ width: { sm: drawerWidth }, flexShrink: { sm: 0 } }}
        aria-label="tool navigation"
      >
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={handleDrawerToggle}
          ModalProps={{
            keepMounted: true,
          }}
          sx={{
            display: { xs: 'block', sm: 'none' },
            '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
          }}
        >
          {drawer}
        </Drawer>
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: 'none', sm: 'block' },
            '& .MuiDrawer-paper': { boxSizing: 'border-box', width: drawerWidth },
          }}
          open
        >
          {drawer}
        </Drawer>
      </Box>
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          width: { sm: `calc(100% - ${drawerWidth}px)` },
        }}
      >
        <Toolbar />
        {children}
      </Box>
    </Box>
  );
}

export default Layout;
