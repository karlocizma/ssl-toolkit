import React from 'react';
import {
  Typography,
  Grid,
  Card,
  CardContent,
  CardActions,
  Button,
  Box,
  Chip,
} from '@mui/material';
import {
  Security as SecurityIcon,
  VpnKey as VpnKeyIcon,
  Description as DescriptionIcon,
  Transform as TransformIcon,
  Search as SearchIcon,
  VerifiedUser as VerifiedUserIcon,
  Link as LinkIcon,
  AccountTree as AccountTreeIcon,
  Policy as PolicyIcon,
  WbSunny as WbSunnyIcon,
  MarkEmailRead as MarkEmailReadIcon,
  Password as PasswordIcon,
  Dns as DnsIcon,
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

const getTools = (t) => [
  {
    titleKey: 'tools.certificateDecoder.title',
    descriptionKey: 'tools.certificateDecoder.description',
    icon: <SecurityIcon sx={{ fontSize: 40 }} />,
    path: '/certificate-decoder',
    color: 'primary',
    featuresKeys: ['tools.certificateDecoder.features.0', 'tools.certificateDecoder.features.1', 'tools.certificateDecoder.features.2', 'tools.certificateDecoder.features.3']
  },
  {
    titleKey: 'tools.csrGenerator.title',
    descriptionKey: 'tools.csrGenerator.description',
    icon: <DescriptionIcon sx={{ fontSize: 40 }} />,
    path: '/csr-generator',
    color: 'secondary',
    featuresKeys: ['tools.csrGenerator.features.0', 'tools.csrGenerator.features.1', 'tools.csrGenerator.features.2', 'tools.csrGenerator.features.3']
  },
  {
    titleKey: 'tools.csrDecoder.title',
    descriptionKey: 'tools.csrDecoder.description',
    icon: <DescriptionIcon sx={{ fontSize: 40 }} />,
    path: '/csr-decoder',
    color: 'info',
    featuresKeys: ['tools.csrDecoder.features.0', 'tools.csrDecoder.features.1', 'tools.csrDecoder.features.2', 'tools.csrDecoder.features.3']
  },
  {
    titleKey: 'tools.sslChecker.title',
    descriptionKey: 'tools.sslChecker.description',
    icon: <SearchIcon sx={{ fontSize: 40 }} />,
    path: '/ssl-checker',
    color: 'success',
    featuresKeys: ['tools.sslChecker.features.0', 'tools.sslChecker.features.1', 'tools.sslChecker.features.2', 'tools.sslChecker.features.3']
  },
  {
    titleKey: 'tools.certificateConverter.title',
    descriptionKey: 'tools.certificateConverter.description',
    icon: <TransformIcon sx={{ fontSize: 40 }} />,
    path: '/certificate-converter',
    color: 'warning',
    featuresKeys: ['tools.certificateConverter.features.0', 'tools.certificateConverter.features.1', 'tools.certificateConverter.features.2', 'tools.certificateConverter.features.3']
  },
  {
    titleKey: 'tools.keyGenerator.title',
    descriptionKey: 'tools.keyGenerator.description',
    icon: <VpnKeyIcon sx={{ fontSize: 40 }} />,
    path: '/key-generator',
    color: 'error',
    featuresKeys: ['tools.keyGenerator.features.0', 'tools.keyGenerator.features.1', 'tools.keyGenerator.features.2', 'tools.keyGenerator.features.3']
  },
  {
    titleKey: 'tools.keyValidator.title',
    descriptionKey: 'tools.keyValidator.description',
    icon: <VerifiedUserIcon sx={{ fontSize: 40 }} />,
    path: '/key-validator',
    color: 'primary',
    featuresKeys: ['tools.keyValidator.features.0', 'tools.keyValidator.features.1', 'tools.keyValidator.features.2', 'tools.keyValidator.features.3']
  },
  {
    titleKey: 'tools.keyCertificateMatch.title',
    descriptionKey: 'tools.keyCertificateMatch.description',
    icon: <LinkIcon sx={{ fontSize: 40 }} />,
    path: '/key-certificate-match',
    color: 'secondary',
    featuresKeys: ['tools.keyCertificateMatch.features.0', 'tools.keyCertificateMatch.features.1', 'tools.keyCertificateMatch.features.2', 'tools.keyCertificateMatch.features.3']
  },
  {
    titleKey: 'tools.certificateChainChecker.title',
    descriptionKey: 'tools.certificateChainChecker.description',
    icon: <AccountTreeIcon sx={{ fontSize: 40 }} />,
    path: '/certificate-chain-checker',
    color: 'info',
    featuresKeys: ['tools.certificateChainChecker.features.0', 'tools.certificateChainChecker.features.1', 'tools.certificateChainChecker.features.2', 'tools.certificateChainChecker.features.3']
  },
  {
    titleKey: 'tools.dmarcManager.title',
    descriptionKey: 'tools.dmarcManager.description',
    icon: <PolicyIcon sx={{ fontSize: 40 }} />,
    path: '/dmarc-tool',
    color: 'success',
    featuresKeys: ['tools.dmarcManager.features.0', 'tools.dmarcManager.features.1', 'tools.dmarcManager.features.2', 'tools.dmarcManager.features.3']
  },
  {
    titleKey: 'tools.spfManager.title',
    descriptionKey: 'tools.spfManager.description',
    icon: <WbSunnyIcon sx={{ fontSize: 40 }} />,
    path: '/spf-tool',
    color: 'warning',
    featuresKeys: ['tools.spfManager.features.0', 'tools.spfManager.features.1', 'tools.spfManager.features.2', 'tools.spfManager.features.3']
  },
  {
    titleKey: 'tools.emailHeaderAnalyzer.title',
    descriptionKey: 'tools.emailHeaderAnalyzer.description',
    icon: <MarkEmailReadIcon sx={{ fontSize: 40 }} />,
    path: '/email-header-analyzer',
    color: 'secondary',
    featuresKeys: ['tools.emailHeaderAnalyzer.features.0', 'tools.emailHeaderAnalyzer.features.1', 'tools.emailHeaderAnalyzer.features.2', 'tools.emailHeaderAnalyzer.features.3']
  },
  {
    titleKey: 'tools.passwordToolkit.title',
    descriptionKey: 'tools.passwordToolkit.description',
    icon: <PasswordIcon sx={{ fontSize: 40 }} />,
    path: '/password-toolkit',
    color: 'error',
    featuresKeys: ['tools.passwordToolkit.features.0', 'tools.passwordToolkit.features.1', 'tools.passwordToolkit.features.2', 'tools.passwordToolkit.features.3']
  },
  {
    titleKey: 'tools.dnsDiagnostics.title',
    descriptionKey: 'tools.dnsDiagnostics.description',
    icon: <DnsIcon sx={{ fontSize: 40 }} />,
    path: '/dns-diagnostics',
    color: 'primary',
    featuresKeys: ['tools.dnsDiagnostics.features.0', 'tools.dnsDiagnostics.features.1', 'tools.dnsDiagnostics.features.2', 'tools.dnsDiagnostics.features.3']
  }
];

function Dashboard() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const tools = getTools(t);

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        {t('app.name')}
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        {t('app.tagline')}
      </Typography>

      <Grid container spacing={3} sx={{ mt: 2 }}>
        {tools.map((tool, index) => (
          <Grid item xs={12} sm={6} md={4} key={index}>
            <Card
              sx={{
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                transition: 'transform 0.2s',
                '&:hover': {
                  transform: 'translateY(-4px)',
                  boxShadow: 3
                }
              }}
            >
              <CardContent sx={{ flexGrow: 1 }}>
                <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                  <Box sx={{ color: `${tool.color}.main`, mr: 2 }}>
                    {tool.icon}
                  </Box>
                  <Typography variant="h6" component="h2">
                    {t(tool.titleKey)}
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" paragraph>
                  {t(tool.descriptionKey)}
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {tool.featuresKeys.map((featureKey, idx) => (
                    <Chip
                      key={idx}
                      label={t(featureKey)}
                      size="small"
                      variant="outlined"
                      color={tool.color}
                    />
                  ))}
                </Box>
              </CardContent>
              <CardActions>
                <Button
                  size="small"
                  color={tool.color}
                  onClick={() => navigate(tool.path)}
                  variant="contained"
                  fullWidth
                >
                  {t('dashboard.openTool')}
                </Button>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Box sx={{ mt: 4, p: 3, bgcolor: 'background.paper', borderRadius: 2 }}>
        <Typography variant="h6" gutterBottom>
          {t('dashboard.aboutTitle')}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {t('dashboard.aboutDescription')}
        </Typography>
      </Box>
    </Box>
  );
}

export default Dashboard;
