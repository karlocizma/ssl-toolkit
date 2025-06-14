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
} from '@mui/icons-material';
import { useNavigate } from 'react-router-dom';

const tools = [
  {
    title: 'Certificate Decoder',
    description: 'Decode and analyze SSL/TLS certificates',
    icon: <SecurityIcon sx={{ fontSize: 40 }} />,
    path: '/certificate-decoder',
    color: 'primary',
    features: ['Parse certificate details', 'View subject/issuer info', 'Check validity dates', 'Show fingerprints']
  },
  {
    title: 'CSR Generator',
    description: 'Generate Certificate Signing Requests',
    icon: <DescriptionIcon sx={{ fontSize: 40 }} />,
    path: '/csr-generator',
    color: 'secondary',
    features: ['Create CSR', 'Generate private key', 'Add Subject Alternative Names', 'RSA/EC key support']
  },
  {
    title: 'CSR Decoder',
    description: 'Decode and analyze Certificate Signing Requests',
    icon: <DescriptionIcon sx={{ fontSize: 40 }} />,
    path: '/csr-decoder',
    color: 'info',
    features: ['Parse CSR details', 'View subject info', 'Check signature', 'Extract SANs']
  },
  {
    title: 'SSL Checker',
    description: 'Check SSL certificates for domains',
    icon: <SearchIcon sx={{ fontSize: 40 }} />,
    path: '/ssl-checker',
    color: 'success',
    features: ['Domain SSL check', 'Certificate validation', 'Expiration monitoring', 'Chain verification']
  },
  {
    title: 'Certificate Converter',
    description: 'Convert certificates between formats',
    icon: <TransformIcon sx={{ fontSize: 40 }} />,
    path: '/certificate-converter',
    color: 'warning',
    features: ['PFX to PEM', 'PEM to DER', 'Format conversion', 'Batch processing']
  },
  {
    title: 'Key Generator',
    description: 'Generate RSA and EC private keys',
    icon: <VpnKeyIcon sx={{ fontSize: 40 }} />,
    path: '/key-generator',
    color: 'error',
    features: ['RSA key generation', 'EC key generation', 'Multiple key sizes', 'Secure generation']
  },
  {
    title: 'Key Validator',
    description: 'Validate and analyze private keys',
    icon: <VerifiedUserIcon sx={{ fontSize: 40 }} />,
    path: '/key-validator',
    color: 'primary',
    features: ['Key validation', 'Algorithm detection', 'Key size check', 'Encryption status']
  },
  {
    title: 'Key-Certificate Match',
    description: 'Check if private key matches certificate',
    icon: <LinkIcon sx={{ fontSize: 40 }} />,
    path: '/key-certificate-match',
    color: 'secondary',
    features: ['Key-cert matching', 'Public key comparison', 'Validation check', 'Security verification']
  },
  {
    title: 'Certificate Chain Checker',
    description: 'Analyze certificate chains',
    icon: <AccountTreeIcon sx={{ fontSize: 40 }} />,
    path: '/certificate-chain-checker',
    color: 'info',
    features: ['Chain validation', 'Root/intermediate certs', 'Trust path', 'Chain completeness']
  }
];

function Dashboard() {
  const navigate = useNavigate();

  return (
    <Box>
      <Typography variant="h4" component="h1" gutterBottom>
        SSL Certificate Toolkit
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        A comprehensive suite of tools for SSL certificate management, generation, validation, and conversion.
        Choose a tool below to get started.
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
                    {tool.title}
                  </Typography>
                </Box>
                <Typography variant="body2" color="text.secondary" paragraph>
                  {tool.description}
                </Typography>
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {tool.features.map((feature, idx) => (
                    <Chip 
                      key={idx}
                      label={feature}
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
                  Open Tool
                </Button>
              </CardActions>
            </Card>
          </Grid>
        ))}
      </Grid>
      
      <Box sx={{ mt: 4, p: 3, bgcolor: 'background.paper', borderRadius: 2 }}>
        <Typography variant="h6" gutterBottom>
          About SSL Toolkit
        </Typography>
        <Typography variant="body2" color="text.secondary">
          This toolkit provides a comprehensive set of tools for SSL/TLS certificate management.
          All operations are performed securely in your browser or on our secure servers.
          Private keys and sensitive data are handled with the highest security standards.
        </Typography>
      </Box>
    </Box>
  );
}

export default Dashboard;

