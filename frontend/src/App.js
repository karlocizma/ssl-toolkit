import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import CertificateDecoder from './components/CertificateDecoder';
import CSRGenerator from './components/CSRGenerator';
import CSRDecoder from './components/CSRDecoder';
import SSLChecker from './components/SSLChecker';
import CertificateConverter from './components/CertificateConverter';
import KeyGenerator from './components/KeyGenerator';
import KeyValidator from './components/KeyValidator';
import KeyCertificateMatch from './components/KeyCertificateMatch';
import CertificateChainChecker from './components/CertificateChainChecker';
import DMARCManager from './components/DMARCManager';
import SPFManager from './components/SPFManager';
import EmailHeaderAnalyzer from './components/EmailHeaderAnalyzer';
import PasswordToolkit from './components/PasswordToolkit';
import DNSDiagnostics from './components/DNSDiagnostics';
import './App.css';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Layout>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/certificate-decoder" element={<CertificateDecoder />} />
            <Route path="/csr-generator" element={<CSRGenerator />} />
            <Route path="/csr-decoder" element={<CSRDecoder />} />
            <Route path="/ssl-checker" element={<SSLChecker />} />
            <Route path="/certificate-converter" element={<CertificateConverter />} />
            <Route path="/key-generator" element={<KeyGenerator />} />
            <Route path="/key-validator" element={<KeyValidator />} />
            <Route path="/key-certificate-match" element={<KeyCertificateMatch />} />
            <Route path="/certificate-chain-checker" element={<CertificateChainChecker />} />
            <Route path="/dmarc-tool" element={<DMARCManager />} />
            <Route path="/spf-tool" element={<SPFManager />} />
            <Route path="/email-header-analyzer" element={<EmailHeaderAnalyzer />} />
            <Route path="/password-toolkit" element={<PasswordToolkit />} />
            <Route path="/dns-diagnostics" element={<DNSDiagnostics />} />
          </Routes>
        </Layout>
      </Router>
    </ThemeProvider>
  );
}

export default App;
