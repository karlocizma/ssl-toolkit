import React, { useState, useMemo } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { ColorModeContext } from './contexts/ColorModeContext';
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
import DKIMManager from './components/DKIMManager';
import SelfSignedGenerator from './components/SelfSignedGenerator';
import SSLConfigGenerator from './components/SSLConfigGenerator';
import JWTDecoder from './components/JWTDecoder';
import './App.css';

function App() {
  const [mode, setMode] = useState(
    () => localStorage.getItem('colorMode') || 'light'
  );

  const colorMode = useMemo(
    () => ({
      toggleColorMode: () => {
        setMode((prev) => {
          const next = prev === 'light' ? 'dark' : 'light';
          localStorage.setItem('colorMode', next);
          return next;
        });
      },
    }),
    []
  );

  const theme = useMemo(
    () =>
      createTheme({
        palette: {
          mode,
          primary: { main: '#1976d2' },
          secondary: { main: '#dc004e' },
        },
      }),
    [mode]
  );

  return (
    <ColorModeContext.Provider value={colorMode}>
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
              <Route path="/dkim-manager" element={<DKIMManager />} />
              <Route path="/self-signed-generator" element={<SelfSignedGenerator />} />
              <Route path="/ssl-config-generator" element={<SSLConfigGenerator />} />
              <Route path="/jwt-decoder" element={<JWTDecoder />} />
            </Routes>
          </Layout>
        </Router>
      </ThemeProvider>
    </ColorModeContext.Provider>
  );
}

export default App;
