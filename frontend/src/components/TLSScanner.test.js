import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import TLSScanner from './TLSScanner';
import { sslCheckAPI } from '../services/api';

jest.mock('../services/api', () => ({ sslCheckAPI: { scanTLS: jest.fn() } }));

const result = {
  reachable: true, hostname: 'example.com', port: 443, grade: 'B', certificate_trusted: true,
  findings: [{ severity: 'warning', message: 'TLSv1.0 is deprecated and should be disabled' }],
  protocols: {
    'TLSv1.0': { supported: true, ciphers: [{ name: 'AES128-SHA', forward_secrecy: false, weakness: { reason: '3DES is vulnerable to Sweet32' } }] },
    'TLSv1.2': { supported: true, ciphers: [{ name: 'ECDHE-RSA-AES128-GCM-SHA256', forward_secrecy: true }] },
    'TLSv1.3': { supported: false },
  },
};

test('scan shows the grade, findings and per-protocol cipher details', async () => {
  sslCheckAPI.scanTLS.mockResolvedValue({ data: { result } });
  render(<TLSScanner />);
  fireEvent.change(screen.getByLabelText('Hostname'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByText('Scan'));
  expect(await screen.findByText('Grade B')).toBeInTheDocument();
  expect(screen.getByText(/TLSv1.0 is deprecated/)).toBeInTheDocument();
  expect(screen.getByText('PFS')).toBeInTheDocument();
  expect(screen.getByText('3DES is vulnerable to Sweet32')).toBeInTheDocument();
  expect(screen.getByText('Not supported')).toBeInTheDocument();
  expect(sslCheckAPI.scanTLS).toHaveBeenCalledWith({ hostname: 'example.com', port: 443 });
});

test('requires a hostname and shows an unreachable host', async () => {
  render(<TLSScanner />);
  fireEvent.click(screen.getByText('Scan'));
  expect(screen.getByText('Hostname is required')).toBeInTheDocument();
  sslCheckAPI.scanTLS.mockResolvedValue({ data: { result: { reachable: false, error: 'No TLS handshake succeeded' } } });
  fireEvent.change(screen.getByLabelText('Hostname'), { target: { value: 'down.example' } });
  fireEvent.click(screen.getByText('Scan'));
  await waitFor(() => expect(screen.getByText('No TLS handshake succeeded')).toBeInTheDocument());
});
