import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import MailTLS from './MailTLS';
import { sslCheckAPI } from '../services/api';

jest.mock('../services/api', () => ({ sslCheckAPI: { scanMailTLS: jest.fn() } }));

const domainResult = {
  domain: 'example.com', grade: 'F',
  findings: [{ severity: 'critical', message: 'mx2.example.com does not offer STARTTLS' }],
  mx: [
    { host: 'mx1.example.com', port: 25, priority: 10, protocol: 'smtp', mode: 'starttls', reachable: true, starttls: true,
      grade: 'A', banner: 'ESMTP ready', findings: [],
      certificate: { subject: 'mx1.example.com', issuer: 'Test CA', days_until_expiry: 80, trusted: true },
      protocols: { 'TLSv1.2': { supported: true }, 'TLSv1.3': { supported: true } } },
    { host: 'mx2.example.com', port: 25, priority: 20, reachable: false, error: 'Connection timed out (many hosting providers block outbound port 25)' },
  ],
};

test('tests all MX hosts of a domain and shows grades, certificate and unreachable hosts', async () => {
  sslCheckAPI.scanMailTLS.mockResolvedValue({ data: { result: domainResult } });
  render(<MailTLS />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByText('Test'));
  expect(await screen.findByText('Worst grade F')).toBeInTheDocument();
  expect(screen.getByText('STARTTLS offered')).toBeInTheDocument();
  expect(screen.getByText(/expires in 80 day/)).toBeInTheDocument();
  expect(screen.getByText(/Connection timed out/)).toBeInTheDocument();
  expect(sslCheckAPI.scanMailTLS).toHaveBeenCalledWith({ domain: 'example.com' });
});

test('shows the server error', async () => {
  sslCheckAPI.scanMailTLS.mockRejectedValue({ response: { data: { error: 'Target resolves to a non-public address' } } });
  render(<MailTLS />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'internal.example' } });
  fireEvent.click(screen.getByText('Test'));
  expect(await screen.findByText('Target resolves to a non-public address')).toBeInTheDocument();
});
