import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import AutodiscoverChecker from './AutodiscoverChecker';
import { sslCheckAPI } from '../services/api';

jest.mock('../services/api', () => ({ sslCheckAPI: { checkAutodiscover: jest.fn() } }));

const result = {
  domain: 'example.com', email: 'test@example.com', status: 'ok',
  findings: [{ severity: 'warning', message: 'No Thunderbird/Mozilla autoconfig found' }],
  dns: { srv_autodiscover: { name: '_autodiscover._tcp.example.com', records: [] } },
  rfc6186: [{ name: '_imaps._tcp.example.com', records: [{ target: 'imap.example.com', port: 993 }] }],
  steps: [{
    step: '2. HTTPS autodiscover host', ok: true, method: 'POST',
    url: 'https://autodiscover.example.com/autodiscover/autodiscover.xml',
    result: 'Endpoint is live and requires authentication (Basic); expected without credentials',
    hops: [{ url: 'x', status: 401 }],
  }],
};

test('runs the check and renders steps, findings and SRV records', async () => {
  sslCheckAPI.checkAutodiscover.mockResolvedValue({ data: { result } });
  render(<AutodiscoverChecker />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByText('Run check'));
  expect(await screen.findByText('Autodiscover works')).toBeInTheDocument();
  expect(screen.getByText(/requires authentication \(Basic\)/)).toBeInTheDocument();
  expect(screen.getByText('No Thunderbird/Mozilla autoconfig found')).toBeInTheDocument();
  expect(screen.getByText(/imap.example.com:993/)).toBeInTheDocument();
  expect(sslCheckAPI.checkAutodiscover).toHaveBeenCalledWith({ domain: 'example.com', email: undefined });
});

test('shows the server error for an invalid domain', async () => {
  sslCheckAPI.checkAutodiscover.mockRejectedValue({ response: { data: { error: 'A valid domain name is required' } } });
  render(<AutodiscoverChecker />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'bad' } });
  fireEvent.click(screen.getByText('Run check'));
  expect(await screen.findByText('A valid domain name is required')).toBeInTheDocument();
});
