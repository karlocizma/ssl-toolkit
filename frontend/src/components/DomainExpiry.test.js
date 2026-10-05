import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import DomainExpiry from './DomainExpiry';
import { sslCheckAPI } from '../services/api';

jest.mock('../services/api', () => ({ sslCheckAPI: { checkDomainRegistration: jest.fn() } }));

const result = {
  domain: 'example.com', registrar: 'Example Registrar Inc.', status: ['client transfer prohibited'],
  registered: '2015-01-01T00:00:00+00:00', last_changed: '2026-01-01T00:00:00+00:00',
  expires: '2027-01-01T00:00:00+00:00', days_until_expiry: 20, nameservers: ['ns1.example.net'], dnssec: true,
  findings: [{ severity: 'warning', message: 'The registration expires in 20 day(s)' }],
};

test('shows expiry, registrar and findings', async () => {
  sslCheckAPI.checkDomainRegistration.mockResolvedValue({ data: { result } });
  render(<DomainExpiry />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByText('Look up'));
  expect(await screen.findByText('20 days left')).toBeInTheDocument();
  expect(screen.getByText('Example Registrar Inc.')).toBeInTheDocument();
  expect(screen.getByText('The registration expires in 20 day(s)')).toBeInTheDocument();
  expect(sslCheckAPI.checkDomainRegistration).toHaveBeenCalledWith({ domain: 'example.com' });
});

test('says so when the registry publishes no expiry date', async () => {
  sslCheckAPI.checkDomainRegistration.mockResolvedValue({ data: { result: { ...result, expires: null, days_until_expiry: null, findings: [] } } });
  render(<DomainExpiry />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'example.de' } });
  fireEvent.click(screen.getByText('Look up'));
  expect(await screen.findByText('Expiry not published')).toBeInTheDocument();
});

test('shows the server error', async () => {
  sslCheckAPI.checkDomainRegistration.mockRejectedValue({ response: { data: { error: 'The domain is not registered' } } });
  render(<DomainExpiry />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'nothere.com' } });
  fireEvent.click(screen.getByText('Look up'));
  expect(await screen.findByText('The domain is not registered')).toBeInTheDocument();
});
