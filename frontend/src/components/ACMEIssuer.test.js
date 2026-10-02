import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import ACMEIssuer from './ACMEIssuer';
import { acmeAPI } from '../services/api';

jest.mock('../services/api', () => ({ acmeAPI: { order: jest.fn(), complete: jest.fn(), issue: jest.fn(), renewalInfo: jest.fn() } }));

beforeEach(() => jest.clearAllMocks());

test('manual flow sends external account binding credentials and a custom directory URL', async () => {
  acmeAPI.order.mockResolvedValue({ data: { result: {
    directory: 'https://acme.zerossl.com/v2/DV90', order_url: 'o', account_key_pem: 'AK', csr_pem: 'CSR', challenge_type: 'dns-01',
    instructions: 'Create the TXT records', challenges: [{ domain: 'example.com', dns_name: '_acme-challenge.example.com', dns_value: 'abc' }],
  } } });
  render(<ACMEIssuer />);
  fireEvent.change(screen.getByLabelText(/Domains/), { target: { value: 'example.com' } });
  fireEvent.mouseDown(screen.getAllByRole('combobox')[0]);
  fireEvent.click(await screen.findByText(/Another ACME CA/));
  fireEvent.change(screen.getByLabelText('ACME directory URL'), { target: { value: 'https://acme.zerossl.com/v2/DV90' } });
  fireEvent.change(screen.getByLabelText('EAB key ID'), { target: { value: 'kid-1' } });
  fireEvent.change(screen.getByLabelText('EAB HMAC key (base64url)'), { target: { value: 'secretkey' } });
  fireEvent.click(screen.getByText('1. Create order'));
  await waitFor(() => expect(acmeAPI.order).toHaveBeenCalled());
  expect(acmeAPI.order.mock.calls[0][0]).toMatchObject({
    domains: ['example.com'], directory: 'https://acme.zerossl.com/v2/DV90', eab_kid: 'kid-1', eab_hmac_key: 'secretkey',
  });
  expect(await screen.findByText('_acme-challenge.example.com')).toBeInTheDocument();
});

test('renewal check shows the window the CA suggests', async () => {
  acmeAPI.renewalInfo.mockResolvedValue({ data: { result: {
    status: 'wait', message: 'The CA suggests renewing in about 30 day(s), from 2026-11-01.',
    suggested_window_start: '2026-11-01T00:00:00Z', suggested_window_end: '2026-11-03T00:00:00Z', explanation_url: null,
  } } });
  render(<ACMEIssuer />);
  fireEvent.click(screen.getByText('Renewal check'));
  fireEvent.change(screen.getByLabelText('Certificate (PEM)'), { target: { value: '-----BEGIN CERTIFICATE-----' } });
  fireEvent.click(screen.getByText('Check renewal window'));
  expect(await screen.findByText(/renewing in about 30 day/)).toBeInTheDocument();
  expect(acmeAPI.renewalInfo).toHaveBeenCalledWith({ certificate: '-----BEGIN CERTIFICATE-----', directory: 'letsencrypt-staging' });
});

test('automatic flow offers acme-dns and posts its settings', async () => {
  acmeAPI.issue.mockResolvedValue({ data: { result: { fullchain_pem: 'F', certificate_pem: 'C', certificate_info: {} } } });
  render(<ACMEIssuer />);
  fireEvent.click(screen.getByText('Automatic (DNS provider)'));
  fireEvent.change(screen.getByLabelText(/Domains/), { target: { value: 'example.com' } });
  fireEvent.mouseDown(screen.getAllByRole('combobox')[1]);
  fireEvent.click(await screen.findByText(/acme-dns \(any DNS host/));
  fireEvent.change(screen.getByLabelText('acme-dns server URL'), { target: { value: 'https://auth.example.org' } });
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'u' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'p' } });
  fireEvent.change(screen.getByLabelText(/Subdomain/), { target: { value: 'sub-1' } });
  fireEvent.click(screen.getByText('Issue certificate'));
  await waitFor(() => expect(acmeAPI.issue).toHaveBeenCalled());
  expect(acmeAPI.issue.mock.calls[0][0].dns_provider).toEqual({
    type: 'acme-dns', server_url: 'https://auth.example.org', username: 'u', password: 'p', subdomain: 'sub-1' });
});
