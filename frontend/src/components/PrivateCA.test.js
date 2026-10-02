import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import PrivateCA from './PrivateCA';
import { caAPI } from '../services/api';

jest.mock('../services/api', () => ({ caAPI: { create: jest.fn(), issue: jest.fn() } }));

test('creating a CA fills the issue form, and issuing sends the CA and the SAN list', async () => {
  caAPI.create.mockResolvedValue({ data: { result: {
    ca_certificate_pem: 'CA-CERT', ca_private_key_pem: 'CA-KEY', warning: 'Store the CA private key offline.' } } });
  caAPI.issue.mockResolvedValue({ data: { result: { certificate_pem: 'LEAF', fullchain_pem: 'LEAF+CA', private_key_pem: 'LEAF-KEY' } } });
  render(<PrivateCA />);
  fireEvent.change(screen.getByLabelText('CA common name'), { target: { value: 'Acme Root' } });
  fireEvent.click(screen.getByText('Create CA'));
  expect(await screen.findByText('Store the CA private key offline.')).toBeInTheDocument();
  expect(caAPI.create).toHaveBeenCalledWith(expect.objectContaining({ common_name: 'Acme Root', validity_days: 3650 }));

  fireEvent.change(screen.getByLabelText('Common name'), { target: { value: 'app.internal' } });
  fireEvent.change(screen.getByLabelText(/Subject alternative names/), { target: { value: 'www.internal, 10.0.0.5, ' } });
  fireEvent.click(screen.getByText('Issue certificate'));
  await waitFor(() => expect(caAPI.issue).toHaveBeenCalled());
  expect(caAPI.issue.mock.calls[0][0]).toMatchObject({
    ca_certificate: 'CA-CERT', ca_private_key: 'CA-KEY', common_name: 'app.internal',
    sans: ['www.internal', '10.0.0.5'], usage: 'server', validity_days: 365,
  });
  expect(await screen.findByDisplayValue('LEAF+CA')).toBeInTheDocument();
});

test('issue is disabled until a CA and a name are present, and errors are shown', async () => {
  render(<PrivateCA />);
  expect(screen.getByText('Issue certificate').closest('button')).toBeDisabled();
  caAPI.create.mockRejectedValue({ response: { data: { error: 'common_name is required' } } });
  fireEvent.change(screen.getByLabelText('CA common name'), { target: { value: 'x' } });
  fireEvent.click(screen.getByText('Create CA'));
  expect(await screen.findByText('common_name is required')).toBeInTheDocument();
});
