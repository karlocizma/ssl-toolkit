import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import ChainBuilder from './ChainBuilder';
import { chainAPI } from '../services/api';

jest.mock('../services/api', () => ({ chainAPI: { build: jest.fn() } }));

const result = {
  complete: true, trusted: true, leaf: 'www.example.com', fullchain_pem: 'LEAF+INT', chain_pem: 'INT',
  findings: [{ severity: 'warning', message: 'The input presented the chain in the wrong order' }],
  chain: [
    { role: 'leaf', subject: 'www.example.com', issuer: 'R3', not_after: '2030-01-01T00:00:00+00:00', signature_hash: 'sha256', source: 'provided', sha256: 'a', expired: false },
    { role: 'intermediate', subject: 'R3', issuer: 'ISRG Root X1', not_after: '2030-01-01T00:00:00+00:00', signature_hash: 'sha256', source: 'downloaded from http://r3.i.lencr.org/', sha256: 'b', expired: false },
  ],
};

test('builds a chain from pasted PEM and shows roles, findings and the fullchain', async () => {
  chainAPI.build.mockResolvedValue({ data: { result } });
  render(<ChainBuilder />);
  fireEvent.change(screen.getByLabelText('Leaf certificate or PEM bundle'), { target: { value: '-----BEGIN CERTIFICATE-----' } });
  fireEvent.click(screen.getByText('Build chain'));
  expect(await screen.findByText('Chain complete')).toBeInTheDocument();
  expect(screen.getByText('intermediate')).toBeInTheDocument();
  expect(screen.getByText(/downloaded from http:\/\/r3.i.lencr.org/)).toBeInTheDocument();
  expect(screen.getByText(/wrong order/)).toBeInTheDocument();
  expect(screen.getByDisplayValue('LEAF+INT')).toBeInTheDocument();
  expect(chainAPI.build).toHaveBeenCalledWith({ certificate: '-----BEGIN CERTIFICATE-----', include_root: false });
});

test('server mode sends the hostname and surfaces errors', async () => {
  chainAPI.build.mockRejectedValue({ response: { data: { error: 'Target resolves to a non-public address' } } });
  render(<ChainBuilder />);
  fireEvent.click(screen.getByText('Check a server'));
  fireEvent.change(screen.getByLabelText('Hostname'), { target: { value: ' 127.0.0.1 ' } });
  fireEvent.click(screen.getByText('Build chain'));
  await waitFor(() => expect(chainAPI.build).toHaveBeenCalledWith({ hostname: '127.0.0.1', include_root: false }));
  expect(await screen.findByText(/non-public address/)).toBeInTheDocument();
});
