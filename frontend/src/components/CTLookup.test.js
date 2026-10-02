import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import CTLookup from './CTLookup';
import { ctAPI, monitorAPI } from '../services/api';

jest.mock('../services/api', () => ({
  ctAPI: { lookup: jest.fn() },
  monitorAPI: { addDomains: jest.fn() },
}));

const result = {
  domain: 'example.com', total_certificates: 3, active_certificates: 2, truncated: false,
  issuers: [{ issuer: "Let's Encrypt R3", count: 3 }],
  findings: [{ severity: 'warning', message: '1 certificate(s) issued by an unexpected CA: Evil CA' }],
  subdomains: [
    { name: 'www.example.com', certificates: 2, first_seen: '2026-01-01T00:00:00', last_seen: '2026-03-01T00:00:00', active: true },
    { name: 'old.example.com', certificates: 1, first_seen: '2025-01-01T00:00:00', last_seen: '2025-01-01T00:00:00', active: false },
  ],
  certificates: [],
};

test('search shows findings and preselects only active hostnames, then adds them to the monitor', async () => {
  ctAPI.lookup.mockResolvedValue({ data: { result } });
  monitorAPI.addDomains.mockResolvedValue({ data: { added: 1, results: [{ hostname: 'www.example.com', status: 'added' }] } });
  render(<CTLookup />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByText('Search'));
  expect(await screen.findByText(/unexpected CA: Evil CA/)).toBeInTheDocument();
  fireEvent.click(screen.getByText('Add 1 to Domain Monitor'));
  await waitFor(() => expect(monitorAPI.addDomains).toHaveBeenCalledWith({ hostnames: ['www.example.com'] }));
  expect(await screen.findByText(/Added 1 host/)).toBeInTheDocument();
});

test('shows the service error', async () => {
  ctAPI.lookup.mockRejectedValue({ response: { data: { error: 'The CT search service is unavailable' } } });
  render(<CTLookup />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByText('Search'));
  expect(await screen.findByText(/CT search service is unavailable/)).toBeInTheDocument();
});
