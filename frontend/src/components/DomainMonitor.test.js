import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import DomainMonitor from './DomainMonitor';
import { accessToken, monitorAPI } from '../services/api';

jest.mock('../services/api', () => {
  const store = {};
  return {
    accessToken: {
      get: jest.fn(() => store.token || ''),
      set: jest.fn((v) => { store.token = v; }),
    },
    monitorAPI: { listDomains: jest.fn(), addDomain: jest.fn(), removeDomain: jest.fn(), checkDomain: jest.fn(),
      getDomain: jest.fn(), importCsv: jest.fn(), exportData: jest.fn() },
  };
});

beforeEach(() => jest.clearAllMocks());

test('lists monitored domains with expiry status', async () => {
  monitorAPI.listDomains.mockResolvedValue({ data: { domains: [{
    id: 'd1', hostname: 'example.com', port: 443, status: 'ok', days_until_expiry: 5,
    issuer: 'R3', not_after: '2030-01-01T00:00:00+00:00', last_check: null, changes: [],
  }] } });
  render(<DomainMonitor />);
  expect(await screen.findByText('example.com')).toBeInTheDocument();
  expect(screen.getByText('5 days left')).toBeInTheDocument();
});

test('shows the server message when authentication is required and stores the token', async () => {
  monitorAPI.listDomains.mockRejectedValueOnce({ response: { data: { error: 'Authentication required' } } });
  monitorAPI.listDomains.mockResolvedValue({ data: { domains: [] } });
  render(<DomainMonitor />);
  expect(await screen.findByText('Authentication required')).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText(/Access token/), { target: { value: 'secret' } });
  fireEvent.click(screen.getByText('Use token'));
  await waitFor(() => expect(accessToken.set).toHaveBeenCalledWith('secret'));
  await waitFor(() => expect(screen.queryByText('Authentication required')).not.toBeInTheDocument());
});

test('imports hosts from CSV text and reports skipped ones', async () => {
  monitorAPI.listDomains.mockResolvedValue({ data: { domains: [] } });
  monitorAPI.importCsv.mockResolvedValue({ data: { added: 1, results: [
    { hostname: 'a.example.com', status: 'added' }, { hostname: 'b.example.com', status: 'exists', message: 'Already being monitored' }] } });
  render(<DomainMonitor />);
  fireEvent.change(screen.getByLabelText(/Import hosts/), { target: { value: 'a.example.com\nb.example.com' } });
  fireEvent.click(screen.getByText('Import hosts'));
  await waitFor(() => expect(monitorAPI.importCsv).toHaveBeenCalledWith('a.example.com\nb.example.com'));
  expect(await screen.findByText(/Imported 1 host\(s\)\. Skipped: b.example.com \(Already being monitored\)/)).toBeInTheDocument();
});

test('opens the expiry history for a domain', async () => {
  const domain = { id: 'd1', hostname: 'example.com', port: 443, status: 'ok', days_until_expiry: 5, issuer: 'R3',
    not_after: '2030-01-01T00:00:00+00:00', last_check: null, changes: [] };
  monitorAPI.listDomains.mockResolvedValue({ data: { domains: [domain] } });
  monitorAPI.getDomain.mockResolvedValue({ data: { domain: { ...domain, history: [] } } });
  render(<DomainMonitor />);
  fireEvent.click(await screen.findByLabelText('History for example.com'));
  expect(await screen.findByText(/at least two/)).toBeInTheDocument();
  expect(monitorAPI.getDomain).toHaveBeenCalledWith('d1');
});
