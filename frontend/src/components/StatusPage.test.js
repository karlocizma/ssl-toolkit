import React from 'react';
import { render, screen } from '@testing-library/react';
import StatusPage from './StatusPage';
import { statusAPI } from '../services/api';

jest.mock('../services/api', () => ({ statusAPI: { get: jest.fn() } }));

const host = (over) => ({ id: 'pub_1', name: 'Shop', status: 'ok', days_until_expiry: 74, not_after: '2027-01-01T00:00:00+00:00',
  last_check: null, domain_expires: null, domain_days_until_expiry: null, ...over });

test('shows the overall state and every published certificate', async () => {
  statusAPI.get.mockResolvedValue({ data: { title: 'Acme certificates', overall: 'problem', generated_at: '2026-10-05T10:00:00+00:00', counts: {},
    hosts: [host({ id: 'a', name: 'Portal', status: 'expired', days_until_expiry: -3 }), host({ id: 'b', name: 'Shop' }),
      host({ id: 'c', name: 'API', status: 'expiring', days_until_expiry: 1, domain_expires: '2028-05-05T00:00:00+00:00' })] } });
  render(<StatusPage />);
  expect(await screen.findByText('Acme certificates')).toBeInTheDocument();
  expect(screen.getByText('Some certificates need attention')).toBeInTheDocument();
  expect(screen.getByText('Expired')).toBeInTheDocument();
  expect(screen.getByText(/expired 3 days ago/)).toBeInTheDocument();
  expect(screen.getByText(/expires in 74 days/)).toBeInTheDocument();
  expect(screen.getByText(/expires in 1 day\)/)).toBeInTheDocument();
  expect(screen.getByText('Valid')).toBeInTheDocument();
  expect(screen.getByText(/Domain registered until/)).toBeInTheDocument();
});

test('says so when nothing is published', async () => {
  statusAPI.get.mockResolvedValue({ data: { title: 'Certificate status', overall: 'ok', hosts: [], generated_at: null } });
  render(<StatusPage />);
  expect(await screen.findByText('No certificates are published yet')).toBeInTheDocument();
});

test('shows a message when the page is disabled or unreachable', async () => {
  statusAPI.get.mockRejectedValueOnce({ response: { status: 404 } });
  render(<StatusPage />);
  expect(await screen.findByText('The status page is not available.')).toBeInTheDocument();
});

test('marks the expiry of an unreachable host as the last known one', async () => {
  statusAPI.get.mockResolvedValue({ data: { title: 'T', overall: 'problem', generated_at: null,
    hosts: [host({ id: 'x', name: 'Mail', status: 'unreachable' })] } });
  render(<StatusPage />);
  expect(await screen.findByText(/Last known certificate valid until/)).toBeInTheDocument();
  expect(screen.getByText('Not reachable')).toBeInTheDocument();
});
