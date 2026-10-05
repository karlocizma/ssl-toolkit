import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import EmailDeliverability from './EmailDeliverability';
import { deliverabilityAPI } from '../services/api';

jest.mock('../services/api', () => ({
  deliverabilityAPI: { overview: jest.fn(), spf: jest.fn(), spfFlatten: jest.fn(), dkim: jest.fn(), dmarcReport: jest.fn(), blocklist: jest.fn() },
}));

test('overview shows the grade, per-check scores and findings', async () => {
  deliverabilityAPI.overview.mockResolvedValue({ data: { result: {
    domain: 'example.com', score: 62, grade: 'C',
    checks: [{ check: 'SPF', points: 30, max_points: 30, detail: '2/10 lookups' }, { check: 'DKIM', points: 0, max_points: 20, detail: 'No key found' }],
    findings: [{ severity: 'warning', message: 'No DKIM key found for the common selectors' }],
  } } });
  render(<EmailDeliverability />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByText('Check domain'));
  expect(await screen.findByText('C · 62/100')).toBeInTheDocument();
  expect(screen.getByText('30/30')).toBeInTheDocument();
  expect(screen.getByText('No DKIM key found for the common selectors')).toBeInTheDocument();
});

test('spf tab shows the lookup count and flags the limit', async () => {
  deliverabilityAPI.spf.mockResolvedValue({ data: { result: {
    has_spf: true, record: 'v=spf1 include:a.net -all', lookups: 11, lookup_limit: 10,
    findings: [{ severity: 'error', message: '11 DNS lookups exceed the limit of 10' }],
    tree: { domain: 'example.com', record: 'v=spf1 include:a.net -all', mechanisms: [], children: [{ domain: 'a.net', record: 'v=spf1 -all', mechanisms: [], children: [] }] },
  } } });
  render(<EmailDeliverability />);
  fireEvent.click(screen.getByText('SPF'));
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByText('Analyze SPF'));
  expect(await screen.findByText('11 / 10 DNS lookups')).toBeInTheDocument();
  expect(screen.getByText(/exceed the limit of 10/)).toBeInTheDocument();
  expect(screen.getByText('a.net')).toBeInTheDocument();
});

test('shows the API error', async () => {
  deliverabilityAPI.blocklist.mockRejectedValue({ response: { data: { error: 'Only public IP addresses can be checked' } } });
  render(<EmailDeliverability />);
  fireEvent.click(screen.getByText('Blocklists'));
  fireEvent.change(screen.getByLabelText('IPv4 address or domain'), { target: { value: '10.0.0.1' } });
  fireEvent.click(screen.getByText('Check blocklists'));
  expect(await screen.findByText('Only public IP addresses can be checked')).toBeInTheDocument();
});

test('flattens an SPF record and shows the records in publishing order', async () => {
  deliverabilityAPI.spfFlatten.mockResolvedValue({ data: { result: {
    domain: 'example.com', original_lookups: 14, lookups_after: 2, network_count: 120,
    warnings: ['"exists:%{i}.x" cannot be flattened and was kept as is'], notes: ['Providers change their sending addresses.'],
    records: [
      { name: 'example.com', value: 'v=spf1 include:_spf1.example.com ~all', length: 38 },
      { name: '_spf1.example.com', value: 'v=spf1 ip4:192.0.2.0/24 ?all', length: 28 },
    ] } } });
  render(<EmailDeliverability />);
  fireEvent.click(screen.getByText('SPF flatten'));
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'example.com' } });
  fireEvent.change(screen.getByLabelText(/Keep these includes/), { target: { value: 'other.org, third.net' } });
  fireEvent.click(screen.getByText('Flatten SPF'));
  expect(await screen.findByText('14 lookups before')).toBeInTheDocument();
  expect(screen.getByText('2 lookups after')).toBeInTheDocument();
  expect(screen.getByText(/cannot be flattened/)).toBeInTheDocument();
  const records = screen.getAllByText(/^v=spf1/).map((el) => el.textContent);
  expect(records[0]).toContain('ip4:192.0.2.0/24'); // helper record first
  expect(deliverabilityAPI.spfFlatten).toHaveBeenCalledWith({ domain: 'example.com', keep: ['other.org', 'third.net'] });
});
