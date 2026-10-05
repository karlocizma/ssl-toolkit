import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import DmarcReports from './DmarcReports';
import { deliverabilityAPI } from '../services/api';

jest.mock('../services/api', () => ({ deliverabilityAPI: { dmarcReports: jest.fn() } }));

const result = {
  reports: 3, duplicates_skipped: 1, errors: [{ file: 'bad.xml', error: 'The report is not valid XML' }],
  period: { start: '2026-10-01T00:00:00+00:00', end: '2026-10-03T23:59:59+00:00' },
  domains: ['example.com'], policies: { 'example.com': { p: 'none', pct: '100' } },
  total_messages: 340, passed_messages: 300, pass_rate: 88.24,
  dispositions: { none: 340 },
  daily: [{ date: '2026-10-01', total: 170, pass: 150, pass_rate: 88.2 }, { date: '2026-10-02', total: 170, pass: 150, pass_rate: 88.2 }],
  reporters: [{ name: 'google.com', reports: 2, messages: 200 }],
  sources: [
    { source_ip: '203.0.113.1', ptr: 'mail.example.net', count: 300, pass_rate: 100, dkim_pass: 300, spf_pass: 300, status: 'authenticated' },
    { source_ip: '198.51.100.9', ptr: null, count: 40, pass_rate: 0, dkim_pass: 0, spf_pass: 0, status: 'failing' },
  ],
  findings: [{ severity: 'warning', message: '198.51.100.9 sent 40 message(s) as your domain and none passed DMARC' }],
};

const pick = (files) => {
  const input = document.querySelector('input[type="file"]');
  fireEvent.change(input, { target: { files } });
};

test('merges the selected reports and shows sources, findings and unreadable files', async () => {
  deliverabilityAPI.dmarcReports.mockResolvedValue({ data: { result } });
  render(<DmarcReports />);
  pick([new File(['<feedback/>'], 'a.xml'), new File(['<feedback/>'], 'b.xml')]);
  expect(await screen.findByText('2 file(s) selected')).toBeInTheDocument();
  fireEvent.click(screen.getByText('Analyze'));
  expect(await screen.findByText('88.24% pass DMARC')).toBeInTheDocument();
  expect(screen.getByText('mail.example.net')).toBeInTheDocument();
  expect(screen.getByText('failing')).toBeInTheDocument();
  expect(screen.getByText(/none passed DMARC/)).toBeInTheDocument();
  expect(screen.getByText(/bad.xml \(The report is not valid XML\)/)).toBeInTheDocument();
  expect(screen.getByText('example.com: p=none')).toBeInTheDocument();
  await waitFor(() => expect(deliverabilityAPI.dmarcReports).toHaveBeenCalledTimes(1));
  const call = deliverabilityAPI.dmarcReports.mock.calls[0][0];
  expect(call.files.map((f) => f.name)).toEqual(['a.xml', 'b.xml']);
  expect(call.lookup_ptr).toBe(true);
});

test('shows the server error', async () => {
  deliverabilityAPI.dmarcReports.mockRejectedValue({ response: { data: { error: 'None of the files is a readable DMARC aggregate report' } } });
  render(<DmarcReports />);
  pick([new File(['x'], 'a.xml')]);
  expect(await screen.findByText('1 file(s) selected')).toBeInTheDocument();
  fireEvent.click(screen.getByText('Analyze'));
  expect(await screen.findByText(/None of the files is a readable/)).toBeInTheDocument();
});

const advice = {
  domains: [{
    domain: 'example.com', verdict: 'not_ready', current: { p: 'none', pct: 100 },
    summary: 'Not ready for p=quarantine; pct=10: 1 thing(s) to resolve',
    data: { messages: 340, pass_rate: 88.24, days: 14 }, next: { p: 'quarantine', pct: 10, required_pass_rate: 98 },
    blockers: ['198.51.100.9 fails 40 of 40 message(s) (11.76% of all mail): fix its SPF/DKIM if it is a legitimate sender, or add it to the ignore list if it is not yours'],
    failing_sources: [{ source_ip: '198.51.100.9', ptr: 'spoof.example.net', messages: 40, failed: 40, share: 11.76 }],
    preview_record: { name: '_dmarc.example.com', value: 'v=DMARC1; p=quarantine; pct=10; rua=mailto:dmarc-reports@example.com' },
    next_record: null, notes: ['Keep each step for one to two weeks'],
  }],
  ignored: [],
};

test('shows the policy advice and re-runs the analysis when a source is ignored', async () => {
  deliverabilityAPI.dmarcReports.mockResolvedValue({ data: { result: { ...result, advice } } });
  render(<DmarcReports />);
  pick([new File(['<feedback/>'], 'a.xml')]);
  expect(await screen.findByText('1 file(s) selected')).toBeInTheDocument();
  fireEvent.click(screen.getByText('Analyze'));
  expect(await screen.findByText('Policy advice for example.com')).toBeInTheDocument();
  expect(screen.getByText('Not ready')).toBeInTheDocument();
  expect(screen.getByText(/Preview of the next step/)).toBeInTheDocument();
  expect(screen.getByText(/p=quarantine; pct=10; rua=/)).toBeInTheDocument();
  fireEvent.click(screen.getByText('Not mine, ignore'));
  await waitFor(() => expect(deliverabilityAPI.dmarcReports).toHaveBeenCalledTimes(2));
  expect(deliverabilityAPI.dmarcReports.mock.calls[1][0].ignore_ips).toEqual(['198.51.100.9']);
  expect(await screen.findByText('Ignored as not yours:')).toBeInTheDocument();
});
