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
