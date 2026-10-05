import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import MailTransport from './MailTransport';
import { deliverabilityAPI } from '../services/api';

jest.mock('../services/api', () => ({
  deliverabilityAPI: { mtaSts: jest.fn(), tlsRpt: jest.fn(), mtaStsGenerate: jest.fn(), tlsRptGenerate: jest.fn(), tlsRptReport: jest.fn() },
}));

test('checks MTA-STS and TLS-RPT and lists MX coverage and findings', async () => {
  deliverabilityAPI.mtaSts.mockResolvedValue({ data: { result: {
    status: 'error', id: '2026', policy: { mode: 'enforce', max_age: '604800' },
    mx_coverage: [{ host: 'mail.example.com', covered: true, pattern: 'mail.example.com' }, { host: 'x.other.net', covered: false, pattern: null }],
    findings: [{ severity: 'error', message: 'MX host x.other.net is not listed in the policy' }] } } });
  deliverabilityAPI.tlsRpt.mockResolvedValue({ data: { result: { status: 'ok', record: 'v=TLSRPTv1; rua=mailto:a@example.com', findings: [] } } });
  render(<MailTransport />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByRole('button', { name: 'Check' }));
  expect(await screen.findByText('mode: enforce')).toBeInTheDocument();
  expect(screen.getByText('MX host x.other.net is not listed in the policy')).toBeInTheDocument();
  expect(screen.getByText(/✘ x.other.net/)).toBeInTheDocument();
  expect(screen.getByText('v=TLSRPTv1; rua=mailto:a@example.com')).toBeInTheDocument();
  expect(deliverabilityAPI.mtaSts).toHaveBeenCalledWith({ domain: 'example.com', verify_mx: false });
});

test('generates a policy and a TLS-RPT record', async () => {
  deliverabilityAPI.mtaStsGenerate.mockResolvedValue({ data: { result: {
    policy: 'version: STSv1\r\nmode: testing', policy_url: 'https://mta-sts.example.com/.well-known/mta-sts.txt',
    dns_name: '_mta-sts.example.com', dns_record: 'v=STSv1; id=1', steps: ['Serve the policy over HTTPS'] } } });
  deliverabilityAPI.tlsRptGenerate.mockResolvedValue({ data: { result: { dns_name: '_smtp._tls.example.com', dns_record: 'v=TLSRPTv1; rua=mailto:t@example.com' } } });
  render(<MailTransport />);
  fireEvent.click(screen.getByText('Generate'));
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'example.com' } });
  fireEvent.change(screen.getByLabelText(/TLS-RPT report address/), { target: { value: 't@example.com' } });
  fireEvent.click(screen.getByRole('button', { name: 'Generate' }));
  expect(await screen.findByText('v=STSv1; id=1')).toBeInTheDocument();
  expect(await screen.findByText('v=TLSRPTv1; rua=mailto:t@example.com')).toBeInTheDocument();
  expect(deliverabilityAPI.tlsRptGenerate).toHaveBeenCalledWith({ domain: 'example.com', rua: ['t@example.com'] });
});

test('summarises a TLS-RPT report', async () => {
  deliverabilityAPI.tlsRptReport.mockResolvedValue({ data: { result: {
    organization: 'Google Inc.', successful: 90, failed: 10, success_rate: 90, start: 'a', end: 'b',
    findings: [{ severity: 'error', message: '10 failed session(s): The MX certificate has expired (certificate-expired)' }],
    policies: [{ type: 'sts', domain: 'example.com', successful: 90, failed: 10,
      failures: [{ count: 10, type: 'certificate-expired', receiving_mx: 'mail.example.com', sending_ip: '203.0.113.5' }] }] } } });
  render(<MailTransport />);
  fireEvent.click(screen.getByText('Read a report'));
  fireEvent.change(screen.getByLabelText(/paste the report JSON/), { target: { value: '{}' } });
  fireEvent.click(screen.getByText('Analyze'));
  expect(await screen.findByText('Google Inc.')).toBeInTheDocument();
  expect(screen.getByText('10 failed')).toBeInTheDocument();
  expect(screen.getByText(/10× certificate-expired at mail.example.com/)).toBeInTheDocument();
});
