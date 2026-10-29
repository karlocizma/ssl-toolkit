import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import CaaDane from './CaaDane';
import { caaDaneAPI } from '../services/api';

jest.mock('../services/api', () => ({
  caaDaneAPI: { caaCheck: jest.fn(), caaGenerate: jest.fn(), daneGenerate: jest.fn(), daneCheck: jest.fn() },
}));

beforeEach(() => jest.clearAllMocks());

test('has a tab for each part of the tool', () => {
  render(<CaaDane />);
  expect(screen.getByRole('tab', { name: 'Check CAA' })).toBeInTheDocument();
  expect(screen.getByRole('tab', { name: 'Generate CAA' })).toBeInTheDocument();
  expect(screen.getByRole('tab', { name: 'TLSA (DANE)' })).toBeInTheDocument();
});

test('checks a domain and lists the allowed CAs and the findings', async () => {
  caaDaneAPI.caaCheck.mockResolvedValue({ data: { result: {
    domain: 'example.com', policy_name: 'example.com', any_ca_may_issue: false, wildcard_any_ca_may_issue: false,
    issuance_blocked: false, wildcard_blocked: false, records: [{ flags: 0, critical: false, tag: 'issue', value: 'letsencrypt.org' }],
    issuers: [{ ca: 'letsencrypt.org', name: "Let's Encrypt", params: {} }],
    wildcard_issuers: [{ ca: 'letsencrypt.org', name: "Let's Encrypt", params: {} }],
    findings: [{ severity: 'info', message: 'No iodef record: CAs have no address to report policy violations to.' }] } } });
  render(<CaaDane />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: ' example.com ' } });
  fireEvent.click(screen.getByRole('button', { name: 'Check' }));
  expect((await screen.findAllByText(/Let's Encrypt/)).length).toBeGreaterThan(0);
  expect(screen.getByText(/No iodef record/)).toBeInTheDocument();
  expect(caaDaneAPI.caaCheck).toHaveBeenCalledWith({ domain: 'example.com' });
});

test('shows a DNS failure from the server', async () => {
  caaDaneAPI.caaCheck.mockRejectedValue({ response: { data: { error: 'A valid domain name is required' } } });
  render(<CaaDane />);
  fireEvent.change(screen.getByLabelText('Domain'), { target: { value: 'x' } });
  fireEvent.click(screen.getByRole('button', { name: 'Check' }));
  expect(await screen.findByText('A valid domain name is required')).toBeInTheDocument();
});

test('generates CAA records from a list of CAs', async () => {
  caaDaneAPI.caaGenerate.mockResolvedValue({ data: { result: {
    records: ['example.com. IN CAA 0 issue "letsencrypt.org; validationmethods=dns-01"'], summary: 'Only Let\'s Encrypt may issue.' } } });
  render(<CaaDane />);
  fireEvent.click(screen.getByRole('tab', { name: 'Generate CAA' }));
  fireEvent.change(screen.getByLabelText('Domain (optional)'), { target: { value: 'example.com' } });
  fireEvent.change(screen.getByLabelText('Allowed CAs (one per line)'), { target: { value: 'letsencrypt.org\n' } });
  fireEvent.click(screen.getByLabelText('Only allow DNS-01 validation'));
  fireEvent.click(screen.getByRole('button', { name: 'Generate' }));
  expect(await screen.findByText(/validationmethods=dns-01/)).toBeInTheDocument();
  expect(caaDaneAPI.caaGenerate).toHaveBeenCalledWith(expect.objectContaining({
    domain: 'example.com', issuers: ['letsencrypt.org'], dns01_only: true, block_all: false, allow_wildcards: true }));
});

test('refuses to generate without a CA unless blocking all issuance is chosen', () => {
  render(<CaaDane />);
  fireEvent.click(screen.getByRole('tab', { name: 'Generate CAA' }));
  fireEvent.click(screen.getByRole('button', { name: 'Generate' }));
  expect(screen.getByText(/Add at least one CA/)).toBeInTheDocument();
  expect(caaDaneAPI.caaGenerate).not.toHaveBeenCalled();
});

test('generates a TLSA record from a certificate', async () => {
  caaDaneAPI.daneGenerate.mockResolvedValue({ data: { result: {
    name: '_443._tcp.example.com', rdata: '3 1 1 abcd', record: '_443._tcp.example.com. IN TLSA 3 1 1 abcd', notes: ['DANE only works if the zone is DNSSEC-signed'] } } });
  render(<CaaDane />);
  fireEvent.click(screen.getByRole('tab', { name: 'TLSA (DANE)' }));
  fireEvent.change(screen.getByLabelText('Certificate (PEM)'), { target: { value: '-----BEGIN CERTIFICATE-----' } });
  fireEvent.change(screen.getByLabelText('Host (generate)'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByRole('button', { name: 'Generate TLSA' }));
  expect(await screen.findByText('_443._tcp.example.com. IN TLSA 3 1 1 abcd')).toBeInTheDocument();
  expect(caaDaneAPI.daneGenerate).toHaveBeenCalledWith(expect.objectContaining({ host: 'example.com', usage: 3, selector: 1, matching_type: 1 }));
});

test('checks a live host against its TLSA records', async () => {
  caaDaneAPI.daneCheck.mockResolvedValue({ data: { result: {
    name: '_443._tcp.example.com', matched: false, dnssec_ad: false,
    records: [{ usage: 3, selector: 1, matching_type: 1, data: 'abcd', match: false }],
    findings: [{ severity: 'error', message: 'None of the TLSA records match the certificate the server presents' }] } } });
  render(<CaaDane />);
  fireEvent.click(screen.getByRole('tab', { name: 'TLSA (DANE)' }));
  fireEvent.change(screen.getByLabelText('Host (check)'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByRole('button', { name: 'Check TLSA' }));
  expect(await screen.findByText(/None of the TLSA records match/)).toBeInTheDocument();
  expect(caaDaneAPI.daneCheck).toHaveBeenCalledWith({ host: 'example.com', port: 443, protocol: 'tcp' });
});
