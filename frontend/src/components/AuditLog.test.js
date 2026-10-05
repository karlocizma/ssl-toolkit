import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import AuditLog from './AuditLog';
import { accessToken, auditAPI } from '../services/api';

jest.mock('../services/api', () => ({
  accessToken: { get: jest.fn(() => ''), isRemembered: jest.fn(() => false), set: jest.fn() },
  auditAPI: { list: jest.fn(), verify: jest.fn(), exportData: jest.fn() },
}));

const entries = [
  { hash: 'h2', ts: '2026-10-05T10:00:00.000+00:00', action: 'auth.denied', result: 'denied', status: 401, actor: { type: 'anonymous' },
    ip: '203.0.113.9', target: 'GET /api/monitor/domain/list', detail: { credentials_presented: false } },
  { hash: 'h1', ts: '2026-10-05T09:00:00.000+00:00', action: 'monitor.domain.add', result: 'success', status: 200, actor: { type: 'api_key', id: 'ci' },
    ip: '198.51.100.7', target: 'a.example:443', detail: { label: 'A' } },
];

beforeEach(() => jest.clearAllMocks());

test('lists entries with actor, target, result and IP', async () => {
  auditAPI.list.mockResolvedValue({ data: { total: 2, entries } });
  render(<AuditLog />);
  expect(await screen.findByText('monitor.domain.add')).toBeInTheDocument();
  expect(screen.getByText('api_key: ci')).toBeInTheDocument();
  expect(screen.getByText('denied (401)')).toBeInTheDocument();
  expect(screen.getByText('203.0.113.9')).toBeInTheDocument();
  expect(screen.getByText('2 entries')).toBeInTheDocument();
});

test('filters are sent to the server', async () => {
  auditAPI.list.mockResolvedValue({ data: { total: 0, entries: [] } });
  render(<AuditLog />);
  await waitFor(() => expect(auditAPI.list).toHaveBeenCalledTimes(1));
  fireEvent.change(screen.getByLabelText(/Search/), { target: { value: 'a.example' } });
  fireEvent.click(screen.getByText('Apply'));
  await waitFor(() => expect(auditAPI.list).toHaveBeenCalledTimes(2));
  expect(auditAPI.list.mock.calls[1][0]).toEqual({ q: 'a.example', limit: 50, offset: 0 });
});

test('asks for the admin token when access is refused and stores the token', async () => {
  auditAPI.list.mockRejectedValueOnce({ response: { status: 401, data: { error: 'Unauthorized' } } });
  auditAPI.list.mockResolvedValue({ data: { total: 0, entries: [] } });
  render(<AuditLog />);
  expect(await screen.findByText(/needs the admin token/)).toBeInTheDocument();
  fireEvent.change(screen.getByLabelText(/Admin token/), { target: { value: 'secret' } });
  fireEvent.click(screen.getByText('Use token'));
  await waitFor(() => expect(accessToken.set).toHaveBeenCalledWith('secret', false));
  await waitFor(() => expect(screen.queryByText(/needs the admin token/)).not.toBeInTheDocument());
});

test('verifies the hash chain and reports a break', async () => {
  auditAPI.list.mockResolvedValue({ data: { total: 2, entries } });
  auditAPI.verify.mockResolvedValue({ data: { valid: false, entries: 1, problem: { file: 'audit.log', line: 2, reason: 'entry was modified' } } });
  render(<AuditLog />);
  fireEvent.click(await screen.findByText('Verify integrity'));
  expect(await screen.findByText('Broken at audit.log line 2: entry was modified')).toBeInTheDocument();
});
