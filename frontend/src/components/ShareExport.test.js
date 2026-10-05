import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import ResultActions from './ResultActions';
import SharedReport from './SharedReport';
import SharedResults from './SharedResults';
import { shareAPI } from '../services/api';
import { buildHtmlReport, escapeHtml } from '../utils/report';

jest.mock('../services/api', () => ({
  shareAPI: { create: jest.fn(), get: jest.fn(), list: jest.fn(), revoke: jest.fn() },
}));

const RESULT = { grade: 'A', hostname: 'example.com', findings: [{ severity: 'warning', message: 'Short validity' }] };

beforeEach(() => jest.clearAllMocks());

test('html report escapes everything and has no scripts', () => {
  const html = buildHtmlReport({ title: '<script>alert(1)</script>', tool: 'ssl-checker', generatedAt: 'now',
    result: { name: '"><img src=x onerror=alert(1)>', findings: [{ severity: 'info', message: '<b>x</b>' }] } });
  expect(html).not.toMatch(/<script/i);
  expect(html).not.toContain('<img');
  expect(html).toContain('&lt;b&gt;x&lt;/b&gt;');
  expect(escapeHtml(`a&b"c'`)).toBe('a&amp;b&quot;c&#39;');
});

test('renders nothing without a result', () => {
  const { container } = render(<ResultActions tool="ssl-checker" title="t" result={null} />);
  expect(container).toBeEmptyDOMElement();
});

test('creates a share link and shows it', async () => {
  shareAPI.create.mockResolvedValue({ data: { share: { token: 'tok123', expires_at: '2030-01-01T00:00:00+00:00' } } });
  render(<ResultActions tool="ssl-checker" title="SSL check" result={RESULT} />);
  fireEvent.click(screen.getByText('Share link'));
  const input = await screen.findByLabelText('Share link', { selector: 'input' });
  expect(input.value).toMatch(/\/shared\/tok123$/);
  expect(shareAPI.create).toHaveBeenCalledWith({ title: 'SSL check', tool: 'ssl-checker', result: RESULT, ttl_hours: 24 });
});

test('explains a missing access token', async () => {
  shareAPI.create.mockRejectedValue({ response: { status: 401, data: {} } });
  render(<ResultActions tool="ssl-checker" title="SSL check" result={RESULT} />);
  fireEvent.click(screen.getByText('Share link'));
  expect(await screen.findByText(/needs the access token/)).toBeInTheDocument();
});

const renderShared = () => render(
  <MemoryRouter initialEntries={['/shared/abc']}><Routes><Route path="/shared/:token" element={<SharedReport />} /></Routes></MemoryRouter>);

test('shared report shows headline, findings and the snapshot notice', async () => {
  shareAPI.get.mockResolvedValue({ data: { title: 'Site report', tool: 'ssl-checker', result: RESULT,
    created_at: '2030-01-01T00:00:00+00:00', expires_at: '2030-01-02T00:00:00+00:00' } });
  renderShared();
  expect(await screen.findByText('Site report')).toBeInTheDocument();
  expect(screen.getByText('grade: A')).toBeInTheDocument();
  expect(screen.getByText('Short validity')).toBeInTheDocument();
  expect(screen.getByText(/read-only snapshot/)).toBeInTheDocument();
  expect(shareAPI.get).toHaveBeenCalledWith('abc');
});

test('expired links show a neutral message', async () => {
  shareAPI.get.mockRejectedValue({ response: { status: 404 } });
  renderShared();
  expect(await screen.findByText(/does not exist or has expired/)).toBeInTheDocument();
});

test('shared results list can revoke', async () => {
  shareAPI.list.mockResolvedValueOnce({ data: { shares: [{ id: 'a1', title: 'Site', tool: 'ssl-checker', created_at: '2030-01-01T00:00:00+00:00', expires_at: '2030-01-02T00:00:00+00:00', views: 3 }] } })
    .mockResolvedValue({ data: { shares: [] } });
  shareAPI.revoke.mockResolvedValue({ data: { success: true } });
  render(<SharedResults />);
  fireEvent.click(await screen.findByLabelText('revoke Site'));
  await waitFor(() => expect(shareAPI.revoke).toHaveBeenCalledWith('a1'));
  expect(await screen.findByText('No active shared results.')).toBeInTheDocument();
});
