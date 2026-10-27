import React from 'react';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import Settings from './Settings';
import { monitorAPI, settingsAPI } from '../services/api';

jest.mock('../services/api', () => ({
  accessToken: { get: jest.fn(() => ''), isRemembered: jest.fn(() => false), set: jest.fn() },
  settingsAPI: { get: jest.fn(), save: jest.fn() },
  monitorAPI: { alertsTest: jest.fn() },
}));

const s = (name, group, extra = {}) => ({ name, group, type: 'str', secret: false, is_set: false, source: 'default', default: '', value: '', ...extra });
const base = [
  s('ALERT_THRESHOLDS', 'alerts', { value: '30,14,7,1', default: '30,14,7,1' }),
  s('ALERT_TEAMS_WEBHOOK_URL', 'alerts', { secret: true, is_set: true, value: null, source: 'env' }),
  s('SMTP_HOST', 'email'),
];

beforeEach(() => jest.clearAllMocks());

test('explains a wrong password and a missing ADMIN_TOKEN', async () => {
  settingsAPI.get.mockRejectedValueOnce({ response: { status: 401, data: {} } });
  const { unmount } = render(<Settings />);
  expect(await screen.findByText(/Wrong password/)).toBeInTheDocument();
  unmount();
  settingsAPI.get.mockRejectedValueOnce({ response: { status: 403, data: {} } });
  render(<Settings />);
  expect(await screen.findByText(/Set ADMIN_TOKEN in .env/)).toBeInTheDocument();
});

test('never shows a secret and sends only the changed fields', async () => {
  settingsAPI.get.mockResolvedValue({ data: { settings: base } });
  settingsAPI.save.mockResolvedValue({ data: { settings: base } });
  render(<Settings />);
  const teams = await screen.findByLabelText('Microsoft Teams webhook URL');
  expect(teams.value).toBe('');
  expect(teams.placeholder).toMatch(/set, type to replace/);
  fireEvent.change(screen.getByLabelText('Alert at (days before expiry)'), { target: { value: '60,30' } });
  fireEvent.click(screen.getByText('Save 1 change'));
  await waitFor(() => expect(settingsAPI.save).toHaveBeenCalledWith({ ALERT_THRESHOLDS: '60,30' }, []));
  expect(await screen.findByText(/Saved/)).toBeInTheDocument();
});

test('shows the server\'s validation error next to the field', async () => {
  settingsAPI.get.mockResolvedValue({ data: { settings: base } });
  settingsAPI.save.mockRejectedValue({ response: { status: 400, data: { errors: { ALERT_THRESHOLDS: 'must be comma-separated whole numbers' } } } });
  render(<Settings />);
  fireEvent.change(await screen.findByLabelText('Alert at (days before expiry)'), { target: { value: 'x' } });
  fireEvent.click(screen.getByText('Save 1 change'));
  expect(await screen.findByText('must be comma-separated whole numbers')).toBeInTheDocument();
});

test('clears a secret and sends a test alert', async () => {
  settingsAPI.get.mockResolvedValue({ data: { settings: base } });
  settingsAPI.save.mockResolvedValue({ data: { settings: base } });
  monitorAPI.alertsTest.mockResolvedValue({ data: { deliveries: [{ channel: 'teams', sent: true }, { channel: 'email', sent: false, reason: 'not configured' }] } });
  render(<Settings />);
  fireEvent.click(await screen.findByText('Clear'));
  await waitFor(() => expect(settingsAPI.save).toHaveBeenCalledWith({ ALERT_TEAMS_WEBHOOK_URL: '' }, []));
  fireEvent.click(screen.getByText('Send test alert'));
  expect(await screen.findByText('teams: sent')).toBeInTheDocument();
  expect(screen.getByText('email: not configured')).toBeInTheDocument();
});

test('switches between groups', async () => {
  settingsAPI.get.mockResolvedValue({ data: { settings: base } });
  render(<Settings />);
  fireEvent.click(await screen.findByRole('tab', { name: 'Email' }));
  expect(await screen.findByLabelText('SMTP host')).toBeInTheDocument();
});
