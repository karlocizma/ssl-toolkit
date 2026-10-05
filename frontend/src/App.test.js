import React from 'react';
import { render, screen } from '@testing-library/react';
import './i18n';
import App from './App';

jest.mock('./services/api');

const at = (path) => {
  window.history.pushState({}, '', path);
  return render(<App />);
};

test('the public status page renders on its own, without the application navigation', async () => {
  at('/status');
  expect(await screen.findByRole('heading', { name: 'Certificate status' })).toBeInTheDocument();
  expect(screen.queryByText('Security & Network Toolkit')).not.toBeInTheDocument();
  expect(screen.queryByText('Domain Monitor')).not.toBeInTheDocument();
});

test('tool pages still render inside the layout with their navigation', async () => {
  at('/domain-expiry');
  expect(await screen.findByRole('heading', { name: /Domain Expiry/ })).toBeInTheDocument();
  expect(screen.getAllByText('Domain Monitor').length).toBeGreaterThan(0); // navigation entry
});

test('the dashboard is still the start page', async () => {
  at('/');
  expect(await screen.findByRole('heading', { level: 1, name: 'Security & Network Toolkit' })).toBeInTheDocument();
});
