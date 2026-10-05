import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, useLocation } from 'react-router-dom';
import '../i18n';
import ToolSearch, { filterTools } from './ToolSearch';

const items = [
  { textKey: 'nav.emailDeliverability', icon: <span />, path: '/email-deliverability' },
  { textKey: 'nav.sslChecker', icon: <span />, path: '/ssl-checker' },
  { textKey: 'nav.mtaSts', icon: <span />, path: '/mta-sts' },
  { textKey: 'nav.auditLog', icon: <span />, path: '/audit-log' },
];

const Where = () => <div data-testid="where">{useLocation().pathname}</div>;

const renderSearch = () => render(
  <MemoryRouter initialEntries={['/']}><ToolSearch items={items} /><Where /></MemoryRouter>);

const box = () => screen.getByRole('combobox');

test('finds a tool by a feature that is not in its title and opens it', async () => {
  renderSearch();
  await userEvent.type(box(), 'flatten');
  const option = screen.getByRole('option', { name: /Email Deliverability/ });
  expect(screen.queryByRole('option', { name: /SSL Checker/ })).not.toBeInTheDocument();
  await userEvent.click(option);
  expect(screen.getByTestId('where')).toHaveTextContent('/email-deliverability');
});

test('finds the DMARC ramp advisor and matches several words in any order', async () => {
  renderSearch();
  await userEvent.type(box(), 'advisor dmarc');
  expect(screen.getByRole('option', { name: /Email Deliverability/ })).toBeInTheDocument();
  expect(screen.getAllByRole('option')).toHaveLength(1);
});

test('says when nothing matches', async () => {
  renderSearch();
  await userEvent.type(box(), 'zzzz');
  expect(screen.getByText('No tool matches')).toBeInTheDocument();
});

test('Ctrl+K focuses the search box', () => {
  renderSearch();
  fireEvent.keyDown(window, { key: 'k', ctrlKey: true });
  expect(box()).toHaveFocus();
});

test('titles that start with the query rank first', () => {
  const opts = [
    { label: 'Audit Log', haystack: 'audit log ssl' },
    { label: 'SSL Checker', haystack: 'ssl checker' },
  ];
  expect(filterTools(opts, 'ssl').map((o) => o.label)).toEqual(['SSL Checker', 'Audit Log']);
});
