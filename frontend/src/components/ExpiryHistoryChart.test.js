import React from 'react';
import { render, screen } from '@testing-library/react';
import ExpiryHistoryChart from './ExpiryHistoryChart';

test('asks for more data when there are fewer than two checks', () => {
  render(<ExpiryHistoryChart history={[{ checked_at: '2026-01-01T00:00:00Z', days_until_expiry: 30 }]} />);
  expect(screen.getByText(/at least two/)).toBeInTheDocument();
});

test('draws the line and marks certificate replacements', () => {
  const history = [
    { checked_at: '2026-01-01T00:00:00Z', days_until_expiry: 10 },
    { checked_at: '2026-01-02T00:00:00Z', days_until_expiry: 9 },
    { checked_at: '2026-01-03T00:00:00Z', days_until_expiry: 89 },
  ];
  const { container } = render(<ExpiryHistoryChart history={history} changes={[{ detected_at: '2026-01-03T00:00:00Z' }]} />);
  expect(screen.getByRole('img', { name: /Days until certificate expiry/ })).toBeInTheDocument();
  expect(container.querySelector('polyline').getAttribute('points').split(' ')).toHaveLength(3);
  expect(screen.getByText(/3 checks · green lines mark 1 certificate replacement/)).toBeInTheDocument();
});
