import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import SecurityHeaders from './SecurityHeaders';
import { sslCheckAPI } from '../services/api';

jest.mock('../services/api', () => ({ sslCheckAPI: { checkHeaders: jest.fn() } }));

test('shows the score and each header check', async () => {
  sslCheckAPI.checkHeaders.mockResolvedValue({ data: { result: {
    score: 62, grade: 'C', final_url: 'https://example.com/', status_code: 200,
    checks: [
      { header: 'Strict-Transport-Security', status: 'pass', points: 20, max_points: 20, detail: 'Good', value: 'max-age=31536000' },
      { header: 'Content-Security-Policy', status: 'fail', points: 0, max_points: 25, detail: 'Header missing' },
    ],
  } } });
  render(<SecurityHeaders />);
  fireEvent.change(screen.getByLabelText('URL or hostname'), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByText('Check'));
  expect(await screen.findByText('C · 62/100')).toBeInTheDocument();
  expect(screen.getByText('Strict-Transport-Security')).toBeInTheDocument();
  expect(screen.getByText('Header missing')).toBeInTheDocument();
  expect(screen.getByText('0/25')).toBeInTheDocument();
  expect(sslCheckAPI.checkHeaders).toHaveBeenCalledWith({ url: 'example.com' });
});

test('shows API errors such as blocked internal targets', async () => {
  sslCheckAPI.checkHeaders.mockRejectedValue({ response: { data: { error: 'Target resolves to a non-public address' } } });
  render(<SecurityHeaders />);
  fireEvent.change(screen.getByLabelText('URL or hostname'), { target: { value: 'http://10.0.0.1' } });
  fireEvent.click(screen.getByText('Check'));
  expect(await screen.findByText(/non-public address/)).toBeInTheDocument();
});
