import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import TokenField from './TokenField';
import { accessToken } from '../services/api';

jest.mock('../services/api', () => ({
  accessToken: { get: jest.fn(() => ''), isRemembered: jest.fn(() => false), set: jest.fn() },
}));

beforeEach(() => jest.clearAllMocks());

test('stores for the tab by default and remembers only when ticked', () => {
  const onUse = jest.fn();
  render(<TokenField label="Admin token" onUse={onUse} />);
  const input = screen.getByLabelText('Admin token');
  fireEvent.change(input, { target: { value: ' secret ' } });
  fireEvent.click(screen.getByText('Use token'));
  expect(accessToken.set).toHaveBeenLastCalledWith('secret', false);

  fireEvent.click(screen.getByLabelText(/Remember on this device/));
  fireEvent.click(screen.getByText('Use token'));
  expect(accessToken.set).toHaveBeenLastCalledWith('secret', true);
  expect(onUse).toHaveBeenCalledTimes(2);
});

test('starts ticked when a token is already remembered', () => {
  accessToken.isRemembered.mockReturnValue(true);
  render(<TokenField label="Admin token" onUse={() => {}} />);
  expect(screen.getByLabelText(/Remember on this device/)).toBeChecked();
});
