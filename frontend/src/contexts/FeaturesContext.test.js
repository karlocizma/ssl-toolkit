import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import { FeaturesProvider, useFeatures } from './FeaturesContext';
import { featuresAPI } from '../services/api';

jest.mock('../services/api', () => ({ featuresAPI: { get: jest.fn() } }));

function Probe() {
  const { acme } = useFeatures();
  return <div data-testid="acme">{String(acme)}</div>;
}

const renderProbe = () => render(<FeaturesProvider><Probe /></FeaturesProvider>);

describe('FeaturesProvider', () => {
  it('treats ACME as off while loading', () => {
    featuresAPI.get.mockReturnValue(new Promise(() => {}));
    renderProbe();
    expect(screen.getByTestId('acme')).toHaveTextContent('false');
  });

  it('turns ACME on when the server says so', async () => {
    featuresAPI.get.mockResolvedValue({ data: { acme: true } });
    renderProbe();
    await waitFor(() => expect(screen.getByTestId('acme')).toHaveTextContent('true'));
  });

  it('keeps ACME off when the request fails', async () => {
    featuresAPI.get.mockRejectedValue(new Error('network'));
    renderProbe();
    await waitFor(() => expect(featuresAPI.get).toHaveBeenCalled());
    expect(screen.getByTestId('acme')).toHaveTextContent('false');
  });
});
