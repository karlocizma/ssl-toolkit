import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

jest.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key) => key, i18n: { language: 'en' } }),
}));

import Dashboard from './Dashboard';
import { FeaturesContext } from '../contexts/FeaturesContext';

const renderDashboard = (features) =>
  render(
    <FeaturesContext.Provider value={features}>
      <MemoryRouter><Dashboard /></MemoryRouter>
    </FeaturesContext.Provider>
  );

describe('Dashboard', () => {
  it('has no ACME tile when ACME is disabled', () => {
    renderDashboard({ acme: false });
    expect(screen.queryByText('tools.acme.title')).not.toBeInTheDocument();
    expect(screen.getByText('tools.privateCA.title')).toBeInTheDocument();
  });

  it('shows the ACME tile when ACME is enabled', () => {
    renderDashboard({ acme: true });
    expect(screen.getByText('tools.acme.title')).toBeInTheDocument();
  });
});
