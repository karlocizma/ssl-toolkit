import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

jest.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key) => key,
    i18n: { language: 'en', changeLanguage: jest.fn() },
  }),
}));


import Layout from './Layout';

const renderLayout = (children = <div data-testid="child">content</div>) =>
  render(
    <MemoryRouter>
      <Layout>{children}</Layout>
    </MemoryRouter>
  );

describe('Layout', () => {
  it('renders child content', () => {
    renderLayout();
    expect(screen.getByTestId('child')).toBeInTheDocument();
  });

  it('renders the dashboard nav item', () => {
    renderLayout();
    expect(screen.getAllByText('nav.dashboard').length).toBeGreaterThan(0);
  });

  it('renders the SSL Checker nav item', () => {
    renderLayout();
    expect(screen.getAllByText('nav.sslChecker').length).toBeGreaterThan(0);
  });

  it('renders the DMARC Manager nav item', () => {
    renderLayout();
    expect(screen.getAllByText('nav.dmarcManager').length).toBeGreaterThan(0);
  });

  it('renders the language switcher showing EN', () => {
    renderLayout();
    expect(screen.getByText('EN')).toBeInTheDocument();
  });

  it('renders the dark mode toggle button', () => {
    renderLayout();
    expect(screen.getByRole('button', { name: /toggle dark mode/i })).toBeInTheDocument();
  });

  it('renders all 15 navigation items', () => {
    const navKeys = [
      'nav.dashboard', 'nav.certificateDecoder', 'nav.csrGenerator',
      'nav.csrDecoder', 'nav.sslChecker', 'nav.certificateConverter',
      'nav.keyGenerator', 'nav.keyValidator', 'nav.keyCertificateMatch',
      'nav.certificateChainChecker', 'nav.dmarcManager', 'nav.spfManager',
      'nav.emailHeaderAnalyzer', 'nav.passwordToolkit', 'nav.dnsDiagnostics',
    ];
    renderLayout();
    navKeys.forEach((key) => {
      expect(screen.getAllByText(key).length).toBeGreaterThan(0);
    });
  });
});
