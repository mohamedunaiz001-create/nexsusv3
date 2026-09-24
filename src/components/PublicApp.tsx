import React from 'react';
import { usePathname } from '../utils/publicRouter';
import { LegalHubPage, LegalPage } from './pages/LegalPages';
import { LoginPage, RegisterPage, EmailVerificationPage, ForgotPasswordPage, ResetPasswordPage, OnboardingPage } from './pages/AuthPages';
import { SupportPage, HelpCenterPage } from './pages/SupportPages';
import { STATUS_ROUTE_COMPONENTS, NotFoundPage } from './pages/StatusPages';

/**
 * Renders the standalone (chrome-free) public pages — legal docs, auth
 * screens, support, and status pages — based on the current pathname.
 * Selected by main.tsx when the pathname matches isPublicRoute().
 */
export default function PublicApp() {
  const pathname = usePathname();

  if (pathname === '/legal') return <LegalHubPage />;
  if (pathname.startsWith('/legal/')) return <LegalPage slug={pathname.replace('/legal/', '')} />;

  if (pathname === '/login') return <LoginPage />;
  if (pathname === '/register') return <RegisterPage />;
  if (pathname === '/verify-email') return <EmailVerificationPage />;
  if (pathname === '/forgot-password') return <ForgotPasswordPage />;
  if (pathname === '/reset-password') return <ResetPasswordPage />;
  if (pathname === '/onboarding') return <OnboardingPage />;

  if (pathname === '/support') return <SupportPage />;
  if (pathname === '/help-center') return <HelpCenterPage />;

  const StatusComponent = STATUS_ROUTE_COMPONENTS[pathname];
  if (StatusComponent) return <StatusComponent />;

  return <NotFoundPage />;
}
