import React, { useState } from 'react';
import { Mail, Lock, Eye, EyeOff, User, Building2, CheckCircle2, ShieldCheck, ArrowRight, RefreshCw } from 'lucide-react';
import { PublicShell, publicInput, publicLabel, publicPrimaryBtn, publicSecondaryBtn, publicLink } from './PublicShell';
import { navigate } from '../../utils/publicRouter';

/* ------------------------------------------------------------------ */
/* LOGIN                                                              */
/* ------------------------------------------------------------------ */

export const LoginPage: React.FC = () => {
  const [showPw, setShowPw] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    // NOTE: wire to POST /api/auth/login (see server/auth.ts) once credentials
    // storage is connected to a real identity provider for this deployment.
    window.setTimeout(() => {
      setSubmitting(false);
      navigate('/');
    }, 600);
  };

  return (
    <PublicShell title="Operator Sign In" subtitle="Authenticate to access the NEXSUS command center." narrow>
      <form onSubmit={handleSubmit} className="space-y-4">
        {error && (
          <div className="rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 font-mono text-[11px] text-rose-300">{error}</div>
        )}
        <div>
          <label className={publicLabel}>Email</label>
          <div className="relative">
            <Mail className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-purple-300/50" />
            <input type="email" required autoComplete="email" placeholder="operator@agency.gov" className={`${publicInput} pl-9`} />
          </div>
        </div>
        <div>
          <label className={publicLabel}>Password</label>
          <div className="relative">
            <Lock className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-purple-300/50" />
            <input type={showPw ? 'text' : 'password'} required autoComplete="current-password" placeholder="••••••••••" className={`${publicInput} pl-9 pr-9`} />
            <button type="button" onClick={() => setShowPw((v) => !v)} className="absolute right-3 top-1/2 -translate-y-1/2 text-purple-300/50 hover:text-purple-200">
              {showPw ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>
        <div className="flex items-center justify-between">
          <label className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider text-purple-200/60">
            <input type="checkbox" className="h-3 w-3 rounded border-purple-500/40 bg-purple-950/40" /> Remember device
          </label>
          <button type="button" onClick={() => navigate('/forgot-password')} className={`font-mono text-[10px] uppercase tracking-wider ${publicLink}`}>
            Forgot password?
          </button>
        </div>
        <button type="submit" disabled={submitting} className={publicPrimaryBtn}>
          {submitting ? 'Authenticating…' : 'Sign In'}
        </button>
      </form>
      <p className="mt-5 text-center font-mono text-[11px] text-purple-200/50">
        No access yet?{' '}
        <button onClick={() => navigate('/register')} className={publicLink}>Request an account</button>
      </p>
    </PublicShell>
  );
};

/* ------------------------------------------------------------------ */
/* REGISTER                                                           */
/* ------------------------------------------------------------------ */

export const RegisterPage: React.FC = () => {
  const [submitting, setSubmitting] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    window.setTimeout(() => {
      setSubmitting(false);
      setSubmitted(true);
    }, 600);
  };

  if (submitted) {
    return (
      <PublicShell title="Check Your Inbox" narrow>
        <div className="flex flex-col items-center gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-5 py-8 text-center">
          <CheckCircle2 className="h-8 w-8 text-emerald-300" />
          <p className="font-mono text-xs text-emerald-200">
            We sent a verification link to your email. Click it to activate your operator account.
          </p>
          <button onClick={() => navigate('/verify-email')} className={`${publicSecondaryBtn} mt-2 max-w-xs`}>
            I have a verification code
          </button>
        </div>
      </PublicShell>
    );
  }

  return (
    <PublicShell title="Request Operator Access" subtitle="Create a NEXSUS account for your organization." narrow>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className={publicLabel}>Full Name</label>
          <div className="relative">
            <User className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-purple-300/50" />
            <input required autoComplete="name" placeholder="Jane Doe" className={`${publicInput} pl-9`} />
          </div>
        </div>
        <div>
          <label className={publicLabel}>Work Email</label>
          <div className="relative">
            <Mail className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-purple-300/50" />
            <input type="email" required autoComplete="email" placeholder="jane@agency.gov" className={`${publicInput} pl-9`} />
          </div>
        </div>
        <div>
          <label className={publicLabel}>Organization</label>
          <div className="relative">
            <Building2 className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-purple-300/50" />
            <input required placeholder="Agency / Team name" className={`${publicInput} pl-9`} />
          </div>
        </div>
        <div>
          <label className={publicLabel}>Password</label>
          <div className="relative">
            <Lock className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-purple-300/50" />
            <input type="password" required minLength={12} autoComplete="new-password" placeholder="Minimum 12 characters" className={`${publicInput} pl-9`} />
          </div>
        </div>
        <label className="flex items-start gap-2 font-mono text-[10px] leading-relaxed text-purple-200/60">
          <input type="checkbox" required className="mt-0.5 h-3 w-3 rounded border-purple-500/40 bg-purple-950/40" />
          <span>
            I agree to the{' '}
            <button type="button" onClick={() => navigate('/legal/terms-of-service')} className={publicLink}>Terms of Service</button>{' '}
            and{' '}
            <button type="button" onClick={() => navigate('/legal/privacy-policy')} className={publicLink}>Privacy Policy</button>.
          </span>
        </label>
        <button type="submit" disabled={submitting} className={publicPrimaryBtn}>
          {submitting ? 'Creating Account…' : 'Create Account'}
        </button>
      </form>
      <p className="mt-5 text-center font-mono text-[11px] text-purple-200/50">
        Already have access?{' '}
        <button onClick={() => navigate('/login')} className={publicLink}>Sign in</button>
      </p>
    </PublicShell>
  );
};

/* ------------------------------------------------------------------ */
/* EMAIL VERIFICATION                                                 */
/* ------------------------------------------------------------------ */

export const EmailVerificationPage: React.FC = () => {
  const [status, setStatus] = useState<'pending' | 'verifying' | 'success' | 'error'>('pending');

  const verify = () => {
    setStatus('verifying');
    window.setTimeout(() => setStatus('success'), 700);
  };

  return (
    <PublicShell title="Verify Your Email" narrow>
      {status === 'success' ? (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-5 py-8 text-center">
          <CheckCircle2 className="h-8 w-8 text-emerald-300" />
          <p className="font-mono text-xs text-emerald-200">Email verified. Your account is now active.</p>
          <button onClick={() => navigate('/onboarding')} className={`${publicPrimaryBtn} mt-2 max-w-xs`}>
            Continue Onboarding <ArrowRight className="ml-1 inline h-3 w-3" />
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          <p className="font-mono text-xs leading-relaxed text-purple-200/60">
            Enter the 6-digit code we emailed you, or click the verification link directly from your inbox.
          </p>
          <div>
            <label className={publicLabel}>Verification Code</label>
            <input inputMode="numeric" maxLength={6} placeholder="000000" className={`${publicInput} tracking-[0.5em] text-center text-base`} />
          </div>
          <button onClick={verify} disabled={status === 'verifying'} className={publicPrimaryBtn}>
            {status === 'verifying' ? 'Verifying…' : 'Verify Email'}
          </button>
          <button className="w-full text-center font-mono text-[10px] uppercase tracking-wider text-purple-300 hover:text-purple-200">
            <RefreshCw className="mr-1 inline h-3 w-3" /> Resend Code
          </button>
        </div>
      )}
    </PublicShell>
  );
};

/* ------------------------------------------------------------------ */
/* FORGOT / RESET PASSWORD                                            */
/* ------------------------------------------------------------------ */

export const ForgotPasswordPage: React.FC = () => {
  const [sent, setSent] = useState(false);
  return (
    <PublicShell title="Forgot Password" subtitle="We'll email you a secure link to reset your password." narrow backTo={{ label: 'Sign In', href: '/login' }}>
      {sent ? (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-5 py-8 text-center">
          <CheckCircle2 className="h-8 w-8 text-emerald-300" />
          <p className="font-mono text-xs text-emerald-200">If an account exists for that email, a reset link is on its way.</p>
        </div>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setSent(true);
          }}
          className="space-y-4"
        >
          <div>
            <label className={publicLabel}>Email</label>
            <div className="relative">
              <Mail className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-purple-300/50" />
              <input type="email" required autoComplete="email" placeholder="operator@agency.gov" className={`${publicInput} pl-9`} />
            </div>
          </div>
          <button type="submit" className={publicPrimaryBtn}>Send Reset Link</button>
        </form>
      )}
    </PublicShell>
  );
};

export const ResetPasswordPage: React.FC = () => {
  const [done, setDone] = useState(false);
  return (
    <PublicShell title="Reset Password" narrow>
      {done ? (
        <div className="flex flex-col items-center gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-5 py-8 text-center">
          <CheckCircle2 className="h-8 w-8 text-emerald-300" />
          <p className="font-mono text-xs text-emerald-200">Password updated. You can now sign in.</p>
          <button onClick={() => navigate('/login')} className={`${publicPrimaryBtn} mt-2 max-w-xs`}>Go to Sign In</button>
        </div>
      ) : (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            setDone(true);
          }}
          className="space-y-4"
        >
          <div>
            <label className={publicLabel}>New Password</label>
            <div className="relative">
              <Lock className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-purple-300/50" />
              <input type="password" required minLength={12} autoComplete="new-password" placeholder="Minimum 12 characters" className={`${publicInput} pl-9`} />
            </div>
          </div>
          <div>
            <label className={publicLabel}>Confirm New Password</label>
            <div className="relative">
              <Lock className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-purple-300/50" />
              <input type="password" required minLength={12} autoComplete="new-password" placeholder="Re-enter password" className={`${publicInput} pl-9`} />
            </div>
          </div>
          <button type="submit" className={publicPrimaryBtn}>Update Password</button>
        </form>
      )}
    </PublicShell>
  );
};

/* ------------------------------------------------------------------ */
/* ONBOARDING                                                         */
/* ------------------------------------------------------------------ */

const ONBOARDING_STEPS = [
  { title: 'Welcome, Operator', body: 'NEXSUS coordinates 8 specialist AI agents under CEO Orchestrator ARCHON to triage, investigate, and report on security incidents.' },
  { title: 'Configure AI Providers', body: 'Connect at least one AI provider from the Provider Hub so ARCHON and the specialist agents can reason over evidence.' },
  { title: 'Upload Your First Evidence', body: 'Drop a log, binary, or PCAP into the Evidence Intake modal to see the specialist pipeline kick off in real time.' },
  { title: "You're Ready", body: 'Explore the command center, or jump straight into creating your first case.' },
];

export const OnboardingPage: React.FC = () => {
  const [step, setStep] = useState(0);
  const isLast = step === ONBOARDING_STEPS.length - 1;

  return (
    <PublicShell title="Get Started with NEXSUS" narrow>
      <div className="mb-6 flex gap-1.5">
        {ONBOARDING_STEPS.map((_, i) => (
          <div key={i} className={`h-1 flex-1 rounded-full ${i <= step ? 'bg-purple-400' : 'bg-purple-500/15'}`} />
        ))}
      </div>
      <div className="rounded-lg border border-purple-500/25 bg-purple-950/20 p-5">
        <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-lg border border-purple-500/40 bg-purple-500/10 text-purple-300">
          <ShieldCheck className="h-4 w-4" />
        </div>
        <h2 className="mb-2 font-cyber text-sm font-bold text-white">{ONBOARDING_STEPS[step].title}</h2>
        <p className="font-mono text-[11px] leading-relaxed text-purple-200/60">{ONBOARDING_STEPS[step].body}</p>
      </div>
      <div className="mt-5 flex gap-3">
        {step > 0 && (
          <button onClick={() => setStep((s) => s - 1)} className={publicSecondaryBtn}>Back</button>
        )}
        <button
          onClick={() => (isLast ? navigate('/') : setStep((s) => s + 1))}
          className={publicPrimaryBtn}
        >
          {isLast ? 'Enter Command Center' : 'Next'}
        </button>
      </div>
    </PublicShell>
  );
};
