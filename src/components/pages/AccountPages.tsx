import React, { useState } from 'react';
import {
  CreditCard, CheckCircle2, XCircle, Clock, ArrowUpCircle, ArrowDownCircle, Ban,
  ShieldAlert, Receipt, ChevronRight, Check,
} from 'lucide-react';
import { PageShell, Panel, StatTile, Pill } from './PageShell';

const btn =
  'flex items-center gap-1.5 rounded-md border border-purple-500/40 bg-purple-500/10 px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-purple-200 transition-colors hover:bg-purple-500/20';
const btnPrimary =
  'flex items-center gap-1.5 rounded-md border border-purple-400/50 bg-purple-600/80 px-3 py-2 font-cyber text-[10px] font-bold uppercase tracking-widest text-white shadow-[0_0_15px_rgba(168,85,247,0.2)] transition-colors hover:bg-purple-600';
const btnDanger =
  'flex items-center gap-1.5 rounded-md border border-rose-500/40 bg-rose-500/10 px-3 py-2 font-mono text-[10px] uppercase tracking-wider text-rose-300 transition-colors hover:bg-rose-500/20';

const PLANS = [
  { id: 'analyst', name: 'Analyst', price: 49, seats: 3, cases: '50 active cases', agents: '3 specialist agents' },
  { id: 'squad', name: 'Squad', price: 149, seats: 10, cases: 'Unlimited cases', agents: '8 specialist agents' },
  { id: 'enterprise', name: 'Enterprise', price: 399, seats: 50, cases: 'Unlimited cases', agents: '8 agents + custom SLAs' },
];

const INVOICES = [
  { id: 'INV-2026-0091', date: 'Aug 1, 2026', amount: '$149.00', status: 'Paid' },
  { id: 'INV-2026-0072', date: 'Jul 1, 2026', amount: '$149.00', status: 'Paid' },
  { id: 'INV-2026-0053', date: 'Jun 1, 2026', amount: '$149.00', status: 'Paid' },
];

/* ------------------------------------------------------------------ */
/* BILLING OVERVIEW                                                    */
/* ------------------------------------------------------------------ */

export const BillingPage: React.FC<{
  onNavigate: (nav: string) => void;
}> = ({ onNavigate }) => {
  const currentPlan = PLANS[1];
  return (
    <PageShell
      title="BILLING & SUBSCRIPTION"
      subtitle="Manage your NEXSUS plan, payment method, and invoice history."
      icon={<CreditCard className="h-4 w-4" />}
      actions={
        <>
          <button onClick={() => onNavigate('billing-upgrade')} className={btnPrimary}><ArrowUpCircle className="h-3 w-3" /> Change Plan</button>
          <button onClick={() => onNavigate('billing-cancel')} className={btnDanger}><Ban className="h-3 w-3" /> Cancel</button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Current Plan" value={currentPlan.name} tone="text-purple-300" />
        <StatTile label="Monthly Cost" value={`$${currentPlan.price}`} />
        <StatTile label="Seats Used" value="7 / 10" tone="text-emerald-300" />
        <StatTile label="Next Renewal" value="Sep 1, 2026" />
      </div>

      <Panel title="PAYMENT METHOD">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-12 items-center justify-center rounded-md border border-purple-500/30 bg-purple-950/30 font-mono text-[9px] text-purple-200">VISA</div>
            <div>
              <p className="font-mono text-[11px] text-slate-200">Visa ending in 4417</p>
              <p className="font-mono text-[9px] text-purple-200/40">Expires 04/2029</p>
            </div>
          </div>
          <button className={btn}>Update Card</button>
        </div>
      </Panel>

      <Panel title="INVOICE HISTORY">
        <div className="divide-y divide-purple-500/10">
          {INVOICES.map((inv) => (
            <div key={inv.id} className="flex items-center justify-between py-2.5">
              <div className="flex items-center gap-2.5">
                <Receipt className="h-3.5 w-3.5 text-purple-300/60" />
                <div>
                  <p className="font-mono text-[11px] text-slate-200">{inv.id}</p>
                  <p className="font-mono text-[9px] text-purple-200/40">{inv.date}</p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <Pill tone="border-emerald-500/40 text-emerald-300 bg-emerald-500/10">{inv.status}</Pill>
                <span className="font-mono text-[11px] text-slate-200">{inv.amount}</span>
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </PageShell>
  );
};

/* ------------------------------------------------------------------ */
/* UPGRADE / DOWNGRADE (shared plan-picker)                           */
/* ------------------------------------------------------------------ */

const PlanPicker: React.FC<{
  mode: 'upgrade' | 'downgrade';
  onNavigate: (nav: string) => void;
}> = ({ mode, onNavigate }) => {
  const currentIdx = 1;
  const eligible = mode === 'upgrade' ? PLANS.filter((_, i) => i > currentIdx) : PLANS.filter((_, i) => i < currentIdx);
  const [selected, setSelected] = useState<string | null>(null);

  return (
    <PageShell
      title={mode === 'upgrade' ? 'UPGRADE PLAN' : 'DOWNGRADE PLAN'}
      subtitle={
        mode === 'upgrade'
          ? 'Upgrades apply immediately — you\'ll be charged a prorated difference for the rest of this cycle.'
          : 'Downgrades take effect at the end of your current billing period. You keep full access until then.'
      }
      icon={mode === 'upgrade' ? <ArrowUpCircle className="h-4 w-4" /> : <ArrowDownCircle className="h-4 w-4" />}
      actions={<button onClick={() => onNavigate('billing')} className={btn}>Back to Billing</button>}
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        {eligible.length === 0 && (
          <p className="col-span-2 rounded-lg border border-dashed border-purple-500/25 px-4 py-8 text-center font-mono text-[11px] text-purple-200/50">
            {mode === 'upgrade' ? 'You are already on the highest available plan.' : 'You are already on the lowest available plan.'}
          </p>
        )}
        {eligible.map((plan) => (
          <button
            key={plan.id}
            onClick={() => setSelected(plan.id)}
            className={`rounded-xl border p-4 text-left transition-colors ${
              selected === plan.id ? 'border-purple-400/70 bg-purple-500/15' : 'border-purple-500/25 bg-purple-950/20 hover:border-purple-400/40'
            }`}
          >
            <div className="mb-2 flex items-center justify-between">
              <span className="font-cyber text-sm font-bold text-white">{plan.name}</span>
              {selected === plan.id && <Check className="h-4 w-4 text-purple-300" />}
            </div>
            <p className="mb-3 font-cyber text-xl font-bold text-purple-300">${plan.price}<span className="font-mono text-[10px] text-purple-200/50">/mo</span></p>
            <ul className="space-y-1 font-mono text-[10px] text-purple-200/60">
              <li>{plan.seats} seats included</li>
              <li>{plan.cases}</li>
              <li>{plan.agents}</li>
            </ul>
          </button>
        ))}
      </div>
      {selected && (
        <button
          onClick={() => onNavigate('payment-success')}
          className={`${btnPrimary} mt-1`}
        >
          Confirm {mode === 'upgrade' ? 'Upgrade' : 'Downgrade'} <ChevronRight className="h-3 w-3" />
        </button>
      )}
    </PageShell>
  );
};

export const UpgradePage: React.FC<{ onNavigate: (nav: string) => void }> = ({ onNavigate }) => (
  <PlanPicker mode="upgrade" onNavigate={onNavigate} />
);
export const DowngradePage: React.FC<{ onNavigate: (nav: string) => void }> = ({ onNavigate }) => (
  <PlanPicker mode="downgrade" onNavigate={onNavigate} />
);

/* ------------------------------------------------------------------ */
/* CANCEL SUBSCRIPTION                                                 */
/* ------------------------------------------------------------------ */

const CANCEL_REASONS = ['Too expensive', 'Missing a feature I need', 'Switching to another tool', 'Investigation wrapped up', 'Other'];

export const CancelSubscriptionPage: React.FC<{ onNavigate: (nav: string) => void }> = ({ onNavigate }) => {
  const [reason, setReason] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);

  if (confirmed) {
    return (
      <PageShell title="SUBSCRIPTION CANCELLED" icon={<Ban className="h-4 w-4" />}>
        <Panel>
          <div className="flex flex-col items-center gap-3 px-4 py-8 text-center">
            <CheckCircle2 className="h-7 w-7 text-emerald-300" />
            <p className="font-mono text-xs text-slate-200">
              Your subscription will remain active until <span className="text-purple-300">Sep 1, 2026</span>, then will not renew.
            </p>
            <button onClick={() => onNavigate('billing')} className={btn}>Back to Billing</button>
          </div>
        </Panel>
      </PageShell>
    );
  }

  return (
    <PageShell
      title="CANCEL SUBSCRIPTION"
      subtitle="We're sorry to see you go. Cancelling keeps your access until the end of the current billing period."
      icon={<Ban className="h-4 w-4" />}
      actions={<button onClick={() => onNavigate('billing')} className={btn}>Back to Billing</button>}
    >
      <Panel title="WHAT HAPPENS NEXT">
        <ul className="space-y-1.5 font-mono text-[11px] text-purple-200/70">
          <li>• You keep full access through the end of this billing period (Sep 1, 2026).</li>
          <li>• Case data and evidence artifacts stay available, read-only, for 30 days after that.</li>
          <li>• You can reactivate anytime before deletion with no data loss.</li>
        </ul>
      </Panel>

      <Panel title="HELP US IMPROVE (OPTIONAL)">
        <div className="space-y-1.5">
          {CANCEL_REASONS.map((r) => (
            <label key={r} className="flex items-center gap-2 rounded-md border border-purple-500/15 bg-purple-950/10 px-3 py-2 font-mono text-[11px] text-slate-300">
              <input type="radio" name="cancel-reason" checked={reason === r} onChange={() => setReason(r)} className="h-3 w-3 border-purple-500/40" />
              {r}
            </label>
          ))}
        </div>
      </Panel>

      <button onClick={() => setConfirmed(true)} className={btnDanger}>
        <ShieldAlert className="h-3 w-3" /> Confirm Cancellation
      </button>
    </PageShell>
  );
};

/* ------------------------------------------------------------------ */
/* PAYMENT RESULT PAGES                                                */
/* ------------------------------------------------------------------ */

export const PaymentSuccessPage: React.FC<{ onNavigate: (nav: string) => void }> = ({ onNavigate }) => (
  <PageShell title="PAYMENT SUCCESSFUL" icon={<CheckCircle2 className="h-4 w-4" />}>
    <Panel>
      <div className="flex flex-col items-center gap-3 px-4 py-10 text-center">
        <CheckCircle2 className="h-10 w-10 text-emerald-300" />
        <p className="font-cyber text-sm font-bold text-white">Payment confirmed</p>
        <p className="max-w-sm font-mono text-[11px] text-purple-200/60">Your plan change is live. A receipt has been emailed to your billing contact.</p>
        <button onClick={() => onNavigate('billing')} className={btnPrimary}>Back to Billing</button>
      </div>
    </Panel>
  </PageShell>
);

export const PaymentFailedPage: React.FC<{ onNavigate: (nav: string) => void }> = ({ onNavigate }) => (
  <PageShell title="PAYMENT FAILED" icon={<XCircle className="h-4 w-4" />}>
    <Panel>
      <div className="flex flex-col items-center gap-3 px-4 py-10 text-center">
        <XCircle className="h-10 w-10 text-rose-300" />
        <p className="font-cyber text-sm font-bold text-white">We couldn't process your payment</p>
        <p className="max-w-sm font-mono text-[11px] text-purple-200/60">Your card was declined. Update your payment method and try again — your plan hasn't changed.</p>
        <button onClick={() => onNavigate('billing')} className={btnPrimary}>Update Payment Method</button>
      </div>
    </Panel>
  </PageShell>
);

export const PaymentPendingPage: React.FC<{ onNavigate: (nav: string) => void }> = ({ onNavigate }) => (
  <PageShell title="PAYMENT PENDING" icon={<Clock className="h-4 w-4" />}>
    <Panel>
      <div className="flex flex-col items-center gap-3 px-4 py-10 text-center">
        <Clock className="h-10 w-10 text-amber-300" />
        <p className="font-cyber text-sm font-bold text-white">Your payment is processing</p>
        <p className="max-w-sm font-mono text-[11px] text-purple-200/60">This can take a few minutes for bank transfers. We'll email you once it clears — no action needed.</p>
        <button onClick={() => onNavigate('billing')} className={btn}>Back to Billing</button>
      </div>
    </Panel>
  </PageShell>
);
