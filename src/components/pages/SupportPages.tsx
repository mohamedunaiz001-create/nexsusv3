import React, { useState } from 'react';
import {
  LifeBuoy, Search, ChevronDown, Mail, MessageSquare, BookOpen, ShieldQuestion,
  KeyRound, Bot, CreditCard, FileWarning,
} from 'lucide-react';
import { PublicShell, publicInput, publicLabel, publicPrimaryBtn } from './PublicShell';
import { PageShell, Panel } from './PageShell';

const FAQ_CATEGORIES = [
  {
    icon: KeyRound,
    label: 'Account & Access',
    items: [
      { q: 'How do I reset my password?', a: 'Go to Sign In → Forgot Password, and follow the emailed reset link. Links expire after 60 minutes.' },
      { q: 'How do I add a teammate?', a: 'Workspace admins can invite operators from Account Settings → Team.' },
    ],
  },
  {
    icon: Bot,
    label: 'Specialist Agents',
    items: [
      { q: 'Why is an agent stuck at "ANALYZING"?', a: 'Each specialist works one artifact at a time. Check System Monitor to confirm the AI provider it depends on is online.' },
      { q: 'Can I reassign a case to a different agent?', a: 'Yes — open the case and use Reassign Agent from the Case Detail modal.' },
    ],
  },
  {
    icon: CreditCard,
    label: 'Billing',
    items: [
      { q: 'How do I upgrade or downgrade my plan?', a: 'Go to Billing → Change Plan. Upgrades apply immediately; downgrades apply at the next renewal.' },
      { q: 'How do refunds work?', a: 'See our Refund Policy — most new-subscription refunds are processed within 5–10 business days.' },
    ],
  },
  {
    icon: FileWarning,
    label: 'Evidence & Cases',
    items: [
      { q: 'What file types can I upload as evidence?', a: 'Logs, PCAPs, binaries, memory dumps, and common archive formats. Files are routed through the full specialist pipeline automatically.' },
      { q: 'How long is case data retained?', a: 'For the life of your subscription, plus 30 days after cancellation. See our Cancellation Policy.' },
    ],
  },
];

const FaqAccordion: React.FC<{ query: string }> = ({ query }) => {
  const [openKey, setOpenKey] = useState<string | null>(null);
  const q = query.trim().toLowerCase();

  const filtered = FAQ_CATEGORIES.map((cat) => ({
    ...cat,
    items: cat.items.filter((i) => !q || i.q.toLowerCase().includes(q) || i.a.toLowerCase().includes(q)),
  })).filter((cat) => cat.items.length > 0);

  if (filtered.length === 0) {
    return <p className="rounded-lg border border-dashed border-purple-500/25 px-4 py-8 text-center font-mono text-[11px] text-purple-200/50">No help articles match "{query}".</p>;
  }

  return (
    <div className="space-y-5">
      {filtered.map((cat) => (
        <div key={cat.label}>
          <div className="mb-2 flex items-center gap-2 font-mono text-[10px] font-bold uppercase tracking-wider text-purple-300">
            <cat.icon className="h-3.5 w-3.5" /> {cat.label}
          </div>
          <div className="space-y-1.5">
            {cat.items.map((item) => {
              const key = `${cat.label}::${item.q}`;
              const open = openKey === key;
              return (
                <div key={key} className="overflow-hidden rounded-md border border-purple-500/20 bg-purple-950/15">
                  <button
                    onClick={() => setOpenKey(open ? null : key)}
                    className="flex w-full items-center justify-between px-3.5 py-2.5 text-left"
                  >
                    <span className="font-mono text-[11px] text-slate-200">{item.q}</span>
                    <ChevronDown className={`h-3.5 w-3.5 flex-shrink-0 text-purple-300/60 transition-transform ${open ? 'rotate-180' : ''}`} />
                  </button>
                  {open && <p className="border-t border-purple-500/15 px-3.5 py-2.5 font-mono text-[10px] leading-relaxed text-purple-200/60">{item.a}</p>}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
};

/** Content shared between the public /help-center route and the in-app Help nav item. */
const HelpCenterBody: React.FC = () => {
  const [query, setQuery] = useState('');
  return (
    <div className="space-y-5">
      <div className="relative">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-purple-300/50" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search the help center…"
          className={`${publicInput} pl-9`}
        />
      </div>
      <FaqAccordion query={query} />
    </div>
  );
};

export const HelpCenterPage: React.FC = () => (
  <PublicShell title="Help Center" subtitle="Answers to the questions operators ask most." backTo={{ label: 'Contact Support', href: '/support' }}>
    <HelpCenterBody />
  </PublicShell>
);

export const HelpCenterPageEmbedded: React.FC = () => (
  <PageShell title="HELP CENTER" subtitle="Answers to the questions operators ask most." icon={<BookOpen className="h-4 w-4" />}>
    <Panel>
      <HelpCenterBody />
    </Panel>
  </PageShell>
);

/* ------------------------------------------------------------------ */
/* SUPPORT / CONTACT                                                  */
/* ------------------------------------------------------------------ */

const SupportBody: React.FC = () => {
  const [sent, setSent] = useState(false);

  if (sent) {
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-5 py-8 text-center">
        <MessageSquare className="h-7 w-7 text-emerald-300" />
        <p className="font-mono text-xs text-emerald-200">Ticket submitted. Our team typically responds within 1 business day.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="rounded-lg border border-purple-500/25 bg-purple-950/20 p-3.5 text-center">
          <Mail className="mx-auto mb-1.5 h-4 w-4 text-purple-300" />
          <p className="font-mono text-[10px] text-purple-200/70">support@nexsus.example</p>
        </div>
        <div className="rounded-lg border border-purple-500/25 bg-purple-950/20 p-3.5 text-center">
          <ShieldQuestion className="mx-auto mb-1.5 h-4 w-4 text-purple-300" />
          <p className="font-mono text-[10px] text-purple-200/70">security@nexsus.example</p>
        </div>
        <div className="rounded-lg border border-purple-500/25 bg-purple-950/20 p-3.5 text-center">
          <BookOpen className="mx-auto mb-1.5 h-4 w-4 text-purple-300" />
          <p className="font-mono text-[10px] text-purple-200/70">Help Center &amp; FAQs</p>
        </div>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          setSent(true);
        }}
        className="space-y-4"
      >
        <div>
          <label className={publicLabel}>Subject</label>
          <input required placeholder="Briefly describe your issue" className={publicInput} />
        </div>
        <div>
          <label className={publicLabel}>Details</label>
          <textarea required rows={5} placeholder="What happened, what you expected, and any case/agent IDs involved." className={`${publicInput} resize-none`} />
        </div>
        <button type="submit" className={publicPrimaryBtn}>Submit Ticket</button>
      </form>
    </div>
  );
};

export const SupportPage: React.FC = () => (
  <PublicShell title="Contact Support" subtitle="We're here to help — reach the NEXSUS team directly." backTo={{ label: 'Help Center', href: '/help-center' }}>
    <SupportBody />
  </PublicShell>
);

export const SupportPageEmbedded: React.FC = () => (
  <PageShell title="SUPPORT" subtitle="We're here to help — reach the NEXSUS team directly." icon={<LifeBuoy className="h-4 w-4" />}>
    <Panel>
      <SupportBody />
    </Panel>
  </PageShell>
);
