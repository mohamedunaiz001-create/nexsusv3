# Malware Intelligence Engine — Connected to Investigation (this delivery)

The Malware Intelligence Engine backend (`python-server/app/malware_intel/`)
was already fully built — static feature extraction, a dependency-free
logistic-regression classifier, a hash/string rule engine, cosine-similarity
matching against a growing corpus, and a knowledge base that extracts IOCs
and family names from uploaded reports. All of it was reachable from the
standalone "Malware Intelligence" page, but **evidence uploaded through the
normal investigation flow never touched it** — `EvidenceUploadModal` faked a
SHA-256 and the "Malware Analysis" specialist's verdict came from a seeded
random generator, entirely disconnected from the real engine.

This delivery wires the two together:

- **`EvidenceUploadModal.tsx`** — file/code uploads now call
  `POST /api/malware-intel/samples/upload` for real: the actual bytes get
  hashed, run through static feature extraction (entropy, PE/ELF headers,
  suspicious API strings), scored by the trained classifier (if one exists),
  checked against detection rules, and compared to the similarity corpus.
  The real `sha256` and full verdict result are attached to the artifact. If
  the malware-intel service is unreachable, upload still succeeds with a
  visible notice — it degrades to the old simulated behavior rather than
  blocking evidence intake.
- **`multiAgentAnalysis.ts`** — when an artifact carries a real verdict, the
  "malware-analysis" specialist's finding is now built directly from it
  (verdict, confidence, matched rules, similar samples, likely family) via
  `findingFromMalwareIntel()`, labeled `[Malware Intelligence Engine]` so
  it's clear which findings are real vs. still simulated. No real result →
  falls back to the previous simulated flavor text, unchanged.
- **`types.ts`** — `EvidenceArtifact` gained an optional `malwareIntelSample`
  field carrying the full `MalwareSample` (verdict + evidence breakdown).

**What this means concretely:** upload a dataset and train a model on the
"Malware Intelligence" page, then upload a real file as case evidence — the
"Malware Analysis" step's verdict now actually reflects that trained model
and the rule/similarity corpus, instead of a coin-flip.

**Still simulated (unchanged, out of scope for this pass):** the other seven
specialists (IOC extraction, network analysis, threat intel, code review,
memory, verification, report generator) still produce flavor-text findings —
only the malware-analysis step has a real backend model behind it right now.
Also unchanged: PCAP and image uploads don't route through malware-intel
(static PE/ELF analysis doesn't apply to them).

Verified: `tsc --noEmit` and `vite build` both clean; the Python backend
imports successfully (46 routes mounted) and a synthetic end-to-end run
(extract → train → rule match → fused verdict) produced a correct
`malicious` verdict with real confidence scoring.

---

# Production-Grade Pages — Added

This pass adds the pages from "High-value production-grade pages people often
forget" that were missing from the NEXSUS codebase. Nothing existing was
removed; everything below is additive.

## How it's wired

NEXSUS's authenticated shell (`App.tsx`) is a single-route, state-driven SPA
(`activeNav`) — there was no router at all. Rather than bolt on a full router
dependency, two layers were added:

1. **`src/utils/publicRouter.ts`** — a ~30-line pathname router (pushState +
   popstate) used only for the small, fixed set of "logged-out" utility
   routes below. `src/main.tsx` now checks `isPublicRoute()` on load and
   renders `PublicApp` (chrome-free) instead of the dashboard `App` when the
   URL matches one of them. The FastAPI server (`python-server/app/main.py`)
   already falls back to `index.html` for every path in production, so
   these are safe to deep-link, bookmark, or share.
2. **New `activeNav` cases** inside the existing dashboard shell, for pages
   that make sense only *after* sign-in (Billing, Support, Help Center, QA
   states gallery).

## Legal (`/legal`, `/legal/<slug>`)

One generic renderer (`LegalPages.tsx`) driven by a content table — adds all
15 docs: Privacy Policy, Terms of Service, Cookie Policy, Cookie
Preferences, Refund Policy, Cancellation Policy, Shipping Policy,
Return/Exchange Policy, Disclaimer, Accessibility Statement, Data Processing
Agreement, Acceptable Use Policy, Security Policy, Responsible Disclosure,
Community Guidelines — plus a `/legal` hub/index page.

> Content is template copy for structural completeness, not legal advice —
> have counsel review before relying on it in production.

## Customer lifecycle

- **Auth** (`AuthPages.tsx`, public routes `/login`, `/register`,
  `/verify-email`, `/forgot-password`, `/reset-password`, `/onboarding`) —
  UI is complete and client-validated; wire the submit handlers to
  `server/auth.ts`'s `/api/auth/*` endpoints for a real identity provider.
- **Account/Billing** (`AccountPages.tsx`, in-app nav: Billing → Upgrade /
  Downgrade / Cancel Subscription) and **payment result pages** (Success /
  Failed / Pending) — plan data is mocked; connect to your billing provider.
- **Support** (`SupportPages.tsx`) — Support and Help Center, each available
  both as a public route (`/support`, `/help-center`) and as an in-app nav
  item so a signed-in operator doesn't have to leave the dashboard chrome.

## UX states

- **Standalone full-screen pages** (`StatusPages.tsx`): 404, 403, 500,
  Maintenance, Offline, Session Expired — reachable at `/404`, `/403`,
  `/500`, `/maintenance`, `/offline`, `/session-expired`, and `/404` is also
  the catch-all for any unrecognized public path.
- **Reusable embeddable components** (also in `StatusPages.tsx`):
  `EmptyState`, `NoSearchResultsState`, `LoadingState`, `ErrorState`,
  `SuccessState` — drop these into any panel/widget instead of a bespoke
  blank div or spinner.
- **QA gallery** — new in-app nav item "UX States (QA)" renders every state
  component together plus links to the standalone pages, so they're never
  "invisible until it breaks in prod."

## Navigation

`Sidebar.tsx` gained an **ACCOUNT & SUPPORT** section (Billing, Help Center,
Support, Legal & Compliance) and an **UX States (QA)** item under
Operations.

## Verified

`npx tsc --noEmit` and `npx vite build` both pass clean against this
checkout (Node 22, Vite 6, React 19).
