# CyberResearch‑X — NEXSUS SOC Command Center

An AI cybersecurity operations command center: CEO orchestrator agent ("Archon"), an 8‑specialist agent hierarchy, live case/IOC management, event streaming, and a customizable dashboard — a Vite/React frontend served alongside a **Python/FastAPI** backend.

> This project's backend was converted from Express/TypeScript to Python (FastAPI). See `python-server/README.md` for the full conversion notes. The frontend (`src/`) is unchanged.

## Malware Intelligence Engine

Underneath the specialist agent layer, NEXSUS includes a defensive **Malware
Intelligence Engine** (`python-server/app/malware_intel/`) that turns
uploaded samples, labeled datasets, and intelligence reports into
structured, evidence-fused verdicts — separate from and complementary to
the LLM agents:

```
Evidence Intake
  -> Static Feature Extraction   (hashes, entropy, PE/ELF headers, strings)
  -> Rule Engine                 (hash / string detection rules)
  -> Similarity Engine           (cosine similarity over feature vectors)
  -> Baseline Classifier         (logistic regression on labeled vectors)
  -> Knowledge Extraction        (IOCs / CVEs / ATT&CK IDs / family mentions)
  -> Evidence Fusion             (final verdict + confidence + rationale)
```

Design principle: **the LLM is never the detector.** Raw sample bytes never
reach an LLM call. The engine produces measurable, auditable evidence
(hashes, entropy, rule hits, similarity scores, a trained model's
probability) and the Malware/IOC/Threat-Intel/Verification agents reason
over that structured output instead.

- **Malware Intelligence Center** (`/malware-intel` in the app) — upload a
  sample, see its fused verdict, similar known samples, rule matches, and
  PE section entropy.
- **Malware Learning Center** (`/malware-learning`) — ingest labeled
  datasets (CSV/JSON) and intelligence reports (txt/md/csv/json), train the
  baseline classifier, manage detection rules, and browse the knowledge
  base (families / IOCs).
- API: `python-server/app/malware_intel/routes.py`, mounted at
  `/api/malware-intel/*`.

### PCAP analysis boundary

PCAP uploads are decoded passively by the backend. The decoder reports packet
counts, endpoints, ports, DNS query names, HTTP `Host` values, and TLS SNI
metadata without decrypting traffic or executing payloads. Dynamic sandbox
execution is intentionally not part of this application; connect an isolated
external analysis service before enabling behavioral execution telemetry.

The authenticated `GET /api/sandbox/status` endpoint reports whether an
external HTTPS sandbox boundary is configured. It never executes samples and
continues to report `executionAvailable: false` until a reviewed service
adapter is deployed.

### Tests

```bash
npm test
npm run typecheck
cd python-server && python -m pytest -q
```

## Prerequisites

- Node.js 20+ (Node 22 recommended) — for the frontend
- Python 3.11+ — for the backend

## Run locally

1. Install frontend dependencies:
   ```bash
   npm install
   ```
2. Install backend dependencies:
   ```bash
   cd python-server && pip install -r requirements.txt && cd ..
   ```
3. Copy the example env file and fill in real secrets:
   ```bash
   cp python-server/.env.example python-server/.env
   ```
   - `GEMINI_API_KEY` — optional. Without it the AI endpoints run in a deterministic fallback mode instead of calling Gemini.
   - `JWT_SECRET` / `CSRF_SECRET` — set these to long random strings in any real deployment. If left blank, the server generates a fresh random secret on every boot (fine for local dev, but it means sessions won't survive a restart).
   - `TOOL_ENCRYPTION_KEY` — 64-char hex string (`openssl rand -hex 32`) used to encrypt connected tool API keys at rest.
   - `ADMIN_INITIAL_PASSWORD` / `ANALYST_INITIAL_PASSWORD` / `VIEWER_INITIAL_PASSWORD` — passwords for the seeded operator accounts. **Required in production** — an account with no password set is left unprovisioned (login fails closed) rather than falling back to a hardcoded password. Locally, leaving these unset prints a fresh random password to your terminal on every boot.
   - `.env` files are already in `.gitignore` — never commit a real one.
4. Start the backend (FastAPI, with autoreload):
   ```bash
   cd python-server && python -m uvicorn app.main:app --reload --port 8000
   ```
5. In a second terminal, start the frontend dev server (Vite, with HMR):
   ```bash
   npm run dev
   ```
   The app is served locally at http://localhost:5173 (Vite's default) — `/api/*` requests are proxied to the FastAPI backend on port 8000. See `vite.config.ts`.

## Production build

```bash
npm run build   # builds the client to dist/
cd python-server && python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
# with NODE_ENV=production set, FastAPI serves the built dist/ directly
```

## Deploy with Docker

```bash
docker build -t nexsus-soc .
docker run -p 8000:8000 \
  -e NODE_ENV=production \
  -e JWT_SECRET="$(openssl rand -hex 32)" \
  -e CSRF_SECRET="$(openssl rand -hex 32)" \
  -e TOOL_ENCRYPTION_KEY="$(openssl rand -hex 32)" \
  -e ADMIN_INITIAL_PASSWORD="$(openssl rand -base64 24)" \
  -e ANALYST_INITIAL_PASSWORD="$(openssl rand -base64 24)" \
  -e VIEWER_INITIAL_PASSWORD="$(openssl rand -base64 24)" \
  -e GEMINI_API_KEY="your-key-here" \
  nexsus-soc
```

The container listens on port 8000 and serves both the API (`/api/*`) and the built static frontend.

## Notes for a real production rollout

- The seeded operator accounts (Admin/Analyst/Viewer) have **no password by default** — each one only exists once its `*_INITIAL_PASSWORD` env var is set (12+ characters). This is intentional: the app no longer ships with a working hardcoded password, so an account you never configured simply can't be logged into.
- There is no "guest" auto-login in production. `/api/auth/bootstrap` (a no-credential convenience login used only during local development) is disabled unless `NODE_ENV` is not `production`, or you explicitly set `ALLOW_DEMO_BOOTSTRAP=true` — only do this for a deliberately public demo with no real data, never for a deployment with real cases/evidence.
- Set `ALLOWED_ORIGINS` (comma‑separated) if the frontend and API will ever be served from different origins; otherwise same‑origin requests are allowed automatically.
- `GEMINI_API_KEY` is only read server‑side (`python-server/app/ai_service.py`) and is never exposed to the browser.
- `GET /api/security/audit` (Admin/Analyst/Viewer only) runs live self-checks — including whether the required secrets/passwords are actually configured — so you can verify a deployment before exposing it.
