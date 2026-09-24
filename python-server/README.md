# NEXSUS — Python Backend

This backend was converted from the original Express/TypeScript server to
**Python 3 + FastAPI**. The React/TypeScript frontend (`src/`) is unchanged.

## What changed

| Original (`server/`, now removed) | Python (`python-server/app/`) |
|---|---|
| `server.ts` | `main.py` — app assembly, security headers, CORS, rate limiting, static serving |
| `auth.ts` | `auth.py` — JWT sessions, PBKDF2 auth, CSRF tokens, RBAC dependencies |
| `security.ts` | `security.py` — SSRF protection, log redaction, secure error responses |
| `database.ts` (`node:sqlite`) | `database.py` (Python's built-in `sqlite3`) |
| `aiService.ts` | `ai_service.py` — provider allowlist, Gemini integration, deterministic fallback |
| `securityAudit.ts` | `security_audit.py` — the same 8 live runtime self-tests |
| `routes.ts` | `routes.py` |
| `tools/*.ts` | `tools/*.py` (crypto, gateway, registry, http_client, routes) |
| `tools/adapters/*.ts` | `tools/adapters/*.py` (VirusTotal, OTX, Shodan, AbuseIPDB) |

Every security control was preserved as-is: AES-256-GCM credential
encryption, SSRF-blocking DNS/IP validation before any outbound tool call,
HMAC-signed CSRF tokens, timing-safe password comparison, and the same
per-route rate limits.

Library equivalents used: `PyJWT` for JWT, `cryptography`'s `AESGCM` for
credential encryption, `httpx` for outbound HTTP, `google-genai` for
Gemini, and Pydantic models in place of `zod` schemas.

## Running it

### 1. Backend (FastAPI)

```bash
cd python-server
python -m venv .venv && source .venv/bin/activate   # optional but recommended
pip install -r requirements.txt
cp .env.example .env   # then fill in secrets — see below
python -m uvicorn app.main:app --reload --port 8000
```

Required env vars for local dev (auto-generated ephemeral values are used
if unset, with a console warning — fine for local testing, **not** for
production):

- `ADMIN_INITIAL_PASSWORD`, `ANALYST_INITIAL_PASSWORD`, `VIEWER_INITIAL_PASSWORD` (12+ chars each) — otherwise those accounts are unprovisioned.
- `JWT_SECRET`, `CSRF_SECRET`, `TOOL_ENCRYPTION_KEY` — required in production (`NODE_ENV=production`); generate with `openssl rand -hex 32` (64 hex chars) for the first two, and `openssl rand -hex 32` for `TOOL_ENCRYPTION_KEY` (32-byte AES key).
- `GEMINI_API_KEY` — optional; without it, ARCHON uses the deterministic conversational fallback engine.

### 2. Frontend (Vite/React) — unchanged

```bash
npm install
npm run dev
```

`vite.config.ts` now proxies `/api/*` requests to `http://localhost:8000`
(override with `PY_API_URL`) so the frontend code needs no changes — it
still calls relative `/api/...` paths exactly as before.

### 3. Production

`npm run build` produces `dist/`. The FastAPI app (`NODE_ENV=production`)
serves that directory directly and falls back to `index.html` for
client-side routing — mirroring what `server.ts` did. See the updated
`Dockerfile` for a single-image multi-stage build (Node builds the
frontend, the final image is Python-only).

```bash
docker build -t nexsus .
docker run -p 8000:8000 --env-file python-server/.env nexsus
```

## Notes / things worth knowing

- SQLite data now lives at `./data/nexsus.sqlite` by default (override with `NEXSUS_DATA_DIR`), same schema as before (with the same additive migration for `plan_tier`).
- Rate limiting is an in-memory fixed-window limiter (same limits as the original: 200/min global, 30/min AI, 20/min auth, 40/min tool-execute) — like the original, this resets on restart and isn't shared across multiple processes/instances. For a multi-worker or multi-instance production deployment, swap this for a shared store (e.g. Redis) exactly as you'd have needed to with the Node version's in-memory limiter too.
- `/docs` (Swagger UI) and `/redoc` are available for free from FastAPI — the original Express API had no equivalent.
