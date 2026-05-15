# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Docker (primary workflow)
```bash
docker compose up --build          # Full build and start
docker compose up -d               # Start in background
docker compose down                # Stop all containers
docker compose logs -f             # Tail all logs
docker compose logs -f backend     # Backend logs only
./rebuild-frontend.sh              # Rebuild frontend if showing default page
./test_api.sh                      # Smoke-test the API
```

### Backend (local dev)
```bash
cd backend
pip install -r requirements.txt
python app.py                      # Dev server on :5000
```

The production entrypoint is `main:app` (used by Gunicorn), not `app.py`. When running locally, `app.py` calls `create_app()` directly.

### Frontend (local dev)
```bash
cd frontend
npm install
npm start                          # Dev server on :3000
npm test                           # Run tests
npm run build                      # Production build
```

## Architecture

Three Docker containers orchestrated by Docker Compose:

```
Browser → Nginx (:80) → /api/* → Flask backend (:5000)
                       → /*    → React frontend (:80, served by nginx)
```

- **`nginx/nginx.conf`** — reverse proxy; routes `/api` to backend, everything else to frontend. HTTPS block is commented out (uncomment + add certs for production).
- **`backend/app/__init__.py`** — Flask app factory (`create_app`). Registers the single blueprint (`ssl_bp`) at `/api`.
- **`backend/app/routes/ssl_routes.py`** — All API endpoints in one blueprint. Imports utilities from `ssl_utils` and services from `services/`.
- **`backend/app/utils/ssl_utils.py`** — Core crypto logic: certificate parsing, CSR generation, key generation, format conversion (uses `cryptography` + `pyOpenSSL`).
- **`backend/app/services/`** — Higher-level services:
  - `ssl_checker.py` — live domain SSL checks, chain analysis, SSL Labs, OCSP/CRL
  - `sysadmin_tools.py` — DMARC/SPF generation & validation, email header analysis, password toolkit, DNS lookups
  - `cert_monitor.py` — in-memory certificate expiration monitoring
  - `batch_processor.py` — parallel batch operations (up to 50 certs / 20 domains)
  - `api_key_manager.py` — API key lifecycle (generate, list, revoke, delete, validate)
- **`frontend/src/services/api.js`** — Axios client; all components import named exports (`certificateAPI`, `csrAPI`, `keyAPI`, `sslCheckAPI`, `sysAdminAPI`, etc.) from this file.
- **`frontend/src/components/`** — One component per tool page. `Layout.js` wraps all pages with nav.
- **`frontend/src/i18n.js`** — i18next setup; translations live in `src/locales/en/` and `src/locales/de/`.

## Rate Limiting

Default limits: 200/hour and 50/minute per IP. The key function (`get_api_key_or_ip` in `app/__init__.py`) allows callers to pass `X-API-Key` header to rate-limit by key instead of IP. Rate-limit storage is in-memory — resets on restart.

## Key Gotcha

The frontend Dockerfile is a two-stage build: Node compiles the React app, then the output is copied into an nginx image. If you see a default nginx page, it means the React build step was skipped or cached incorrectly — run `./rebuild-frontend.sh` or `docker compose build frontend --no-cache`.
