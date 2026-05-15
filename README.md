# Security & Network Toolkit

A self-hosted, web-based toolkit for SSL/TLS certificate management, email security, network diagnostics, and cryptographic tooling. Built with a Flask backend and React frontend, orchestrated with Docker Compose.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Development Setup](#development-setup)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Security](#security)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

---

## Features

### SSL / TLS Tools

| Tool | Description |
|------|-------------|
| Certificate Decoder | Parse and display full certificate details (subject, issuer, validity, SANs, fingerprints) |
| CSR Generator | Generate Certificate Signing Requests with a new RSA or EC private key |
| CSR Decoder | Parse and display CSR content |
| SSL Checker | Live SSL check for any domain — chain, expiry, cipher info |
| Certificate Converter | Convert between PEM, DER, and PFX/PKCS12 formats |
| Key Generator | Generate RSA (2048/4096) or EC (P-256/P-384/P-521) private keys |
| Key Validator | Validate a private key and report its type and size |
| Key–Certificate Match | Verify that a private key matches a given certificate |
| Certificate Chain Checker | Validate the full certificate chain for a domain |
| Self-Signed Cert Generator | Generate self-signed X.509 certificates with custom SANs |

### Email Security Tools

| Tool | Description |
|------|-------------|
| DMARC Manager | Generate and validate DMARC policies via DNS lookup or inline |
| SPF Manager | Build and validate SPF TXT records |
| Email Header Analyzer | Parse email headers, trace hops, and check authentication results |
| DKIM Manager | Generate RSA DKIM key pairs and validate existing DKIM records |

### Network & Security Tools

| Tool | Description |
|------|-------------|
| Password Toolkit | Secure password generation, strength analysis, and hashing |
| DNS Diagnostics | Look up A, AAAA, MX, TXT, NS, and other DNS record types |
| SSL Config Generator | Generate production-ready Nginx, Apache, or HAProxy TLS config snippets |
| JWT Decoder | Decode JWT header and payload in-browser, with expiry status chip |

### Advanced API Features

- **OCSP / CRL Revocation Checking** — verify certificate revocation in real time
- **Certificate Monitoring** — track certificates and list those expiring within N days
- **Batch Processing** — process up to 50 certificates or 20 domains in a single request
- **API Key Management** — generate, revoke, and rate-limit by key

---

## Architecture

```
Browser
  │
  ▼
Nginx (:80)
  ├── /api/*  ──► Flask backend (:5000)
  └── /*      ──► React static frontend (served by nginx)
```

Three Docker containers managed by Compose:

| Container | Image | Role |
|-----------|-------|------|
| `nginx` | `nginx:alpine` | Reverse proxy + static frontend |
| `backend` | custom Python | Flask/Gunicorn API server |
| `frontend` | build artifact | React app compiled into nginx image |

**Key source files:**

| Path | Purpose |
|------|---------|
| `nginx/nginx.conf` | Proxy rules; HTTPS block is present but commented out |
| `backend/app/__init__.py` | Flask app factory, rate limiter setup |
| `backend/app/routes/ssl_routes.py` | All 44 API route handlers |
| `backend/app/utils/ssl_utils.py` | Core crypto: cert parsing, CSR/key/self-signed generation |
| `backend/app/services/ssl_checker.py` | Live domain checks, OCSP, CRL, chain analysis |
| `backend/app/services/sysadmin_tools.py` | DMARC, SPF, DKIM, email headers, DNS lookups, SSL config, passwords |
| `backend/app/services/cert_monitor.py` | In-memory certificate expiry monitoring |
| `backend/app/services/batch_processor.py` | Parallel batch operations (ThreadPoolExecutor) |
| `backend/app/services/api_key_manager.py` | API key lifecycle management |
| `frontend/src/services/api.js` | Axios API client — all named exports |
| `frontend/src/components/` | One React component per tool page |
| `frontend/src/locales/` | i18n translations (English, German) |

---

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- Git

### Run

```bash
git clone <repository-url>
cd ssl-toolkit
docker compose up --build
```

Open **http://localhost** in your browser.

> If you see a default nginx page instead of the app, run `./rebuild-frontend.sh`.  
> This is a known Docker build-cache issue — see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

### Useful commands

```bash
docker compose up -d            # Start in background
docker compose down             # Stop all containers
docker compose logs -f          # Tail all logs
docker compose logs -f backend  # Backend logs only
./rebuild-frontend.sh           # Force-rebuild the frontend
./test_api.sh                   # Smoke-test the API
```

---

## Development Setup

### Backend

```bash
cd backend
pip install -r requirements.txt
python app.py          # Dev server on :5000
```

The production entrypoint used by Gunicorn is `main:app`. `app.py` calls `create_app()` directly for local dev.

### Frontend

```bash
cd frontend
npm install
npm start              # Dev server on :3000 with hot reload
npm test               # Jest tests
npm run build          # Production build
```

---

## Configuration

### Environment variables

```env
SECRET_KEY=change-this-in-production        # Flask secret key
FLASK_ENV=production
ADMIN_TOKEN=your-admin-bearer-token         # Required for /api/admin/* endpoints
REACT_APP_API_URL=/api
```

### Rate limiting defaults

| Scope | Limit |
|-------|-------|
| Per IP (no key) | 200 req/hour, 50 req/min |
| Per API key | Configurable at key creation time |

Set `X-API-Key: <key>` on requests to rate-limit by key instead of IP.

### Language

English (default) and German are bundled. Use the globe icon in the top bar to switch. Translation files live in `frontend/src/locales/`.

### HTTPS

HTTPS is disabled by default. To enable it in production:

1. Place your certificate and key in `nginx/certs/`
2. Uncomment the HTTPS server block in `nginx/nginx.conf`
3. Restart: `docker compose restart nginx`

---

## API Reference

All endpoints are prefixed with `/api`. POST requests must set `Content-Type: application/json` unless using multipart/form-data for file upload.

**Authentication headers:**
- `X-API-Key: <key>` — optional; switches rate-limiting to per-key mode
- `Authorization: Bearer <ADMIN_TOKEN>` — required for all `/api/admin/*` endpoints

---

### Certificate

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/certificate/decode` | Parse PEM certificate, return all fields |
| `POST` | `/api/certificate/fingerprint` | SHA-1 and SHA-256 fingerprints |
| `POST` | `/api/certificate/self-signed` | Generate self-signed certificate |

**Self-signed certificate request:**
```json
{
  "common_name": "localhost",
  "organization": "ACME Corp",
  "country": "US",
  "validity_days": 365,
  "key_type": "RSA",
  "key_size": 2048,
  "sans": ["localhost", "127.0.0.1"]
}
```

---

### CSR

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/csr/generate` | Generate CSR + private key |
| `POST` | `/api/csr/decode` | Parse and return CSR details |

---

### Keys

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/key/generate` | Generate RSA or EC private key |
| `POST` | `/api/key/validate` | Validate key, return algorithm and size |
| `POST` | `/api/key/match-certificate` | Check if key matches certificate |

---

### Certificate Conversion

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/convert` | Convert between PEM, DER, PFX formats |

---

### SSL Checking

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/check/domain` | Live SSL check for a domain |
| `POST` | `/api/check/chain` | Validate certificate chain |
| `POST` | `/api/check/ssl-labs` | SSL Labs-style rating |
| `POST` | `/api/check/ocsp` | OCSP revocation check |
| `POST` | `/api/check/crl` | CRL revocation check |

---

### File Upload

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/upload/certificate` | Upload `.pem/.crt/.cer/.pfx/.p12/.der` |
| `POST` | `/api/upload/csr` | Upload CSR file |

---

### DMARC

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/dmarc/generate` | Build a DMARC TXT record |
| `POST` | `/api/dmarc/validate` | Validate a domain's DMARC record via DNS |

---

### SPF

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/spf/generate` | Build an SPF TXT record |
| `POST` | `/api/spf/validate` | Validate a domain's SPF record via DNS |

---

### DKIM

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/dkim/generate` | Generate RSA key pair and DNS record |
| `POST` | `/api/dkim/validate` | Validate record via DNS or inline |

**Generate request:**
```json
{ "domain": "example.com", "selector": "mail", "key_size": 2048 }
```

**Validate via DNS:**
```json
{ "domain": "example.com", "selector": "mail" }
```

**Validate inline:**
```json
{ "record": "v=DKIM1; k=rsa; p=..." }
```

---

### Email Headers

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/email/header/analyze` | Parse headers, extract auth results and hops |

---

### Password

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/security/password/generate` | Generate secure passwords with options |

---

### DNS

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/dns/lookup` | Look up DNS records for a domain |

---

### SSL Config Generator

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/ssl-config/generate` | Generate server TLS config snippet |

```json
{
  "server": "nginx",
  "domain": "example.com",
  "cert_path": "/etc/ssl/certs/server.crt",
  "key_path": "/etc/ssl/private/server.key",
  "chain_path": "/etc/ssl/certs/chain.pem",
  "min_tls": "TLSv1.2",
  "hsts": true,
  "ocsp_stapling": true
}
```

`server` values: `nginx`, `apache`, `haproxy`.

---

### Certificate Monitoring

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/monitor/certificate/add` | Add certificate to monitoring |
| `GET` | `/api/monitor/certificate/list` | List all monitored certificates |
| `GET` | `/api/monitor/certificate/<id>` | Get single monitored certificate |
| `PATCH` | `/api/monitor/certificate/<id>` | Update label / tags |
| `DELETE` | `/api/monitor/certificate/remove/<id>` | Remove from monitoring |
| `GET` | `/api/monitor/expiring?days=30` | List certificates expiring within N days |

---

### Batch Processing

| Method | Endpoint | Limit |
|--------|----------|-------|
| `POST` | `/api/batch/certificates/decode` | 50 certificates |
| `POST` | `/api/batch/domains/check` | 20 domains |
| `POST` | `/api/batch/ocsp/check` | 30 certificates |
| `POST` | `/api/batch/crl/check` | 20 certificates |

---

### Admin — API Keys

All require `Authorization: Bearer <ADMIN_TOKEN>`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/admin/apikey/generate` | Create a new API key |
| `GET` | `/api/admin/apikey/list` | List all keys |
| `POST` | `/api/admin/apikey/validate` | Validate a key |
| `POST` | `/api/admin/apikey/revoke` | Revoke (deactivate) a key |
| `DELETE` | `/api/admin/apikey/delete` | Permanently delete a key |

---

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Returns `{"status": "healthy"}` |

---

## Security

| Measure | Detail |
|---------|--------|
| Input size cap | All PEM/text fields are limited to 64 KB |
| Rate limiting | 200 req/hour, 50 req/min per IP by default |
| API key auth | Pass `X-API-Key` for per-key limits |
| Admin auth | Bearer token required for `/api/admin/*` |
| Non-root containers | Backend and nginx run as unprivileged users |
| Temporary file cleanup | Uploaded files are removed after processing |

To report a security vulnerability, open a GitHub issue with the `security` label. Do not describe active exploits in public comments.

---

## Deployment

### Production checklist

- [ ] `SECRET_KEY` set to a random 32+ character string
- [ ] `ADMIN_TOKEN` set for API key management
- [ ] HTTPS enabled in `nginx/nginx.conf` with real certificates
- [ ] Image versions pinned in `docker-compose.yml`
- [ ] JSON file storage replaced with PostgreSQL (cert monitor, API keys)
- [ ] In-memory rate limiter replaced with Redis (`storage_uri` in `app/__init__.py`)
- [ ] `FLASK_ENV=production`
- [ ] Log aggregation configured
- [ ] Health check (`GET /api/health`) wired into load balancer

### Horizontal scaling

The backend is stateless by design. Replace the in-memory rate limiter and cert monitor with Redis + PostgreSQL, then run multiple backend replicas behind the nginx upstream.

---

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed solutions.

| Symptom | Quick fix |
|---------|-----------|
| Default nginx page | `./rebuild-frontend.sh` |
| Backend won't start | `docker compose build backend --no-cache && docker compose up -d` |
| View all logs | `docker compose logs -f` |

---

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the planned feature roadmap with phases, priorities, and rationale.

---

## Contributing

See [docs/WIKI.md](docs/WIKI.md) for the full developer wiki, including architecture details and a step-by-step guide to adding a new tool.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes and add/update tests
4. Run backend tests: `cd backend && pytest`
5. Run frontend tests: `cd frontend && npm test`
6. Open a pull request

---

## License

MIT — see [LICENSE](LICENSE) for details.
