# Roadmap

This document tracks the development direction of the Security & Network Toolkit. Items are grouped into phases. Completed phases are listed for historical context. Priorities within a phase can shift based on user feedback.

---

## Completed Phases

### Phase 1 — Foundation
Core SSL/TLS tools: certificate decode, CSR generator/decoder, SSL domain checker, certificate converter, key generator/validator, key–certificate match, certificate chain checker.

### Phase 2 — Email Security
DMARC generator/validator, SPF generator/validator, email header analyzer.

### Phase 3 — Advanced SSL Features
OCSP revocation checking, CRL revocation checking, certificate monitoring (add/list/remove/expiring), batch certificate and domain processing.

### Phase 4 — Platform & Security
API key management (generate/list/revoke/delete), per-key rate limiting, i18n (English + German), dark/light mode, admin token protection.

### Phase 5 — Cryptographic Utilities
DKIM key pair generator and record validator, self-signed certificate generator (RSA/EC + SANs), SSL/TLS server config generator (Nginx/Apache/HAProxy), JWT decoder (client-side).

---

## Phase 6 — Persistence & Notifications
*Target: next major iteration*

### 6.1 Database Backend
Replace JSON file storage with a proper relational database.

- Migrate certificate monitoring from `/tmp/*.json` to PostgreSQL
- Migrate API keys from `/tmp/*.json` to PostgreSQL with field-level encryption for key values
- Add a `docker-compose.override.yml` with a `postgres` service for local dev
- Add Alembic migrations

**Why:** JSON file storage is not safe for concurrent writes and is lost on container restarts.

### 6.2 Email / Webhook Alerts
Notify operators when monitored certificates are about to expire.

- Configurable expiry thresholds (e.g., 30, 14, 7 days)
- SMTP email alerts
- Generic webhook (POST JSON payload to a user-configured URL — compatible with Slack incoming webhooks, Teams, PagerDuty, etc.)
- Alert delivery log in the UI

**Why:** Monitoring is only useful if someone is notified. Without alerts, the monitor is a dashboard that must be manually checked.

### 6.3 Scheduled Domain Checks
Automatically re-check monitored domains on a schedule without user interaction.

- Configurable check interval (daily by default)
- Results stored in the database with history
- Drift detection: alert when a certificate changes unexpectedly

---

## Phase 7 — Certificate Lifecycle
*Planned*

### 7.1 Let's Encrypt Integration
Issue and renew certificates from Let's Encrypt via ACME.

- HTTP-01 and DNS-01 challenge support
- Automatic renewal before expiry
- Domain ownership verification UI

**Why:** The most common certificate issuance path; closes the gap between "generating a CSR" and "having a valid cert."

### 7.2 Certificate Templates
Pre-filled subject/SAN configurations for common use cases (web server, internal CA, code signing).

- Saveable and shareable template library
- Quick-fill into the CSR generator

### 7.3 Internal CA Management
A lightweight Certificate Authority for internal/development use.

- Generate a root CA certificate
- Issue leaf certificates signed by that root CA
- Download CA bundle for trust store import
- CRL endpoint for issued certificates

**Why:** Development and internal tooling often needs a trusted internal CA. Self-signed certs solve part of this; a proper CA UI solves it completely.

---

## Phase 8 — Developer Experience
*Planned*

### 8.1 REST API Authentication
Replace the simple `ADMIN_TOKEN` bearer with a proper user-facing auth system.

- User accounts with hashed passwords (bcrypt)
- JWT-based session tokens
- Scoped API keys (read-only vs. admin vs. certificate-management)
- Audit log: who did what, when

### 8.2 OpenAPI / Swagger UI
Auto-generate interactive API documentation from Flask route definitions.

- Swagger UI served at `/api/docs`
- OpenAPI 3.0 spec downloadable as JSON/YAML
- Request/response examples for every endpoint

### 8.3 SDKs and CLI
- Python SDK (thin wrapper around the API)
- Shell CLI (`ssl-toolkit check domain example.com`)
- GitHub Action for CI certificate validation

---

## Phase 9 — Monitoring & Observability
*Planned*

### 9.1 Prometheus Metrics
Expose a `/metrics` endpoint for Prometheus scraping.

- Request count and latency per endpoint
- Certificate monitor stats (total tracked, expiring soon, expired)
- Rate limiter hit count per key / IP

### 9.2 Grafana Dashboard
Pre-built dashboard JSON for the Prometheus metrics above.

### 9.3 Structured Logging
Switch backend logging from plaintext to structured JSON (compatible with ELK, Loki, Datadog).

---

## Phase 10 — Advanced Cryptographic Tools
*Exploratory — evaluated based on demand*

| Feature | Description |
|---------|-------------|
| PGP / GPG key management | Generate and inspect PGP public/private key pairs |
| SSH key generator | Generate ed25519 and RSA SSH key pairs; output public key in `authorized_keys` format |
| S/MIME certificate generator | Self-signed S/MIME certs for email signing |
| PKCS11 / HSM info viewer | Inspect slots and certificates stored on a hardware security token |
| Certificate Transparency log search | Look up domains in public CT logs |
| DANE / TLSA record generator | Build TLSA DNS records for DNS-based Authentication of Named Entities |
| PDF / CSV export | Export certificate inventory and expiry reports |

---

## Deferred / Won't Fix (for now)

| Item | Reason |
|------|--------|
| Native mobile app | The web app is already responsive; a native app does not add enough value to justify the maintenance burden |
| Kubernetes manifests | Out of scope until a concrete production deployment use case arises |
| Real SSL Labs API dependency | The SSL Labs public API has strict rate limits and requires registration; the current implementation provides equivalent data without the external dependency |

---

## How to propose a feature

Open a GitHub issue with the `enhancement` label and include:

1. What problem it solves
2. Who it is for (developer, sysadmin, security team, etc.)
3. Whether you would be willing to contribute it

Features with clear use cases and willing contributors move up the queue.
