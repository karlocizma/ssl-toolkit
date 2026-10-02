# Security Policy

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private reporting instead:

1. Go to the [Security tab](https://github.com/karlocizma/ssl-toolkit/security) of this repository.
2. Choose **Report a vulnerability** and describe the problem, how to reproduce it and the impact.

You can expect an acknowledgement within a few days and a fix or mitigation plan as soon as the issue is understood. Please give us reasonable time to release a fix before disclosing publicly; we will credit you in the release notes unless you prefer otherwise.

## Supported versions

This project is under active development. Security fixes are made on the `main` branch and the most recent release; older releases are not patched.

## What this tool does, and the security model

SSL Toolkit connects to hosts you choose and handles certificates and keys, so a few design points matter when you deploy it:

- **Outbound connections are restricted.** Every check that connects to a user-supplied host or URL goes through an SSRF guard that refuses private, loopback and link-local addresses. `ALLOW_PRIVATE_TARGETS=true` disables that; only enable it on a trusted internal deployment.
- **No private keys or certificates are stored.** The private CA and the ACME client are stateless and return keys to the caller. API keys are stored as SHA-256 hashes.
- **The monitor requires authentication** by default (`ADMIN_TOKEN` or an API key); `MONITOR_PUBLIC=true` opts out. Set a strong random `ADMIN_TOKEN` and `SECRET_KEY` in production.
- **Put it behind HTTPS.** The bundled nginx config terminates plain HTTP; use a TLS-terminating reverse proxy (see the deployment section of the README) and restrict who can reach the admin endpoints.
- **CORS is off by default**; list trusted origins in `CORS_ORIGINS` only if you host the frontend elsewhere.

In scope: the application code in this repository, the Docker images and the default configuration. Out of scope: vulnerabilities in third-party services it queries (crt.sh, DNS blocklists, ACME CAs) and findings that require an already-compromised host or `ADMIN_TOKEN`.
