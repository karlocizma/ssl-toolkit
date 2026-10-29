# ACME off-by-default flag and a new CAA & DANE tool

Date: 2026-10-29

## Intent

The owner runs SSL Toolkit privately. It is not exposed publicly and no inbound ports can be opened, so ACME
HTTP-01 validation can never succeed, and the owner has security concerns about the Let's Encrypt (ACME)
module (it handles CA account keys and, for `/acme/issue`, DNS-provider credentials). Two changes:

1. Make the ACME module unavailable by default, behind a single flag, without deleting the code.
2. Add a replacement tool that is useful in a private, outbound-only deployment: **CAA & DANE**.

## Goals

- `ENABLE_ACME` (default `false`) switches the whole ACME module on or off.
- With the flag off, there is no ACME endpoint, page, navigation entry, search hit or dashboard tile.
- A new "CAA & DANE" tool that needs only outbound DNS lookups and outbound TLS connections: no inbound ports,
  no accounts, no stored credentials, no state kept on the server.

## Non-goals

- Deleting the ACME code or its tests (they keep running in CI; Pebble integration tests are untouched).
- Any ACME or certificate issuance in the new tool.
- Writing DNS records, DNS-provider integrations, or any credentials handling.
- Local DNSSEC validation; zone-file import; monitoring or alerting on CAA/TLSA changes (possible later).

## Anti-goals

- The flag must not be switchable from the web UI (see decisions): a UI session must not be able to turn ACME on.
- The CAA generator must not let someone accidentally publish a policy that forbids all issuance. "Nobody may
  issue" must be an explicit choice.
- No new runtime dependencies if avoidable (`dnspython` and `cryptography` are already present).

## Part 1: ACME flag

Decisions (the builder's calls are marked "builder's call"):

- **Env-only flag**, `ENABLE_ACME`, default false, accepted values `1/true/yes/on` (case-insensitive).
  It is deliberately *not* added to `settings_store` (which is editable from the Settings page).
  Add it to the `SETTINGS` tuple in `backend/app/utils/env.py` so inline `.env` comments are tolerated.
  Pass it through `docker-compose.yml` as `ENABLE_ACME=${ENABLE_ACME:-false}`; document it in `.env.example`.
- **Backend gate:** a `before_request` on `ssl_bp` that answers every path under `/api/acme/` with
  HTTP 404 and `{"error": "ACME is disabled on this server (set ENABLE_ACME=true to enable it)"}`.
  Read the flag at request time so tests can toggle it.
- **Feature discovery:** new `GET /api/features` returning `{"acme": <bool>}` (no secrets, no auth beyond what
  other GET routes have). The frontend fetches it once at startup and keeps it in a small context/hook.
  While loading or if the request fails, treat ACME as disabled (no flash of a link that then 404s).
- **Frontend with flag off:** hide the `/acme` entry from the sidebar, the tool search (`ToolSearch.js`) and the
  dashboard (`Dashboard.js`), and do not register the `/acme` route (a direct visit shows the existing
  not-found page). Builder's call: leave the `ACME_DNS_RESOLVERS` setting in Settings; it is harmless.
- **OpenAPI:** omit the `/acme/*` paths when the flag is off (builder's call; follow how `openapi.py` is built).
- **Tests:** existing ACME tests must run with the flag on (set it in a fixture or `conftest.py`). Add tests for:
  endpoints return 404 when off, work when on, `/features` reflects the flag, default is off, `env.py` handles
  `ENABLE_ACME=false  # comment`. Frontend: sidebar/search/dashboard omit ACME when the feature is off.
- **Docs:** README, SECURITY.md, docs/WIKI.md and CHANGELOG mention the flag and that ACME is off by default
  (this is a behaviour change for anyone who used it: call it out in the changelog).

## Part 2: CAA & DANE tool

One page, `/caa-dane`, in the sidebar's SSL/TLS group, with three tabs. Backend service
`backend/app/services/caa_dane.py`, following the pattern of `mail_transport.py` (findings with severity, plain
`ValueError` for bad input, reuse `valid_domain` and the shared DNS resolver from `deliverability.py`).

### Tab 1: Check CAA

Input: domain. Behaviour (RFC 8659):

- Look up CAA at the name; if there is no CAA RRset, climb to the parent, and so on. Stop before querying a bare
  single-label name (no public-suffix list; builder's call). Report which name the effective policy came from.
- Parse each record: critical flag, tag, value. Understand `issue`, `issuewild`, `iodef`; parse parameters such
  as `accounturi` and `validationmethods` (RFC 8657) and show them.
- Compute the effective policy: who may issue normal certificates (`issue`; none present means any CA may
  issue), who may issue wildcards (`issuewild` if present, else `issue`), and treat `;` or an empty value as
  "nobody".
- Show friendly names for well-known CAs by CAA domain (small built-in map: letsencrypt.org, digicert.com,
  sectigo.com, comodoca.com, globalsign.com, pki.goog, amazon.com and amazontrust.com, ssl.com, buypass.com,
  certum.pl, and similar); unknown values are shown as-is.
- Findings: no CAA at all (any CA can issue), unknown tag marked critical (CAs must refuse), `iodef` that is not
  a `mailto:` or `https://` URL, wildcard policy looser or stricter than the normal policy, `issue ";"` (issuance
  blocked), conflicting duplicate records, and DNS failure (SERVFAIL/timeout) reported as an error, not as
  "no CAA".

### Tab 2: Generate CAA

Input: list of allowed CA domains (with a picker of the well-known ones plus free entry), optional separate list
for wildcards, a toggle "no wildcards", an explicit "block all issuance" toggle, optional `iodef` (mailto or https),
optional "restrict to DNS-01 validation" (`validationmethods=dns-01`, relevant because this deployment cannot do
HTTP-01), optional domain name for the record owner. Output: zone-file lines and a plain-language summary.
Validation: CA values must be valid host names (no quotes, spaces, or semicolons injected); an empty issuer list
without "block all issuance" is a 400 error. `accounturi` per CA is out of scope for v1.

### Tab 3: TLSA (DANE)

- **Generate:** input is a PEM certificate (first certificate used; say so if more are pasted), host, port,
  protocol (default `tcp`), usage (0-3, default 3), selector (0 full certificate / 1 public key, default 1),
  matching type (0 raw / 1 SHA-256 / 2 SHA-512, default 1). Output: record name (`_443._tcp.host`), the
  `usage selector matching hex` rdata, and a zone-file line, computed with `cryptography`.
- **Check:** input is host, port (default 443), protocol. Look up the TLSA RRset, open a live TLS connection
  through `net_safety.safe_create_connection` (so `ALLOW_PRIVATE_TARGETS` rules apply), and compare every TLSA record
  with the presented certificate. Usage 3/1 need the leaf only. For usage 0/2 the certificate chain is needed:
  reuse the chain retrieval already in `ssl_checker.py` if it fits; otherwise report those records as "cannot be
  verified from the leaf alone" rather than failing (builder's call).
- DANE is meaningless without DNSSEC: query with DNSSEC requested and report whether the resolver set the AD
  flag, labelled as "reported by the resolver, not validated locally"; warn if it is not set.

### API

All JSON, success shape `{"success": true, "result": ...}`, errors `{"error": ...}` with 400 for bad input,
generic 500 helper for unexpected failures (same as the other tool routes):

- `POST /api/caa/check` `{domain}`
- `POST /api/caa/generate` `{...}`
- `POST /api/dane/generate` `{certificate, host, port, protocol, usage, selector, matching_type}`
- `POST /api/dane/check` `{host, port, protocol}`

Apply `_check_input_size` to the certificate field. Add the routes to `openapi.py` (and whatever the existing
OpenAPI test enforces), and to rate limiting like the other routes.

### Frontend

- `frontend/src/components/CaaDane.js`, route `/caa-dane`, `caaDaneAPI` in `services/api.js`.
- Sidebar entry in the SSL/TLS group (`nav.caaDane`), `Dashboard.js` tile with four feature lines,
  `ToolSearch.js` keywords (`caa dane tlsa dns certification authority authorization issuance`).
- English and German strings in `src/locales/en/` and `src/locales/de/`. Follow the surrounding components for
  layout, result display and error handling.

### Tests

- Backend: unit tests with a mocked resolver and mocked TLS connection (see `test_mail_transport.py`): climbing
  to the parent, effective-policy cases (no issue, `;`, issuewild precedence, critical unknown tag, bad iodef),
  generator validation (injection attempts, empty list, block-all), TLSA hash values against a known certificate
  for every usage/selector/matching combination, and check results for match, mismatch and no TLSA record.
- Frontend: render test for the page, one interaction test per tab, and the sidebar/search/dashboard entries.

## Left to the builder

Exact response field names, the findings wording, German translations, the CA picker contents beyond the list
above, layout details, and the choice between a service-wide or per-function test fixture.

## Delivery

Two separate commits (flag, then CAA & DANE) so the flag can be reviewed and reverted on its own.
Rebuild with `docker compose up -d --build frontend backend`, then restart `ssl-toolkit-nginx` (nginx caches the
upstream container IPs).
