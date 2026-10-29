# ACME flag and CAA & DANE tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the ACME module unavailable unless `ENABLE_ACME` is set, and add a CAA & DANE tool that needs only outbound DNS/TLS.

**Architecture:** An env-only flag gates `/api/acme/*` in a `before_request` and is exposed to the UI through `GET /api/features`. The new tool is a backend service (`caa_dane.py`) with four POST routes and one React page with three tabs, wired like the existing MTA-STS tool.

**Tech Stack:** Flask, dnspython 2.8, cryptography 41, pytest; React, MUI, i18next, Jest.

**Spec:** `docs/superpowers/specs/2026-10-29-acme-flag-and-caa-dane-design.md`

## Global Constraints

- `ENABLE_ACME` default `false`; truthy values `1/true/yes/on` (case-insensitive); env-only, never in `settings_store`.
- Disabled ACME answers HTTP 404 with `{"error": "ACME is disabled on this server (set ENABLE_ACME=true to enable it)"}`.
- No new runtime dependencies. Success shape `{"success": true, "result": ...}`; bad input is 400.
- New tool route `/caa-dane`, nav key `nav.caaDane`, in the SSL/TLS group; English and German strings.
- Two commits at least: flag first, tool second. Commit messages end with the Co-Authored-By line from the session.

## Review Focus

- Domain with trailing dot / uppercase / IDN-looking input to `/caa/check` is normalised or rejected with 400.
- CAA lookup that hits SERVFAIL or a timeout reports an error, never "no CAA".
- Generator input containing quotes, spaces or `;` in a CA name is rejected.
- Pasting a certificate chain or garbage into the TLSA generator gives a clear 400, not a 500.
- Frontend `/features` request failing leaves ACME hidden and the rest of the app working.

---

### Task 1: ACME flag (backend)

**Files:**
- Modify: `backend/app/utils/env.py` (add `ENABLE_ACME` to `SETTINGS`), `backend/app/routes/ssl_routes.py` (gate + `/features`), `backend/app/openapi.py`, `docker-compose.yml`, `.env.example`, `backend/tests/conftest.py`
- Test: `backend/tests/test_acme_flag.py`

**Interfaces:**
- Produces: `acme_enabled() -> bool` in `backend/app/utils/features.py`; `GET /api/features` -> `{"acme": bool}`.

- [ ] **Step 1:** Write `test_acme_flag.py`: `test_acme_off_by_default` (POST `/api/acme/order` -> 404 with the exact message), `test_acme_on_reaches_service` (monkeypatch env `ENABLE_ACME=true`, request is not 404), `test_features_reflects_flag`, `test_env_comment_tolerated` (`ENABLE_ACME=false  # x` sanitises to `false`), `test_truthy_values` (`1,true,YES,On` on; `0,false,,no` off).
- [ ] **Step 2:** Run `cd backend && python -m pytest tests/test_acme_flag.py -q`; expect FAIL.
- [ ] **Step 3:** Implement `acme_enabled()` reading `os.environ` at call time; add `@ssl_bp.before_request` returning the 404 for paths starting with `/api/acme/`; add `/features`; omit `/acme/*` from `openapi.py` when disabled; add compose/env entries.
- [ ] **Step 4:** In `conftest.py` add an autouse fixture setting `ENABLE_ACME=true` for `test_acme.py` and `test_acme_extras.py` only; run `python -m pytest -q` for the whole backend; expect all pass.
- [ ] **Step 5:** Commit `feat: make ACME opt-in via ENABLE_ACME (off by default)`.

### Task 2: ACME flag (frontend)

**Files:**
- Create: `frontend/src/contexts/FeaturesContext.js`
- Modify: `frontend/src/services/api.js` (`featuresAPI.get`), `frontend/src/index.js` or `App.js` (provider), `components/Layout.js`, `components/ToolSearch.js` usage, `components/Dashboard.js`, `App.js` (route)
- Test: `frontend/src/components/Layout.test.js`, `Dashboard` test if present

**Interfaces:**
- Produces: `useFeatures() -> { acme: boolean }` (false while loading or on error).

- [ ] **Step 1:** Add tests: with features `{acme:false}` the sidebar, search items and dashboard have no ACME entry; with `{acme:true}` they do; a rejected request leaves ACME hidden.
- [ ] **Step 2:** Run `cd frontend && CI=true npx react-scripts test --watchAll=false`; expect the new tests FAIL.
- [ ] **Step 3:** Implement the context (fetch once on mount), filter the `/acme` item out of `menuGroups`/`searchItems`/dashboard tiles when `acme` is false, and render the `/acme` route only when true.
- [ ] **Step 4:** Rerun the full frontend tests; expect pass.
- [ ] **Step 5:** Commit `feat: hide ACME in the UI unless the server enables it`.

### Task 3: CAA check and generate (service)

**Files:**
- Create: `backend/app/services/caa_dane.py`
- Test: `backend/tests/test_caa_dane.py`

**Interfaces:**
- Produces: `check_caa(domain: str) -> dict` with keys `domain`, `policy_name`, `records` (list of `{flags, critical, tag, value, params}`), `issuers` / `wildcard_issuers` (lists of `{ca, name}`), `any_ca_may_issue: bool`, `findings` (list of `{severity, message}`); `generate_caa(domain, issuers, wildcard_issuers=None, allow_wildcards=True, block_all=False, iodef=None, dns01_only=False) -> dict` with `records` (list of zone-file lines) and `summary`.
- Consumes: `valid_domain`, `_resolver` from `app.services.deliverability`.

- [ ] **Step 1:** Write tests with a monkeypatched resolver: climbing to the parent, `issuewild` precedence, `;` blocks all, unknown critical tag finding, bad `iodef` finding, SERVFAIL raises/returns error finding (not "no CAA"), generator rejects `bad"name`, `a b`, `x;y`, empty issuers without `block_all`, outputs `0 issue "letsencrypt.org; validationmethods=dns-01"` for `dns01_only`.
- [ ] **Step 2:** Run `python -m pytest tests/test_caa_dane.py -q`; expect FAIL.
- [ ] **Step 3:** Implement both functions plus the `KNOWN_CAS` map. Stop climbing before a single-label name.
- [ ] **Step 4:** Run the file; expect pass.
- [ ] **Step 5:** Commit together with Task 4 and 5.

### Task 4: TLSA generate and check (service)

**Files:** Modify `backend/app/services/caa_dane.py`; Test `backend/tests/test_caa_dane.py`

**Interfaces:**
- Produces: `generate_tlsa(certificate_pem: str, host: str, port: int = 443, protocol: str = 'tcp', usage: int = 3, selector: int = 1, matching_type: int = 1) -> dict` with `name`, `rdata`, `record`, `notes`; `check_tlsa(host: str, port: int = 443, protocol: str = 'tcp') -> dict` with `name`, `records`, `dnssec_ad: bool`, `matches` per record, `findings`.

- [ ] **Step 1:** Tests: build a cert with `cryptography` in the test, compare all 12 usage/selector/matching combos' hex against values computed independently with `hashlib`; chain input uses the first cert and adds a note; garbage PEM raises `ValueError`; `check_tlsa` with mocked DNS and mocked connection covers match, mismatch, no TLSA record, and AD flag unset warning.
- [ ] **Step 2:** Run; expect FAIL.
- [ ] **Step 3:** Implement with `cryptography` (SPKI via `public_bytes(DER, SubjectPublicKeyInfo)`); connect via `net_safety.safe_create_connection`; usage 0/2 reported "cannot be verified from the leaf alone" unless chain retrieval from `ssl_checker.py` is reusable.
- [ ] **Step 4:** Run; expect pass.

### Task 5: Routes and OpenAPI

**Files:** Modify `backend/app/routes/ssl_routes.py`, `backend/app/openapi.py`; Test `backend/tests/test_caa_dane.py` (route tests) and `test_openapi.py`

**Interfaces:** `POST /api/caa/check`, `/caa/generate`, `/dane/generate`, `/dane/check` as in the spec; certificate field passes `_check_input_size`.

- [ ] **Step 1:** Route tests: 200 shape, 400 on `ValueError`, 400 on missing domain.
- [ ] **Step 2:** Run; expect FAIL.
- [ ] **Step 3:** Add a helper like `_transport` and the four routes; document them in `openapi.py`.
- [ ] **Step 4:** Run the whole backend suite; expect pass.
- [ ] **Step 5:** Commit `feat: add CAA & DANE service and API`.

### Task 6: CAA & DANE page

**Files:**
- Create: `frontend/src/components/CaaDane.js`, `frontend/src/components/CaaDane.test.js`
- Modify: `services/api.js` (`caaDaneAPI`), `App.js`, `Layout.js`, `Dashboard.js`, `ToolSearch.js`, `locales/en/translation.json`, `locales/de/translation.json`

- [ ] **Step 1:** Tests: page renders three tabs; checking a domain shows issuers and findings from a mocked API; generator shows records; TLSA tab shows rdata; sidebar and search include the tool.
- [ ] **Step 2:** Run; expect FAIL.
- [ ] **Step 3:** Implement following `MailTransport.js` layout; add nav, dashboard tile (four feature lines), search keywords `caa dane tlsa dns certification authority authorization issuance`, EN and DE strings.
- [ ] **Step 4:** Run the full frontend tests and `npx eslint src`; expect pass.
- [ ] **Step 5:** Commit `feat: add CAA & DANE tool page`.

### Task 7: Docs and deploy check

**Files:** `README.md`, `SECURITY.md`, `docs/WIKI.md`, `CHANGELOG.md`

- [ ] **Step 1:** Document `ENABLE_ACME` (off by default, behaviour change) and the new tool.
- [ ] **Step 2:** `docker compose up -d --build backend frontend`, `podman restart ssl-toolkit-nginx`, then check `/api/features` returns `{"acme":false}`, `/api/acme/order` is 404, `/api/caa/check` works for a real domain.
- [ ] **Step 3:** Commit `docs: document ENABLE_ACME and the CAA & DANE tool`.
