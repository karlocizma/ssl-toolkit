# Security & Network Toolkit — Developer Wiki

This document is the technical reference for contributors and operators. For user-facing docs see [README.md](../README.md). For planned work see [ROADMAP.md](../ROADMAP.md).

---

## Contents

1. [Project structure](#1-project-structure)
2. [Backend architecture](#2-backend-architecture)
3. [Frontend architecture](#3-frontend-architecture)
4. [Docker setup](#4-docker-setup)
5. [Adding a new tool (end-to-end guide)](#5-adding-a-new-tool-end-to-end-guide)
6. [Rate limiting](#6-rate-limiting)
7. [API key management](#7-api-key-management)
8. [i18n and translations](#8-i18n-and-translations)
9. [Testing](#9-testing)
10. [Security design decisions](#10-security-design-decisions)
11. [Storage](#11-storage)
12. [Known limitations](#12-known-limitations)

---

## 1. Project structure

```
ssl-toolkit/
├── backend/
│   ├── app/
│   │   ├── __init__.py            # Flask app factory, rate limiter
│   │   ├── routes/
│   │   │   └── ssl_routes.py      # All 44 route handlers, one blueprint
│   │   ├── services/
│   │   │   ├── ssl_checker.py     # Live domain SSL, OCSP, CRL, chain
│   │   │   ├── sysadmin_tools.py  # DMARC, SPF, DKIM, DNS, passwords, SSL config
│   │   │   ├── cert_monitor.py    # In-memory certificate expiry monitor
│   │   │   ├── batch_processor.py # Parallel batch operations
│   │   │   └── api_key_manager.py # API key CRUD and validation
│   │   └── utils/
│   │       └── ssl_utils.py       # Core crypto: cert/CSR/key/self-signed generation
│   ├── main.py                    # Gunicorn entrypoint (create_app())
│   ├── app.py                     # Local dev entrypoint
│   ├── requirements.txt
│   ├── Dockerfile
│   └── pytest.ini
│
├── frontend/
│   ├── src/
│   │   ├── App.js                 # Router and theme provider
│   │   ├── components/            # One .js file per tool page
│   │   ├── contexts/
│   │   │   └── ColorModeContext.js
│   │   ├── services/
│   │   │   └── api.js             # Axios client, all named exports
│   │   ├── locales/
│   │   │   ├── en/translation.json
│   │   │   └── de/translation.json
│   │   └── i18n.js                # i18next setup
│   ├── package.json
│   └── Dockerfile
│
├── nginx/
│   └── nginx.conf
│
├── docker-compose.yml
├── README.md
├── ROADMAP.md
├── CHANGELOG.md
├── TROUBLESHOOTING.md
└── docs/
    └── WIKI.md                    # This file
```

---

## 2. Backend architecture

### App factory

`backend/app/__init__.py` exports `create_app()`. It:

1. Creates the Flask app
2. Configures Flask-CORS
3. Initialises Flask-Limiter with the `get_api_key_or_ip` key function
4. Registers the `ssl_bp` blueprint at the `/api` prefix

The blueprint is the single source of all routes. There is intentionally one blueprint — splitting routes across multiple blueprints would not provide meaningful organisation benefits at the current scale.

### Route conventions

Every route in `ssl_routes.py` follows this pattern:

```python
@ssl_bp.route('/thing/action', methods=['POST'])
def thing_action():
    try:
        data = request.get_json() or {}
        _check_input_size(data, 'field_with_large_text')   # 64 KB cap
        result = service_function(data)
        return jsonify({'success': True, 'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500
```

`ValueError` is for expected user errors (bad input). Generic `Exception` covers unexpected failures. Never swallow errors silently.

### Service layer

Business logic lives in `services/` or `utils/`. Routes call services; services never import routes. The split:

- `ssl_utils.py` — cryptographic primitives (parse, generate, convert). Pure functions, no I/O.
- `services/` — anything involving I/O: network calls, file reads, thread pools.

### Input size guard

```python
_MAX_TEXT_BYTES = 65_536  # 64 KB
```

`_check_input_size(data, *keys)` is called before any route that accepts PEM, key, or raw text. Raises `ValueError` if any field exceeds 64 KB. This prevents memory exhaustion from maliciously large inputs.

---

## 3. Frontend architecture

### Component pattern

Every tool page is a single file in `src/components/`. Each component uses this state shape:

```js
const [form, setForm] = useState({ /* form fields */ });
const [result, setResult] = useState(null);
const [error, setError] = useState('');
const [loading, setLoading] = useState(false);
```

API calls always follow this template:

```js
setLoading(true);
setError('');
setResult(null);
try {
  const response = await someAPI.doThing(form);
  setResult(response.data.result);
} catch (err) {
  setError(err.response?.data?.error || 'Something went wrong');
} finally {
  setLoading(false);
}
```

### API client (`src/services/api.js`)

Named exports grouped by domain:

| Export | Routes |
|--------|--------|
| `certificateAPI` | `/certificate/*` |
| `csrAPI` | `/csr/*` |
| `keyAPI` | `/key/*` |
| `conversionAPI` | `/convert` |
| `sslCheckAPI` | `/check/*` |
| `sysAdminAPI` | `/dmarc/*`, `/spf/*`, `/dkim/*`, `/email/*`, `/security/*`, `/dns/*`, `/ssl-config/*` |
| `healthAPI` | `/health` |

When adding a new endpoint, add its method to the appropriate existing group. Add a new group only if the feature is genuinely unrelated to any existing group.

### Routing (`App.js`)

React Router v6. Each tool gets exactly one `<Route>`. Import the component and add the route — there is no lazy loading yet, so keep components reasonably sized (under ~400 lines).

### Navigation (`Layout.js`)

`menuGroups` is a static array. Add a new item to the correct group:

```js
{ textKey: 'nav.myTool', icon: <SomeIcon />, path: '/my-tool' }
```

Import the MUI icon at the top of the file. Add the `textKey` value to both translation files.

### Theming

Dark/light mode is toggled via `ColorModeContext`. The selected mode persists in `localStorage` under `colorMode`. Components use `useTheme()` or Material-UI's built-in theme awareness — do not hardcode colours.

---

## 4. Docker setup

### Container overview

```
docker-compose.yml
  backend  → backend/Dockerfile   → python:3.11-slim → gunicorn main:app
  frontend → frontend/Dockerfile  → node:18-alpine (build stage)
                                  → nginx:alpine (serve stage)
  nginx    → nginx:alpine         → nginx/nginx.conf
```

### Frontend two-stage build

1. **Build stage (Node):** `npm run build` → `/app/build`
2. **Serve stage (nginx):** Copy `/app/build` to `/usr/share/nginx/html`

If Docker caches stage 1 incorrectly, nginx serves stale or empty HTML. Run `./rebuild-frontend.sh` (wraps `docker compose build frontend --no-cache`) to force a clean rebuild.

### Nginx proxy rules

`nginx/nginx.conf` routes:
- `/api/` → upstream `backend:5000`
- Everything else → static files in `/usr/share/nginx/html`

The HTTPS server block is present but fully commented out. To enable HTTPS, uncomment it and mount certs at the paths referenced in the config.

---

## 5. Adding a new tool (end-to-end guide)

This is the canonical process used in every phase. Follow it to keep the codebase consistent.

### Step 1 — Backend service function

Add a function to the appropriate file:

- Pure crypto or cert manipulation → `backend/app/utils/ssl_utils.py`
- Network I/O, DNS, external APIs → `backend/app/services/sysadmin_tools.py` (or a new service file)
- Live domain SSL → `backend/app/services/ssl_checker.py`

```python
def my_tool(params: dict) -> dict:
    params = params or {}
    value = params.get('required_field', '').strip()
    if not value:
        raise ValueError('required_field is required')
    # do the work
    return {'success': True, 'output': ...}
```

### Step 2 — Backend route

Add to `backend/app/routes/ssl_routes.py`. Update the import block at the top of the file.

```python
@ssl_bp.route('/my-tool/action', methods=['POST'])
def my_tool_action():
    try:
        data = request.get_json() or {}
        _check_input_size(data, 'large_text_field')
        result = my_tool(data)
        return jsonify({'success': True, 'result': result})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Unexpected error: {str(e)}'}), 500
```

### Step 3 — Frontend API method

Add to the appropriate group in `frontend/src/services/api.js`:

```js
myAction: (data) => api.post('/my-tool/action', data),
```

### Step 4 — Frontend component

Create `frontend/src/components/MyTool.js`. Follow the state pattern from section 3. Keep side-effects inside the click handler, not in `useEffect`.

### Step 5 — Navigation

In `frontend/src/components/Layout.js`:
1. Import the MUI icon at the top
2. Add the item to the correct `menuGroups` entry

### Step 6 — Translation keys

`frontend/src/locales/en/translation.json`:
```json
"nav": {
  "myTool": "My Tool"
}
```

`frontend/src/locales/de/translation.json`:
```json
"nav": {
  "myTool": "Mein Werkzeug"
}
```

### Step 7 — App routing

`frontend/src/App.js`:
```js
import MyTool from './components/MyTool';
// ...
<Route path="/my-tool" element={<MyTool />} />
```

### Step 8 — Tests

Backend: add a pytest file in `backend/tests/`.  
Frontend: add a Jest test alongside the component (`MyTool.test.js`).

---

## 6. Rate limiting

Flask-Limiter is configured in `backend/app/__init__.py`. The key function:

```python
def get_api_key_or_ip():
    api_key = request.headers.get('X-API-Key')
    if api_key:
        return f'key:{api_key}'
    return get_remote_address()
```

Default limits: `200 per hour` and `50 per minute` (applied globally).

**Production note:** `storage_uri="memory://"` means limits are per-process and reset on restart. For production or multi-replica deployments, set `storage_uri="redis://redis:6379"`.

Per-route overrides use the `rate_limit` helper decorator defined in `ssl_routes.py`.

---

## 7. API key management

API keys are stored as JSON in `/tmp/ssl-toolkit/api_keys.json` inside the backend container.

Each entry:
```json
{
  "name": "CI pipeline",
  "api_key": "sslkit_<32-char-urlsafe-token>",
  "rate_limit": "500 per hour",
  "created_at": "2026-01-01T00:00:00",
  "last_used": null,
  "usage_count": 0,
  "active": true
}
```

Keys are generated with `secrets.token_urlsafe(32)` prefixed with `sslkit_`.

All `/api/admin/apikey/*` endpoints require `Authorization: Bearer <ADMIN_TOKEN>`. If `ADMIN_TOKEN` is not set, these routes return 403.

**Production note:** Move key storage to PostgreSQL and encrypt the `api_key` column at rest.

---

## 8. i18n and translations

i18next is configured in `frontend/src/i18n.js`. Language choice persists in `localStorage`.

Translation files:
- `frontend/src/locales/en/translation.json` — English (default)
- `frontend/src/locales/de/translation.json` — German

### Adding a new language

1. Create `frontend/src/locales/<lang>/translation.json` with the same key structure as the English file
2. In `i18n.js`, add the language to the `resources` object
3. Add a `<MenuItem>` for the language in `Layout.js`'s language switcher menu

### Key conventions

Keys follow the JSON nesting with dot notation in code:
- `t('nav.myTool')` → `{ "nav": { "myTool": "My Tool" } }`
- `t('common.loading')` → `{ "common": { "loading": "Loading..." } }`

---

## 9. Testing

### Backend

```bash
cd backend && pytest
```

Configuration: `backend/pytest.ini`. Tests: `backend/tests/`.

Conventions:
- Use `pytest.mark.parametrize` for data-driven tests
- Do not mock the `cryptography` library — it is fast enough to use directly
- Test service functions directly, not through HTTP

### Frontend

```bash
cd frontend && npm test
```

Uses Jest and React Testing Library. Test files live alongside components (`ComponentName.test.js`) or in `frontend/src/` for utility tests.

### Smoke tests

```bash
./test_api.sh
```

Runs `curl` commands against a running stack. Good for a quick sanity check after rebuilding containers.

---

## 10. Security design decisions

### Why 64 KB input cap?

The largest legitimate input is a PFX file containing a full chain — rarely more than a few KB in practice. 64 KB provides a generous buffer while preventing multi-MB payloads from occupying memory in the parsing layer.

### Why no persistent sessions?

All operations are stateless from the user's perspective. Adding sessions would require CSRF protection, session storage, and logout flows — significant complexity for a tool that never stores user-owned private keys server-side.

### Why is the admin API protected by a single shared token?

The admin endpoints manage API keys, not user data. The `ADMIN_TOKEN` bearer pattern is appropriate for a single-operator self-hosted tool. Multi-user auth is planned for Phase 8.

### Why is OCSP/CRL done server-side?

Browser CORS restrictions prevent the frontend from making direct HTTP requests to external OCSP responders or CRL distribution points. The backend makes the request and returns the result. This also avoids exposing the user's IP to external OCSP responders.

### Why is the JWT Decoder client-side only?

JWT decoding is just base64url-decode + JSON parse. It requires no secret and produces no sensitive output. Sending a token to the server would be a privacy regression with no benefit.

---

## 11. Storage

### Development (current)

| Data | Location | Format |
|------|----------|--------|
| Certificate monitor | `/tmp/ssl-toolkit/monitored_certificates.json` | JSON |
| API keys | `/tmp/ssl-toolkit/api_keys.json` | JSON |
| Rate limiter state | Process memory | In-memory dict |

Both JSON files are created automatically on first use. They live inside the container and are lost when the container is replaced.

To persist them across restarts, add a named volume in `docker-compose.yml`:
```yaml
volumes:
  - ssl-toolkit-data:/tmp/ssl-toolkit
```

### Production (recommended)

| Data | Target |
|------|--------|
| Certificate monitor | PostgreSQL table |
| API keys | PostgreSQL table with encrypted `api_key` column |
| Rate limiter | Redis (`storage_uri="redis://redis:6379"`) |

Migration path: replace the JSON read/write calls in `cert_monitor.py` and `api_key_manager.py` with SQLAlchemy model calls. Add Alembic for schema migrations. No route changes required.

---

## 12. Known limitations

| Limitation | Detail |
|------------|--------|
| JSON storage is ephemeral | Cert monitor and API keys are lost on container restart unless `/tmp/ssl-toolkit` is volume-mounted |
| In-memory rate limiter | Limits reset on backend restart; does not work correctly with multiple backend replicas |
| OCSP/CRL require internet access | Certificates from internal CAs or those without distribution points return "unavailable" |
| Cert monitor not thread-safe | The in-memory dict in `cert_monitor.py` is not protected by a lock; concurrent Gunicorn workers can race on writes |
| No server-side key storage | Private keys are returned to the browser and not retained; the user is responsible for saving them |
| Admin endpoint error leaks config state | If `ADMIN_TOKEN` is not set, the 403 response body reveals that the variable is missing |
