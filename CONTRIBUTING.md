# Contributing to SSL Toolkit

Thanks for helping out! This guide gets you from a fresh clone to a merged pull request.

## Quick start

```bash
git clone https://github.com/karlocizma/ssl-toolkit.git && cd ssl-toolkit

# Backend (Python 3.11+)
cd backend && python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py                  # dev server on :5000
python -m pytest -q            # run the tests

# Frontend (Node 22)
cd ../frontend && npm ci
npm start                      # dev server on :3000, proxies /api to :5000
npm test -- --watchAll=false
```

`make help` lists the shortcuts for all of this. To run the whole stack: `docker compose up --build`.

## Tests you should know about

- **Backend**: `pytest` in `backend/`. The ACME tests are *integration* tests against [Pebble](https://github.com/letsencrypt/pebble), the Let's Encrypt test CA. They are skipped when Pebble is not installed. To run them:
  ```bash
  go install github.com/letsencrypt/pebble/v2/cmd/pebble@latest
  go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@latest
  PEBBLE_BIN_DIR="$(go env GOPATH)/bin" python -m pytest -q
  ```
- **Frontend**: Jest + Testing Library. CI builds with `CI=true`, which turns ESLint warnings into errors, so run `CI=true npm run build` before pushing.
- Tests must not need the internet. Mock DNS and HTTP at the module boundary (look at `tests/test_deliverability.py` for the pattern), or use a local server on `127.0.0.1`.

## Making a change

1. Open an issue first for anything bigger than a small fix, so we can agree on the approach.
2. Branch from `main`: `git checkout -b feat/short-description`.
3. Keep the change focused; add or update tests; update `CHANGELOG.md` and the docs if behaviour changes.
4. Run the backend and frontend tests and the strict build (see above).
5. Open a pull request. CI must be green. Describe *why* the change is needed, not just what it does.

Commit messages: a short imperative summary line, then a body explaining the reasoning when it is not obvious.

## Adding a new tool

[`docs/WIKI.md`](docs/WIKI.md#5-adding-a-new-tool-end-to-end-guide) walks through it end to end: service function, route, API client, React component, navigation, translations, tests. In short:

- Put logic in `backend/app/services/`, keep routes thin, and **route every outbound connection through `app/utils/net_safety.py`** (never call `requests` or `socket.create_connection` directly on a user-supplied target).
- Validate and size-limit all input; return `400` with a clear message for bad input.
- Add the endpoint's request body to `backend/app/openapi.py` so `/api/docs` stays complete.
- Add strings to **both** `frontend/src/locales/en` and `de`.

## Code style

- Python: PEP 8, type hints where they help, no unused imports. Match the surrounding code.
- JavaScript: function components and hooks, MUI for UI. No unused imports or variables (the strict build fails on them).
- `.editorconfig` is provided; line endings are LF (`.gitattributes` enforces it). Optional: `pip install pre-commit && pre-commit install`.

## Security

Please do not open public issues for vulnerabilities. See [`SECURITY.md`](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating you agree to uphold it.

## License

By contributing you agree that your contributions are licensed under the project's [license](LICENSE).
