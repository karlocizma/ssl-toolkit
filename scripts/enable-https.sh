#!/usr/bin/env bash
# Enable HTTPS in the bundled nginx (self-signed certificate) and redirect plain HTTP to it.
#
# Usage: scripts/enable-https.sh [--force] [--no-redirect] [host-or-ip ...]    (default names: localhost 127.0.0.1)
# Writes certs/cert.pem, certs/key.pem, certs/https.conf and certs/http-redirect.conf; then restart nginx:
#   docker compose restart nginx
# Existing files are kept unless --force is given, so rerunning only refreshes the redirect.
# --no-redirect leaves HTTP open (and removes an existing redirect).
# The redirect points at HTTPS_PORT (environment or .env, default 443): rerun after changing it.
# List every name or IP address people will use to open the site; browsers reject names that are missing.
# For a certificate your browsers trust without a warning, use your own CA (the Private CA tool can issue one)
# and put its cert.pem and key.pem in certs/ instead.
set -euo pipefail

cd "$(dirname "$0")/.."
force=false
redirect=true
while [ $# -gt 0 ]; do
  case "$1" in
    --force) force=true; shift ;;
    --no-redirect) redirect=false; shift ;;
    -*) echo "unknown option: $1" >&2; exit 2 ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || set -- localhost 127.0.0.1

mkdir -p certs
if [ ! -w certs ]; then
  echo "certs/ is not writable by $(id -un) (owner: $(stat -c %U certs)); fix with: sudo chown -R \"\$USER\": certs" >&2
  exit 1
fi

if [ "$force" != true ] && [ -e certs/cert.pem ] && [ -e certs/key.pem ]; then
  echo "Keeping the existing certs/cert.pem and certs/key.pem (use --force to replace them)"
else
  san=""
  for name in "$@"; do
    [[ "$name" =~ ^[A-Za-z0-9.:_-]+$ ]] || { echo "invalid name: $name" >&2; exit 2; }
    if [[ "$name" =~ ^[0-9.]+$ ]] || [[ "$name" == *:* ]]; then kind=IP; else kind=DNS; fi
    san+="${san:+,}$kind:$name"
  done
  umask 077
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
    -keyout certs/key.pem -out certs/cert.pem -subj "/CN=$1" -addext "subjectAltName=$san"
  chmod 644 certs/cert.pem
  echo "Created certs/cert.pem (valid 365 days, names: $san) and certs/key.pem"
fi

if [ "$force" = true ] || [ ! -e certs/https.conf ]; then
  cp nginx/https.conf.example certs/https.conf
  echo "Wrote certs/https.conf"
fi

if [ "$redirect" = true ]; then
  port="${HTTPS_PORT:-}"
  if [ -z "$port" ] && [ -f .env ]; then
    port=$(grep -E '^HTTPS_PORT=' .env | tail -1 | cut -d= -f2- | sed 's/[[:space:]]*#.*//; s/[[:space:]]//g' || true)
  fi
  port="${port:-443}"
  [[ "$port" =~ ^[0-9]+$ ]] || { echo "HTTPS_PORT must be a number, got: $port" >&2; exit 2; }
  target='https://$host'
  [ "$port" = 443 ] || target+=":$port"
  # /api/health stays on HTTP so the container healthcheck keeps testing the backend
  cat > certs/http-redirect.conf <<CONF
# Written by scripts/enable-https.sh: send plain HTTP to HTTPS (port $port)
if (\$request_uri != "/api/health") {
    return 301 $target\$request_uri;
}
CONF
  echo "Wrote certs/http-redirect.conf (HTTP redirects to HTTPS on port $port)"
else
  rm -f certs/http-redirect.conf
  echo "HTTP stays open (no redirect)"
fi

echo "Now run: docker compose restart nginx"
