#!/usr/bin/env bash
# Tell the bundled nginx which reverse proxies to trust for the real client address.
#
# Usage: scripts/trust-proxy.sh <ip-or-cidr> [...]     e.g. scripts/trust-proxy.sh 172.18.0.0/16 192.168.1.10
#        scripts/trust-proxy.sh --remove
# Writes certs/realip.conf; then restart nginx:  docker compose restart nginx
# Without it the backend sees the proxy's address as every visitor's IP (shared rate limit, audit log).
# Only list addresses of proxies you run: they may set X-Forwarded-For, so anyone who can connect from
# a listed address can claim any client IP. Do not list 0.0.0.0/0.
set -euo pipefail

cd "$(dirname "$0")/.."
if [ "${1:-}" = "--remove" ]; then
  rm -f certs/realip.conf
  echo "Removed certs/realip.conf; restart nginx: docker compose restart nginx"
  exit 0
fi
[ $# -gt 0 ] || { sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }

lines=""
for addr in "$@"; do
  [[ "$addr" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ || "$addr" =~ ^[0-9A-Fa-f:]+(/[0-9]{1,3})?$ ]] \
    || { echo "invalid address: $addr (use an IP or CIDR, e.g. 172.18.0.0/16)" >&2; exit 2; }
  case "$addr" in
    0.0.0.0/0|::/0|0.0.0.0|::) echo "refusing to trust everything: $addr" >&2; exit 2 ;;
  esac
  lines+="set_real_ip_from ${addr};"$'\n'
done

mkdir -p certs
if [ ! -w certs ]; then
  echo "certs/ is not writable by $(id -un) (owner: $(stat -c %U certs)); fix with: sudo chown -R \"\$USER\": certs" >&2
  exit 1
fi
{
  echo "# Written by scripts/trust-proxy.sh"
  printf '%s' "$lines"
  echo "real_ip_header X-Forwarded-For;"
  echo "real_ip_recursive on;"
} > certs/realip.conf
echo "Wrote certs/realip.conf; restart nginx: docker compose restart nginx"
