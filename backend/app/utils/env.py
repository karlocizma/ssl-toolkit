"""Tolerate inline comments in .env files.

`docker compose` strips a trailing "# comment" from `KEY=value  # comment`, but other readers
(Podman compose, Portainer, `docker run --env-file`, systemd, ...) keep it as part of the value, so
`RBL_RESOLVERS=   # your own resolver` arrives as the text "# your own resolver" and breaks the feature.
Only the application's own settings are touched, and never secrets (a password may contain " #").
"""
import logging
import os
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

SETTINGS = (
    'MONITOR_PUBLIC', 'CORS_ORIGINS', 'ALLOW_PRIVATE_TARGETS', 'RATE_LIMIT_STORAGE_URI', 'ALERT_THRESHOLDS',
    'ALERT_CHECK_INTERVAL_HOURS', 'ALERT_WEBHOOK_URL', 'ALERT_TEAMS_WEBHOOK_URL', 'APP_URL', 'SMTP_HOST',
    'SMTP_PORT', 'SMTP_USER', 'SMTP_STARTTLS', 'ALERT_EMAIL_FROM', 'ALERT_EMAIL_TO', 'CT_API_URL',
    'STATUS_PAGE_TITLE', 'STATUS_PAGE_ENABLED', 'AUDIT_LOG_MAX_BYTES', 'AUDIT_LOG_KEEP', 'RDAP_CACHE_SECONDS',
    'RDAP_BOOTSTRAP_URL', 'CT_CACHE_SECONDS', 'RBL_RESOLVERS', 'RBL_LISTS', 'ACME_DNS_RESOLVERS', 'DISABLE_SCHEDULER',
)
_COMMENT = re.compile(r'(^|\s)#.*$')


def sanitize_env(environ: Optional[Dict[str, str]] = None) -> List[str]:
    """Remove "# comment" text from the application's settings. Returns the names that were changed."""
    environ = os.environ if environ is None else environ
    changed = []
    for name in SETTINGS:
        value = environ.get(name)
        if value is None or '#' not in value:
            continue
        cleaned = _COMMENT.sub('', value).strip()
        if cleaned != value.strip():
            environ[name] = cleaned
            changed.append(name)
    if changed:
        logger.warning('Ignored inline comments in %s: put comments on their own line in .env', ', '.join(changed))
    return changed
