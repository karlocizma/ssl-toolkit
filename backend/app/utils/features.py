"""Server-side feature flags. Read from the environment on every call; never editable from the web UI."""
import os

_TRUTHY = ('1', 'true', 'yes', 'on')


def acme_enabled() -> bool:
    """ACME (Let's Encrypt and compatible CAs) is off unless ENABLE_ACME is set to a true value."""
    return os.environ.get('ENABLE_ACME', '').strip().lower() in _TRUTHY
