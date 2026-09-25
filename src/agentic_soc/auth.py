"""HMAC-SHA256 request authentication.

The Wazuh hook and this service share a secret. The hook signs the raw alert
body; the service recomputes the signature and compares it in constant time.
This proves an incoming alert came from our own hook, not an attacker who can
reach the port.
"""

from __future__ import annotations

import hashlib
import hmac


def sign(body: bytes, secret: str) -> str:
    """Return the hex HMAC-SHA256 of ``body`` under ``secret``."""
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def verify(body: bytes, secret: str, signature: str) -> bool:
    """Constant-time check that ``signature`` matches ``body`` signed with ``secret``."""
    return hmac.compare_digest(sign(body, secret), signature)
