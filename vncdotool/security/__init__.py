"""Security type handlers: specs/security-handler-architecture.md is the design."""
from __future__ import annotations

from .ard import DiffieHellmanSecurity
from .base import (
    MAX_REASON_LENGTH,
    SecurityError,
    SecurityHandler,
    decode_reason,
    security_result,
)
from .none import NoneSecurity
from .vnc import VncAuthentication

__all__ = [
    "HANDLERS",
    "MAX_REASON_LENGTH",
    "SecurityError",
    "SecurityHandler",
    "decode_reason",
    "for_connection",
    "security_result",
]

HANDLERS = {
    handler.SECURITY_TYPE: handler
    for handler in (NoneSecurity, VncAuthentication, DiffieHellmanSecurity)
}


def for_connection() -> dict[int, SecurityHandler]:
    """A fresh handler instance per security type, for one connection."""
    return {sec_type: handler() for sec_type, handler in HANDLERS.items()}
