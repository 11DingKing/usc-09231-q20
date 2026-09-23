"""Security type registry: one handler per offered auth type."""
from __future__ import annotations

from ..const import AuthTypes
from .base import (
    MAX_REASON_LENGTH,
    REASON_TRUNCATED_MARKER,
    SecurityError,
    SecurityHandler,
    security_result,
)
from .diffie_hellman import DiffieHellmanHandler
from .none_security import NoneSecurityHandler
from .vnc_authentication import VNCAuthenticationHandler

HANDLERS: dict[AuthTypes, type[SecurityHandler]] = {
    AuthTypes.NONE: NoneSecurityHandler,
    AuthTypes.VNC_AUTHENTICATION: VNCAuthenticationHandler,
    AuthTypes.DIFFIE_HELLMAN: DiffieHellmanHandler,
}


def for_connection() -> dict[AuthTypes, SecurityHandler]:
    return {sec_type: cls() for sec_type, cls in HANDLERS.items()}


__all__ = [
    "HANDLERS",
    "MAX_REASON_LENGTH",
    "REASON_TRUNCATED_MARKER",
    "SecurityError",
    "SecurityHandler",
    "for_connection",
    "security_result",
]
