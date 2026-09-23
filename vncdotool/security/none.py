"""No authentication, RFC 6143 section 7.2.1."""
from __future__ import annotations

from typing import Any, Generator

from ..const import AuthTypes
from .base import SecurityHandler, security_result


class NoneSecurity(SecurityHandler):
    """No credentials; from 3.8 the server still sends a security result."""

    SECURITY_TYPE = AuthTypes.NONE

    def handle(self, client: Any) -> Generator[int, bytes, bool]:
        if client._version < (3, 8):
            return True
        return (yield from security_result(client))
