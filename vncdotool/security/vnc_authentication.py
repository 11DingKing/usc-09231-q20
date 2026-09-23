""":rfc:`6143` section 7.2.2 VNC Authentication."""
from __future__ import annotations

from typing import Any, Generator

from ..const import AuthTypes
from .base import SecurityHandler, security_result

CHALLENGE_LENGTH = 16


class VNCAuthenticationHandler(SecurityHandler):
    SECURITY_TYPE = AuthTypes.VNC_AUTHENTICATION

    def handle(self, client: Any) -> Generator[int, bytes, bool]:
        client._challenge = yield CHALLENGE_LENGTH
        client.vncRequestPassword()
        return (yield from security_result(client))
