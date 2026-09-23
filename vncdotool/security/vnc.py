"""VNC authentication, RFC 6143 section 7.2.2."""
from __future__ import annotations

from typing import Any, Generator

from ..const import AuthTypes
from .base import SecurityHandler, security_result


class VncAuthentication(SecurityHandler):
    """The classic 16-byte challenge answered with the DES-encrypted password.

    The challenge is left on the client and the password is asked for, but
    the answer is not waited for here: ``sendPassword`` writes it whenever
    it is ready, and the security result that follows completes the
    exchange.
    """

    SECURITY_TYPE = AuthTypes.VNC_AUTHENTICATION

    def handle(self, client: Any) -> Generator[int, bytes, bool]:
        client._challenge = yield 16
        client.vncRequestPassword()
        return (yield from security_result(client))
