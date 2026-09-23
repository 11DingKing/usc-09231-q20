""":rfc:`6143` section 7.2.1 No Security."""
from __future__ import annotations

from typing import Any, Generator

from ..const import AuthTypes
from .base import SecurityHandler, security_result


class NoneSecurityHandler(SecurityHandler):
    SECURITY_TYPE = AuthTypes.NONE

    def handle(self, client: Any) -> Generator[int, bytes, bool]:
        # Before 3.7 there is no security result at all.
        if client._version < (3, 8):
            return True
        return (yield from security_result(client))
