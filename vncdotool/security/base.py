"""specs/security-handler-architecture.md is the design."""
from __future__ import annotations

from struct import unpack
from typing import Any, ClassVar, Generator

from twisted.python import log

from ..const import AuthTypes

# A reason string only ever ends up in an error message for a human, so a
# few KiB is generous; a server that declares more gets truncated to this
# instead of making the client buffer its full claim.
MAX_REASON_LENGTH = 4096


class SecurityError(Exception):
    """A security type could not be negotiated or completed."""


class SecurityHandler:
    """One RFB security type: RFC 6143 section 7.2."""

    SECURITY_TYPE: ClassVar[AuthTypes]

    def handle(self, client: Any) -> Generator[int, bytes, bool]:
        """Yield the byte counts this security type needs, each satisfied in
        full, and return whether the connection proceeds to initialisation.
        The security type is already settled: written by the client on 3.7+,
        dictated by the server on 3.3.
        """
        raise NotImplementedError


def decode_reason(data: bytes, declared_len: int | None = None) -> str:
    """Decode a server-sent reason string for an error message.

    The wire format does not name an encoding, so decode as UTF-8 and
    replace anything that is not; a short string comes through unchanged
    and an empty one as "".  When the server declared more bytes than were
    read (see MAX_REASON_LENGTH) the text is marked as truncated.
    """
    text = data.decode("utf-8", errors="replace")
    if declared_len is not None and declared_len > len(data):
        text += f"... [truncated: server declared {declared_len} bytes]"
    return text


def security_result(client: Any) -> Generator[int, bytes, bool]:
    """RFC 6143 section 7.1.3, and the reason string 3.8 adds on failure."""
    (result,) = unpack("!I", (yield 4))
    if result == 0:  # OK
        return True
    elif result == 1:  # failed
        reason = "authentication failed"
    elif result == 2:  # too many
        reason = "too many tries to log in"
    else:
        log.msg(f"unknown auth response ({result})")
        client.transport.loseConnection()
        return False

    if client._version < (3, 8):
        client.vncAuthFailed(reason)
    else:
        (declared_len,) = unpack("!I", (yield 4))
        # Wait for at most MAX_REASON_LENGTH bytes, however long a reason
        # the server claimed; the rest of its claim is never buffered.
        block = yield min(declared_len, MAX_REASON_LENGTH)
        client.vncAuthFailed(decode_reason(block, declared_len))
    client.transport.loseConnection()
    return False
