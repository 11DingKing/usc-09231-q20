"""specs/security-handler-architecture.md is the design."""
from __future__ import annotations

from struct import unpack
from typing import Any, ClassVar, Generator

from twisted.python import log

from ..const import AuthTypes

# A failure reason is diagnostic text, never bulk data. Cap the bytes the
# parser will wait for before trusting a server-declared length, which can
# otherwise reach 4 GiB and pin the connection on an allocation-sized read.
MAX_REASON_LENGTH = 1 << 16
REASON_TRUNCATED_MARKER = b" [truncated]"
REASON_TRUNCATED_TEXT = REASON_TRUNCATED_MARKER.decode("ascii")


class SecurityError(Exception):
    """The security handshake cannot proceed."""


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


def bounded_reason(length: int) -> tuple[int, bool]:
    """Bound a server-declared reason length.

    Returns the number of bytes to actually read and whether the declared
    string was longer than the cap.
    """
    truncated = length > MAX_REASON_LENGTH
    return min(length, MAX_REASON_LENGTH), truncated


def read_failure_reason() -> Generator[int, bytes, bytes]:
    """Read a 3.8 SecurityFailure reason string with a hard size bound.

    Yields the four length bytes first, so the pump never parks on the
    declared length itself. An oversized reason is truncated to
    ``MAX_REASON_LENGTH`` bytes and marked rather than read in full; an empty
    reason yields nothing and returns ``b""``.
    """
    (waitfor,) = unpack("!I", (yield 4))
    size, truncated = bounded_reason(waitfor)
    if size == 0:
        return b""
    reason = yield size
    if truncated:
        log.msg(
            f"truncating {waitfor} byte failure reason to "
            f"{MAX_REASON_LENGTH} bytes"
        )
        reason += REASON_TRUNCATED_MARKER
    return reason


def decode_reason(block: bytes) -> str:
    """Decode a reason string for display.

    RFC 6143 does not name an encoding for the text, so treat it as UTF-8
    and substitute for bytes that are not valid text instead of failing the
    connection teardown.
    """
    return block.decode("utf-8", errors="replace")


def security_result(client: Any) -> Generator[int, bytes, bool]:
    """RFC 6143 section 7.1.3, and the reason string 3.8 adds on failure."""
    (result,) = unpack("!I", (yield 4))
    if result == 0:  # OK
        return True
    elif result == 1:  # failed
        reason: str | bytes = "authentication failed"
    elif result == 2:  # too many
        reason = "too many tries to log in"
    else:
        log.msg(f"unknown auth response ({result})")
        client.transport.loseConnection()
        return False

    if client._version < (3, 8):
        client.vncAuthFailed(reason)
    else:
        client.vncAuthFailed((yield from read_failure_reason()))
    client.transport.loseConnection()
    return False
