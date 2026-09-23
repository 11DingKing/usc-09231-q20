"""Server to client message handlers, RFC 6143 section 7.6.

Like the rectangle decoders, a handler is a generator that yields the
number of bytes it needs next; the client's ``_pump`` drives it and
reports :class:`decoders.DecodeError` as a protocol failure.
"""
from __future__ import annotations

from struct import unpack
from typing import Any, ClassVar, Generator

from . import decoders
from .const import FenceFlags, MsgS2C


class MessageHandler:
    """One server to client message type."""

    MESSAGE: ClassVar[MsgS2C]

    def handle(self, client: Any) -> Generator[int, bytes, None]:
        raise NotImplementedError


class Bell(MessageHandler):
    """RFC 6143 section 7.6.2: no payload, just ring."""

    MESSAGE = MsgS2C.BELL

    def handle(self, client: Any) -> Generator[int, bytes, None]:
        client.bell()
        return
        yield  # unreachable; only here to make this a generator


class ServerCutText(MessageHandler):
    """RFC 6143 section 7.6.4: the server's clipboard, ISO 8859-1."""

    MESSAGE = MsgS2C.SERVER_CUT_TEXT

    def handle(self, client: Any) -> Generator[int, bytes, None]:
        (length,) = unpack("!xxxI", (yield 7))
        client.requirePayload(length)
        data = yield length
        client.copy_text(data.decode("iso-8859-1"))


class ServerFence(MessageHandler):
    """rfbproto fence extension: synchronise the data stream on request."""

    MESSAGE = MsgS2C.SERVER_FENCE

    def handle(self, client: Any) -> Generator[int, bytes, None]:
        (flags, length) = unpack("!IBxxx", (yield 8))
        payload = yield length
        if flags & FenceFlags.SYNC_NEXT:
            client.clientFence(FenceFlags.SYNC_NEXT, payload)


HANDLERS = {
    handler.MESSAGE: handler
    for handler in (Bell, ServerCutText, ServerFence)
}


def for_connection() -> dict[MsgS2C, MessageHandler]:
    """A fresh handler instance per message type, for one connection."""
    return {message: handler() for message, handler in HANDLERS.items()}
