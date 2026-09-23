"""Generator based handlers for server-to-client messages.

A handler yields the byte counts it needs, each satisfied in full by
``RFBClient._pump``.
"""
from __future__ import annotations

from struct import unpack
from typing import Any, ClassVar, Generator

from .const import FenceFlags, MsgS2C


class MessageHandler:
    """One server-to-client message other than FramebufferUpdate."""

    MESSAGE_TYPE: ClassVar[MsgS2C]

    def handle(self, client: Any) -> Generator[int, bytes, None]:
        raise NotImplementedError


class ServerFence(MessageHandler):
    """:rfc:`6143` section 7.6.5 ServerFence."""

    MESSAGE_TYPE = MsgS2C.SERVER_FENCE

    def handle(self, client: Any) -> Generator[int, bytes, None]:
        # message-type and 3 padding bytes were consumed by the dispatcher;
        # what remains is u32 flags and u8 payload-length.
        flags, length = unpack("!IB", (yield 8))
        payload = yield length
        if flags & FenceFlags.REQUEST and flags & FenceFlags.SYNC_NEXT:
            client.clientFence(flags, payload)


class ServerCutText(MessageHandler):
    """:rfc:`6143` section 7.6.4 ServerCutText."""

    MESSAGE_TYPE = MsgS2C.SERVER_CUT_TEXT

    def handle(self, client: Any) -> Generator[int, bytes, None]:
        (length,) = unpack("!xxxI", (yield 7))
        client.requirePayload(length)
        block = yield length
        client.copy_text(block.decode("iso-8859-1"))


MESSAGES: dict[MsgS2C, type[MessageHandler]] = {
    MsgS2C.SERVER_FENCE: ServerFence,
    MsgS2C.SERVER_CUT_TEXT: ServerCutText,
}


def for_connection() -> dict[MsgS2C, MessageHandler]:
    return {msgtype: cls() for msgtype, cls in MESSAGES.items()}
