"""Protocol constants: RFC 6143 and the rfbproto extensions in use."""
from __future__ import annotations

from enum import IntEnum


class _Lookup:
    """An IntEnum that can fall back to the bare value for unknown members."""

    @classmethod
    def lookup(cls, value: int) -> int:
        """The matching member, or the value itself when it is not one."""
        try:
            return cls(value)
        except ValueError:
            return value


class AuthTypes(_Lookup, IntEnum):
    """https://www.rfc-editor.org/rfc/rfc6143#section-7.1.2"""

    INVALID = 0
    NONE = 1
    VNC_AUTHENTICATION = 2
    TIGHT = 16
    DIFFIE_HELLMAN = 30  # Apple Remote Desktop


class Encoding(_Lookup, IntEnum):
    """https://www.rfc-editor.org/rfc/rfc6143#section-7.7"""

    RAW = 0
    COPY_RECT = 1
    RRE = 2
    HEXTILE = 5
    ZLIB = 6
    TIGHT = 7
    ZLIBHEX = 8
    ZRLE = 16
    PSEUDO_LAST_RECT = -224


class FenceFlags(_Lookup, IntEnum):
    """https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#fence"""

    BLOCK_BEFORE = 1
    BLOCK_AFTER = 2
    SYNC_NEXT = 4


class MsgC2S(_Lookup, IntEnum):
    """Client to server message types, RFC 6143 section 7.5."""

    SET_PIXEL_FORMAT = 0
    SET_ENCODING = 2
    FRAMEBUFFER_UPDATE_REQUEST = 3
    KEY_EVENT = 4
    POINTER_EVENT = 5
    CLIENT_CUT_TEXT = 6
    CLIENT_FENCE = 0xF8  # fence extension, 248 in both directions


class MsgS2C(_Lookup, IntEnum):
    """Server to client message types, RFC 6143 section 7.6."""

    FRAMEBUFFER_UPDATE = 0
    SET_COLOR_MAP = 1
    BELL = 2
    SERVER_CUT_TEXT = 3
    SERVER_FENCE = 0xF8  # fence extension
