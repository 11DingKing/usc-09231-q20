"""Generator based framebuffer decoders.

A decoder yields the byte counts it needs, each satisfied in full by
``RFBClient._pump``, and returns an :class:`Outcome` describing the decoded
rectangle.
"""
from __future__ import annotations

from dataclasses import dataclass
from struct import unpack
from typing import Any, ClassVar, Generator

from .const import Encoding
from .pixelformat import PixelFormat

Rect = tuple[int, int, int, int]


class DecodeError(Exception):
    """A server message cannot be decoded as the negotiated encoding."""


@dataclass(frozen=True)
class RectBuffer:
    """Backing store for one rectangle, reused across rectangles."""

    width: int
    height: int
    bypp: int
    backing: bytearray


@dataclass(frozen=True)
class Outcome:
    """What a decoder produced for one rectangle."""

    paste: tuple[bytes, PixelFormat] | None = None
    changed: bool = False


class Decoder:
    """One RFB encoding."""

    ENCODING: ClassVar[Encoding]

    def encodingsOffered(self, encodings: frozenset[Encoding]) -> None:
        """Tell the decoder which encodings the client offered."""

    def decode(
        self, client: Any, rect: Rect, pixel_format: PixelFormat
    ) -> Generator[int, bytes, Outcome]:
        raise NotImplementedError


class RawDecoder(Decoder):
    """:rfc:`6143` section 7.7.1 Raw Encoding."""

    ENCODING = Encoding.RAW

    def decode(
        self, client: Any, rect: Rect, pixel_format: PixelFormat
    ) -> Generator[int, bytes, Outcome]:
        _x, _y, width, height = rect
        client.requireFits(width, height)
        length = width * height * pixel_format.bypp
        block = yield length
        return Outcome(paste=(block, pixel_format), changed=bool(length))


DECODERS: dict[Encoding, type[Decoder]] = {
    Encoding.RAW: RawDecoder,
}


def for_connection() -> dict[Encoding, Decoder]:
    return {encoding: cls() for encoding, cls in DECODERS.items()}
