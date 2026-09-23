"""Framebuffer rectangle decoders.

A decoder is a generator: it yields the number of bytes it needs next and
is sent exactly that many, finally returning an :class:`Outcome`.  The
client's ``_pump`` drives the generator and turns :class:`DecodeError`
into a clean disconnect, so decoders raise it for anything the server
should not have sent.
"""
from __future__ import annotations

from struct import unpack
from typing import Any, ClassVar, Generator, NamedTuple

from .const import Encoding
from .pixelformat import PixelFormat


class DecodeError(Exception):
    """The server sent rectangle data that cannot be decoded."""


class Outcome(NamedTuple):
    """What decoding one rectangle produced.

    ``paste`` is ``(pixels, pixel_format)`` to draw, or None when the
    rectangle only referenced existing framebuffer content.
    ``changed`` says whether the rectangle belongs in the update commit.
    """

    paste: tuple[bytes, PixelFormat] | None = None
    changed: bool = True


class RectBuffer:
    """A writable view over one rectangle, backed by reused memory."""

    def __init__(self, width: int, height: int, bypp: int, backing: bytearray) -> None:
        self.width = width
        self.height = height
        self.bypp = bypp
        self._backing = backing

    def __len__(self) -> int:
        return self.width * self.height * self.bypp

    def write(self, data: bytes, offset: int = 0) -> None:
        self._backing[offset : offset + len(data)] = data

    def bytes(self) -> bytes:
        """A copy of exactly this rectangle's pixels."""
        return bytes(self._backing[: len(self)])


class Decoder:
    """One rectangle encoding; subclasses set ENCODING and decode()."""

    ENCODING: ClassVar[Encoding]

    def decode(
        self, client: Any, rect: tuple[int, int, int, int], pixel_format: PixelFormat
    ) -> Generator[int, bytes, Outcome]:
        raise NotImplementedError

    def encodingsOffered(self, encodings: frozenset[Encoding]) -> None:
        """Note which encodings the client told the server it accepts."""


class RawDecoder(Decoder):
    """RFC 6143 section 7.7.1: width*height pixels, no compression."""

    ENCODING = Encoding.RAW

    def decode(
        self, client: Any, rect: tuple[int, int, int, int], pixel_format: PixelFormat
    ) -> Generator[int, bytes, Outcome]:
        x, y, width, height = rect
        client.requireFits(width, height)
        data = yield width * height * pixel_format.bypp
        return Outcome(paste=(data, pixel_format))


class CopyRectDecoder(Decoder):
    """RFC 6143 section 7.7.2: copy a rectangle already on screen."""

    ENCODING = Encoding.COPY_RECT

    def decode(
        self, client: Any, rect: tuple[int, int, int, int], pixel_format: PixelFormat
    ) -> Generator[int, bytes, Outcome]:
        x, y, width, height = rect
        client.requireFits(width, height)
        (srcx, srcy) = unpack("!HH", (yield 4))
        client.copyRectangle(srcx, srcy, x, y, width, height)
        return Outcome()


DECODERS = {
    decoder.ENCODING: decoder
    for decoder in (RawDecoder, CopyRectDecoder)
}


def for_connection() -> dict[Encoding, Decoder]:
    """A fresh decoder instance per encoding, for one connection."""
    return {encoding: decoder() for encoding, decoder in DECODERS.items()}
