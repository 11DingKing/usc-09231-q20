""":rfc:`6143` section 7.4. Pixel Format Data Structure."""
from __future__ import annotations

from dataclasses import astuple, dataclass
from struct import Struct
from typing import ClassVar, cast


@dataclass(frozen=True)
class PixelFormat:
    bpp: int = 32  # u8: bits-per-pixel
    depth: int = 24  # u8
    bigendian: bool = False  # u8
    truecolor: bool = True  # u8
    redmax: int = 255  # u16
    greenmax: int = 255  # u16
    bluemax: int = 255  # u16
    redshift: int = 0  # u8
    greenshift: int = 8  # u8
    blueshift: int = 16  # u8

    STRUCT: ClassVar = Struct("!BB??HHHBBBxxx")

    @property
    def bypp(self) -> int:
        """bytes per pixel"""
        return (7 + self.bpp) // 8

    @classmethod
    def from_bytes(cls, block: bytes) -> "PixelFormat":
        return cls(*cls.STRUCT.unpack(block))

    def to_bytes(self) -> bytes:
        return cast(bytes, self.STRUCT.pack(*astuple(self)))
