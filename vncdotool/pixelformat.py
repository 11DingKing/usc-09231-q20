"""The RFB pixel format structure, RFC 6143 section 7.4."""
from __future__ import annotations

from dataclasses import dataclass
from struct import pack, unpack

_PIXEL_FORMAT = "!BBBBHHHBBBxxx"


@dataclass
class PixelFormat:
    """One framebuffer pixel layout; the default is the usual 32-bit true colour."""

    bits_per_pixel: int = 32
    depth: int = 24
    big_endian: bool = False
    true_color: bool = True
    red_max: int = 255
    green_max: int = 255
    blue_max: int = 255
    red_shift: int = 16
    green_shift: int = 8
    blue_shift: int = 0

    @property
    def bypp(self) -> int:
        """Bytes per pixel, rounded up for sub-byte formats."""
        return (self.bits_per_pixel + 7) // 8

    @classmethod
    def from_bytes(cls, data: bytes) -> PixelFormat:
        """Parse the 16-byte ServerInit pixel-format structure."""
        (
            bits_per_pixel,
            depth,
            big_endian,
            true_color,
            red_max,
            green_max,
            blue_max,
            red_shift,
            green_shift,
            blue_shift,
        ) = unpack(_PIXEL_FORMAT, data)
        return cls(
            bits_per_pixel=bits_per_pixel,
            depth=depth,
            big_endian=bool(big_endian),
            true_color=bool(true_color),
            red_max=red_max,
            green_max=green_max,
            blue_max=blue_max,
            red_shift=red_shift,
            green_shift=green_shift,
            blue_shift=blue_shift,
        )

    def to_bytes(self) -> bytes:
        """The 16-byte wire form, for SetPixelFormat."""
        return pack(
            _PIXEL_FORMAT,
            self.bits_per_pixel,
            self.depth,
            self.big_endian,
            self.true_color,
            self.red_max,
            self.green_max,
            self.blue_max,
            self.red_shift,
            self.green_shift,
            self.blue_shift,
        )

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}({self.bits_per_pixel}bpp, "
            f"depth={self.depth}, "
            f"{'big' if self.big_endian else 'little'}-endian, "
            f"{'true' if self.true_color else 'mapped'} colour, "
            f"rgb max {self.red_max}/{self.green_max}/{self.blue_max}, "
            f"shift {self.red_shift}/{self.green_shift}/{self.blue_shift})"
        )
