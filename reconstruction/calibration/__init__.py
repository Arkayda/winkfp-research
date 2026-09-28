"""Calibration and flash image reconnaissance module.

Pure offline, read-only analysis tools for BMW EDIABAS Intel Hex files (.0da, .0pa).
Strictly decoupled from physical hardware transport.
"""

from reconstruction.calibration.hex_parser import (
    IntelHexParser,
    MemorySegment,
    ParsedHexImage,
)

__all__ = [
    "IntelHexParser",
    "MemorySegment",
    "ParsedHexImage",
]
