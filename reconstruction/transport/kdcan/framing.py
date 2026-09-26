"""BMW-FAST (DS2) frame encoding and parsing.

Adapted from open6hp (https://github.com/Arkayda/open6hp) protocol framing.
Copyright (c) open6hp contributors. Licensed under the MIT License.

Frame formats:
- Short (payload <= 0x3F bytes): ``0x80 | len, dst, src, payload..., CS``
- Long  (payload <= 0xFF bytes): ``0x80, dst, src, len, payload..., CS``
- 2-byte length (receive only):  ``0x80, dst, src, 0x00, lenHi, lenLo, payload..., CS``
Checksum: Additive sum of all preceding bytes modulo 256.
"""

from __future__ import annotations

from dataclasses import dataclass

TESTER_ADDRESS = 0xF1
MAX_PAYLOAD_LEN = 0xFF

# Standard KWP2000 Service Identifiers (SID)
SID_START_DIAGNOSTIC_SESSION = 0x10
SID_ECU_RESET = 0x11
SID_READ_STATUS_OF_DTC = 0x18
SID_READ_ECU_IDENTIFICATION = 0x1A
SID_READ_DATA_BY_LOCAL_IDENTIFIER = 0x21
SID_READ_DATA_BY_COMMON_IDENTIFIER = 0x22
SID_SECURITY_ACCESS = 0x27
SID_TESTER_PRESENT = 0x3E

# Standard Negative Response Codes (NRC)
NRC_GENERAL_REJECT = 0x10
NRC_SERVICE_NOT_SUPPORTED = 0x11
NRC_SUBFUNCTION_NOT_SUPPORTED = 0x12
NRC_BUSY_REPEAT_REQUEST = 0x21
NRC_CONDITIONS_NOT_CORRECT = 0x22
NRC_REQUEST_SEQUENCE_ERROR = 0x24
NRC_REQUEST_OUT_OF_RANGE = 0x31
NRC_SECURITY_ACCESS_DENIED = 0x33
NRC_INVALID_KEY = 0x35
NRC_EXCEEDED_NUMBER_OF_ATTEMPTS = 0x36
NRC_REQUIRED_TIME_DELAY_NOT_EXPIRED = 0x37
NRC_SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7E


@dataclass(frozen=True)
class Telegram:
    dst: int
    src: int
    payload: bytes
    raw: bytes


def checksum(data: bytes) -> int:
    """Additive checksum: sum of bytes modulo 256."""
    return sum(data) & 0xFF


def body_length(header: bytes) -> int:
    """Length of telegram body without trailing checksum byte."""
    short = header[0] & 0x3F
    if short != 0:
        return short + 3
    if len(header) < 4:
        raise ValueError("Header must be at least 4 bytes")
    if header[3] == 0:
        if len(header) < 6:
            raise ValueError("2-byte extended length requires at least 6 header bytes")
        return ((header[4] << 8) + header[5]) + 6
    return header[3] + 4


def build(dst: int, src: int, payload: bytes) -> bytes:
    """Construct a complete DS2/BMW-FAST telegram with checksum."""
    if not payload:
        raise ValueError("Empty payload prohibited in DS2")
    if len(payload) > MAX_PAYLOAD_LEN:
        raise ValueError(f"Payload length {len(payload)} exceeds maximum {MAX_PAYLOAD_LEN}")
    if len(payload) <= 0x3F:
        head = bytes([0x80 | len(payload), dst, src])
    else:
        head = bytes([0x80, dst, src, len(payload)])
    body = head + payload
    return body + bytes([checksum(body)])


def parse(frame: bytes) -> Telegram:
    """Parse and validate a complete DS2/BMW-FAST telegram."""
    if len(frame) < 4:
        raise ValueError("Telegram shorter than minimal header")
    if frame[0] & 0xC0 != 0x80:
        raise ValueError(f"Invalid DS2 header byte: 0x{frame[0]:02X}")
    total = body_length(frame)
    if len(frame) != total + 1:
        raise ValueError(f"Frame length {len(frame)} mismatch with header ({total + 1})")
    expected_cs = checksum(frame[:-1])
    actual_cs = frame[-1]
    if actual_cs != expected_cs:
        raise ValueError(
            f"Checksum mismatch: received 0x{actual_cs:02X}, expected 0x{expected_cs:02X}"
        )
    short = frame[0] & 0x3F
    if short != 0:
        payload = frame[3:-1]
    elif frame[3] != 0:
        payload = frame[4:-1]
    else:
        payload = frame[6:-1]
    return Telegram(dst=frame[1], src=frame[2], payload=payload, raw=bytes(frame))
