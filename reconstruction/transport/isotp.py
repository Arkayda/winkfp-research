"""Standalone ISO 15765-2 (ISO-TP) sender — transport implementation.

This is NOT a reconstruction of winkfpt: the original delegates byte-level
framing to EDIABAS IFH driver DLLs [C, verified]. This module exists as a
drop-in transport for a custom toolchain.

Rev 3 fixes (external audit):
  * payload > 4095 bytes now rejected — the classic-CAN FirstFrame length
    field is 12-bit; sending 4096 silently declared length 0.
  * reserved STmin values (0x80–0xF0, 0xFA–0xFF) now raise instead of
    degrading to 0 ms (aggressive transmission on ECU error).
  * FC waits accept a deadline-aware reader: read_flow_control(timeout)
    receives the remaining budget — a blocking reader must honour it.
  * timing names fixed: waiting for FC on the sender side is N_Bs
    (N_Cr belongs to the receiving side).
"""

import time
from typing import Callable, Tuple

FC_CTS, FC_WAIT, FC_OVFL = 0x00, 0x01, 0x02
MAX_CLASSIC_PAYLOAD = 0xFFF          # 12-bit FF length field
N_BS_TIMEOUT = 1.0                   # s, [R] typical value


class ISOTPError(RuntimeError):
    pass


def _stmin_ms(raw: int) -> float:
    """ISO 15765-2: 0x00–0x7F → ms; 0xF1–0xF9 → 100–900 µs; the rest is
    reserved → protocol violation, never silently 0 ms."""
    if raw <= 0x7F:
        return float(raw)
    if 0xF1 <= raw <= 0xF9:
        return (raw - 0xF0) / 10.0
    raise ISOTPError(f"reserved STmin value {raw:#04x}")


def _await_fc(read_flow_control, fc_timeout: float, max_wait_frames: int):
    """Read FC frames honouring N_Bs. The reader receives the remaining
    timeout budget and MUST be non-blocking or deadline-bound."""
    deadline = time.monotonic() + fc_timeout
    waits_left = max_wait_frames
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ISOTPError("N_Bs timeout waiting for FlowControl")
        fs, bs, st = read_flow_control(timeout=remaining)
        if fs == FC_CTS:
            return bs, st
        if fs == FC_WAIT:
            waits_left -= 1
            if waits_left < 0:
                raise ISOTPError("too many FC WAIT frames")
            continue
        raise ISOTPError(f"FC overflow/abort (FS={fs:#x})")


def isotp_send(payload: bytes,
               write: Callable[[bytes], None],
               read_flow_control: Callable[..., Tuple[int, int, int]],
               stmin_floor_ms: float = 0.0,
               fc_timeout: float = N_BS_TIMEOUT,
               max_wait_frames: int = 10) -> None:
    """Send one diagnostic message (classic CAN, 8-byte frames).

    read_flow_control(timeout=<seconds remaining>) -> (FS, BS, STmin)
    must return quickly; a blocking socket must use the given timeout.
    BS = 0 per spec means UNLIMITED consecutive frames (no invented
    block limit)."""
    n = len(payload)
    if n <= 7:                                          # SingleFrame
        write(bytes([0x0 | n]) + payload.ljust(8, b"\x00"))
        return
    if n > MAX_CLASSIC_PAYLOAD:
        raise ISOTPError(
            f"payload {n} bytes exceeds classic CAN ISO-TP maximum "
            f"{MAX_CLASSIC_PAYLOAD} (12-bit FF length; CAN-FD escape "
            "frames not implemented)")

    ff = bytes([0x10 | ((n >> 8) & 0x0F), n & 0xFF]) + payload[:6]
    write(ff.ljust(8, b"\x00"))                         # FirstFrame
    block_size, st_raw = _await_fc(read_flow_control, fc_timeout,
                                   max_wait_frames)     # N_Bs
    delay = max(_stmin_ms(st_raw), stmin_floor_ms) / 1000.0

    seq, sent_in_block = 0, 0
    for off in range(6, n, 7):                          # ConsecutiveFrames
        write((bytes([0x20 | (seq & 0x0F)]) + payload[off:off + 7])
              .ljust(8, b"\x00"))
        seq = (seq + 1) & 0x0F
        sent_in_block += 1
        if block_size and sent_in_block >= block_size:
            sent_in_block = 0
            block_size, st_raw = _await_fc(read_flow_control, fc_timeout,
                                           max_wait_frames)   # N_Bs
            delay = max(_stmin_ms(st_raw), stmin_floor_ms) / 1000.0
        time.sleep(delay)


def build_flow_control(fs: int = FC_CTS, block_size: int = 8,
                       stmin_raw: int = 10) -> bytes:
    """FC frame builder for the receiving side. FS strictly limited to
    CTS/WAIT/OVFL and STmin validated separately — no combined
    and/or condition that lets an invalid FS slip through."""
    if fs not in (FC_CTS, FC_WAIT, FC_OVFL):
        raise ISOTPError(f"invalid FlowStatus {fs:#04x}")
    if not (stmin_raw <= 0x7F or 0xF1 <= stmin_raw <= 0xF9):
        raise ISOTPError(f"invalid STmin {stmin_raw:#04x}")
    if not 0 <= block_size <= 0xFF:
        raise ISOTPError(f"invalid BlockSize {block_size:#x}")
    return bytes([0x30 | fs, block_size & 0xFF, stmin_raw]) + b"\x00" * 5
