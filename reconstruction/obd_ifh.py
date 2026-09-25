"""Pure-Python reconstruction of the EDIABAS IFH driver OBD32.dll
(STD:OBD interface handler, K-Line over the serial OBD head).

Reversed from OBD32.dll 6.4.7 (execution-differential-proven in
obd_emulate.py — original machine code under Unicorn vs this model):

  export INITIALIZE 0x100040c0 -> FUN_100024c0 (obd.ini defaults)
                            + FUN_10001800: open COM at 9600 8E1
  export WRITEDATA  0x100041b0 -> FUN_10001320 interface-command dispatch
  export READDATA   0x100041f0: hand out the global answer buffer
  answer layout: [status][len LE16][payload], len = payload + 3

  cmd 1  FUN_10004290 purge + re-read obd.ini + reopen COM
  cmd 2  FUN_10004300 close (protocol := 0)
  cmd 5  FUN_100048b0 set line parameters from payload words
                -> FUN_10004d10 ctx + FUN_10001680 SetCommState
  cmd 6  FUN_10004a70 send_and_receive telegram (protocol from ctx)
  cmd 7  FUN_100047f0 receive-only
  cmd 10 FUN_10004330 protocol probe: DS2@9600 8E1, then KWP@115200 8N1,
                each announced with the wake telegram 00 55 FF (sent
                without checksum), protocol ctx reset afterwards

  telegram send FUN_100019e0 -> FUN_10001b40 (SendData):
    P4 gap wait -> PurgeComm(0xC) -> optional per-byte timed writes ->
    K-Line echo read-back & compare; mismatch = collision.  obd.ini
    RETRY=ON (default OFF) then auto-resends the telegram ONCE.
    With the ctx checksum flag (default on) FUN_10001220 first APPENDS
    the XOR checksum byte to the telegram — the SGBD supplies the frame
    without it, the driver completes it.
  telegram recv FUN_100022d0:
    [hdr][total_len][payload..] with first-byte/inter-byte timeouts,
    hdr==0xB8 selects the long-frame variant; FUN_100012a0 verifies
    XOR of the whole frame == 0 when the ctx verify flag is on.
"""

from __future__ import annotations

import struct as _struct
from dataclasses import dataclass, field


def _pack_params(*words: int) -> bytes:
    return _struct.pack(f"<{len(words)}H", *words)

# interface command codes (first byte of the WRITEDATA payload)
CMD_REINIT = 1
CMD_CLOSE = 2
CMD_SET_PARAMS = 5
CMD_SEND_RECV = 6
CMD_RECV = 7
CMD_PROBE_PROTOCOLS = 10

# protocol ids stored in the port context (FUN_10004d10)
PROT_DS2_KLINE = 6          # BMW DS2 / K-Line 9600 8E1
PROT_KWP_FAST = 0xF         # KWP, 115200 8N1 (baud word 0xC200 -> 0x1C200)

WAKE_PATTERN = bytes((0x00, 0x55, 0xFF))     # cmd10 wake-up telegram
LONG_FRAME_HDR = 0xB8                        # alternate response framing


def xor_checksum(frame: bytes) -> int:
    """FUN_10001220/100012a0: XOR over every byte; a valid frame folds to 0."""
    c = 0
    for b in frame:
        c ^= b
    return c


def build_frame(payload: bytes, hdr: int = 0x80, with_checksum: bool = False):
    """[hdr][total_len][payload] (+ [xor] when with_checksum).
    total_len counts the whole frame INCLUDING the checksum byte."""
    total = 2 + len(payload) + (1 if with_checksum else 0)
    frame = bytes((hdr, total)) + payload
    if with_checksum:
        frame += bytes((xor_checksum(frame),))
    return frame


def parse_frame(data: bytes) -> tuple[int, bytes]:
    """Split a raw (checksum-verified) frame into (header, payload)."""
    if len(data) < 2:
        raise ValueError("short frame")
    if data[1] != len(data):
        raise ValueError(f"len byte {data[1]} != {len(data)}")
    return data[0], data[2:-1]


class ComDevice:
    """Virtual K-Line COM head: echoes writes, queues ECU bytes."""

    def __init__(self, echo: bool = True):
        self.echo = echo
        self.rx: bytearray = bytearray()
        self.writes: list[bytes] = []               # one entry per WriteFile
        self.dcb: list[tuple[int, int, int]] = []   # (baud, bytesize, parity)
        self.on_write = None                        # called after each write

    def write(self, data: bytes) -> None:
        self.writes.append(bytes(data))
        if self.echo:
            self.rx += data
        if self.on_write:
            self.on_write(bytes(data))

    def feed(self, data: bytes) -> None:
        self.rx += data

    def read(self, n: int) -> bytes:
        out = bytes(self.rx[:n])
        del self.rx[:n]
        return out

    @property
    def cb_in_que(self) -> int:
        return len(self.rx)


@dataclass
class PortContext:
    """The 0x40-byte block at DAT_10015940 (FUN_10004d10 / FUN_10004f10)."""
    protocol: int = 0
    baud: int = 9600
    t_first_ms: int = 100       # ctx+0x14 first-byte timeout (0 -> 60000)
    p4_gap_ms: int = 10         # ctx+0x18 min gap between telegrams
    t_interbyte_ms: int = 10    # ctx+0x1c inter-byte timeout
    byte_delay_ms: int = 0      # ctx+0x20 per-byte send delay
    append_checksum: bool = True    # ctx+0x34 flag bit0 (FUN_10001220)
    verify_checksum: bool = True    # ctx+0x30 flag bit2 == 0
    bytesize: int = 8           # ctx+0x28
    parity: int = 2             # ctx+0x2c EVEN for DS2, NONE for KWP
    dtr: int = 0                # ctx+0x38


@dataclass
class IfhState:
    status: int = 0
    answer: bytearray = field(default_factory=bytearray)


class ObdIfh:
    """API-compatible model of the OBD32.dll IFH exports."""

    def __init__(self, dev: ComDevice):
        self.dev = dev
        self.ctx = PortContext()
        self.st = IfhState()
        self.port_open = False
        self.events: list[tuple] = []
        self.retry = False       # obd.ini RETRY: OFF default; ON = auto-resend
        self.now_ms = 0          # mock clock (P4 bookkeeping, DAT_1000ff84)
        self.next_allowed_ms = 0
        self.last_frame: bytes = b""

    # -- helpers ----------------------------------------------------------
    def _evt(self, kind: str, *data):
        self.events.append((kind,) + data)

    def _answer(self, status: int, payload: bytes = b""):
        ln = len(payload) + 3
        self.st.answer = bytearray(bytes((status,)) +
                                   ln.to_bytes(2, "little") + payload)

    # -- exports ----------------------------------------------------------
    def initialize(self) -> int:
        """INITIALIZE: obd.ini defaults (RETRY=OFF) + open COM 9600 8E1."""
        self.st.status = 0
        self._open_port()
        return 0

    def _open_port(self, baud: int = 9600, bytesize: int = 8,
                   parity: int = 2) -> None:
        """FUN_10001800: CreateFileA + SetupComm(20000) + Purge + DCB."""
        self.port_open = True
        self._evt("setupcomm", 20000, 20000)
        self._evt("purge", 0xC)
        self.dev.dcb.append((baud, bytesize, parity))
        self._evt("set_comm_state", baud, bytesize, parity)

    def writedata(self, data: bytes) -> int:
        """WRITEDATA: interface-command dispatcher FUN_10001320."""
        self.st.status = 2
        cmd = data[0]
        if cmd == CMD_REINIT:
            self.ctx.protocol = 0
            self._evt("purge", 0xC)               # FUN_10001970
            self._open_port()
            self._answer(1)
            return 0
        if cmd == CMD_CLOSE:
            self.ctx.protocol = 0
            self.port_open = False
            self._answer(1)
            return 0
        if cmd == CMD_SET_PARAMS:
            self._set_params(data[3:])
            ok = self._setup_connection()
            self._answer(1 if ok else 4)
            return 0
        if cmd == CMD_SEND_RECV:
            self._send_and_receive(data[3:])
            return 0
        if cmd == CMD_RECV:
            self._receive_only()
            return 0
        if cmd == CMD_PROBE_PROTOCOLS:
            self._probe_protocols()
            return 0
        self._answer(5)                           # unknown command
        return 0

    def readdata(self) -> bytes:
        """READDATA: the global answer buffer (unchanged until next job)."""
        self.st.status = 0
        return bytes(self.st.answer)

    # -- parameter blocks (FUN_10004d10 = DS2, FUN_10004f10 = KWP) --------
    def _set_params(self, words: bytes) -> None:
        w = [int.from_bytes(words[i:i + 2], "little")
             for i in range(0, min(len(words), 20), 2)]
        c = self.ctx
        c.protocol = 6 if w[0] == 5 else w[0]
        c.baud = 0x1C200 if w[1] == 0xC200 else w[1]
        if len(w) > 5:
            c.t_first_ms = w[5] or 60000
            c.p4_gap_ms = w[6]
            c.t_interbyte_ms = w[7]
        if len(w) > 8:
            c.byte_delay_ms = w[8]
        flags = w[9] if len(w) > 9 else 1
        c.append_checksum = bool(flags & 1)
        c.verify_checksum = (flags & 2) == 0
        if c.protocol == 4:
            c.protocol = 2

    def _set_params_kwp(self, words: bytes) -> None:
        """FUN_10004f10: direct ctx fields — 8 data bits, NO parity, DTR."""
        w = [int.from_bytes(words[i:i + 2], "little")
             for i in range(0, len(words), 2)]
        c = self.ctx
        c.protocol = w[0] & 0xFF
        c.baud = 0x1C200 if w[1] == 0xC200 else w[1]
        c.t_first_ms, c.p4_gap_ms, c.t_interbyte_ms = w[2], w[3], w[4]
        c.byte_delay_ms = 0
        c.bytesize, c.parity, c.dtr = 8, 0, 1
        flags = w[7] if len(w) > 7 else 1
        c.append_checksum = bool(flags & 1)
        c.verify_checksum = (flags & 2) == 0

    def _setup_connection(self) -> bool:
        """FUN_10001680: purge + DCB from context (SetupConnection)."""
        self._evt("purge", 0xC)
        self.dev.dcb.append((self.ctx.baud, self.ctx.bytesize,
                             self.ctx.parity))
        self._evt("set_comm_state", self.ctx.baud, self.ctx.bytesize,
                  self.ctx.parity)
        return True

    # -- telegram layer ----------------------------------------------------
    def _send_telegram(self, frame: bytes, checksum: bool | None = None):
        """FUN_100019e0: optional checksum append + SendData (+1 retry)."""
        if checksum is None:
            checksum = self.ctx.append_checksum
        if checksum:                              # FUN_10001220
            frame = frame + bytes((xor_checksum(frame),))
        attempts = 2 if self.retry else 1         # sVar1==2 -> one resend
        for _ in range(attempts):
            if self._send_data(frame) == 0:
                return True
        return False

    def _send_data(self, frame: bytes) -> int:
        """FUN_10001b40: P4 wait, purge, write, echo compare.
        0 = ok, 1 = fail, 2 = collision (auto-resendable)."""
        if self.ctx.p4_gap_ms and self.now_ms < self.next_allowed_ms:
            self.now_ms = self.next_allowed_ms
        self._evt("purge", 0xC)
        if self.ctx.byte_delay_ms < 1:
            self.dev.write(frame)
        else:
            for b in frame:                       # per-byte timed path
                self.dev.write(bytes((b,)))
        echo = self.dev.read(len(frame))
        if echo != frame:                          # K-Line echo mismatch
            return 2 if not self.retry else 1
        if self.ctx.p4_gap_ms:
            self.next_allowed_ms = self.now_ms + self.ctx.p4_gap_ms
        return 0

    def _read_byte(self, timeout_ms: int):
        """FUN_100020f0: poll cbInQue every 1ms, then read one byte."""
        if self.dev.cb_in_que:
            return self.dev.read(1)[0]
        if timeout_ms:
            deadline = self.now_ms + 1 + timeout_ms
            while self.now_ms < deadline:
                self.now_ms += 1                  # Sleep(1)
                if self.dev.cb_in_que:
                    return self.dev.read(1)[0]
        return None

    def _read_telegram(self) -> int:
        """FUN_100022d0: [hdr][len][payload..], optional XOR check.
        1 ok, 2 first-byte timeout, 3 inter-byte/checksum error."""
        hdr = self._read_byte(self.ctx.t_first_ms)
        if hdr is None:
            return 2
        ln = self._read_byte(self.ctx.t_interbyte_ms)
        if ln is None:
            return 3
        frame = bytearray((hdr, ln))
        if hdr == LONG_FRAME_HDR:
            total = None
            while len(frame) < 4:
                b = self._read_byte(self.ctx.t_interbyte_ms)
                if b is None:
                    return 3
                frame.append(b)
            total = frame[3] + 4
            while len(frame) < total:
                b = self._read_byte(self.ctx.t_interbyte_ms)
                if b is None:
                    return 3
                frame.append(b)
        else:
            while len(frame) < max(2, ln):
                b = self._read_byte(self.ctx.t_interbyte_ms)
                if b is None:
                    return 3
                frame.append(b)
        if self.ctx.p4_gap_ms:
            self.next_allowed_ms = self.now_ms + self.ctx.p4_gap_ms
        if self.ctx.verify_checksum and xor_checksum(frame) != 0:
            return 3
        self.last_frame = bytes(frame)
        return 1

    # -- commands 6/7/10 ----------------------------------------------------
    def _send_and_receive(self, telegram: bytes) -> None:
        """cmd 6 -> FUN_10004a70 -> FUN_10002230 (K-Line protocol path)."""
        if self.ctx.protocol == PROT_DS2_KLINE:
            res = 1
            if telegram:
                if not self._send_telegram(telegram):
                    res = 0x71                    # send failed
            if res == 1:
                res = self._read_telegram()
        else:
            res = 4                                # protocol not set up
        if res == 1:
            self._answer(1, self.last_frame)       # +3 header in _answer
        else:
            self._answer(res)

    def _receive_only(self) -> None:
        """cmd 7 -> FUN_100047f0."""
        res = self._read_telegram()
        if res == 1:
            self._answer(1, self.last_frame)
        else:
            self._answer(res)

    def _probe_protocols(self) -> None:
        """cmd 10 -> FUN_10004330: DS2@9600 then KWP@115200, wake 00 55 FF
        (wake is sent WITHOUT checksum), protocol ctx reset afterwards."""
        p6 = _pack_params(PROT_DS2_KLINE, 9600, 0, 0, 0, 100, 10, 10)
        self._set_params(p6)
        if not (self._setup_connection()
                and self._send_telegram(WAKE_PATTERN, checksum=False)):
            self.ctx.protocol = 0
            self._answer(6)
            return
        pf = _pack_params(PROT_KWP_FAST, 0xC200, 100, 10, 10, 0, 0)
        self._set_params_kwp(pf)
        if not (self._setup_connection()
                and self._send_telegram(WAKE_PATTERN, checksum=False)):
            self.ctx.protocol = 0
            self._answer(6)
            return
        self.ctx.protocol = 0                      # success resets it
        self._answer(1)
