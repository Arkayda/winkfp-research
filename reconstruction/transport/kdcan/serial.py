"""K+DCAN serial transport over FTDI/CH340 hardware in D-CAN / DS2 mode.

Adapted from open6hp (https://github.com/Arkayda/open6hp) SerialBmwFastTransport.
Copyright (c) open6hp contributors. Licensed under the MIT License.

Key behaviors:
- Serial 115200 8N1, raw BMW-FAST framing (cable firmware handles CAN translation).
- Automatic discovery of macOS FTDI/CH340 ports (/dev/cu.usbserial-*).
- Adaptive echo cancellation (cable may echo transmitted bytes).
- Enforced inter-byte timeouts and bus regeneration pause (regen_delay).
"""

from __future__ import annotations

import threading
import time
from typing import Optional

try:
    import serial
except ImportError:
    serial = None

from . import framing
from .base import KdcanError, KdcanTransport


class SerialKdcanTransport(KdcanTransport):
    """Direct serial K+DCAN transport implementation."""

    def __init__(
        self,
        port: Optional[str] = None,
        baud: int = 115200,
        adapter_echo: bool = False,
        response_timeout: float = 1.0,
        interbyte_timeout: float = 0.15,
        regen_delay: float = 0.015,
        dtr: Optional[bool] = None,
        rts: Optional[bool] = None,
    ) -> None:
        super().__init__()
        self.port = port
        self.baud = baud
        self.adapter_echo = adapter_echo
        self.response_timeout = response_timeout
        self.interbyte_timeout = interbyte_timeout
        self.regen_delay = regen_delay
        self._dtr = adapter_echo if dtr is None else dtr
        self._rts = adapter_echo if rts is None else rts
        self._ser: Optional[serial.Serial] = None
        self._last_response_at = 0.0
        self._lock = threading.RLock()

    @staticmethod
    def auto_detect_port() -> Optional[str]:
        """Auto-detect available K+DCAN serial adapter port (FTDI / CH340)."""
        if serial is None:
            return None
        try:
            from serial.tools import list_ports

            ports = list_ports.comports()
            candidates = [
                p.device
                for p in ports
                if "usbserial" in p.device.lower()
                or "0403:6001" in (p.hwid or "")
                or "ch340" in p.device.lower()
                or "wchusbserial" in p.device.lower()
            ]
            if candidates:
                # Prefer /dev/cu.* on macOS
                cu_ports = [p for p in candidates if "cu." in p]
                return cu_ports[0] if cu_ports else candidates[0]
        except Exception:
            pass
        return None

    def open(self) -> None:
        with self._lock:
            if self._ser is not None:
                return
            if serial is None:
                raise ImportError(
                    "pyserial is required for K+DCAN physical communication: pip install pyserial"
                )
            if not self.port:
                self.port = self.auto_detect_port()
            if not self.port:
                raise KdcanError("No K+DCAN serial adapter found or specified")
            try:
                self._ser = serial.Serial(
                    port=self.port,
                    baudrate=self.baud,
                    bytesize=serial.EIGHTBITS,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE,
                    timeout=self.interbyte_timeout,
                    write_timeout=1.0,
                    exclusive=True,
                )
            except TypeError:
                self._ser = serial.Serial(
                    port=self.port,
                    baudrate=self.baud,
                    bytesize=serial.EIGHTBITS,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE,
                    timeout=self.interbyte_timeout,
                    write_timeout=1.0,
                )
            except Exception as exc:
                self._ser = None
                raise KdcanError(f"Failed to open port {self.port}: {exc}") from exc
            self._ser.dtr = self._dtr
            self._ser.rts = self._rts

    def close(self) -> None:
        with self._lock:
            if self._ser is not None:
                try:
                    self._ser.close()
                except Exception:
                    pass
                self._ser = None

    def send_job_raw(
        self,
        dst: int,
        payload: bytes,
        src: int = 0xF1,
        timeout: Optional[float] = None,
    ) -> tuple[bytes, bytes, bytes, float]:
        """Transmit DS2 frame and return (raw_tx, raw_rx, payload, rtt_ms)."""
        with self._lock:
            if self._ser is None:
                self.open()
            if self._ser is None:
                raise KdcanError(
                    f"K+DCAN adapter not connected ({self.port or 'waiting for device'})"
                )
            frame = framing.build(dst, src, payload)
            self._wait_regen()
            eff_timeout = self.response_timeout if timeout is None else timeout
            t0 = time.perf_counter()
            try:
                self._ser.reset_input_buffer()
                self._ser.write(frame)
                self._ser.flush()
                if self.adapter_echo:
                    self._read_echo(frame)
                response = self._read_telegram(eff_timeout)
                rtt_ms = (time.perf_counter() - t0) * 1000.0
                self._last_response_at = time.monotonic()
                parsed = framing.parse(response)
                # Auto-detect cable echo: if we received our own outgoing frame
                if parsed.dst == dst and parsed.src == src:
                    self.adapter_echo = True
                    t0 = time.perf_counter()
                    response = self._read_telegram(eff_timeout)
                    rtt_ms = (time.perf_counter() - t0) * 1000.0
                    self._last_response_at = time.monotonic()
                    parsed = framing.parse(response)
                if parsed.dst != src:
                    raise KdcanError(
                        f"Response not addressed to us: dst=0x{parsed.dst:02X} (expected 0x{src:02X})"
                    )
                if parsed.src != dst:
                    raise KdcanError(
                        f"Response from unexpected ECU: src=0x{parsed.src:02X} (expected 0x{dst:02X})"
                    )
                return frame, response, parsed.payload, rtt_ms
            except Exception:
                try:
                    if self._ser is not None:
                        self._ser.reset_input_buffer()
                except Exception:
                    pass
                raise
            finally:
                self._last_response_at = time.monotonic()

    def send_job(
        self,
        dst: int,
        payload: bytes,
        src: int = 0xF1,
        timeout: Optional[float] = None,
    ) -> bytes:
        _raw_tx, _raw_rx, parsed_payload, _rtt = self.send_job_raw(
            dst, payload, src=src, timeout=timeout
        )
        return parsed_payload

    def transceive_raw(
        self,
        wire_frame: bytes,
        timeout: Optional[float] = None,
    ) -> bytes:
        """Transmit exact DS2 wire frame and return raw response frame without re-encoding."""
        with self._lock:
            if self._ser is None:
                self.open()
            if self._ser is None:
                raise KdcanError(
                    f"K+DCAN adapter not connected ({self.port or 'waiting for device'})"
                )
            self._wait_regen()
            eff_timeout = self.response_timeout if timeout is None else timeout
            try:
                self._ser.reset_input_buffer()
                self._ser.write(wire_frame)
                self._ser.flush()
                if self.adapter_echo:
                    self._read_echo(wire_frame)
                response = self._read_telegram(eff_timeout)
                self._last_response_at = time.monotonic()
                if response == wire_frame:
                    self.adapter_echo = True
                    response = self._read_telegram(eff_timeout)
                    self._last_response_at = time.monotonic()
                return response
            except Exception:
                try:
                    if self._ser is not None:
                        self._ser.reset_input_buffer()
                except Exception:
                    pass
                raise
            finally:
                self._last_response_at = time.monotonic()

    def _wait_regen(self) -> None:
        elapsed = time.monotonic() - self._last_response_at
        if elapsed < self.regen_delay:
            time.sleep(self.regen_delay - elapsed)

    def _read_echo(self, frame: bytes) -> None:
        echoed = self._read_exact(len(frame))
        if echoed != frame:
            raise KdcanError(
                f"Adapter echo mismatch: received {echoed.hex(' ') if echoed else '<empty>'}"
            )

    def _read_telegram(self, timeout: float) -> bytes:
        header = self._read_exact(4, first_timeout=timeout)
        if len(header) < 4:
            raise KdcanError("No response from ECU (header timeout)")
        if header[0] & 0x3F == 0 and len(header) < 6:
            needs = 6 if header[3] == 0 else 4
            more = self._read_exact(needs - len(header))
            header += more
            if len(header) < needs:
                raise KdcanError("Incomplete header from ECU (timeout)")
        total = framing.body_length(header)
        rest = self._read_exact(total + 1 - len(header))
        if len(header) + len(rest) < total + 1:
            raise KdcanError("Incomplete response body from ECU (timeout)")
        return header + rest

    def _read_exact(self, count: int, first_timeout: float | None = None) -> bytes:
        assert self._ser is not None
        if count <= 0:
            return b""
        buf = b""
        if first_timeout is not None:
            saved = self._ser.timeout
            self._ser.timeout = first_timeout
            first = self._ser.read(1)
            self._ser.timeout = saved
            if not first:
                return b""
            buf = first
        while len(buf) < count:
            chunk = self._ser.read(count - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf
