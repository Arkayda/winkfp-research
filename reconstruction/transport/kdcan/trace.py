"""Diagnostic session tracing for K+DCAN wire transactions.

Adapted from open6hp (https://github.com/Arkayda/open6hp) SessionTracer.
Copyright (c) open6hp contributors. Licensed under the MIT License.
"""

from __future__ import annotations

import datetime
import time
from pathlib import Path
from typing import Optional, TextIO

from . import framing
from .base import KdcanTransport


def _hexdump(data: bytes) -> str:
    return " ".join(f"{b:02X}" for b in data)


def _ascii_preview(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in data)


class SessionTracer:
    """Detailed file and memory logger for raw K+DCAN wire interactions."""

    def __init__(self, log_path: Optional[str | Path] = None) -> None:
        if log_path is None:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.log_path = Path("logs") / f"kdcan_trace_{ts}.log"
        else:
            self.log_path = Path(log_path)
        self._file: Optional[TextIO] = None
        self.records: list[dict] = []

    def open(self) -> None:
        if self._file is not None:
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.log_path, "a", encoding="utf-8")
        self.log_comment(f"=== Session Started: {datetime.datetime.now().isoformat()} ===")
        self.log_comment("=== WinKFP-Research Direct K+DCAN Wire Trace ===")

    def close(self) -> None:
        if self._file is not None:
            self.log_comment(f"=== Session Ended: {datetime.datetime.now().isoformat()} ===")
            self._file.close()
            self._file = None

    def log_comment(self, comment: str) -> None:
        line = f"# {comment}\n"
        if self._file:
            self._file.write(line)
            self._file.flush()

    def log_tx(self, dst: int, src: int, payload: bytes, raw_frame: Optional[bytes] = None) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        raw = raw_frame or framing.build(dst, src, payload)
        self.records.append({
            "timestamp": ts,
            "direction": "TX",
            "dst": dst,
            "src": src,
            "raw": raw,
            "payload": payload,
        })
        line = (
            f"[{ts}] TX dst=0x{dst:02X} src=0x{src:02X} len={len(payload)}\n"
            f"       RAW: {_hexdump(raw)}\n"
            f"       PAY: {_hexdump(payload)} | {_ascii_preview(payload)}\n"
        )
        if self._file:
            self._file.write(line)
            self._file.flush()

    def log_rx(
        self,
        dst: int,
        src: int,
        payload: bytes,
        raw_frame: Optional[bytes] = None,
        duration_ms: Optional[float] = None,
    ) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        dur_str = f" rtt={duration_ms:.1f}ms" if duration_ms is not None else ""
        raw = raw_frame or framing.build(dst, src, payload)
        self.records.append({
            "timestamp": ts,
            "direction": "RX",
            "dst": dst,
            "src": src,
            "raw": raw,
            "payload": payload,
            "duration_ms": duration_ms,
        })
        line = (
            f"[{ts}] RX dst=0x{dst:02X} src=0x{src:02X} len={len(payload)}{dur_str}\n"
            f"       RAW: {_hexdump(raw)}\n"
            f"       PAY: {_hexdump(payload)} | {_ascii_preview(payload)}\n"
        )
        if self._file:
            self._file.write(line)
            self._file.flush()

    def log_error(self, message: str) -> None:
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        line = f"[{ts}] ERROR: {message}\n"
        if self._file:
            self._file.write(line)
            self._file.flush()


class TracedKdcanTransport(KdcanTransport):
    """Decorator wrapping any KdcanTransport with automatic SessionTracer logging."""

    def __init__(self, inner: KdcanTransport, tracer: SessionTracer) -> None:
        self.inner = inner
        self.tracer = tracer

    def open(self) -> None:
        self.tracer.open()
        try:
            self.inner.open()
        except Exception as exc:
            self.tracer.log_error(f"Failed to open transport: {exc}")
            raise

    def close(self) -> None:
        try:
            self.inner.close()
        finally:
            self.tracer.close()

    def send_job(
        self,
        dst: int,
        payload: bytes,
        src: int = 0xF1,
        timeout: Optional[float] = None,
    ) -> bytes:
        raw_tx = framing.build(dst, src, payload)
        self.tracer.log_tx(dst, src, payload, raw_frame=raw_tx)
        start = time.monotonic()
        try:
            response_payload = self.inner.send_job(dst, payload, src=src, timeout=timeout)
            duration_ms = (time.monotonic() - start) * 1000.0
            raw_rx = framing.build(src, dst, response_payload)
            self.tracer.log_rx(src, dst, response_payload, raw_frame=raw_rx, duration_ms=duration_ms)
            return response_payload
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000.0
            self.tracer.log_error(f"send_job failed after {duration_ms:.1f}ms: {exc}")
            raise

    def send_job_raw(
        self,
        dst: int,
        payload: bytes,
        src: int = 0xF1,
        timeout: Optional[float] = None,
    ) -> tuple[bytes, bytes, bytes, float]:
        raw_tx = framing.build(dst, src, payload)
        self.tracer.log_tx(dst, src, payload, raw_frame=raw_tx)
        start = time.monotonic()
        try:
            raw_tx_out, raw_rx_out, response_payload, duration_ms = self.inner.send_job_raw(
                dst, payload, src=src, timeout=timeout
            )
            self.tracer.log_rx(src, dst, response_payload, raw_frame=raw_rx_out, duration_ms=duration_ms)
            return raw_tx_out, raw_rx_out, response_payload, duration_ms
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000.0
            self.tracer.log_error(f"send_job_raw failed after {duration_ms:.1f}ms: {exc}")
            raise
