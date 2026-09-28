"""Base transport abstraction for K+DCAN physical diagnostics.

Adapted from open6hp (https://github.com/Arkayda/open6hp) transport layer.
Copyright (c) open6hp contributors. Licensed under the MIT License.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, Protocol, runtime_checkable


class KdcanError(RuntimeError):
    """Transport-level failure: timeout, frame error, device disconnected."""


@runtime_checkable
class RawKdcanTransport(Protocol):
    """Protocol defining the raw K+DCAN wire transport interface."""

    def open(self) -> None:
        """Open physical port/device."""
        ...

    def close(self) -> None:
        """Close physical port/device."""
        ...

    def transceive_raw(
        self,
        wire_frame: bytes,
        timeout: Optional[float] = None,
    ) -> bytes:
        """Transmit raw DS2 wire frame and return raw DS2 wire response frame."""
        ...


class KdcanTransport(ABC):
    """Abstract communication interface to vehicle diagnostic gateway."""

    @abstractmethod
    def open(self) -> None:
        """Open physical port/device."""
        ...

    @abstractmethod
    def close(self) -> None:
        """Close physical port/device."""
        ...

    def __enter__(self) -> "KdcanTransport":
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @abstractmethod
    def send_job(
        self,
        dst: int,
        payload: bytes,
        src: int = 0xF1,
        timeout: Optional[float] = None,
    ) -> bytes:
        """Transmit DS2 frame and return the response payload."""
        ...

    def send_job_raw(
        self,
        dst: int,
        payload: bytes,
        src: int = 0xF1,
        timeout: Optional[float] = None,
    ) -> tuple[bytes, bytes, bytes, float]:
        """Transmit DS2 frame and return (raw_tx, raw_rx, payload, rtt_ms)."""
        import time
        from . import framing

        raw_tx = framing.build(dst, src, payload)
        t0 = time.perf_counter()
        resp_payload = self.send_job(dst, payload, src=src, timeout=timeout)
        rtt_ms = (time.perf_counter() - t0) * 1000.0
        raw_rx = framing.build(src, dst, resp_payload)
        return raw_tx, raw_rx, resp_payload, rtt_ms

    @abstractmethod
    def transceive_raw(
        self,
        wire_frame: bytes,
        timeout: Optional[float] = None,
    ) -> bytes:
        """Transmit raw DS2 wire frame and return raw DS2 response frame.

        Direct raw-wire primitive: exact bytes supplied must reach the backend
        without alteration.
        """
        ...
