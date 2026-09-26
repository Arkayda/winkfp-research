"""Base transport abstraction for K+DCAN physical diagnostics.

Adapted from open6hp (https://github.com/Arkayda/open6hp) transport layer.
Copyright (c) open6hp contributors. Licensed under the MIT License.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class KdcanError(RuntimeError):
    """Transport-level failure: timeout, frame error, device disconnected."""


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
