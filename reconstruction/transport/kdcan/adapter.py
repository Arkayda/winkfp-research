"""K+DCAN DiagnosticTransport Adapter (Milestone 5.13).

Adapts the native K+DCAN transport layer (reconstruction.transport.kdcan) to the
canonical DiagnosticTransport protocol (reconstruction.ediabas.transport).

STRICT ARCHITECTURAL BOUNDARY:
- Pure byte-level boundary: transceive_ds2(wire_frame: bytes, timeout: float = 1.0) -> bytes.
- The adapter accepts raw DS2 wire frame bytes and returns raw DS2 wire response bytes.
- The adapter knows NOTHING about:
    * WinKFP / EDIABAS jobs
    * SGBD routines or logic
    * Evidence classifications
    * Dangerous service IDs
    * ECU job names
- auto_open: bool = False by default (hardware quarantine; no automatic opening).
- Exception translation:
    * TimeoutError or KdcanError with 'timeout' -> TransportTimeoutError
    * Other KdcanError or lower-level Exception -> TransportError
    * Existing TransportError/TransportTimeoutError re-raised as-is.
"""

import time
from typing import Dict, List, Optional, Tuple

from reconstruction.ediabas.transport import (
    DiagnosticTransport,
    TransportError,
    TransportTimeoutError,
)
from .base import KdcanError, KdcanTransport
from . import framing


class KdcanDiagnosticAdapter:
    """Adapts any KdcanTransport backend to the canonical DiagnosticTransport protocol.

    PURE BYTE-LEVEL PROTOCOL BOUNDARY:
    - Accepts raw DS2 wire frame (bytes)
    - Returns raw DS2 wire response frame (bytes)
    - Fully decoupled from SGBD semantics and WinKFP logic.
    """

    def __init__(
        self,
        backend: KdcanTransport,
        auto_open: bool = False,
    ) -> None:
        """Initialize the adapter.

        Args:
            backend: Underlying KdcanTransport instance.
            auto_open: If True, automatically call backend.open() on transceive.
                       Defaults to False (hardware-quarantined offline safety).
        """
        self.backend = backend
        self.auto_open = auto_open
        self.history: List[Tuple[bytes, float]] = []
        self.response_history: List[bytes] = []
        self.rtt_history: List[float] = []

    def transceive_ds2(
        self,
        wire_frame: bytes,
        timeout: float = 1.0,
    ) -> bytes:
        """Transmit raw DS2 wire frame and return raw DS2 wire response frame.

        Args:
            wire_frame: Complete physical DS2 request frame (bytes, with checksum).
            timeout: Response timeout in seconds.

        Returns:
            Complete physical DS2 wire response frame (bytes, with checksum).

        Raises:
            TransportTimeoutError: If response timeout occurs.
            TransportError: If underlying transport or communication fails.
        """
        if self.auto_open:
            self.backend.open()

        self.history.append((wire_frame, timeout))

        t0 = time.perf_counter()
        try:
            resp = self.backend.transceive_raw(wire_frame, timeout=timeout)
            rtt_ms = (time.perf_counter() - t0) * 1000.0
            self.response_history.append(resp)
            self.rtt_history.append(rtt_ms)
            return resp
        except (TransportTimeoutError, TransportError):
            raise
        except TimeoutError as exc:
            raise TransportTimeoutError(f"K+DCAN transceive timeout: {exc}") from exc
        except KdcanError as exc:
            msg = str(exc).lower()
            if "timeout" in msg:
                raise TransportTimeoutError(f"K+DCAN transceive timeout: {exc}") from exc
            raise TransportError(f"K+DCAN transport error: {exc}") from exc
        except Exception as exc:
            raise TransportError(f"K+DCAN communication failure: {exc}") from exc


class ScriptedKdcanBackend(KdcanTransport):
    """Offline scriptable KdcanTransport backend for deterministic testing and simulation.

    Operates strictly off-hardware. Does not open any physical serial port.
    """

    def __init__(
        self,
        responses: Optional[Dict[bytes, bytes]] = None,
        default_response: Optional[bytes] = None,
        timeout_error: bool = False,
        bus_error: Optional[Exception] = None,
    ) -> None:
        self.responses: Dict[bytes, bytes] = dict(responses) if responses else {}
        self.default_response = default_response
        self.timeout_error = timeout_error
        self.bus_error = bus_error
        self.is_open: bool = False
        self.history: List[Tuple[bytes, Optional[float]]] = []

    def open(self) -> None:
        self.is_open = True

    def close(self) -> None:
        self.is_open = False

    def add_response(self, request_wire: bytes, response_wire: bytes) -> None:
        """Register a canned request->response wire frame mapping."""
        self.responses[request_wire] = response_wire

    def transceive_raw(
        self,
        wire_frame: bytes,
        timeout: Optional[float] = None,
    ) -> bytes:
        """Transmit raw wire frame and return canned response frame."""
        self.history.append((wire_frame, timeout))
        if self.timeout_error:
            raise KdcanError(f"Response timeout after {int((timeout or 1.0) * 1000)}ms")
        if self.bus_error is not None:
            raise self.bus_error

        if wire_frame in self.responses:
            return self.responses[wire_frame]
        if self.default_response is not None:
            return self.default_response

        raise KdcanError(f"ScriptedKdcanBackend: unhandled wire frame: {wire_frame.hex()}")

    def send_job(
        self,
        dst: int,
        payload: bytes,
        src: int = 0xF1,
        timeout: Optional[float] = None,
    ) -> bytes:
        """Transmit job payload via framing and return response payload."""
        raw_tx = framing.build(dst, src, payload)
        raw_rx = self.transceive_raw(raw_tx, timeout=timeout)
        parsed = framing.parse(raw_rx)
        return parsed.payload
