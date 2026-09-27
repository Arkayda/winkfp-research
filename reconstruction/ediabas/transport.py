"""Offline-First Diagnostic Transport Boundary.

Defines the minimal byte-level transceive contract between the canonical GKE195
job/pipeline layer and communication backends.

STRICT PROTOCOL BOUNDARY:
- DiagnosticTransport knows NOTHING about:
    * SGBD jobs
    * WinKFP / EDIABAS result fields
    * Evidence classifications
- DiagnosticTransport ONLY transmits and receives raw DS2 wire frames.
- STRICTLY OFF-HARDWARE: Provides offline FixtureTransport and MockTransport.
  Physical serial transport remains isolated in reconstruction.transport.kdcan.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Set, Tuple, Union

from .trace_loader import TraceFixture, load_trace_fixture


class TransportError(Exception):
    """Base error for diagnostic transport communication failures."""
    pass


class TransportTimeoutError(TransportError):
    """Raised when diagnostic transceive times out waiting for a response."""
    pass


class DiagnosticTransport(Protocol):
    """Pure byte-level transport protocol for DS2 diagnostic communication."""

    def transceive_ds2(self, wire_frame: bytes, timeout: float = 1.0) -> bytes:
        """Transmit a canonical DS2 wire frame and receive the raw DS2 response frame.

        Args:
            wire_frame: Complete physical DS2 request frame (including trailing checksum).
            timeout: Response timeout in seconds.

        Returns:
            Complete physical DS2 wire response frame (including trailing checksum).

        Raises:
            TransportTimeoutError: If no response is received within timeout.
            TransportError: On lower-level transport communication failure.
        """
        ...


class FixtureTransport:
    """Offline transport replaying immutable stored responses from traces or fixtures.

    Authoritative offline implementation: exercises the canonical request building,
    framing validation, and SGBD parsing path against stored trace data.
    """

    def __init__(
        self,
        fixture_or_data: Union[TraceFixture, bytes, bytearray, dict, str, Path],
        expected_tx: Optional[bytes] = None,
        strict_tx_match: bool = False,
        source_name: Optional[str] = None,
    ):
        self.source_name = source_name
        self.expected_tx = expected_tx
        self.strict_tx_match = strict_tx_match
        self._raw_rx: bytes = b""
        self.history: List[bytes] = []

        # Resolve fixture input to raw bytes
        if isinstance(fixture_or_data, TraceFixture):
            self._raw_rx = fixture_or_data.raw_rx
            self.expected_tx = expected_tx or fixture_or_data.raw_tx
            self.source_name = source_name or fixture_or_data.path.name
        elif isinstance(fixture_or_data, (str, Path)):
            p = Path(fixture_or_data)
            self.source_name = source_name or p.name
            if p.suffix.lower() == ".json":
                tf = load_trace_fixture(p)
                self._raw_rx = tf.raw_rx
                self.expected_tx = expected_tx or tf.raw_tx
            else:
                # Raw hex string
                s = str(fixture_or_data).replace(" ", "").strip()
                try:
                    self._raw_rx = bytes.fromhex(s)
                except ValueError as exc:
                    raise TransportError(f"Invalid hex string for fixture transport: {exc}") from exc
        elif isinstance(fixture_or_data, dict):
            for k in ("raw_rx", "rx", "raw"):
                if k in fixture_or_data and isinstance(fixture_or_data[k], (bytes, bytearray)):
                    self._raw_rx = bytes(fixture_or_data[k])
                    break
                if k in fixture_or_data and isinstance(fixture_or_data[k], str):
                    try:
                        self._raw_rx = bytes.fromhex(fixture_or_data[k].replace(" ", "").strip())
                        break
                    except ValueError:
                        pass
            if not self._raw_rx and "tx" in fixture_or_data and "rx" in fixture_or_data:
                raise TransportError("Dict fixture must contain raw response bytes in 'rx' or 'raw_rx'")
        elif isinstance(fixture_or_data, (bytes, bytearray)):
            self._raw_rx = bytes(fixture_or_data)
        else:
            raise TransportError(f"Unsupported fixture input type: {type(fixture_or_data)}")

    @property
    def raw_response(self) -> bytes:
        """Stored raw response frame."""
        return self._raw_rx

    def transceive_ds2(self, wire_frame: bytes, timeout: float = 1.0) -> bytes:
        """Return the stored raw response, optionally asserting TX frame match."""
        self.history.append(wire_frame)

        if self.strict_tx_match and self.expected_tx is not None:
            if wire_frame != self.expected_tx:
                raise TransportError(
                    f"FixtureTransport strict TX mismatch: expected {self.expected_tx.hex(' ').upper()}, "
                    f"got {wire_frame.hex(' ').upper()}"
                )

        if not self._raw_rx:
            raise TransportError("FixtureTransport contains empty response frame")

        return self._raw_rx


class MockTransport:
    """Configurable mock transport for deterministic testing and negative error paths."""

    def __init__(
        self,
        default_response: Optional[bytes] = None,
        responses: Optional[Dict[bytes, bytes]] = None,
        handler: Optional[Callable[[bytes], bytes]] = None,
        always_timeout: bool = False,
        timeout_requests: Optional[Set[bytes]] = None,
        error: Optional[Exception] = None,
    ):
        self.default_response = default_response
        self.responses = dict(responses) if responses else {}
        self.handler = handler
        self.always_timeout = always_timeout
        self.timeout_requests = set(timeout_requests) if timeout_requests else set()
        self.error = error
        self.history: List[Tuple[bytes, float]] = []

    def set_response(self, request_frame: bytes, response_frame: bytes) -> None:
        """Map a specific request frame to a response frame."""
        self.responses[request_frame] = response_frame

    def transceive_ds2(self, wire_frame: bytes, timeout: float = 1.0) -> bytes:
        """Simulate transceive based on configured rules."""
        self.history.append((wire_frame, timeout))

        if self.error is not None:
            raise self.error

        if self.always_timeout or wire_frame in self.timeout_requests:
            raise TransportTimeoutError(f"Transport timed out after {timeout:.2f}s for frame {wire_frame.hex(' ').upper()}")

        if self.handler is not None:
            return self.handler(wire_frame)

        if wire_frame in self.responses:
            return self.responses[wire_frame]

        if self.default_response is not None:
            return self.default_response

        raise TransportError(f"MockTransport: No configured response for request {wire_frame.hex(' ').upper()}")
