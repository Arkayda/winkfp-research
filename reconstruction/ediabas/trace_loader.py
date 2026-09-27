"""Immutable Trace Fixture Loader for GKE195 Offline Execution.

Loads and strictly validates captured physical traces and sanitized factory traces
without modifying source files. Performs rigorous DS2 framing and checksum verification.

STRICTLY OFF-HARDWARE: Pure file-based fixture loader.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Union

from reconstruction.transport.kdcan.framing import (
    Telegram,
    checksum as ds2_checksum,
    parse as parse_ds2_frame,
)


@dataclass(frozen=True)
class TraceFixture:
    """Immutable representation of a verified diagnostic trace fixture."""

    path: Path
    raw_tx: bytes
    raw_rx: bytes
    tx_payload: bytes
    rx_payload: bytes
    rtt_ms: float
    checksum_valid: bool
    target: int
    tester: int
    probe: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def rx_len(self) -> int:
        """Total frame length of RX telegram."""
        return len(self.raw_rx)

    @property
    def payload_len(self) -> int:
        """Length of RX payload."""
        return len(self.rx_payload)


def load_trace_fixture(
    trace_path: Union[Path, str],
    validate_checksum: bool = True,
    validate_framing: bool = True,
) -> TraceFixture:
    """Load and validate an immutable JSON trace fixture from disk.

    Verification steps:
      1. Reads raw JSON trace (pure read-only).
      2. Extracts raw TX and RX byte streams.
      3. Validates 8-bit additive DS2 checksum on RX frame.
      4. Validates DS2 framing (short inline-length or extended-length header).
      5. Extracts verified payload bytes.

    Raises:
      FileNotFoundError: If the trace file does not exist.
      ValueError: If JSON structure is missing fields, checksum is invalid,
                  or DS2 framing is corrupted.
    """
    path = Path(trace_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Trace fixture not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Trace fixture at {path} must be a JSON dictionary")

    # Extract TX
    tx_hex = data.get("raw_tx") or data.get("tx")
    if not tx_hex:
        raise ValueError(f"Trace fixture {path.name} missing 'tx' / 'raw_tx'")
    raw_tx = bytes.fromhex(tx_hex.replace(" ", "").strip())

    # Extract RX
    rx_hex = data.get("raw_rx") or data.get("rx")
    if not rx_hex:
        raise ValueError(f"Trace fixture {path.name} missing 'rx' / 'raw_rx'")
    raw_rx = bytes.fromhex(rx_hex.replace(" ", "").strip())

    # Checksum validation
    if validate_checksum:
        if len(raw_rx) < 2:
            raise ValueError(f"RX frame too short for checksum validation: {len(raw_rx)} bytes")
        expected_cs = ds2_checksum(raw_rx[:-1])
        actual_cs = raw_rx[-1]
        if actual_cs != expected_cs:
            raise ValueError(
                f"Invalid DS2 checksum in {path.name}: "
                f"actual 0x{actual_cs:02X} != calculated 0x{expected_cs:02X}"
            )

    # DS2 Framing validation
    if validate_framing:
        try:
            rx_telegram: Telegram = parse_ds2_frame(raw_rx)
            rx_payload = rx_telegram.payload
        except Exception as e:
            raise ValueError(f"Invalid DS2 framing in RX telegram of {path.name}: {e}") from e

        try:
            tx_telegram: Telegram = parse_ds2_frame(raw_tx)
            tx_payload = tx_telegram.payload
        except Exception as e:
            raise ValueError(f"Invalid DS2 framing in TX telegram of {path.name}: {e}") from e
    else:
        # Fallback if framing validation is explicitly disabled
        rx_payload = raw_rx[3:-1] if len(raw_rx) >= 4 else raw_rx
        tx_payload = raw_tx[3:-1] if len(raw_tx) >= 4 else raw_tx

    rtt_ms = float(data.get("rtt_ms", 0.0))
    target = int(data.get("target", "0x18"), 16) if isinstance(data.get("target"), str) else int(data.get("target", 0x18))
    tester = int(data.get("tester", "0xF1"), 16) if isinstance(data.get("tester"), str) else int(data.get("tester", 0xF1))
    probe = str(data.get("probe", "unknown"))

    return TraceFixture(
        path=path,
        raw_tx=raw_tx,
        raw_rx=raw_rx,
        tx_payload=tx_payload,
        rx_payload=rx_payload,
        rtt_ms=rtt_ms,
        checksum_valid=True,
        target=target,
        tester=tester,
        probe=probe,
        metadata=data,
    )
