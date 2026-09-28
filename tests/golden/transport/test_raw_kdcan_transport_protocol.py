"""Golden tests for RawKdcanTransport protocol and KdcanTransport abstract methods.

Verifies:
1. RawKdcanTransport is a runtime_checkable Protocol.
2. Concrete transports (SerialKdcanTransport, ScriptedKdcanBackend, TracedKdcanTransport)
   satisfy the RawKdcanTransport protocol.
3. KdcanTransport cannot be instantiated without implementing transceive_raw.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from reconstruction.transport.kdcan import (
    KdcanTransport,
    RawKdcanTransport,
    ScriptedKdcanBackend,
    SerialKdcanTransport,
    SessionTracer,
    TracedKdcanTransport,
)


class TestRawKdcanTransportProtocol(unittest.TestCase):
    """Verify runtime checkability and conformance of RawKdcanTransport."""

    def test_protocol_conformance(self) -> None:
        """All primary transport classes must conform to RawKdcanTransport."""
        serial_transport = SerialKdcanTransport(port="MOCK")
        scripted_transport = ScriptedKdcanBackend()
        traced_transport = TracedKdcanTransport(scripted_transport, SessionTracer())

        self.assertIsInstance(serial_transport, RawKdcanTransport)
        self.assertIsInstance(scripted_transport, RawKdcanTransport)
        self.assertIsInstance(traced_transport, RawKdcanTransport)

    def test_incomplete_class_rejected_by_protocol(self) -> None:
        """A class missing transceive_raw must NOT be an instance of RawKdcanTransport."""
        class IncompleteTransport:
            def open(self) -> None: ...
            def close(self) -> None: ...

        incomplete = IncompleteTransport()
        self.assertNotIsInstance(incomplete, RawKdcanTransport)

    def test_kdcan_transport_requires_transceive_raw(self) -> None:
        """KdcanTransport subclasses cannot be instantiated without transceive_raw."""
        class MissingTransceiveRaw(KdcanTransport):
            def open(self) -> None: ...
            def close(self) -> None: ...
            def send_job(self, dst, payload, src=0xF1, timeout=None): return b""

        with self.assertRaises(TypeError) as ctx:
            MissingTransceiveRaw()  # type: ignore[abstract]
        self.assertIn("transceive_raw", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
