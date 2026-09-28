"""Golden test verifying SerialKdcanTransport initialization and opening lifecycle.

Invariants verified:
1. Construct != Open: Instantiating SerialKdcanTransport does NOT open serial port.
2. Offline Isolation: SerialKdcanTransport can be instantiated offline even when pyserial is missing.
3. Explicit Open Requirement: pyserial presence is required ONLY when open() is called.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from reconstruction.transport.kdcan.serial import SerialKdcanTransport


class TestSerialTransportLifecycle(unittest.TestCase):
    """Verify SerialKdcanTransport construction vs opening lifecycle."""

    def test_construction_does_not_open_port(self) -> None:
        """Constructor must configure properties but leave internal serial handle None."""
        transport = SerialKdcanTransport(port="/dev/test_port", baud=115200)
        self.assertIsNone(transport._ser)
        self.assertEqual(transport.port, "/dev/test_port")
        self.assertEqual(transport.baud, 115200)

    def test_construction_succeeds_without_pyserial(self) -> None:
        """Constructor must not raise ImportError when serial is None."""
        with patch("reconstruction.transport.kdcan.serial.serial", None):
            transport = SerialKdcanTransport(port="/dev/test_port")
            self.assertIsNone(transport._ser)

    def test_open_fails_when_pyserial_missing(self) -> None:
        """Calling open() when serial is None must raise ImportError."""
        with patch("reconstruction.transport.kdcan.serial.serial", None):
            transport = SerialKdcanTransport(port="/dev/test_port")
            with self.assertRaises(ImportError) as ctx:
                transport.open()
            self.assertIn("pyserial is required", str(ctx.exception))

    @patch("reconstruction.transport.kdcan.serial.serial")
    def test_open_calls_serial_only_when_invoked(self, mock_serial_module: MagicMock) -> None:
        """pyserial Serial constructor must be called ONLY on explicit open()."""
        mock_ser_instance = MagicMock()
        mock_serial_module.Serial.return_value = mock_ser_instance
        mock_serial_module.EIGHTBITS = 8
        mock_serial_module.PARITY_NONE = "N"
        mock_serial_module.STOPBITS_ONE = 1

        transport = SerialKdcanTransport(port="/dev/test_port")
        mock_serial_module.Serial.assert_not_called()

        transport.open()
        mock_serial_module.Serial.assert_called_once()
        self.assertIs(transport._ser, mock_ser_instance)

        # Idempotent open
        transport.open()
        self.assertEqual(mock_serial_module.Serial.call_count, 1)

        transport.close()
        mock_ser_instance.close.assert_called_once()
        self.assertIsNone(transport._ser)


if __name__ == "__main__":
    unittest.main()
