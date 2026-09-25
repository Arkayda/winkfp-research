"""Golden tests for FlashRunner integration and state orchestration."""

import unittest
from pathlib import Path
from reconstruction.runner import FlashRunner, SafetyContext, AuthConfig
from reconstruction.ediabas import MockBus
from reconstruction.safety import Limits
from reconstruction.auth import As2KeyStore


class TestGoldenFlash(unittest.TestCase):
    def setUp(self):
        fixtures_dir = Path(__file__).resolve().parents[2] / "fixtures" / "synthetic"
        c_path = fixtures_dir / "synthetic_sgidc.as2"
        d_path = fixtures_dir / "synthetic_sgidd.as2"
        self.store = As2KeyStore.from_paths({3: c_path, 4: d_path})

        limits_path = fixtures_dir / "synthetic_limits.txt"
        self.limits = Limits.from_limits_file(
            str(limits_path), ecu_family="GKE19", ecu_part_number="7592144"
        )
        self.image = (fixtures_dir / "synthetic_image.bin").read_bytes()

    def make_safety(self, battery_v=13.2):
        state = {
            "battery_v": battery_v,
            "ignition_on": True,
            "programming_voltage_enabled": True,
            "zb_number_matches": True,
        }
        return SafetyContext(limits=self.limits, read_state=lambda k: state[k])

    def test_flash_happy_path(self):
        """FlashRunner successfully completes flashing cycle on MockBus."""
        bus = MockBus(sig_seq=["OKAY"], ident="GKE192", auth_offer="T_SMB")
        cfg = AuthConfig(
            ecu_name="GKE192", key_index=3, art="Symetrisch", store=self.store, nonce=b"ab3f"
        )
        safety = self.make_safety(battery_v=13.2)
        runner = FlashRunner(bus, self.image, blocksize=16, safety=safety, auth=cfg)
        rep = runner.flash()
        self.assertTrue(rep.ok, f"Flash failed: {rep.error}")
        self.assertTrue(rep.auth_ok)
        self.assertEqual(rep.blocks_written, 16)
        self.assertEqual(rep.bytes_written, 256)
        self.assertTrue(any(j[1] == "FLASH_SCHREIBEN" for j in bus.jobs))
        self.assertTrue(any(j[1] == "EXIT_VDLE" for j in bus.jobs))

    def test_safety_gate_rejection(self):
        """FlashRunner hard-refuses if battery voltage is out of range."""
        from reconstruction.runner import FlashFailure
        bus = MockBus(sig_seq=["OKAY"])
        low_voltage_safety = self.make_safety(battery_v=10.5)
        runner = FlashRunner(bus, self.image, blocksize=16, safety=low_voltage_safety)
        with self.assertRaises(FlashFailure) as cm:
            runner.flash()
        self.assertIn("battery", str(cm.exception).lower())


if __name__ == "__main__":
    unittest.main()
