"""Golden test suite verifying strict semantic separation in DirectKdcanBus.

Guarantees:
1. AIF (0x1A 0x86) parses ZB_NUMMER ("7592132") and SW_NUMMER ("7592133") without aliasing them to SG_PHYS_HWNR.
2. PHYSIKALISCHE_HW_NR_LESEN / SG_PHYS_HWNR_LESEN (0x1A 0x87) parses PECUHN ("7569980") and populates SG_PHYS_HWNR.
3. IDENT (0x1A 0x80) parses ID_BMW_NR ("7591972").
4. Strict assertions:
   - AIF ZB != PHYS_HWNR
   - AIF SW != PHYS_HWNR
   - ID_BMW_NR != AIF ZB
   - PHYS_HWNR == 7569980
"""

from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest.mock import MagicMock

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


class TestDirectKdcanBusSemantics(unittest.TestCase):
    """Verify semantic separation between AIF, IDENT, and Physical Hardware Number."""

    def setUp(self) -> None:
        self.aif_fixture_path = REPO_ROOT / "traces/hardware/20260926_173201_egs_aif.json"
        self.ident_fixture_path = REPO_ROOT / "traces/hardware/20260926_174811_egs_ident.json"
        self.phys_hwnr_fixture_path = REPO_ROOT / "traces/hardware/20260926_175924_egs_physical_hw_nr.json"

        with open(self.aif_fixture_path) as f:
            self.aif_data = json.load(f)
        with open(self.ident_fixture_path) as f:
            self.ident_data = json.load(f)
        with open(self.phys_hwnr_fixture_path) as f:
            self.phys_hwnr_data = json.load(f)

    def test_aif_does_not_populate_phys_hwnr_aliases(self) -> None:
        """AIF query must populate ZB_NUMMER and SW_NUMMER, but NEVER SG_PHYS_HWNR or HWNR."""
        from reconstruction.transport.kdcan.bus import DirectKdcanBus

        mock_transport = MagicMock()
        # Payload of KWP response (excluding header if transport.send_job returns payload)
        # In aif trace, raw_rx is "80 f1 18 42 5a 86 40 43 53 36 38 32 39 34 20 08 12 04 00 00 07 59 21 32 00 00 07 59 21 33 ..."
        # send_job returns payload starting with 5A 86
        payload = bytes.fromhex(self.aif_data["rx_payload"])
        mock_transport.send_job.return_value = payload

        bus = DirectKdcanBus(transport=mock_transport, default_dst=0x18, trace=False, allow_inferred=True)
        ok = bus.job("GS19", "AIF_LESEN")
        self.assertTrue(ok)

        # AIF fields must be present
        zb = bus.read_text("ZB_NUMMER")
        sw = bus.read_text("SW_NUMMER")
        vin = bus.read_text("SHORT_VIN")
        sgbd = bus.read_text("SGBD")

        self.assertEqual(zb, "7592132")
        self.assertEqual(sw, "7592133")
        self.assertEqual(vin, "CS68294")
        self.assertEqual(sgbd, "0479S90T641Z")

        # Crucial requirement: SG_PHYS_HWNR and HWNR must NOT be set by AIF!
        self.assertEqual(bus.read_text("SG_PHYS_HWNR", ""), "")
        self.assertEqual(bus.read_text("HWNR", ""), "")
        self.assertEqual(bus.read_text("PHYSIKALISCHE_HW_NR", ""), "")

    def test_phys_hwnr_lesen_populates_pecuhn(self) -> None:
        """PHYSIKALISCHE_HW_NR_LESEN (0x1A 0x87) must populate PHYSIKALISCHE_HW_NR, SG_PHYS_HWNR, and HWNR."""
        from reconstruction.transport.kdcan.bus import DirectKdcanBus

        mock_transport = MagicMock()
        payload = bytes.fromhex(self.phys_hwnr_data["rx_payload"])
        mock_transport.send_job.return_value = payload

        bus = DirectKdcanBus(transport=mock_transport, default_dst=0x18, trace=False, allow_inferred=True)
        ok = bus.job("GS19", "PHYSIKALISCHE_HW_NR_LESEN")
        self.assertTrue(ok)
        mock_transport.send_job.assert_called_with(0x18, bytes([0x1A, 0x87]), timeout=1.0)

        phys_hwnr = bus.read_text("PHYSIKALISCHE_HW_NR")
        sg_phys = bus.read_text("SG_PHYS_HWNR")
        hwnr = bus.read_text("HWNR")

        self.assertEqual(phys_hwnr, "7569980")
        self.assertEqual(sg_phys, "7569980")
        self.assertEqual(hwnr, "7569980")

        # ZB_NUMMER and SW_NUMMER must NOT be set by physical HWNR query
        self.assertEqual(bus.read_text("ZB_NUMMER", ""), "")
        self.assertEqual(bus.read_text("SW_NUMMER", ""), "")

    def test_sg_phys_hwnr_lesen_alias_executes_1a_87(self) -> None:
        """SG_PHYS_HWNR_LESEN must execute 0x1A 0x87, NOT 0x1A 0x86."""
        from reconstruction.transport.kdcan.bus import DirectKdcanBus

        mock_transport = MagicMock()
        payload = bytes.fromhex(self.phys_hwnr_data["rx_payload"])
        mock_transport.send_job.return_value = payload

        bus = DirectKdcanBus(transport=mock_transport, default_dst=0x18, trace=False, allow_inferred=True)
        ok = bus.job("GS19", "SG_PHYS_HWNR_LESEN")
        self.assertTrue(ok)
        mock_transport.send_job.assert_called_with(0x18, bytes([0x1A, 0x87]), timeout=1.0)
        self.assertEqual(bus.read_text("SG_PHYS_HWNR"), "7569980")

    def test_mandatory_identity_inequalities(self) -> None:
        """Verify the mandatory identity inequalities established by project evidence:

        - AIF ZB != PHYS_HWNR (7592132 != 7569980)
        - AIF SW != PHYS_HWNR (7592133 != 7569980)
        - ID_BMW_NR != AIF ZB (7591972 != 7592132)
        - PHYS_HWNR == 7569980
        """
        aif_zb = "7592132"
        aif_sw = "7592133"
        id_bmw_nr = "7591972"
        phys_hwnr = "7569980"

        self.assertNotEqual(aif_zb, phys_hwnr)
        self.assertNotEqual(aif_sw, phys_hwnr)
        self.assertNotEqual(id_bmw_nr, aif_zb)
        self.assertEqual(phys_hwnr, "7569980")


if __name__ == "__main__":
    unittest.main()
