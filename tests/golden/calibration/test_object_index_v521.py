"""TDD Test Suite for Milestone 5.21 Gate 1: Canonical Object Index and Taxonomy."""

from __future__ import annotations

import unittest
from pathlib import Path

from reconstruction.calibration.hex_parser import IntelHexParser
from reconstruction.calibration.object_index_v521 import (
    CanonicalObjectIndexBuilder,
    DirectoryAccounting,
)

DA_FILE = Path("/Users/blogman/bmw_flash_re/spdaten_gke/E60/data/GKE195/A7592133.0da")


class TestCanonicalObjectIndexV521(unittest.TestCase):
    """Test suite for Gate 1 canonical object index, accounting, and taxonomy."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.image = IntelHexParser.parse_file(DA_FILE)
        cls.builder = CanonicalObjectIndexBuilder(cls.image)
        cls.catalog = cls.builder.build_catalog()

    def test_01_directory_accounting_identity(self) -> None:
        """Verify the exact mathematical accounting identity of Segment 4 pointers."""
        acct: DirectoryAccounting = self.catalog.accounting
        self.assertEqual(acct.directory_entries, 9176)
        self.assertEqual(acct.unique_target_addresses, 6017)
        self.assertEqual(acct.alias_groups, 1197)
        self.assertEqual(acct.alias_entries, 3159)

        # Mathematical identity: unique + alias = total
        self.assertEqual(
            acct.unique_target_addresses + acct.alias_entries,
            acct.directory_entries,
        )

        # Sub-category breakdown identity: payload + indirect + gap = total
        self.assertEqual(acct.pointers_into_payload, 8451)
        self.assertEqual(acct.pointers_into_directory, 720)
        self.assertEqual(acct.pointers_into_gap, 5)
        self.assertEqual(
            acct.pointers_into_payload + acct.pointers_into_directory + acct.pointers_into_gap,
            acct.directory_entries,
        )

    def test_02_gap_and_indirect_pointers_audited(self) -> None:
        """Verify specific gap pointers and indirect pointers are recorded."""
        acct = self.catalog.accounting
        self.assertEqual(len(acct.gap_entries), 5)
        gap_addrs = {e["target_address"] for e in acct.gap_entries}
        self.assertIn("0x0005FFF4", gap_addrs)
        self.assertIn("0x0005FFFE", gap_addrs)
        self.assertEqual(len(acct.indirect_entries), 720)

    def test_03_all_directory_entries_indexed(self) -> None:
        """Verify every directory index (0..9175) is accounted for."""
        self.assertEqual(len(self.catalog.entries), 9176)
        first = self.catalog.entries[0]
        self.assertEqual(first.directory_index, 0)
        self.assertEqual(first.directory_address, "0x00076000")
        self.assertEqual(first.target_address, "0x0005069E")

    def test_04_normalized_families_distribution(self) -> None:
        """Verify normalized taxonomy distribution and absence of heuristic names."""
        families = self.catalog.family_distribution
        expected_classes = {
            "SCALAR", "AXIS", "CURVE_1D", "TABLE_2D", "TABLE_3D",
            "LOOKUP_TABLE", "DESCRIPTOR", "CONSTANT_BLOCK", "STATE_TABLE",
            "DATA_BLOCK", "INDIRECT_DESCRIPTOR", "GAP_REFERENCE", "UNKNOWN"
        }
        self.assertTrue(set(families.keys()).issubset(expected_classes))
        self.assertEqual(sum(families.values()), 9176)


if __name__ == "__main__":
    unittest.main()
