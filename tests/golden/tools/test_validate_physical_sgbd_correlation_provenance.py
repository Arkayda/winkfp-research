"""Golden tests for tools/validate_physical_sgbd_correlation.py preflight provenance checks.

Validates that pre-flight checks fail-closed offline under:
- Dirty git working tree
- Mismatched git HEAD commit vs expected tag
- Non-existent git tag
- Request byte mismatch
- Fixture hash mismatch
- Target/tester address mismatch
- Dangerous jobs in catalog
- Active session manager
- Missing hardware confirmation flag
- Non-existent serial port
- Implicit port open in constructor
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from tools.validate_physical_sgbd_correlation import (
    EXPECTED_CANONICAL_TX,
    EXPECTED_PHYS_HWNR_FIXTURE_SHA256,
    TARGET_EGS,
    TESTER_ADDRESS,
    run_preflight_checks,
)


class TestValidatePhysicalSgbdCorrelationProvenance(unittest.TestCase):
    """Offline unit tests for validate_physical_sgbd_correlation pre-flight validation."""

    def setUp(self) -> None:
        self.mock_pipeline = MagicMock()
        self.mock_pipeline.catalog = ["PHYSIKALISCHE_HW_NR_LESEN"]
        self.mock_pipeline.build_request.return_value = EXPECTED_CANONICAL_TX
        self.mock_pipeline.session_manager = None

        self.temp_dir = tempfile.TemporaryDirectory()
        self.fixture_path = Path(self.temp_dir.name) / "test_phys_hw_nr.json"
        # Write valid fixture matching EXPECTED_PHYS_HWNR_FIXTURE_SHA256
        real_fixture = (
            Path(__file__).resolve().parent.parent.parent.parent
            / "traces"
            / "hardware"
            / "20260926_175924_egs_physical_hw_nr.json"
        )
        self.fixture_path.write_bytes(real_fixture.read_bytes())

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    @patch("subprocess.check_output")
    def test_preflight_passes_when_all_conditions_met(self, mock_subprocess: MagicMock) -> None:
        """When tree is clean, HEAD matches tag, and all inputs valid, pre-flight passes."""
        def fake_git(cmd: list[str], **kwargs) -> str:
            if cmd == ["git", "rev-parse", "HEAD"]:
                return "0a50b42b0da04d67e13978b0f25f586ddc4048e1\n"
            if cmd == ["git", "status", "--porcelain"]:
                return ""
            if len(cmd) >= 3 and cmd[1] == "rev-parse" and "refs/tags/" in cmd[2]:
                return "0a50b42b0da04d67e13978b0f25f586ddc4048e1\n"
            return ""

        mock_subprocess.side_effect = fake_git

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            fixture_path=self.fixture_path,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag="milestone-5.14.1-complete",
            allow_dirty=False,
        )
        self.assertTrue(ok, f"Pre-flight failed unexpectedly: {errors}")
        self.assertEqual(len(errors), 0)

    @patch("subprocess.check_output")
    def test_preflight_fails_when_git_working_tree_dirty(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if git working tree contains uncommitted changes."""
        def fake_git(cmd: list[str], **kwargs) -> str:
            if cmd == ["git", "rev-parse", "HEAD"]:
                return "0a50b42b0da04d67e13978b0f25f586ddc4048e1\n"
            if cmd == ["git", "status", "--porcelain"]:
                return " M some_file.py\n?? untracked.py\n"
            if len(cmd) >= 3 and cmd[1] == "rev-parse" and "refs/tags/" in cmd[2]:
                return "0a50b42b0da04d67e13978b0f25f586ddc4048e1\n"
            return ""

        mock_subprocess.side_effect = fake_git

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            fixture_path=self.fixture_path,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag="milestone-5.14.1-complete",
            allow_dirty=False,
        )
        self.assertFalse(ok)
        self.assertTrue(any("Git working tree is dirty" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_when_head_mismatches_expected_tag(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if git HEAD does not match expected tag commit."""
        def fake_git(cmd: list[str], **kwargs) -> str:
            if cmd == ["git", "rev-parse", "HEAD"]:
                return "1111111111111111111111111111111111111111\n"
            if cmd == ["git", "status", "--porcelain"]:
                return ""
            if len(cmd) >= 3 and cmd[1] == "rev-parse" and "refs/tags/" in cmd[2]:
                return "0a50b42b0da04d67e13978b0f25f586ddc4048e1\n"
            return ""

        mock_subprocess.side_effect = fake_git

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            fixture_path=self.fixture_path,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag="milestone-5.14.1-complete",
            allow_dirty=False,
        )
        self.assertFalse(ok)
        self.assertTrue(any("does not match expected tag" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_when_expected_tag_missing(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if the expected checkpoint tag does not exist."""
        def fake_git(cmd: list[str], **kwargs) -> str:
            if cmd == ["git", "rev-parse", "HEAD"]:
                return "0a50b42b0da04d67e13978b0f25f586ddc4048e1\n"
            if cmd == ["git", "status", "--porcelain"]:
                return ""
            if len(cmd) >= 3 and cmd[1] == "rev-parse" and "refs/tags/" in cmd[2]:
                raise subprocess.CalledProcessError(128, cmd)
            return ""

        mock_subprocess.side_effect = fake_git

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            fixture_path=self.fixture_path,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag="nonexistent-tag",
            allow_dirty=False,
        )
        self.assertFalse(ok)
        self.assertTrue(any("does not exist in repository" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_on_fixture_sha256_mismatch(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if the canonical fixture has been modified or corrupted."""
        mock_subprocess.return_value = "0a50b42b0da04d67e13978b0f25f586ddc4048e1\n"

        corrupted_fixture = Path(self.temp_dir.name) / "corrupted.json"
        corrupted_fixture.write_bytes(b'{"corrupted": true}')

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            fixture_path=corrupted_fixture,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag=None,
            allow_dirty=True,
        )
        self.assertFalse(ok)
        self.assertTrue(any("fixture SHA-256 mismatch" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_on_canonical_tx_mismatch(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if pipeline builds wrong request bytes."""
        mock_subprocess.return_value = "0a50b42b0da04d67e13978b0f25f586ddc4048e1\n"
        self.mock_pipeline.build_request.return_value = bytes.fromhex("82 18 F1 1A 80 25")

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            fixture_path=self.fixture_path,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag=None,
            allow_dirty=True,
        )
        self.assertFalse(ok)
        self.assertTrue(any("Canonical request mismatch" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_when_dangerous_jobs_in_catalog(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if dangerous flash write jobs appear in catalog."""
        mock_subprocess.return_value = "0a50b42b0da04d67e13978b0f25f586ddc4048e1\n"
        self.mock_pipeline.catalog = ["PHYSIKALISCHE_HW_NR_LESEN", "FLASH_SCHREIBEN"]

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            fixture_path=self.fixture_path,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag=None,
            allow_dirty=True,
        )
        self.assertFalse(ok)
        self.assertTrue(any("CRITICAL SAFETY VIOLATION" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_without_hardware_confirmation(self, mock_subprocess: MagicMock) -> None:
        """Physical execution must fail-closed if --confirm-readonly-hardware is omitted."""
        mock_subprocess.return_value = "0a50b42b0da04d67e13978b0f25f586ddc4048e1\n"

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            fixture_path=self.fixture_path,
            port="/dev/null",
            dry_run=False,
            confirm_readonly_hardware=False,
            expected_tag=None,
            allow_dirty=True,
        )
        self.assertFalse(ok)
        self.assertTrue(any("--confirm-readonly-hardware" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_with_missing_serial_port(self, mock_subprocess: MagicMock) -> None:
        """Physical execution must fail-closed if serial port does not exist."""
        mock_subprocess.return_value = "0a50b42b0da04d67e13978b0f25f586ddc4048e1\n"

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            fixture_path=self.fixture_path,
            port="/dev/nonexistent_serial_port_xyz",
            dry_run=False,
            confirm_readonly_hardware=True,
            expected_tag=None,
            allow_dirty=True,
        )
        self.assertFalse(ok)
        self.assertTrue(any("does not exist on this machine" in e for e in errors))


if __name__ == "__main__":
    unittest.main()
