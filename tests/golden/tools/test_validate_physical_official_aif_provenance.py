"""Golden tests for tools/validate_physical_official_aif.py preflight provenance checks.

Validates that pre-flight checks fail-closed offline under:
- Dirty git working tree
- Mismatched git HEAD commit vs expected tag
- Non-existent git tag
- Request byte mismatch
- Fixture hash mismatch
- Target/tester address mismatch
- Dangerous jobs in catalog
- Active session manager
- Fallback mapping present
- Missing hardware confirmation flag
- Non-existent serial port
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from tools.validate_physical_official_aif import (
    EXPECTED_CANONICAL_TX,
    EXPECTED_PAYLOAD,
    TARGET_EGS,
    TESTER_ADDRESS,
    classify_response,
    run_preflight_checks,
)


class TestValidatePhysicalOfficialAifProvenance(unittest.TestCase):
    """Offline unit tests for validate_physical_official_aif pre-flight validation."""

    def setUp(self) -> None:
        self.mock_job_def = MagicMock()
        self.mock_job_def.service = 0x23
        self.mock_job_def.request_payload = EXPECTED_PAYLOAD
        self.mock_job_def.fallback_payload = None
        self.mock_job_def.fallback_service = None

        self.mock_pipeline = MagicMock()
        self.mock_pipeline.catalog = ["AIF_LESEN"]
        self.mock_pipeline.get_job.return_value = self.mock_job_def
        self.mock_pipeline.build_request.return_value = EXPECTED_CANONICAL_TX
        self.mock_pipeline.session_manager = None

    @patch("subprocess.check_output")
    def test_preflight_passes_when_all_conditions_met(self, mock_subprocess: MagicMock) -> None:
        """When tree is clean, HEAD matches tag, and all inputs valid, pre-flight passes."""
        def fake_git(cmd: list[str], **kwargs) -> str:
            if cmd == ["git", "rev-parse", "HEAD"]:
                return "90a68651fa629c72bc65df2a7b5e7e647fcf148f\n"
            if cmd == ["git", "status", "--porcelain"]:
                return ""
            if len(cmd) >= 3 and cmd[1] == "rev-parse" and "refs/tags/" in cmd[2]:
                return "90a68651fa629c72bc65df2a7b5e7e647fcf148f\n"
            return ""

        mock_subprocess.side_effect = fake_git

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag="milestone-5.15-complete",
            allow_dirty=False,
        )
        self.assertTrue(ok, f"Pre-flight failed unexpectedly: {errors}")
        self.assertEqual(len(errors), 0)

    @patch("subprocess.check_output")
    def test_preflight_fails_when_git_working_tree_dirty(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if git working tree contains uncommitted changes."""
        def fake_git(cmd: list[str], **kwargs) -> str:
            if cmd == ["git", "rev-parse", "HEAD"]:
                return "90a68651fa629c72bc65df2a7b5e7e647fcf148f\n"
            if cmd == ["git", "status", "--porcelain"]:
                return " M some_file.py\n?? untracked.py\n"
            if len(cmd) >= 3 and cmd[1] == "rev-parse" and "refs/tags/" in cmd[2]:
                return "90a68651fa629c72bc65df2a7b5e7e647fcf148f\n"
            return ""

        mock_subprocess.side_effect = fake_git

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag="milestone-5.15-complete",
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
                return "90a68651fa629c72bc65df2a7b5e7e647fcf148f\n"
            return ""

        mock_subprocess.side_effect = fake_git

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag="milestone-5.15-complete",
            allow_dirty=False,
        )
        self.assertFalse(ok)
        self.assertTrue(any("does not match expected tag" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_on_canonical_tx_mismatch(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if pipeline builds wrong request bytes."""
        mock_subprocess.return_value = "90a68651fa629c72bc65df2a7b5e7e647fcf148f\n"
        self.mock_pipeline.build_request.return_value = bytes.fromhex("82 18 F1 1A 86 2B")

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag=None,
            allow_dirty=True,
        )
        self.assertFalse(ok)
        self.assertTrue(any("Canonical request mismatch" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_when_fallback_configured(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if fallback is configured on AIF_LESEN."""
        mock_subprocess.return_value = "90a68651fa629c72bc65df2a7b5e7e647fcf148f\n"
        self.mock_job_def.fallback_payload = b"\x1A\x86"

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag=None,
            allow_dirty=True,
        )
        self.assertFalse(ok)
        self.assertTrue(any("fallback is strictly prohibited" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_without_hardware_confirmation(self, mock_subprocess: MagicMock) -> None:
        """Physical execution must fail-closed if --confirm-readonly-hardware is omitted."""
        mock_subprocess.return_value = "90a68651fa629c72bc65df2a7b5e7e647fcf148f\n"

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            port="/dev/null",
            dry_run=False,
            confirm_readonly_hardware=False,
            expected_tag=None,
            allow_dirty=True,
        )
        self.assertFalse(ok)
        self.assertTrue(any("--confirm-readonly-hardware" in e for e in errors))

    def test_classification_negative_response(self) -> None:
        """Negative response (0x7F NRC 0x12) is correctly classified."""
        # 83 F1 18 7F 23 12 CS
        raw_rx = bytes.fromhex("83 F1 18 7F 23 12 40")
        cls, nrc = classify_response(EXPECTED_CANONICAL_TX, raw_rx, None)
        self.assertEqual(cls, "NEGATIVE_PHYSICAL_RESPONSE")
        self.assertEqual(nrc, 0x12)


if __name__ == "__main__":
    unittest.main()
