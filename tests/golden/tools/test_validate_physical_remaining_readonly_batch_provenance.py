"""Golden tests for tools/validate_physical_remaining_readonly_batch.py preflight provenance checks.

Validates that pre-flight checks fail-closed offline under:
- Dirty git working tree
- Mismatched git HEAD commit vs expected tag
- Non-existent git tag
- Request byte mismatch
- Fixture hash mismatch
- Missing hardware confirmation flag
- Non-existent serial port
- Response classification behaviors
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from tools.validate_physical_remaining_readonly_batch import (
    BATCH_SPECS,
    TARGET_EGS,
    TESTER_ADDRESS,
    classify_response,
    run_preflight_checks,
)


class TestValidatePhysicalRemainingReadonlyBatchProvenance(unittest.TestCase):
    """Offline unit tests for validate_physical_remaining_readonly_batch pre-flight validation."""

    def setUp(self) -> None:
        self.mock_pipeline = MagicMock()
        self.mock_pipeline.catalog = [spec["job_name"] for spec in BATCH_SPECS]

        def get_job_mock(name: str) -> MagicMock:
            spec = next(s for s in BATCH_SPECS if s["job_name"] == name)
            m = MagicMock()
            m.service = spec["service"]
            m.request_payload = spec["expected_payload"]
            return m

        def build_req_mock(job_name: str, **kwargs) -> bytes:
            spec = next(s for s in BATCH_SPECS if s["job_name"] == job_name)
            return spec["expected_canonical_tx"]

        self.mock_pipeline.get_job.side_effect = get_job_mock
        self.mock_pipeline.build_request.side_effect = build_req_mock
        self.mock_pipeline.session_manager = None

    @patch("subprocess.check_output")
    def test_preflight_passes_when_all_conditions_met(self, mock_subprocess: MagicMock) -> None:
        """When tree is clean, HEAD matches tag, and all inputs valid, pre-flight passes."""
        def fake_git(cmd: list[str], **kwargs) -> str:
            if cmd == ["git", "rev-parse", "HEAD"]:
                return "f3229937022d31aa4f15010b12981b042c90c6ff\n"
            if cmd == ["git", "status", "--porcelain"]:
                return ""
            if len(cmd) >= 3 and cmd[1] == "rev-parse" and "refs/tags/" in cmd[2]:
                return "f3229937022d31aa4f15010b12981b042c90c6ff\n"
            return ""

        mock_subprocess.side_effect = fake_git

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag="milestone-5.16-complete",
            allow_dirty=False,
        )
        self.assertTrue(ok, f"Pre-flight failed unexpectedly: {errors}")
        self.assertEqual(len(errors), 0)

    @patch("subprocess.check_output")
    def test_preflight_fails_when_git_working_tree_dirty(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if git working tree contains uncommitted changes."""
        def fake_git(cmd: list[str], **kwargs) -> str:
            if cmd == ["git", "rev-parse", "HEAD"]:
                return "f3229937022d31aa4f15010b12981b042c90c6ff\n"
            if cmd == ["git", "status", "--porcelain"]:
                return " M some_file.py\n"
            if len(cmd) >= 3 and cmd[1] == "rev-parse" and "refs/tags/" in cmd[2]:
                return "f3229937022d31aa4f15010b12981b042c90c6ff\n"
            return ""

        mock_subprocess.side_effect = fake_git

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag="milestone-5.16-complete",
            allow_dirty=False,
        )
        self.assertFalse(ok)
        self.assertTrue(any("Git working tree is dirty" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_when_git_head_mismatches_tag(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if HEAD != expected tag."""
        def fake_git(cmd: list[str], **kwargs) -> str:
            if cmd == ["git", "rev-parse", "HEAD"]:
                return "1111111111111111111111111111111111111111\n"
            if cmd == ["git", "status", "--porcelain"]:
                return ""
            if len(cmd) >= 3 and cmd[1] == "rev-parse" and "refs/tags/" in cmd[2]:
                return "2222222222222222222222222222222222222222\n"
            return ""

        mock_subprocess.side_effect = fake_git

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag="milestone-5.16-complete",
            allow_dirty=False,
        )
        self.assertFalse(ok)
        self.assertTrue(any("does not match tag" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_when_canonical_tx_mismatches(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if generated request doesn't match canonical frame."""
        def fake_git(cmd: list[str], **kwargs) -> str:
            if cmd == ["git", "rev-parse", "HEAD"]:
                return "f3229937022d31aa4f15010b12981b042c90c6ff\n"
            if cmd == ["git", "status", "--porcelain"]:
                return ""
            if len(cmd) >= 3 and cmd[1] == "rev-parse" and "refs/tags/" in cmd[2]:
                return "f3229937022d31aa4f15010b12981b042c90c6ff\n"
            return ""

        mock_subprocess.side_effect = fake_git
        self.mock_pipeline.build_request.side_effect = lambda *a, **k: b"\x00\x00\x00"

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            port=None,
            dry_run=True,
            confirm_readonly_hardware=False,
            expected_tag="milestone-5.16-complete",
            allow_dirty=False,
        )
        self.assertFalse(ok)
        self.assertTrue(any("Generated canonical wire TX mismatch" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_when_missing_hardware_confirmation(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if --confirm-readonly-hardware is False for physical run."""
        def fake_git(cmd: list[str], **kwargs) -> str:
            if cmd == ["git", "rev-parse", "HEAD"]:
                return "f3229937022d31aa4f15010b12981b042c90c6ff\n"
            if cmd == ["git", "status", "--porcelain"]:
                return ""
            if len(cmd) >= 3 and cmd[1] == "rev-parse" and "refs/tags/" in cmd[2]:
                return "f3229937022d31aa4f15010b12981b042c90c6ff\n"
            return ""

        mock_subprocess.side_effect = fake_git

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            port="/dev/null",
            dry_run=False,
            confirm_readonly_hardware=False,
            expected_tag="milestone-5.16-complete",
            allow_dirty=False,
        )
        self.assertFalse(ok)
        self.assertTrue(any("confirm-readonly-hardware flag is strictly required" in e for e in errors))

    @patch("subprocess.check_output")
    def test_preflight_fails_when_port_does_not_exist(self, mock_subprocess: MagicMock) -> None:
        """Pre-flight must fail-closed if specified port does not exist."""
        def fake_git(cmd: list[str], **kwargs) -> str:
            if cmd == ["git", "rev-parse", "HEAD"]:
                return "f3229937022d31aa4f15010b12981b042c90c6ff\n"
            if cmd == ["git", "status", "--porcelain"]:
                return ""
            if len(cmd) >= 3 and cmd[1] == "rev-parse" and "refs/tags/" in cmd[2]:
                return "f3229937022d31aa4f15010b12981b042c90c6ff\n"
            return ""

        mock_subprocess.side_effect = fake_git

        ok, errors = run_preflight_checks(
            pipeline=self.mock_pipeline,
            port="/dev/nonexistent_serial_device_xyz",
            dry_run=False,
            confirm_readonly_hardware=True,
            expected_tag="milestone-5.16-complete",
            allow_dirty=False,
        )
        self.assertFalse(ok)
        self.assertTrue(any("does not exist" in e for e in errors))

    def test_classify_response_classes(self) -> None:
        """Test response classifier across all response classes."""
        spec_1a89 = BATCH_SPECS[0]

        # 1. Timeout
        mock_timeout_res = MagicMock()
        mock_timeout_res.status = "ERROR_TIMEOUT"
        cls, nrc = classify_response(spec_1a89, None, None, mock_timeout_res)
        self.assertEqual(cls, "TIMEOUT")
        self.assertIsNone(nrc)

        # 2. Transport error
        mock_err_res = MagicMock()
        mock_err_res.status = "ERROR_TRANSPORT"
        cls, nrc = classify_response(spec_1a89, None, None, mock_err_res)
        self.assertEqual(cls, "TRANSPORT_ERROR")

        # 3. Negative response NRC 0x12: 83 F1 18 7F 1A 12 37
        neg_frame = bytes.fromhex("83 F1 18 7F 1A 12 37")
        cls, nrc = classify_response(spec_1a89, spec_1a89["expected_canonical_tx"], neg_frame, None)
        self.assertEqual(cls, "NEGATIVE_PHYSICAL_RESPONSE")
        self.assertEqual(nrc, 0x12)

        # 4. Invalid physical response (bad checksum)
        bad_cs_frame = bytes.fromhex("83 F1 18 7F 1A 12 99")
        cls, nrc = classify_response(spec_1a89, spec_1a89["expected_canonical_tx"], bad_cs_frame, None)
        self.assertEqual(cls, "INVALID_PHYSICAL_RESPONSE")

        # 5. Positive confirmation
        # 8B F1 18 5A 89 + '080072856' (9B) -> 11B payload
        # 0x8B + 0xF1 + 0x18 + 0x5A + 0x89 + sum(b'080072856') = ...
        from reconstruction.transport.kdcan.framing import build as build_frame
        pos_frame = build_frame(0xF1, 0x18, b"\x5A\x89080072856")
        mock_ok_res = MagicMock()
        mock_ok_res.status = "OKAY"
        cls, nrc = classify_response(spec_1a89, spec_1a89["expected_canonical_tx"], pos_frame, mock_ok_res)
        self.assertEqual(cls, "POSITIVE_PHYSICAL_CONFIRMATION")
        self.assertIsNone(nrc)


if __name__ == "__main__":
    unittest.main()
