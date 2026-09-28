"""Architectural test: enforce zero internal imports of flash_runner compatibility shim.

reconstruction/flash_runner.py is strictly a backwards-compatibility shim for external consumers.
All internal modules within reconstruction/ must import directly from their canonical locations
(e.g., reconstruction.runner).
"""

from __future__ import annotations

import ast
import os
import unittest
from pathlib import Path


class TestNoInternalFlashRunnerImports(unittest.TestCase):
    """Scan all Python modules under reconstruction/ to ensure none import flash_runner."""

    def test_no_internal_flash_runner_imports(self) -> None:
        reconstruction_dir = (
            Path(__file__).resolve().parent.parent.parent.parent / "reconstruction"
        )
        self.assertTrue(reconstruction_dir.is_dir())

        violations: list[str] = []

        for py_path in reconstruction_dir.rglob("*.py"):
            # The shim itself is allowed to exist as a shim
            if py_path.name == "flash_runner.py":
                continue

            try:
                tree = ast.parse(py_path.read_text(encoding="utf-8"), filename=str(py_path))
            except SyntaxError as e:
                self.fail(f"Syntax error in {py_path}: {e}")

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if "flash_runner" in alias.name:
                            rel_path = py_path.relative_to(reconstruction_dir)
                            violations.append(f"{rel_path}:{node.lineno} -> import {alias.name}")
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    if "flash_runner" in mod:
                        rel_path = py_path.relative_to(reconstruction_dir)
                        dots = "." * node.level
                        violations.append(
                            f"{rel_path}:{node.lineno} -> from {dots}{mod} import ..."
                        )

        self.assertEqual(
            violations,
            [],
            f"Found forbidden internal imports of flash_runner shim in reconstruction/:\n"
            + "\n".join(violations),
        )


if __name__ == "__main__":
    unittest.main()
