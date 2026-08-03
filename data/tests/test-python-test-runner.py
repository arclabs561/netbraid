#!/usr/bin/env python3
"""Tests for the repository-wide hermetic Python test runner."""

from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path, PurePosixPath
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = ROOT / "eval" / "run-python-tests.py"
SPEC = importlib.util.spec_from_file_location(
    "netbraid_python_test_runner", RUNNER_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("test_runner_import_unavailable")
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


class PythonTestRunnerTests(unittest.TestCase):
    def test_discovery_is_sorted_tracked_and_scope_bounded(self) -> None:
        discovered = RUNNER.discover_tests()

        self.assertEqual(discovered, tuple(sorted(discovered)))
        self.assertIn(
            PurePosixPath("data/tests/test-python-test-runner.py"), discovered
        )
        self.assertIn(
            PurePosixPath("eval/test-evaluate-ruff-uwb-cross-distance.py"),
            discovered,
        )
        self.assertTrue(
            all(
                path.parts[:2] == ("data", "tests") or path.parts[:1] == ("eval",)
                for path in discovered
            )
        )

    def test_interpreter_and_inline_metadata_routing(self) -> None:
        self.assertEqual(
            RUNNER.command_for(
                PurePosixPath("data/tests/test-fetch-controlled-jamming.py")
            ),
            (
                "uv",
                "run",
                "--python",
                "3.11",
                "data/tests/test-fetch-controlled-jamming.py",
            ),
        )
        self.assertEqual(
            RUNNER.command_for(PurePosixPath("data/tests/test-fetch-smorffi.py")),
            (
                "uv",
                "run",
                "--python",
                "3.10",
                "data/tests/test-fetch-smorffi.py",
            ),
        )
        self.assertEqual(
            RUNNER.command_for(PurePosixPath("eval/test_hdf5_window.py")),
            ("uv", "run", "--script", "eval/test_hdf5_window.py"),
        )

    def test_empty_and_overbound_inventories_fail_closed(self) -> None:
        with mock.patch.object(RUNNER, "_tracked_files", return_value=()):
            with self.assertRaisesRegex(
                RUNNER.TestRunnerError, "python_test_count_outside_bound"
            ):
                RUNNER.discover_tests()

        overbound = tuple(
            PurePosixPath(f"eval/test-{index:03d}.py")
            for index in range(RUNNER.MAX_TEST_FILES + 1)
        )
        with mock.patch.object(RUNNER, "_tracked_files", return_value=overbound):
            with self.assertRaisesRegex(
                RUNNER.TestRunnerError, "python_test_count_outside_bound"
            ):
                RUNNER.discover_tests()

    def test_nonregular_and_symlink_tests_are_rejected(self) -> None:
        relative = PurePosixPath("eval/test-boundary.py")
        with tempfile.TemporaryDirectory() as directory:
            temporary_root = Path(directory)
            (temporary_root / "eval").mkdir()
            with (
                mock.patch.object(RUNNER, "ROOT", temporary_root),
                mock.patch.object(RUNNER, "_tracked_files", return_value=(relative,)),
            ):
                with self.assertRaisesRegex(
                    RUNNER.TestRunnerError, "python_test_not_regular"
                ):
                    RUNNER.discover_tests()

                target = temporary_root / "target.py"
                target.write_text("pass\n", encoding="utf-8")
                (temporary_root / "eval" / "test-boundary.py").symlink_to(target)
                with self.assertRaisesRegex(
                    RUNNER.TestRunnerError, "python_test_not_regular"
                ):
                    RUNNER.discover_tests()

    def test_list_mode_uses_discovered_inventory_without_execution(self) -> None:
        inventory = (PurePosixPath("eval/test-one.py"),)
        output = io.StringIO()
        with (
            mock.patch.object(RUNNER, "discover_tests", return_value=inventory),
            mock.patch.object(RUNNER.subprocess, "run") as run,
            redirect_stdout(output),
        ):
            self.assertEqual(RUNNER.main(["--list"]), 0)

        run.assert_not_called()
        self.assertEqual(output.getvalue(), "eval/test-one.py\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
