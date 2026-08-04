#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.4.2", "scipy==1.17.1"]
# ///
"""Hermetic tests for the bounded mmWave MAT layout profiler."""

from __future__ import annotations

import importlib.util
import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np
from scipy.io import savemat

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "profile_mmwave_jamming_mat_layout",
    HERE / "profile-mmwave-jamming-mat-layout.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

PRIVATE_MARKERS = (
    "PRIVATE_PATH",
    "PRIVATE_PAIR",
    "PRIVATE_CONDITION_PRESENT",
    "PRIVATE_CONDITION_ABSENT",
)


class MmwaveJammingMatLayoutProfileTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def pair(
        self,
        *,
        left: np.ndarray,
        right: np.ndarray,
        compressed: bool = False,
    ) -> tuple[MODULE.ProfileInput, MODULE.ProfileInput]:
        root = self.temporary_directory() / PRIVATE_MARKERS[0]
        root.mkdir()
        left_path = root / "left-private.mat"
        right_path = root / "right-private.mat"
        savemat(left_path, {"private_signal": left}, do_compression=compressed)
        savemat(right_path, {"private_signal": right}, do_compression=compressed)
        return (
            MODULE.ProfileInput(
                left_path,
                left_path.stat().st_size,
                PRIVATE_MARKERS[1],
                PRIVATE_MARKERS[2],
            ),
            MODULE.ProfileInput(
                right_path,
                right_path.stat().st_size,
                PRIVATE_MARKERS[1],
                PRIVATE_MARKERS[3],
            ),
        )

    def test_profiles_pair_invariance_without_paths_labels_or_values(self):
        inputs = self.pair(
            left=np.zeros((2, 16), dtype=np.float64),
            right=np.ones((2, 16), dtype=np.float64),
        )

        first = MODULE.profile_inputs(inputs, expected_pairs=1)
        second = MODULE.profile_inputs(inputs, expected_pairs=1)
        rendered = MODULE.render_report(first)

        self.assertEqual(first, second)
        self.assertEqual(rendered, MODULE.render_report(second))
        self.assertEqual(first["status"], "pass")
        self.assertEqual(first["inventory"]["artifacts"], 2)
        self.assertEqual(first["inventory"]["paired_cells"], 1)
        self.assertEqual(first["mat_metadata"]["array_values_materialized"], 0)
        self.assertEqual(
            first["pair_invariance"]["mat_layout_signature"]["matching_pairs"],
            1,
        )
        self.assertEqual(first["feature_admission"]["reasons"], [])
        text = rendered.decode("ascii")
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        self.assertNotIn("left-private.mat", text)
        self.assertNotIn("private_signal", text)

    def test_shape_difference_is_a_layout_blocker(self):
        inputs = self.pair(
            left=np.zeros((2, 16), dtype=np.float64),
            right=np.zeros((2, 8), dtype=np.float64),
        )

        report = MODULE.profile_inputs(inputs, expected_pairs=1)

        self.assertEqual(report["status"], "blocked")
        self.assertEqual(
            report["pair_invariance"]["mat_layout_signature"]["mismatching_pairs"],
            1,
        )
        self.assertIn(
            "mat_layout_not_pair_invariant",
            report["feature_admission"]["reasons"],
        )

    def test_compressed_extent_difference_is_a_storage_blocker(self):
        inputs = self.pair(
            left=np.zeros((2, 4096), dtype=np.float64),
            right=np.arange(8192, dtype=np.float64).reshape(2, 4096),
            compressed=True,
        )
        self.assertNotEqual(inputs[0].expected_bytes, inputs[1].expected_bytes)

        report = MODULE.profile_inputs(inputs, expected_pairs=1)

        self.assertEqual(
            report["pair_invariance"]["mat_layout_signature"]["matching_pairs"],
            1,
        )
        self.assertEqual(
            report["pair_invariance"]["exact_storage_extent"]["mismatching_pairs"],
            1,
        )
        self.assertIn(
            "exact_storage_extent_not_pair_invariant",
            report["feature_admission"]["reasons"],
        )

    def test_symlink_malformed_container_and_size_drift_fail_closed(self):
        inputs = list(
            self.pair(
                left=np.zeros((2, 16), dtype=np.float64),
                right=np.zeros((2, 16), dtype=np.float64),
            )
        )
        target = inputs[0].path
        target.unlink()
        target.symlink_to(inputs[1].path)
        with self.assertRaisesRegex(MODULE.LayoutProfileError, "missing_or_unsafe"):
            MODULE.profile_inputs(inputs, expected_pairs=1)

        inputs = list(
            self.pair(
                left=np.zeros((2, 16), dtype=np.float64),
                right=np.zeros((2, 16), dtype=np.float64),
            )
        )
        inputs[0].path.write_bytes(b"not a mat file")
        inputs[0] = MODULE.ProfileInput(
            inputs[0].path,
            inputs[0].path.stat().st_size,
            inputs[0].pair_group,
            inputs[0].condition,
        )
        with self.assertRaisesRegex(
            MODULE.LayoutProfileError, "unsupported_mat_container"
        ):
            MODULE.profile_inputs(inputs, expected_pairs=1)

        inputs = list(
            self.pair(
                left=np.zeros((2, 16), dtype=np.float64),
                right=np.zeros((2, 16), dtype=np.float64),
            )
        )
        inputs[0] = MODULE.ProfileInput(
            inputs[0].path,
            inputs[0].expected_bytes + 1,
            inputs[0].pair_group,
            inputs[0].condition,
        )
        with self.assertRaisesRegex(MODULE.LayoutProfileError, "missing_or_unsafe"):
            MODULE.profile_inputs(inputs, expected_pairs=1)

    def test_mutation_during_metadata_read_is_detected(self):
        inputs = self.pair(
            left=np.zeros((2, 16), dtype=np.float64),
            right=np.zeros((2, 16), dtype=np.float64),
        )
        original_whosmat = MODULE.whosmat
        target = inputs[0].path

        def mutate(source, **kwargs):
            value = original_whosmat(source, **kwargs)
            with target.open("ab") as output:
                output.write(b"x")
            return value

        with mock.patch.object(MODULE, "whosmat", side_effect=mutate):
            with self.assertRaisesRegex(
                MODULE.LayoutProfileError, "changed_during_read"
            ):
                MODULE.inspect_mat(inputs[0])

    def test_pair_inventory_and_resource_bounds_fail_closed(self):
        inputs = self.pair(
            left=np.zeros((2, 16), dtype=np.float64),
            right=np.zeros((2, 16), dtype=np.float64),
        )
        duplicate_condition = (
            inputs[0],
            MODULE.ProfileInput(
                inputs[1].path,
                inputs[1].expected_bytes,
                inputs[1].pair_group,
                inputs[0].condition,
            ),
        )
        with self.assertRaisesRegex(MODULE.LayoutProfileError, "pair_inventory"):
            MODULE.profile_inputs(duplicate_condition, expected_pairs=1)

        with mock.patch.object(
            MODULE, "MAX_ARTIFACT_BYTES", inputs[0].expected_bytes - 1
        ):
            with self.assertRaisesRegex(MODULE.LayoutProfileError, "byte_limit"):
                MODULE.profile_inputs(inputs, expected_pairs=1)

    def test_report_is_atomic_private_and_rejects_symlink_destination(self):
        inputs = self.pair(
            left=np.zeros((2, 16), dtype=np.float64),
            right=np.zeros((2, 16), dtype=np.float64),
        )
        rendered = MODULE.render_report(MODULE.profile_inputs(inputs, expected_pairs=1))
        root = self.temporary_directory()
        output = root / "reports" / "profile.json"

        MODULE.write_report(output, rendered)

        self.assertEqual(output.read_bytes(), rendered)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(
            json.loads(output.read_text(encoding="ascii"))["schema"], MODULE.SCHEMA
        )
        self.assertEqual(list(output.parent.glob(f".{output.name}.*")), [])

        output.unlink()
        target = root / "outside.json"
        target.write_text("unchanged", encoding="ascii")
        output.symlink_to(target)
        with self.assertRaisesRegex(MODULE.LayoutProfileError, "unsafe_report_path"):
            MODULE.write_report(output, rendered)
        self.assertEqual(target.read_text(encoding="ascii"), "unchanged")

        output.unlink()
        output.symlink_to(root / "missing.json")
        with self.assertRaisesRegex(MODULE.LayoutProfileError, "unsafe_report_path"):
            MODULE.write_report(output, rendered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
