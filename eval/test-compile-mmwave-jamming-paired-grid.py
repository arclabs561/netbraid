#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2", "scipy==1.17.1"]
# ///
"""Hermetic tests for the mmWave pair-aligned content-grid compiler."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
from scipy.io import savemat

HERE = Path(__file__).resolve().parent
COMPILER_PATH = HERE / "compile-mmwave-jamming-paired-grid.py"
SPEC = importlib.util.spec_from_file_location(
    "compile_mmwave_jamming_paired_grid", COMPILER_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("compiler_import_failed")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _digests(path: Path) -> tuple[str, str]:
    payload = path.read_bytes()
    return (
        hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        hashlib.sha256(payload).hexdigest(),
    )


def _input(
    path: Path,
    observation_id: str,
    pair_group_id: str,
) -> MODULE.GridInput:
    md5, sha256 = _digests(path)
    return MODULE.GridInput(
        path=path,
        expected_bytes=path.stat().st_size,
        expected_md5=md5,
        expected_sha256=sha256,
        observation_id=observation_id,
        pair_group_id=pair_group_id,
    )


def _position_values(shape: tuple[int, int, int]) -> np.ndarray:
    first, second, third = np.indices(shape, dtype=np.float64)
    return first * 100_000.0 + second * 100.0 + third


def _write_mat(
    path: Path,
    variable_name: str,
    values: np.ndarray,
    *,
    compressed: bool,
) -> None:
    savemat(
        path,
        {variable_name: values},
        appendmat=False,
        do_compression=compressed,
        format="5",
    )


class PairAlignmentTests(unittest.TestCase):
    def test_integer_stratification_is_endpoint_inclusive_and_unique(self):
        indices = MODULE.stratified_indices(32, 16)
        self.assertEqual(
            indices.tolist(),
            [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 31],
        )
        with self.assertRaisesRegex(
            MODULE.PairedGridCompileError, "insufficient_common_extent"
        ):
            MODULE.stratified_indices(15, 16)

    def test_mismatched_shapes_share_indices_and_erase_source_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left = root / "condition-looking-left.mat"
            right = root / "different-storage-right.mat"
            left_values = _position_values((16, 16, 8))
            right_values = _position_values((20, 18, 10))
            right_values[16:, :, :] = -900_000_000.0
            right_values[:, 16:, :] = 800_000_000.0
            right_values[:, :, 8:] = -700_000_000.0
            _write_mat(left, "left_private_name", left_values, compressed=True)
            _write_mat(right, "right_private_name", right_values, compressed=False)
            inputs = (
                _input(right, "b" * 64, "c" * 64),
                _input(left, "a" * 64, "c" * 64),
            )
            outputs = MODULE.OutputSet(root / "adapter.json", root / "matrix.npy")

            adapter = MODULE.write_cache(
                outputs,
                inputs,
                inventory_id="inventory-v0",
                oracle_schema="oracle-v0",
                expected_pairs=1,
            )

            mapped = np.load(outputs.matrix, mmap_mode="r", allow_pickle=False)
            self.assertIsInstance(mapped, np.memmap)
            self.assertFalse(mapped.flags.writeable)
            self.assertEqual(mapped.shape, (2, 16, 16, 8, 2))
            np.testing.assert_array_equal(mapped[0], mapped[1])
            np.testing.assert_array_equal(mapped[0, ..., 0], left_values.astype("<f4"))
            np.testing.assert_array_equal(mapped[..., 1], 0.0)
            self.assertEqual(
                adapter["rows"],
                [
                    {"observation_id": "a" * 64, "row": 0},
                    {"observation_id": "b" * 64, "row": 1},
                ],
            )
            encoded = outputs.adapter.read_text()
            for forbidden in (
                left.name,
                right.name,
                "left_private_name",
                "right_private_name",
                "c" * 64,
                inputs[0].expected_md5,
                inputs[0].expected_sha256,
                os.fspath(root),
            ):
                self.assertNotIn(forbidden, encoded)
            self.assertEqual(adapter["privacy"]["source_shapes_retained"], 0)
            self.assertEqual(adapter["privacy"]["condition_labels_retained"], 0)

    def test_complex_values_use_explicit_real_and_imaginary_components(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = (root / "first.mat", root / "second.mat")
            base = _position_values((16, 16, 8))
            values = base + 1j * (base + 7.0)
            for path, name in zip(paths, ("first", "second"), strict=True):
                _write_mat(path, name, values, compressed=True)
            inputs = tuple(
                _input(path, character * 64, "c" * 64)
                for path, character in zip(paths, ("a", "b"), strict=True)
            )
            outputs = MODULE.OutputSet(root / "adapter.json", root / "matrix.npy")

            MODULE.write_cache(
                outputs,
                inputs,
                inventory_id="inventory",
                oracle_schema="oracle",
                expected_pairs=1,
            )

            matrix = np.load(outputs.matrix, allow_pickle=False)
            np.testing.assert_array_equal(matrix[0, ..., 0], base.astype("<f4"))
            np.testing.assert_array_equal(matrix[0, ..., 1], (base + 7.0).astype("<f4"))


class OutputContractTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[MODULE.GridInput, MODULE.GridInput]:
        first = root / "first.mat"
        second = root / "second.mat"
        values = _position_values((16, 16, 8))
        _write_mat(first, "one", values, compressed=True)
        _write_mat(second, "two", values + 1.0, compressed=True)
        return (
            _input(first, "a" * 64, "c" * 64),
            _input(second, "b" * 64, "c" * 64),
        )

    def test_repeated_outputs_are_byte_identical_private_memmaps(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = self._fixture(root)
            outputs = [
                MODULE.OutputSet(
                    root / f"adapter-{suffix}.json", root / f"matrix-{suffix}.npy"
                )
                for suffix in ("first", "second")
            ]
            documents = [
                MODULE.write_cache(
                    output,
                    inputs,
                    inventory_id="inventory",
                    oracle_schema="oracle",
                    expected_pairs=1,
                )
                for output in outputs
            ]

            self.assertEqual(documents[0], documents[1])
            self.assertEqual(
                outputs[0].adapter.read_bytes(), outputs[1].adapter.read_bytes()
            )
            self.assertEqual(
                outputs[0].matrix.read_bytes(), outputs[1].matrix.read_bytes()
            )
            for output in outputs:
                self.assertEqual(stat.S_IMODE(output.adapter.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(output.matrix.stat().st_mode), 0o600)
            adapter = json.loads(outputs[0].adapter.read_text())
            digest = hashlib.sha256(outputs[0].matrix.read_bytes()).hexdigest()
            self.assertEqual(adapter["matrix"]["sha256"], digest)
            self.assertEqual(
                adapter["matrix"]["bytes"], outputs[0].matrix.stat().st_size
            )

    def test_rejects_nonfinite_selected_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = _position_values((16, 16, 8))
            values[0, 0, 0] = np.nan
            inputs = []
            for index in range(2):
                path = root / f"source-{index}.mat"
                _write_mat(path, f"value_{index}", values, compressed=True)
                inputs.append(_input(path, str(index) * 64, "c" * 64))
            with self.assertRaisesRegex(
                MODULE.PairedGridCompileError, "selected_grid_invalid"
            ):
                MODULE.write_cache(
                    MODULE.OutputSet(root / "adapter.json", root / "matrix.npy"),
                    inputs,
                    inventory_id="inventory",
                    oracle_schema="oracle",
                    expected_pairs=1,
                )

    def test_rejects_insufficient_common_extent_and_digest_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            small = root / "small.mat"
            regular = root / "regular.mat"
            _write_mat(small, "small", np.zeros((15, 16, 8)), compressed=True)
            _write_mat(regular, "regular", np.zeros((16, 16, 8)), compressed=True)
            inputs = (
                _input(small, "a" * 64, "c" * 64),
                _input(regular, "b" * 64, "c" * 64),
            )
            with self.assertRaisesRegex(
                MODULE.PairedGridCompileError, "insufficient_common_extent"
            ):
                MODULE.write_cache(
                    MODULE.OutputSet(root / "adapter.json", root / "matrix.npy"),
                    inputs,
                    inventory_id="inventory",
                    oracle_schema="oracle",
                    expected_pairs=1,
                )

            valid_inputs = list(self._fixture(root))
            valid_inputs[0] = MODULE.GridInput(
                **{
                    **valid_inputs[0].__dict__,
                    "expected_sha256": "0" * 64,
                }
            )
            with self.assertRaisesRegex(
                MODULE.PairedGridCompileError, "source_digest_mismatch"
            ):
                MODULE.write_cache(
                    MODULE.OutputSet(root / "adapter-2.json", root / "matrix-2.npy"),
                    valid_inputs,
                    inventory_id="inventory",
                    oracle_schema="oracle",
                    expected_pairs=1,
                )

    def test_rejects_symlink_and_duplicate_output_targets(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = self._fixture(root)
            target = root / "target.json"
            target.write_text("{}\n")
            linked = root / "linked.json"
            linked.symlink_to(target)
            with self.assertRaisesRegex(
                MODULE.PairedGridCompileError, "unsafe_output_path"
            ):
                MODULE.write_cache(
                    MODULE.OutputSet(linked, root / "matrix.npy"),
                    inputs,
                    inventory_id="inventory",
                    oracle_schema="oracle",
                    expected_pairs=1,
                )
            duplicate = root / "same"
            with self.assertRaisesRegex(
                MODULE.PairedGridCompileError, "duplicate_output_path"
            ):
                MODULE.write_cache(
                    MODULE.OutputSet(duplicate, duplicate),
                    inputs,
                    inventory_id="inventory",
                    oracle_schema="oracle",
                    expected_pairs=1,
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
