#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["h5py==3.16.0"]
# ///

"""Hermetic tests for the bounded HDF5 column-window reader."""

from __future__ import annotations

import json
import math
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import h5py
import hdf5_window as window


def _write_dataset(
    path: Path,
    values: list[list[float]],
    *,
    dataset: str = "samples",
    dtype: str = "float64",
    compression: str | None = "gzip",
    chunks: tuple[int, ...] | bool | None = True,
) -> None:
    with h5py.File(path, "w") as output:
        output.create_dataset(
            dataset,
            data=values,
            dtype=dtype,
            compression=compression,
            chunks=chunks,
        )


def _naive(values: list[float]) -> dict[str, int | float]:
    result: dict[str, int | float] = {
        "finite": 0,
        "nonfinite": 0,
        "zero": 0,
        "sum": 0.0,
        "sumsq": 0.0,
    }
    for value in values:
        if not math.isfinite(value):
            result["nonfinite"] += 1
            continue
        result["finite"] += 1
        if value == 0.0:
            result["zero"] += 1
        result["sum"] += value
        result["sumsq"] += value * value
    return result


class Hdf5WindowTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "PRIVATE_SOURCE.mat"

    def test_exact_naive_oracle_parity_and_path_free_metadata(self) -> None:
        values = [
            [1.5, -2.0, 0.0, -0.0, math.nan, 4.25, math.inf, -3.0],
            [-1.0, 2.5, 3.0, 0.0, -math.inf, 8.0, math.nan, 0.5],
        ]
        _write_dataset(self.source, values)
        before = self.source.read_bytes()

        result = window.read_column_window(self.source, "samples", 1, 8)

        self.assertEqual(result["rows"][0], _naive(values[0][1:8]))
        self.assertEqual(result["rows"][1], _naive(values[1][1:8]))
        self.assertEqual(result["selected_bytes"], 2 * 7 * 8)
        self.assertFalse(result["truncated"])
        self.assertEqual(self.source.read_bytes(), before)
        encoded = json.dumps(result, allow_nan=False, sort_keys=True)
        self.assertNotIn(str(self.root), encoded)
        self.assertNotIn(self.source.name, encoded)
        self.assertNotIn("samples", encoded)

    def test_chunk_boundary_and_tail_truncation_use_only_requested_slabs(self) -> None:
        values = [
            [float(value) for value in range(10)],
            [float(-value) for value in range(10)],
        ]
        _write_dataset(self.source, values, chunks=(2, 3))
        selections: list[tuple[int, int]] = []
        original = window._read_hyperslab

        def recording_read(dataset, start, stop):
            selections.append((start, stop))
            return original(dataset, start, stop)

        with (
            mock.patch.object(window, "READ_BLOCK_BYTES", 2 * 2 * 8),
            mock.patch.object(window, "_read_hyperslab", side_effect=recording_read),
        ):
            result = window.read_column_window(self.source, "samples", 2, 14)

        self.assertEqual(selections, [(2, 4), (4, 6), (6, 8), (8, 10)])
        self.assertEqual(result["requested_interval"], {"start": 2, "stop": 14})
        self.assertEqual(result["selected_interval"], {"start": 2, "stop": 10})
        self.assertTrue(result["truncated"])
        self.assertEqual(result["rows"][0], _naive(values[0][2:10]))
        self.assertEqual(result["rows"][1], _naive(values[1][2:10]))

    def test_interval_and_byte_budgets_are_bounded(self) -> None:
        _write_dataset(self.source, [[0.0] * 8, [0.0] * 8])
        self.assertEqual(window.DEFAULT_BYTE_BUDGET, 16 * 1024 * 1024)
        self.assertEqual(window.HARD_BYTE_BUDGET, 64 * 1024 * 1024)
        invalid_requests = (
            (-1, 2, window.DEFAULT_BYTE_BUDGET, "invalid_column_interval"),
            (3, 2, window.DEFAULT_BYTE_BUDGET, "invalid_column_interval"),
            (3, 3, window.DEFAULT_BYTE_BUDGET, "invalid_column_interval"),
            (8, 20, window.DEFAULT_BYTE_BUDGET, "invalid_column_interval"),
            (9, 10, window.DEFAULT_BYTE_BUDGET, "invalid_column_interval"),
            (False, 2, window.DEFAULT_BYTE_BUDGET, "invalid_column_interval"),
            (0, 8, 127, "byte_budget_exceeded"),
            (0, 8, window.HARD_BYTE_BUDGET + 1, "invalid_byte_budget"),
        )
        for start, stop, budget, reason in invalid_requests:
            with (
                self.subTest(start=start, stop=stop, budget=budget),
                self.assertRaisesRegex(window.Hdf5WindowError, reason),
            ):
                window.read_column_window(
                    self.source,
                    "samples",
                    start,
                    stop,
                    byte_budget=budget,
                )

    def test_source_and_chunk_storage_are_bounded(self) -> None:
        _write_dataset(self.source, [[0.0] * 8, [0.0] * 8], chunks=(2, 8))
        with (
            mock.patch.object(
                window, "MAX_SOURCE_BYTES", self.source.stat().st_size - 1
            ),
            self.assertRaisesRegex(window.Hdf5WindowError, "source_size_limit"),
        ):
            window.read_column_window(self.source, "samples", 0, 1)

        with (
            mock.patch.object(window, "HARD_BYTE_BUDGET", 64),
            self.assertRaisesRegex(window.Hdf5WindowError, "dataset_chunk_size_limit"),
        ):
            window.read_column_window(self.source, "samples", 0, 1, byte_budget=64)

    def test_rejects_malformed_rank_extent_dtype_and_filter_pipeline(self) -> None:
        cases = {
            "rank": lambda output: output.create_dataset(
                "samples", data=[1.0, 2.0], compression="gzip", chunks=True
            ),
            "extent": lambda output: output.create_dataset(
                "samples",
                data=[[1.0], [2.0], [3.0]],
                compression="gzip",
                chunks=True,
            ),
            "dtype": lambda output: output.create_dataset(
                "samples",
                data=[[1.0], [2.0]],
                dtype="float32",
                compression="gzip",
                chunks=True,
            ),
            "contiguous": lambda output: output.create_dataset(
                "samples", data=[[1.0], [2.0]], dtype="float64"
            ),
            "wrong_filter": lambda output: output.create_dataset(
                "samples",
                data=[[1.0], [2.0]],
                dtype="float64",
                compression="lzf",
                chunks=True,
            ),
            "extra_filter": lambda output: output.create_dataset(
                "samples",
                data=[[1.0], [2.0]],
                dtype="float64",
                compression="gzip",
                shuffle=True,
                chunks=True,
            ),
        }
        for name, create in cases.items():
            with self.subTest(name=name):
                path = self.root / f"{name}.h5"
                with h5py.File(path, "w") as output:
                    create(output)
                with self.assertRaises(window.Hdf5WindowError):
                    window.read_column_window(path, "samples", 0, 1)

    def test_rejects_soft_external_alias_and_filesystem_links(self) -> None:
        target = self.root / "target.h5"
        _write_dataset(target, [[1.0, 2.0], [3.0, 4.0]], dataset="real")

        soft = self.root / "soft.h5"
        with h5py.File(soft, "w") as output:
            output["samples"] = h5py.SoftLink("/real")
            output.create_dataset(
                "real",
                data=[[1.0], [2.0]],
                compression="gzip",
                chunks=True,
            )
        external = self.root / "external.h5"
        with h5py.File(external, "w") as output:
            output["samples"] = h5py.ExternalLink(target.name, "/real")
        alias = self.root / "alias.h5"
        with h5py.File(alias, "w") as output:
            dataset = output.create_dataset(
                "samples",
                data=[[1.0], [2.0]],
                compression="gzip",
                chunks=True,
            )
            output["alias"] = dataset

        for path in (soft, external, alias):
            with (
                self.subTest(path=path.name),
                self.assertRaisesRegex(window.Hdf5WindowError, "unsafe_dataset_link"),
            ):
                window.read_column_window(path, "samples", 0, 1)

        filesystem_link = self.root / "PRIVATE_LINK.h5"
        filesystem_link.symlink_to(target)
        with self.assertRaisesRegex(window.Hdf5WindowError, "source_not_regular"):
            window.read_column_window(filesystem_link, "real", 0, 1)

    def test_rejects_external_and_virtual_dataset_storage(self) -> None:
        external = self.root / "external-storage.h5"
        external_raw = self.root / "PRIVATE_EXTERNAL.raw"
        with h5py.File(external, "w") as output:
            output.create_dataset(
                "samples",
                shape=(2, 2),
                dtype="float64",
                external=[(str(external_raw), 0, h5py.h5f.UNLIMITED)],
            )

        virtual_source = self.root / "virtual-source.h5"
        _write_dataset(
            virtual_source,
            [[1.0, 2.0], [3.0, 4.0]],
            dataset="source",
        )
        virtual = self.root / "virtual.h5"
        layout = h5py.VirtualLayout(shape=(2, 2), dtype="float64")
        layout[:, :] = h5py.VirtualSource(str(virtual_source), "source", shape=(2, 2))
        with h5py.File(virtual, "w") as output:
            output.create_virtual_dataset("samples", layout)

        for path in (external, virtual):
            with (
                self.subTest(path=path.name),
                self.assertRaisesRegex(
                    window.Hdf5WindowError, "unsafe_dataset_storage"
                ),
            ):
                window.read_column_window(path, "samples", 0, 1)

    def test_detects_source_change_during_hyperslab_read(self) -> None:
        _write_dataset(self.source, [[1.0, 2.0], [3.0, 4.0]])
        original = window._read_hyperslab

        def changing_read(dataset, start, stop):
            slab = original(dataset, start, stop)
            metadata = self.source.stat()
            os.utime(
                self.source,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000),
            )
            return slab

        with (
            mock.patch.object(window, "_read_hyperslab", side_effect=changing_read),
            self.assertRaisesRegex(
                window.Hdf5WindowError, "source_changed_during_read"
            ),
        ):
            window.read_column_window(self.source, "samples", 0, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
