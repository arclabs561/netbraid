#!/usr/bin/env python3
"""Hermetic tests for the pinned KaggleHub SMoRFFI fetcher."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "fetch_smorffi", HERE.parent / "fetch" / "fetch-smorffi.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class FakeKaggleHub:
    def __init__(self, writer=None, returned=None, error=None):
        self.writer = writer or self._write_regular_tree
        self.returned = returned
        self.error = error
        self.calls = []

    @staticmethod
    def _write_regular_tree(output_dir):
        root = Path(output_dir)
        (root / "nested").mkdir()
        (root / "z-last.bin").write_bytes(b"last")
        (root / "nested" / "a-first.bin").write_bytes(b"first")

    def dataset_download(self, handle, *, output_dir):
        self.calls.append((handle, output_dir))
        if self.error is not None:
            raise self.error
        self.writer(output_dir)
        return output_dir if self.returned is None else self.returned


def paths(directory):
    base = Path(directory)
    return base / "raw" / "smorffi-v3", base / "receipts" / "smorffi-v3.json"


class FetchSmorffiTests(unittest.TestCase):
    def test_pep723_metadata_pins_current_release_and_python_310(self):
        script = (HERE.parent / "fetch" / "fetch-smorffi.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('# requires-python = ">=3.10"', script)
        self.assertIn('# dependencies = ["kagglehub==1.0.2"]', script)
        self.assertEqual(
            MODULE.DATASET_HANDLE,
            "yinchen1986/rffi-123-m5stack-iq-wifi-802-11g-2-4g/versions/3",
        )

    def test_default_status_and_list_are_network_free(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, receipt_path = paths(directory)
            with (
                mock.patch.object(MODULE, "DEFAULT_RAW_DIR", raw_dir),
                mock.patch.object(MODULE, "DEFAULT_RECEIPT_PATH", receipt_path),
                mock.patch.object(
                    MODULE,
                    "_load_kagglehub",
                    side_effect=AssertionError("network path reached"),
                ) as loader,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                self.assertEqual(MODULE.main([]), 0)
                self.assertEqual(json.loads(output.getvalue()), {"state": "absent"})
                output.seek(0)
                output.truncate()
                self.assertEqual(MODULE.main(["list"]), 0)
                catalog = json.loads(output.getvalue())
            loader.assert_not_called()
            self.assertFalse(raw_dir.parent.exists())
            self.assertFalse(receipt_path.parent.exists())
            self.assertEqual(catalog["version"], 3)
            self.assertEqual(catalog["dependency"], "kagglehub==1.0.2")

    def test_explicit_fetch_uses_output_dir_and_writes_deterministic_receipt(self):
        fake = FakeKaggleHub()
        receipt = None
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, receipt_path = paths(directory)
            result = MODULE.fetch_dataset(raw_dir, receipt_path, kagglehub_module=fake)
            self.assertEqual(result["disposition"], "downloaded")
            self.assertEqual(fake.calls[0][0], MODULE.DATASET_HANDLE)
            staging = Path(fake.calls[0][1])
            self.assertEqual(staging.parent, raw_dir.parent)
            self.assertFalse(staging.exists())
            self.assertEqual((raw_dir / "z-last.bin").read_bytes(), b"last")
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["source"]["version"], 3)
            self.assertNotIn("publisher_checksum", json.dumps(receipt))
            self.assertEqual(
                [item["path"] for item in receipt["integrity"]["files"]],
                ["nested/a-first.bin", "z-last.bin"],
            )
            self.assertTrue(
                all(len(item["sha256"]) == 64 for item in receipt["integrity"]["files"])
            )
            self.assertEqual(
                len(receipt["integrity"]["inventory"]["local_inventory_sha256"]),
                64,
            )
            self.assertEqual(
                MODULE.verify_local(raw_dir, receipt_path)["state"], "verified"
            )
            self.assertEqual(
                MODULE.fetch_dataset(raw_dir, receipt_path, kagglehub_module=fake)[
                    "disposition"
                ],
                "reused",
            )
            self.assertEqual(len(fake.calls), 1)

        with tempfile.TemporaryDirectory() as directory:
            raw_dir, receipt_path = paths(directory)
            MODULE.fetch_dataset(
                raw_dir, receipt_path, kagglehub_module=FakeKaggleHub()
            )
            self.assertEqual(
                json.loads(receipt_path.read_text(encoding="utf-8")), receipt
            )

    def test_output_escape_is_rejected_without_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, receipt_path = paths(directory)
            escaped = Path(directory) / "escaped"
            escaped.mkdir()
            fake = FakeKaggleHub(returned=escaped)
            with self.assertRaisesRegex(MODULE.FetchError, "kagglehub_output_escape"):
                MODULE.fetch_dataset(raw_dir, receipt_path, kagglehub_module=fake)
            self.assertFalse(raw_dir.exists())
            self.assertFalse(receipt_path.exists())

    def test_symlink_and_nonregular_outputs_are_rejected(self):
        cases = []

        def write_symlink(output_dir):
            root = Path(output_dir)
            target = root.parent / "outside"
            target.write_bytes(b"outside")
            (root / "escape").symlink_to(target)

        cases.append((write_symlink, "symlink_output_rejected"))
        if hasattr(os, "mkfifo"):

            def write_fifo(output_dir):
                os.mkfifo(Path(output_dir) / "pipe")

            cases.append((write_fifo, "nonregular_output_rejected"))

        for writer, error_code in cases:
            with (
                self.subTest(error_code=error_code),
                tempfile.TemporaryDirectory() as directory,
            ):
                raw_dir, receipt_path = paths(directory)
                with self.assertRaisesRegex(MODULE.FetchError, error_code):
                    MODULE.fetch_dataset(
                        raw_dir,
                        receipt_path,
                        kagglehub_module=FakeKaggleHub(writer=writer),
                    )
                self.assertFalse(raw_dir.exists())
                self.assertFalse(receipt_path.exists())

    def test_file_mutation_during_inventory_is_rejected(self):
        fake = FakeKaggleHub()
        original = MODULE._digest_regular_file
        mutated = False

        def mutate_then_digest(path, expected, bounds):
            nonlocal mutated
            if not mutated:
                mutated = True
                path.write_bytes(path.read_bytes() + b"changed")
            return original(path, expected, bounds)

        with tempfile.TemporaryDirectory() as directory:
            raw_dir, receipt_path = paths(directory)
            with (
                mock.patch.object(
                    MODULE, "_digest_regular_file", side_effect=mutate_then_digest
                ),
                self.assertRaisesRegex(
                    MODULE.FetchError, "unsafe_or_changed_output_file"
                ),
            ):
                MODULE.fetch_dataset(raw_dir, receipt_path, kagglehub_module=fake)
            self.assertFalse(raw_dir.exists())
            self.assertFalse(receipt_path.exists())

    def test_entry_file_total_file_size_and_depth_bounds_fail_closed(self):
        def write_many(output_dir):
            root = Path(output_dir)
            (root / "a").write_bytes(b"1234")
            (root / "b").write_bytes(b"5678")

        cases = (
            (MODULE.Bounds(max_entries=1), "max_entries_exceeded"),
            (MODULE.Bounds(max_files=1), "max_files_exceeded"),
            (MODULE.Bounds(max_total_bytes=7), "max_total_bytes_exceeded"),
            (MODULE.Bounds(max_file_bytes=3), "max_file_bytes_exceeded"),
            (MODULE.Bounds(max_depth=1), None),
        )
        for bounds, error_code in cases:
            with (
                self.subTest(error_code=error_code),
                tempfile.TemporaryDirectory() as directory,
            ):
                raw_dir, receipt_path = paths(directory)
                if error_code is None:
                    result = MODULE.fetch_dataset(
                        raw_dir,
                        receipt_path,
                        bounds,
                        FakeKaggleHub(writer=write_many),
                    )
                    self.assertEqual(result["state"], "verified")
                else:
                    with self.assertRaisesRegex(MODULE.FetchError, error_code):
                        MODULE.fetch_dataset(
                            raw_dir,
                            receipt_path,
                            bounds,
                            FakeKaggleHub(writer=write_many),
                        )
                    self.assertFalse(raw_dir.exists())

        def write_nested(output_dir):
            nested = Path(output_dir) / "one" / "two"
            nested.mkdir(parents=True)
            (nested / "three.bin").write_bytes(b"x")

        with tempfile.TemporaryDirectory() as directory:
            raw_dir, receipt_path = paths(directory)
            with self.assertRaisesRegex(MODULE.FetchError, "max_depth_exceeded"):
                MODULE.fetch_dataset(
                    raw_dir,
                    receipt_path,
                    MODULE.Bounds(max_depth=2),
                    FakeKaggleHub(writer=write_nested),
                )

    def test_changed_data_and_unsafe_receipt_fail_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, receipt_path = paths(directory)
            MODULE.fetch_dataset(
                raw_dir, receipt_path, kagglehub_module=FakeKaggleHub()
            )
            (raw_dir / "z-last.bin").write_bytes(b"mutated")
            with self.assertRaisesRegex(
                MODULE.FetchError, "local_data_or_receipt_mismatch"
            ):
                MODULE.verify_local(raw_dir, receipt_path)

        with tempfile.TemporaryDirectory() as directory:
            raw_dir, receipt_path = paths(directory)
            MODULE.fetch_dataset(
                raw_dir, receipt_path, kagglehub_module=FakeKaggleHub()
            )
            receipt_path.unlink()
            target = receipt_path.parent / "other.json"
            target.write_text("{}", encoding="utf-8")
            receipt_path.symlink_to(target)
            with self.assertRaisesRegex(MODULE.FetchError, "receipt_missing_or_unsafe"):
                MODULE.verify_local(raw_dir, receipt_path)

    def test_download_failure_does_not_echo_exception_or_credentials(self):
        fake = FakeKaggleHub(error=RuntimeError("KAGGLE_API_TOKEN=do-not-print"))
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, receipt_path = paths(directory)
            with (
                mock.patch.object(MODULE, "DEFAULT_RAW_DIR", raw_dir),
                mock.patch.object(MODULE, "DEFAULT_RECEIPT_PATH", receipt_path),
                mock.patch.object(MODULE, "_load_kagglehub", return_value=fake),
                contextlib.redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(MODULE.main(["fetch"]), 2)
            self.assertEqual(errors.getvalue(), "kagglehub_download_failed\n")
            self.assertNotIn("do-not-print", errors.getvalue())
            self.assertEqual(Path(fake.calls[0][1]).parent, raw_dir.parent)

    def test_receipt_failure_rolls_back_promoted_data(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, receipt_path = paths(directory)
            with (
                mock.patch.object(
                    MODULE,
                    "_write_receipt",
                    side_effect=MODULE.FetchError("receipt_write_failed"),
                ),
                self.assertRaisesRegex(MODULE.FetchError, "receipt_write_failed"),
            ):
                MODULE.fetch_dataset(
                    raw_dir,
                    receipt_path,
                    kagglehub_module=FakeKaggleHub(),
                )
            self.assertFalse(raw_dir.exists())
            self.assertFalse(receipt_path.exists())

    def test_default_paths_are_both_gitignored(self):
        self.assertEqual(
            MODULE.DEFAULT_RAW_DIR, MODULE.REPOSITORY / "data/raw/smorffi-v3"
        )
        self.assertEqual(
            MODULE.DEFAULT_RECEIPT_PATH,
            MODULE.REPOSITORY / "data/receipts/smorffi-v3.json",
        )
        ignores = set((MODULE.REPOSITORY / ".gitignore").read_text().splitlines())
        self.assertIn("/data/raw/", ignores)
        self.assertIn("/data/receipts/", ignores)


if __name__ == "__main__":
    unittest.main(verbosity=2)
