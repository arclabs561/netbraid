#!/usr/bin/env python3
"""Hermetic tests for the central-directory-only XRF55 profiler."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "profile_xrf55_layout", HERE / "profile-xrf55-layout.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FIXED_TIME = (2024, 1, 1, 0, 0, 0)


def write_zip(path: Path, entries, *, reverse=False):
    ordered = list(entries)
    if reverse:
        ordered.reverse()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
            for name, payload in ordered:
                info = zipfile.ZipInfo(name, FIXED_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = stat.S_IFREG << 16
                archive.writestr(info, payload)


def source(name: str, filename: str, size: int) -> dict[str, object]:
    payload = filename.encode("utf-8")
    return {
        "kaggle_ref": f"synthetic/{name}",
        "version": 1,
        "metadata_bytes": size + 1,
        "archive_bytes": size,
        "archive_md5": hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        "filename": filename,
    }


def prepare_corpus(base: Path, *, reverse=False):
    raw = base / "raw"
    receipts = base / "receipts"
    raw.mkdir()
    entries = {
        "part1": (
            ("scene1/WiFi/01_01_01.npy", b"wifi-one"),
            ("scene1/RFID/01_01_01.npy", b"rfid-one"),
            ("scene1/mmWave/01_01_01.npy", b"mmwave-one"),
        ),
        "part2": (
            ("scene1_data2/WiFi/02_01_01.npy", b"wifi-two"),
            ("scene1_data2/RFID/02_01_01.npy", b"rfid-two"),
            ("scene1_data2/mmWave/02_01_01.npy", b"mmwave-two"),
        ),
        "raw": (
            ("raw/device-a/sample-1.bin", b"raw-one"),
            ("raw/device-a/sample-1.json", b"{}"),
        ),
    }
    specs = {}
    for name, members in entries.items():
        filename = f"{name}.zip"
        archive = raw / filename
        write_zip(archive, members, reverse=reverse)
        spec = source(name, filename, archive.stat().st_size)
        specs[name] = spec
        receipt = MODULE.FETCH.legacy_receipt_path(archive)
        receipt.write_text(
            json.dumps(
                MODULE.FETCH.source_receipt(
                    spec,
                    archive.stat().st_size,
                    hashlib.sha256(archive.read_bytes()).hexdigest(),
                )
            ),
            encoding="utf-8",
        )
    return raw, receipts, specs


def processed_contracts():
    contract = {
        "subject_groups": 1,
        "scenes": frozenset({1}),
        "actions": frozenset({1}),
        "repetitions": frozenset({1}),
    }
    return {"part1": contract, "part2": contract}


class Xrf55ProfileTests(unittest.TestCase):
    def test_profiles_formats_and_path_overlap_without_retaining_names(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            raw, receipts, specs = prepare_corpus(base)
            report = MODULE.profile_corpus(raw, receipts, specs, processed_contracts())

            self.assertEqual(report["schema"], MODULE.SCHEMA)
            self.assertEqual(
                report["archives"]["part1"]["file_format_counts"],
                {"npy": 3},
            )
            pair = next(
                item
                for item in report["cross_archive"]["pairwise_exact_path_counts"]
                if item["left"] == "part1" and item["right"] == "part2"
            )
            self.assertEqual(pair["exact_member_path_overlap"], 0)
            self.assertEqual(pair["exact_stem_path_overlap"], 0)
            self.assertEqual(
                report["publisher_processed_alignment"]["complete_trimodal_events"],
                2,
            )
            rendered = json.dumps(report, sort_keys=True)
            self.assertNotIn("device-a", rendered)
            self.assertNotIn("01_01_01", rendered)
            self.assertNotIn(str(base), rendered)
            self.assertFalse(report["integrity"]["archive_payload_digest_verified"])
            self.assertEqual(report["privacy"]["member_payload_bytes_read"], 0)

    def test_member_payload_apis_are_never_used(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            raw, receipts, specs = prepare_corpus(base)
            forbidden = AssertionError("member payload API was called")
            with contextlib.ExitStack() as stack:
                for method in ("open", "read", "extract", "extractall"):
                    stack.enter_context(
                        mock.patch.object(
                            MODULE.zipfile.ZipFile, method, side_effect=forbidden
                        )
                    )
                report = MODULE.profile_corpus(
                    raw, receipts, specs, processed_contracts()
                )
            self.assertEqual(report["privacy"]["member_payload_bytes_read"], 0)

    def test_member_order_does_not_change_aggregate_report(self):
        with (
            tempfile.TemporaryDirectory() as first_directory,
            tempfile.TemporaryDirectory() as second_directory,
        ):
            first = Path(first_directory)
            second = Path(second_directory)
            first_raw, first_receipts, first_specs = prepare_corpus(first)
            second_raw, second_receipts, second_specs = prepare_corpus(
                second, reverse=True
            )
            self.assertEqual(
                MODULE.profile_corpus(
                    first_raw, first_receipts, first_specs, processed_contracts()
                ),
                MODULE.profile_corpus(
                    second_raw, second_receipts, second_specs, processed_contracts()
                ),
            )

    def test_unsafe_member_and_receipt_drift_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            raw, receipts, specs = prepare_corpus(base)
            archive = raw / str(specs["part1"]["filename"])
            write_zip(archive, (("../escape.npy", b"unsafe"),))
            specs["part1"] = source("part1", archive.name, archive.stat().st_size)
            receipt = MODULE.FETCH.legacy_receipt_path(archive)
            receipt.write_text(
                json.dumps(
                    MODULE.FETCH.source_receipt(
                        specs["part1"],
                        archive.stat().st_size,
                        hashlib.sha256(archive.read_bytes()).hexdigest(),
                    )
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.Xrf55ProfileError, "unsafe_member_name"):
                MODULE.profile_corpus(raw, receipts, specs, processed_contracts())

            receipt.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(
                MODULE.Xrf55ProfileError, "archive_or_receipt_metadata_unready"
            ):
                MODULE.profile_corpus(raw, receipts, specs, processed_contracts())

    def test_main_writes_deterministic_report(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            raw, receipts, specs = prepare_corpus(base)
            report_path = base / "derived" / "report.json"
            with (
                mock.patch.object(MODULE.FETCH, "SOURCES", specs),
                mock.patch.object(MODULE, "PROCESSED_CONTRACTS", processed_contracts()),
                mock.patch("builtins.print"),
            ):
                first = MODULE.main(
                    [
                        "--raw-dir",
                        str(raw),
                        "--receipt-dir",
                        str(receipts),
                        "--report",
                        str(report_path),
                    ]
                )
                first_bytes = report_path.read_bytes()
                second = MODULE.main(
                    [
                        "--raw-dir",
                        str(raw),
                        "--receipt-dir",
                        str(receipts),
                        "--report",
                        str(report_path),
                    ]
                )
            self.assertEqual((first, second), (0, 0))
            self.assertEqual(first_bytes, report_path.read_bytes())


if __name__ == "__main__":
    unittest.main(verbosity=2)
