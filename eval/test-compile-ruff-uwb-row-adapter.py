#!/usr/bin/env python3
"""Hermetic tests for the RUFF-UWB one-meter row adapter compiler."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import struct
import sys
import tempfile
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest import mock


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "compile_ruff_uwb_row_adapter", HERE / "compile-ruff-uwb-row-adapter.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
EVALUATOR_SPEC = importlib.util.spec_from_file_location(
    "evaluate_ruff_uwb_heldout_location",
    HERE / "evaluate-ruff-uwb-heldout-location.py",
)
assert EVALUATOR_SPEC is not None and EVALUATOR_SPEC.loader is not None
EVALUATOR = importlib.util.module_from_spec(EVALUATOR_SPEC)
sys.modules[EVALUATOR_SPEC.name] = EVALUATOR
EVALUATOR_SPEC.loader.exec_module(EVALUATOR)


def npy_bytes(dtype, shape, payload):
    header = repr({"descr": dtype, "fortran_order": False, "shape": shape}).encode(
        "latin1"
    )
    padding = 16 - (10 + len(header) + 1) % 16
    header += b" " * padding + b"\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header + payload


def label_npy(rows):
    payload = b"".join(struct.pack("<qq", *row) for row in rows)
    return npy_bytes("<i8", (len(rows), 2), payload)


def waveform_npy(row_count, sample_count):
    values = []
    for row in range(row_count):
        for sample in range(sample_count):
            values.extend((float(row + sample), float(row - sample)))
    payload = struct.pack("<" + "d" * len(values), *values)
    return npy_bytes("<c16", (row_count, sample_count), payload)


def member_contract(info, *, dtype, shape, sha256=None):
    return MODULE.ZipMemberContract(
        name=info.filename,
        file_bytes=info.file_size,
        compressed_bytes=info.compress_size,
        crc32=info.CRC,
        compression=info.compress_type,
        flags=info.flag_bits,
        header_offset=info.header_offset,
        dtype=dtype,
        shape=shape,
        sha256=sha256,
    )


class Fixture:
    def __init__(self, case):
        temporary = tempfile.TemporaryDirectory()
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.archive_path = self.root / "PRIVATE_ARCHIVE.zip"
        self.waveform_path = self.root / "derived" / "PRIVATE_WAVEFORMS.npy"
        self.adapter_path = self.root / "derived" / "PRIVATE_ADAPTER.json"
        self.rows = [
            (source, location)
            for location in range(10)
            for source in range(2)
            for _ in range(2)
        ]
        self.labels = label_npy(self.rows)
        self.waveforms = waveform_npy(len(self.rows), 8)
        self.source = {
            "bytes": 0,
            "doi": "PRIVATE_DOI",
            "filename": self.archive_path.name,
            "group": "PRIVATE_GROUP",
            "license": "PRIVATE_LICENSE",
            "md5": "0" * 32,
            "record": "PRIVATE_RECORD",
            "record_bytes": 0,
            "representation": "npy",
            "url": "https://invalid.example/PRIVATE_ARCHIVE",
        }
        self._write_archive()

    def _write_archive(self):
        with zipfile.ZipFile(
            self.archive_path, "w", compression=zipfile.ZIP_DEFLATED
        ) as archive:
            archive.writestr("PRIVATE_WAVEFORM.data.npy", self.waveforms)
            archive.writestr("PRIVATE_LABELS.labels.npy", self.labels)
        self.refresh_contract()

    def refresh_contract(self):
        encoded = self.archive_path.read_bytes()
        with zipfile.ZipFile(self.archive_path) as archive:
            waveform = archive.getinfo("PRIVATE_WAVEFORM.data.npy")
            label = archive.getinfo("PRIVATE_LABELS.labels.npy")
            self.contract = MODULE.ArchiveContract(
                filename=self.archive_path.name,
                archive_bytes=len(encoded),
                archive_md5=hashlib.md5(encoded, usedforsecurity=False).hexdigest(),
                archive_sha256=hashlib.sha256(encoded).hexdigest(),
                receipt_source=self.source,
                collection_token="PRIVATE_DISTANCE_ONE",
                source_count=2,
                location_count=10,
                label=member_contract(
                    label,
                    dtype="<i8",
                    shape=(len(self.rows), 2),
                    sha256=hashlib.sha256(self.labels).hexdigest(),
                ),
                waveform=member_contract(
                    waveform,
                    dtype="<c16",
                    shape=(len(self.rows), 8),
                ),
            )
        self.write_receipt()

    def write_receipt(self, **changes):
        receipt = {
            "schema": MODULE.RECEIPT_SCHEMA,
            "source": self.source,
            "bytes": self.contract.archive_bytes,
            "md5": self.contract.archive_md5,
            "sha256": self.contract.archive_sha256,
            "archive": self.contract.filename,
        }
        receipt.update(changes)
        self.receipt_path = self.root / "receipts" / f"{self.archive_path.name}.json"
        self.receipt_path.parent.mkdir(mode=0o700, exist_ok=True)
        self.receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        os.chmod(self.receipt_path, 0o600)

    def compile(self):
        return MODULE.compile_row_adapter(
            self.archive_path,
            self.receipt_path,
            self.waveform_path,
            self.adapter_path,
            self.contract,
        )


class RuffUwbRowAdapterCompilerTests(unittest.TestCase):
    def test_ordered_labels_become_gap_free_opaque_spans_and_private_npy(self):
        fixture = Fixture(self)
        archive_before = fixture.archive_path.read_bytes()
        receipt_before = fixture.receipt_path.read_bytes()

        adapter, reused = fixture.compile()

        self.assertFalse(reused)
        self.assertEqual(fixture.waveform_path.read_bytes(), fixture.waveforms)
        self.assertEqual(fixture.archive_path.read_bytes(), archive_before)
        self.assertEqual(fixture.receipt_path.read_bytes(), receipt_before)
        self.assertEqual(stat.S_IMODE(fixture.waveform_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(fixture.adapter_path.stat().st_mode), 0o600)
        self.assertEqual(adapter["counts"]["rows"], len(fixture.rows))
        self.assertEqual(adapter["counts"]["spans"], 20)
        self.assertEqual(adapter["waveform_source"]["dtype"], "<c16")
        self.assertEqual(adapter["waveform_source"]["samples_per_row"], 8)

        expanded = []
        expected_start = 0
        domains = {
            "distance_collection": set(),
            "physical_source": set(),
            "physical_device": set(),
            "location": set(),
        }
        for span in adapter["spans"]:
            self.assertEqual(span["row_start"], expected_start)
            self.assertGreater(span["row_stop"], span["row_start"])
            expected_start = span["row_stop"]
            expanded.extend(
                (
                    span["physical_source"],
                    span["physical_device"],
                    span["location"],
                )
                for _ in range(span["row_stop"] - span["row_start"])
            )
            for domain in domains:
                domains[domain].add(span[domain])
        self.assertEqual(expected_start, len(fixture.rows))
        self.assertEqual(len(expanded), len(fixture.rows))
        source_projection = {}
        device_projection = {}
        location_projection = {}
        for raw, opaque_values in zip(fixture.rows, expanded):
            raw_source, raw_location = raw
            source_id, device_id, location_id = opaque_values
            source_projection.setdefault(raw_source, source_id)
            device_projection.setdefault(raw_source, device_id)
            location_projection.setdefault(raw_location, location_id)
            self.assertEqual(source_projection[raw_source], source_id)
            self.assertEqual(device_projection[raw_source], device_id)
            self.assertEqual(location_projection[raw_location], location_id)
        for left, left_values in domains.items():
            for right, right_values in domains.items():
                if left < right:
                    self.assertFalse(left_values & right_values)

        encoded = MODULE.render_adapter(adapter).decode("utf-8")
        for private in (
            str(fixture.root),
            fixture.archive_path.name,
            fixture.contract.label.name,
            fixture.contract.waveform.name,
            "PRIVATE_DISTANCE_ONE",
            "PRIVATE_DOI",
        ):
            self.assertNotIn(private, encoded)

        evaluator_binding = EVALUATOR.RowAdapterBinding(
            archive=adapter["archive"],
            label_member=adapter["label_member"],
            waveform_member={
                key: value
                for key, value in adapter["waveform_member"].items()
                if key != "sha256"
            },
        )
        loaded = EVALUATOR.validate_row_adapter(adapter, evaluator_binding)
        self.assertEqual(len(loaded.rows), len(fixture.rows))
        self.assertEqual(
            loaded.source_contract.sha256,
            hashlib.sha256(fixture.waveforms).hexdigest(),
        )

    def test_verified_file_and_manifest_are_idempotent_without_waveform_open(self):
        fixture = Fixture(self)
        first, _ = fixture.compile()
        before = (
            fixture.waveform_path.stat().st_ino,
            fixture.waveform_path.stat().st_mtime_ns,
            fixture.adapter_path.stat().st_ino,
            fixture.adapter_path.stat().st_mtime_ns,
        )
        original_open = MODULE.zipfile.ZipFile.open

        def guarded_open(archive, name, *args, **kwargs):
            candidate = name.filename if isinstance(name, zipfile.ZipInfo) else name
            if candidate == fixture.contract.waveform.name:
                raise AssertionError("waveform member opened during idempotent verify")
            return original_open(archive, name, *args, **kwargs)

        with mock.patch.object(MODULE.zipfile.ZipFile, "open", guarded_open):
            second, reused = fixture.compile()

        self.assertTrue(reused)
        self.assertEqual(first, second)
        self.assertEqual(
            before,
            (
                fixture.waveform_path.stat().st_ino,
                fixture.waveform_path.stat().st_mtime_ns,
                fixture.adapter_path.stat().st_ino,
                fixture.adapter_path.stat().st_mtime_ns,
            ),
        )

    def test_receipt_is_mandatory_exact_and_duplicate_key_safe(self):
        fixture = Fixture(self)
        fixture.receipt_path.unlink()
        with self.assertRaisesRegex(MODULE.AdapterCompileError, "receipt_unavailable"):
            fixture.compile()

        fixture.write_receipt(bytes=fixture.contract.archive_bytes + 1)
        with self.assertRaisesRegex(
            MODULE.AdapterCompileError, "archive_receipt_mismatch"
        ):
            fixture.compile()

        fixture.receipt_path.write_text(
            '{"schema":"first","schema":"second"}', encoding="utf-8"
        )
        with self.assertRaisesRegex(
            MODULE.AdapterCompileError, "receipt_duplicate_json_key"
        ):
            fixture.compile()

    def test_label_digest_shape_and_member_extent_are_pinned(self):
        fixture = Fixture(self)
        bad_contracts = (
            (
                replace(
                    fixture.contract,
                    label=replace(fixture.contract.label, sha256="0" * 64),
                ),
                "label_member_digest_mismatch",
            ),
            (
                replace(
                    fixture.contract,
                    label=replace(
                        fixture.contract.label,
                        shape=(len(fixture.rows) - 1, 2),
                    ),
                ),
                "invalid_archive_contract",
            ),
            (
                replace(
                    fixture.contract,
                    waveform=replace(
                        fixture.contract.waveform,
                        compressed_bytes=fixture.contract.waveform.compressed_bytes + 1,
                    ),
                ),
                "archive_member_metadata_mismatch",
            ),
        )
        for contract, code in bad_contracts:
            with self.subTest(code=code):
                with self.assertRaisesRegex(MODULE.AdapterCompileError, code):
                    MODULE.compile_row_adapter(
                        fixture.archive_path,
                        fixture.receipt_path,
                        fixture.waveform_path,
                        fixture.adapter_path,
                        contract,
                    )

    def test_stream_failure_preserves_existing_outputs_and_inputs(self):
        fixture = Fixture(self)
        fixture.waveform_path.parent.mkdir(parents=True)
        fixture.waveform_path.write_bytes(b"PRIVATE_EXISTING_WAVEFORM")
        fixture.adapter_path.write_bytes(b"PRIVATE_EXISTING_ADAPTER")
        waveform_before = fixture.waveform_path.read_bytes()
        adapter_before = fixture.adapter_path.read_bytes()
        archive_before = fixture.archive_path.read_bytes()
        receipt_before = fixture.receipt_path.read_bytes()

        with mock.patch.object(
            MODULE,
            "_stream_waveform_to_temp",
            side_effect=MODULE.AdapterCompileError("injected_stream_failure"),
        ):
            with self.assertRaisesRegex(
                MODULE.AdapterCompileError, "injected_stream_failure"
            ):
                fixture.compile()

        self.assertEqual(fixture.waveform_path.read_bytes(), waveform_before)
        self.assertEqual(fixture.adapter_path.read_bytes(), adapter_before)
        self.assertEqual(fixture.archive_path.read_bytes(), archive_before)
        self.assertEqual(fixture.receipt_path.read_bytes(), receipt_before)
        self.assertEqual(list(fixture.waveform_path.parent.glob(".*.*")), [])

    def test_corrupt_waveform_crc_fails_before_destination_replace(self):
        fixture = Fixture(self)
        encoded = bytearray(fixture.archive_path.read_bytes())
        with zipfile.ZipFile(fixture.archive_path) as archive:
            member = archive.getinfo(fixture.contract.waveform.name)
            with fixture.archive_path.open("rb") as source:
                data_offset = MODULE._local_data_offset(source, member)
        encoded[data_offset + member.compress_size // 2] ^= 0x01
        fixture.archive_path.write_bytes(encoded)
        fixture.refresh_contract()

        with self.assertRaisesRegex(
            MODULE.AdapterCompileError, "waveform_member_read_failed"
        ):
            fixture.compile()

        self.assertFalse(fixture.waveform_path.exists())
        self.assertFalse(fixture.adapter_path.exists())

    def test_source_never_uses_bulk_archive_extraction(self):
        source = (HERE / "compile-ruff-uwb-row-adapter.py").read_text(encoding="utf-8")
        forbidden = "extract" + "all"
        self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
