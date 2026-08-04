#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Hermetic tests for the SMoRFFI CSV/IQ adapter compiler."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "compile_smorffi_csv_iq_adapter", HERE / "compile-smorffi-csv-iq-adapter.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class Fixture:
    def __init__(self, case: unittest.TestCase, *, malformed: bool = False):
        temporary = tempfile.TemporaryDirectory()
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.raw = self.root / "PRIVATE_RAW"
        self.raw.mkdir(mode=0o700)
        self.receipt = self.root / "PRIVATE_RECEIPT.json"
        self.iq = self.root / "derived" / "PRIVATE_IQ.npy"
        self.offsets = self.root / "derived" / "PRIVATE_OFFSETS.npy"
        self.adapter = self.root / "derived" / "PRIVATE_ADAPTER.json"
        canonical = ",".join(MODULE.CANONICAL_HEADER)
        headers = (
            "Device Number,10:20:30:40:50:60,preamble" if malformed else canonical,
            canonical,
        )
        rows = (
            (
                '7,10:20:30:40:50:60,"[(1+2j)\n (3-4j)]"\n',
                "7,10:20:30:40:50:60,[(5+0j)]\n",
            ),
            ("11,AA:BB:CC:DD:EE:FF,[(0-1j) (2+3j) (4+5j)]\n",),
        )
        self.files: list[Path] = []
        for index, (header, body) in enumerate(zip(headers, rows)):
            path = self.raw / f"PRIVATE_{index}.csv"
            path.write_text("\ufeff" + header + "\n" + "".join(body), encoding="utf-8")
            self.files.append(path)
        marker = self.raw / "PRIVATE.complete"
        marker.write_text("complete\n", encoding="utf-8")
        self.files.append(marker)
        self._write_receipt(malformed=malformed)

    def _items(self) -> list[dict[str, object]]:
        return [
            {
                "path": path.name,
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in sorted(self.files)
        ]

    def _write_receipt(self, *, malformed: bool) -> None:
        items = self._items()
        encoded = json.dumps(
            items, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        inventory_sha256 = hashlib.sha256(encoded).hexdigest()
        errata = (
            frozenset(
                item["sha256"] for item in items if item["path"] == "PRIVATE_0.csv"
            )
            if malformed
            else frozenset()
        )
        self.contract = MODULE.CorpusContract(
            inventory_sha256=inventory_sha256,
            total_bytes=sum(int(item["bytes"]) for item in items),
            receipt_files=3,
            csv_files=2,
            rows=3,
            samples=6,
            minimum_samples_per_row=1,
            maximum_samples_per_row=3,
            rows_with_288_samples=0,
            sources=2,
            errata_sha256=errata,
        )
        receipt = {
            "schema": MODULE.RECEIPT_SCHEMA,
            "source": MODULE.SOURCE,
            "integrity": {
                "basis": MODULE.INTEGRITY_BASIS,
                "inventory": {
                    "entries": 3,
                    "directories": 0,
                    "files": 3,
                    "bytes": self.contract.total_bytes,
                    "local_inventory_sha256": inventory_sha256,
                },
                "files": items,
            },
        }
        self.receipt.write_text(json.dumps(receipt), encoding="utf-8")
        os.chmod(self.receipt, 0o600)

    def compile(self):
        return MODULE.compile_adapter(
            self.raw,
            self.receipt,
            self.iq,
            self.offsets,
            self.adapter,
            self.contract,
            max_rows=10,
            max_samples=100,
            max_samples_per_row=10,
        )


class SmorffiAdapterCompilerTests(unittest.TestCase):
    def test_production_contract_pins_exact_local_inventory_and_erratum(self):
        contract = MODULE.PRODUCTION_CONTRACT
        self.assertEqual(contract.receipt_files, 124)
        self.assertEqual(contract.csv_files, 123)
        self.assertEqual(contract.rows, 122_511)
        self.assertEqual(contract.samples, 38_561_309)
        self.assertEqual(contract.minimum_samples_per_row, 288)
        self.assertEqual(contract.maximum_samples_per_row, 579)
        self.assertEqual(contract.rows_with_288_samples, 37_288)
        self.assertEqual(contract.sources, 123)
        self.assertEqual(contract.errata_sha256, {MODULE.ANOMALOUS_HEADER_SHA256})

    def test_compiles_variable_rows_to_mmap_ready_flat_arrays(self):
        fixture = Fixture(self)

        report = fixture.compile()

        iq = np.load(fixture.iq, mmap_mode="r", allow_pickle=False)
        offsets = np.load(fixture.offsets, mmap_mode="r", allow_pickle=False)
        self.assertIsInstance(iq, np.memmap)
        self.assertIsInstance(offsets, np.memmap)
        np.testing.assert_array_equal(
            iq,
            np.array([1 + 2j, 3 - 4j, 5 + 0j, 0 - 1j, 2 + 3j, 4 + 5j]),
        )
        np.testing.assert_array_equal(offsets, np.array([0, 2, 3, 6], dtype="<u8"))
        self.assertEqual(
            report["counts"],
            {
                "files": 2,
                "rows": 3,
                "samples": 6,
                "spans": 2,
                "minimum_samples_per_row": 1,
                "maximum_samples_per_row": 3,
                "rows_with_288_samples": 0,
            },
        )
        self.assertEqual(
            report["axes"]["physical_source"]["state"], "publisher_claimed"
        )
        self.assertEqual(report["axes"]["acquisition_session"]["state"], "unknown")
        self.assertEqual(report["provenance"]["header_errata_applied"], 0)
        self.assertEqual(oct(fixture.iq.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(fixture.offsets.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(fixture.adapter.stat().st_mode & 0o777), "0o600")

    def test_adapter_is_path_free_and_drops_raw_publisher_values(self):
        fixture = Fixture(self)
        fixture.compile()

        encoded = fixture.adapter.read_text(encoding="ascii")

        for forbidden in (
            os.fspath(fixture.root),
            "PRIVATE_0.csv",
            "10:20:30:40:50:60",
            "AA:BB:CC:DD:EE:FF",
            '"7"',
            '"11"',
            "(1+2j)",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_digest_bound_structural_header_erratum_is_applied_once(self):
        fixture = Fixture(self, malformed=True)

        report = fixture.compile()

        self.assertEqual(report["provenance"]["header_errata_applied"], 1)
        self.assertEqual(report["counts"]["rows"], 3)

    def test_unlisted_malformed_header_fails_closed_without_replacing_outputs(self):
        fixture = Fixture(self, malformed=True)
        fixture.contract = MODULE.CorpusContract(
            **{**fixture.contract.__dict__, "errata_sha256": frozenset()}
        )
        fixture.iq.parent.mkdir()
        for path in (fixture.iq, fixture.offsets, fixture.adapter):
            path.write_bytes(b"sentinel")

        with self.assertRaisesRegex(
            MODULE.AdapterCompileError, "unexpected_csv_header"
        ):
            fixture.compile()

        for path in (fixture.iq, fixture.offsets, fixture.adapter):
            self.assertEqual(path.read_bytes(), b"sentinel")

    def test_receipt_bound_raw_mutation_is_rejected(self):
        fixture = Fixture(self)
        fixture.files[0].write_bytes(fixture.files[0].read_bytes() + b"\n")

        with self.assertRaisesRegex(MODULE.AdapterCompileError, "raw_size_mismatch"):
            fixture.compile()

    def test_mixed_identity_and_nonfinite_samples_are_rejected(self):
        for replacement, expected in (
            ("8,10:20:30:40:50:60,[(5+0j)]", "mixed_identity_file"),
            ("7,10:20:30:40:50:60,[(nan+0j)]", "nonfinite_sample"),
        ):
            with self.subTest(expected=expected):
                fixture = Fixture(self)
                text = fixture.files[0].read_text(encoding="utf-8")
                fixture.files[0].write_text(
                    text.replace("7,10:20:30:40:50:60,[(5+0j)]", replacement),
                    encoding="utf-8",
                )
                fixture._write_receipt(malformed=False)
                with self.assertRaisesRegex(MODULE.AdapterCompileError, expected):
                    fixture.compile()

    def test_row_and_sample_bounds_fail_closed(self):
        fixture = Fixture(self)
        with self.assertRaisesRegex(MODULE.AdapterCompileError, "max_rows_exceeded"):
            MODULE.compile_adapter(
                fixture.raw,
                fixture.receipt,
                fixture.iq,
                fixture.offsets,
                fixture.adapter,
                fixture.contract,
                max_rows=2,
            )

    def test_outputs_cannot_alias_the_receipt_or_raw_tree(self):
        fixture = Fixture(self)
        for alias in (fixture.receipt, fixture.files[0], fixture.raw / "new.npy"):
            with self.subTest(alias=alias):
                with self.assertRaisesRegex(
                    MODULE.AdapterCompileError, "output_aliases_input"
                ):
                    MODULE.compile_adapter(
                        fixture.raw,
                        fixture.receipt,
                        alias,
                        fixture.offsets,
                        fixture.adapter,
                        fixture.contract,
                    )

    def test_adapter_remains_commit_marker_when_publication_is_interrupted(self):
        fixture = Fixture(self)
        fixture.adapter.parent.mkdir()
        fixture.adapter.write_bytes(b"old-adapter")
        real_replace = MODULE.os.replace
        replacements = 0

        def interrupted_replace(source, destination):
            nonlocal replacements
            replacements += 1
            if replacements == 2:
                raise OSError("injected")
            return real_replace(source, destination)

        with mock.patch.object(MODULE.os, "replace", side_effect=interrupted_replace):
            with self.assertRaisesRegex(
                MODULE.AdapterCompileError, "output_write_failed"
            ):
                fixture.compile()

        self.assertEqual(fixture.adapter.read_bytes(), b"old-adapter")


if __name__ == "__main__":
    unittest.main(verbosity=2)
