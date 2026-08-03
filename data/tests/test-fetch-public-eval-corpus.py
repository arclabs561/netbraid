#!/usr/bin/env python3
"""Hermetic metadata tests for the public evaluation corpus fetcher."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import ssl
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
FETCHER = ROOT / "data" / "fetch" / "fetch-public-eval-corpus.py"
TRUSTSTORE = types.ModuleType("truststore")
TRUSTSTORE.SSLContext = ssl.SSLContext
sys.modules.setdefault("truststore", TRUSTSTORE)
SPEC = importlib.util.spec_from_file_location("fetch_public_eval_corpus", FETCHER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

EXPECTED = {
    "gnss-rff-readme": (
        13846381,
        "readme.txt",
        2_556,
        "7a19ff1553fba9030567d5e724d45467",
        "gnss-rff",
    ),
    "gnss-rff-demo": (
        13846381,
        "demo.py",
        4_712,
        "80283bad9185b09aeaad154ae541fdba",
        "gnss-rff",
    ),
    "gnss-rff-data": (
        13846381,
        "Data.zip",
        6_358_035_306,
        "e6ded5b0cb014265d321f61a801686c4",
        "gnss-rff",
    ),
    "mmwave-5g-rff-bfk06002-long": (
        18481702,
        "bfk06002_long.mat",
        11_796_492_464,
        "6986b42361428742020b361cf4160ed6",
        "mmwave-5g-rff",
    ),
    "mmwave-5g-rff-bfk06003-long": (
        18481702,
        "bfk06003_long.mat",
        11_796_492_464,
        "71f034ea573bd985d4702d5f8ae3f963",
        "mmwave-5g-rff",
    ),
    "mmwave-5g-rff-bfk06003-20ms": (
        18481702,
        "bfk06003_20ms.mat",
        157_298_864,
        "bed9b0f9f706622ab9fa2c55d453de0b",
        "mmwave-5g-rff",
    ),
    "mmwave-5g-rff-box-long": (
        18481702,
        "box_long.mat",
        11_796_492_464,
        "d0c06d6cb219258ed14f643698618e7a",
        "mmwave-5g-rff",
    ),
    "mmwave-5g-rff-tx-5g-ssb": (
        18481702,
        "TX_5G_SSB.mat",
        17_063_489,
        "87fae9fd1d1a03d967637b13806e16cc",
        "mmwave-5g-rff",
    ),
    "mmwave-5g-rff-box-20ms": (
        18481702,
        "box_20ms.mat",
        157_298_864,
        "12c70486fac2feef1fe01a16fe3be1f7",
        "mmwave-5g-rff",
    ),
    "mmwave-5g-rff-bfk06002-20ms": (
        18481702,
        "bfk06002_20ms.mat",
        157_298_864,
        "97fbe537ac0069fc805ed2af9e9da74c",
        "mmwave-5g-rff",
    ),
    "inria-pla-rff": (
        18268648,
        "PLA_dataset.zip",
        710_685_409,
        "aff583bee6f4efccd08fe78c731bf03d",
        "inria-pla-rff",
    ),
    "ruff-uwb-2m-npy": (
        11083153,
        "UWB_mesures2meters.npy_format.zip",
        1_724_857_002,
        "cf0a3274285bb6fc58fecfb4cb252d7d",
        "ruff-uwb-rff",
    ),
    "ruff-uwb-1m-npy": (
        11083153,
        "UWB_mesures1meter.npy_format.zip",
        793_083_301,
        "035d22d657c84b77df980a482cff47b1",
        "ruff-uwb-rff",
    ),
    "wlan-rff-anechoic": (
        18515187,
        "anechoic_chamber.zip",
        137_021_472,
        "9af7491dc891d89969832f0efdee89de",
        "wlan-rff",
    ),
    "wlan-rff-office": (
        18515187,
        "office_room.zip",
        107_795_533,
        "8cb50121448016a6c7a1293051b26e1b",
        "wlan-rff",
    ),
}
TOTALS = {
    "gnss-rff": 6_358_042_574,
    "mmwave-5g-rff": 35_878_437_473,
    "inria-pla-rff": 710_685_409,
    "ruff-uwb-rff": 3_835_056_792,
    "wlan-rff": 244_817_005,
}


def synthetic_source(payload: bytes) -> dict[str, object]:
    return {
        "url": "https://example.test/public-eval.bin",
        "filename": "public-eval.bin",
        "bytes": len(payload),
        "md5": hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "format": "file",
        "license": "CC0",
        "group": "baseline",
    }


class FetcherMetadataTests(unittest.TestCase):
    def test_default_and_custom_receipt_placement(self):
        payload = b"verified public artifact"
        source = synthetic_source(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            raw_dir = base / "raw"
            raw_dir.mkdir()
            archive = raw_dir / str(source["filename"])
            archive.write_bytes(payload)

            default_receipts = base / "default-receipts"
            with (
                mock.patch.object(MODULE, "DEFAULT_RECEIPT_DIR", default_receipts),
                mock.patch.object(MODULE, "SOURCES", {"synthetic": source}),
                mock.patch.object(MODULE, "GROUPS", frozenset({"baseline"})),
                mock.patch.object(MODULE.urllib.request, "urlopen") as urlopen,
                mock.patch("builtins.print"),
            ):
                arguments = MODULE.parse_args(["synthetic"])
                exit_code = MODULE.main(["synthetic", "--output-dir", str(raw_dir)])
            self.assertEqual(arguments.receipt_dir, default_receipts)
            self.assertEqual(exit_code, 0)
            urlopen.assert_not_called()
            self.assertTrue(MODULE.receipt_path(archive, default_receipts).is_file())
            self.assertIn(
                "data/receipts/public-eval-corpus",
                MODULE.parse_args(["v2i-80211ad"]).receipt_dir.as_posix(),
            )

            custom_receipts = base / "custom-receipts"
            MODULE.verify_existing_archive(archive, source, custom_receipts)
            receipt = MODULE.receipt_path(archive, custom_receipts)
            self.assertTrue(receipt.is_file())
            self.assertFalse(MODULE.legacy_receipt_path(archive).exists())
            receipt_value = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(
                receipt_value,
                MODULE.archive_receipt(
                    source,
                    len(payload),
                    str(source["md5"]),
                    str(source["sha256"]),
                ),
            )
            self.assertNotIn(str(raw_dir), json.dumps(receipt_value, sort_keys=True))

    def test_adjacent_legacy_receipt_is_reused_without_refetch(self):
        payload = b"already downloaded public artifact"
        source = synthetic_source(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            raw_dir = base / "raw"
            raw_dir.mkdir()
            archive = raw_dir / str(source["filename"])
            archive.write_bytes(payload)
            size, md5, sha256 = MODULE.digest_file(archive)
            legacy = MODULE.legacy_receipt_path(archive)
            legacy.write_text(
                json.dumps(MODULE.archive_receipt(source, size, md5, sha256)),
                encoding="utf-8",
            )
            receipt_dir = base / "receipts"

            with mock.patch.object(MODULE.urllib.request, "urlopen") as urlopen:
                reused = MODULE.download(source, raw_dir, receipt_dir)

            self.assertEqual(reused, archive)
            urlopen.assert_not_called()
            self.assertTrue(MODULE.receipt_path(archive, receipt_dir).is_file())
            self.assertTrue(legacy.read_text(encoding="utf-8").startswith("{"))

    def test_inventory_is_path_free_and_contains_verified_integrity(self):
        payload = b"inventory payload"
        source = synthetic_source(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive = base / str(source["filename"])
            archive.write_bytes(payload)
            receipt_dir = base / "receipts"
            MODULE.verify_existing_archive(archive, source, receipt_dir)

            inventory = MODULE.inspect_archive(archive, source, receipt_dir)
            rendered = json.dumps(inventory, sort_keys=True)

            self.assertEqual(inventory["archive"], archive.name)
            self.assertEqual(inventory["bytes"], len(payload))
            self.assertEqual(inventory["md5"], source["md5"])
            self.assertEqual(inventory["sha256"], source["sha256"])
            self.assertNotIn(str(base), rendered)
            self.assertNotIn(str(source["url"]), rendered)
            self.assertNotIn("source", inventory)

    def test_inspect_cli_atomically_writes_path_free_inventory(self):
        payload = b"cli inventory payload"
        source = synthetic_source(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            raw_dir = base / "raw"
            raw_dir.mkdir()
            archive = raw_dir / str(source["filename"])
            archive.write_bytes(payload)
            receipt_dir = base / "receipts"
            inventory_path = base / "inventory.json"
            inventory_path.write_text("old", encoding="utf-8")

            with (
                mock.patch.object(MODULE, "SOURCES", {"synthetic": source}),
                mock.patch.object(MODULE, "GROUPS", frozenset({"baseline"})),
                mock.patch.object(MODULE.urllib.request, "urlopen") as urlopen,
                mock.patch.object(
                    MODULE.os, "replace", wraps=MODULE.os.replace
                ) as replace,
                mock.patch("builtins.print"),
            ):
                exit_code = MODULE.main(
                    [
                        "synthetic",
                        "--output-dir",
                        str(raw_dir),
                        "--receipt-dir",
                        str(receipt_dir),
                        "--inspect",
                        "--inspect-output",
                        str(inventory_path),
                    ]
                )

            self.assertEqual(exit_code, 0)
            urlopen.assert_not_called()
            replace.assert_called_once()
            inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
            self.assertEqual(inventory["archive"], archive.name)
            self.assertEqual(inventory["bytes"], len(payload))
            rendered = json.dumps(inventory, sort_keys=True)
            self.assertNotIn(str(base), rendered)
            self.assertNotIn(str(source["url"]), rendered)

    def test_receipt_and_inventory_writes_reject_unsafe_paths(self):
        payload = b"safe regular bytes"
        source = synthetic_source(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            archive = base / str(source["filename"])
            archive.write_bytes(payload)
            receipt_dir = base / "receipts"
            receipt_dir.mkdir()
            receipt = MODULE.receipt_path(archive, receipt_dir)
            receipt_target = base / "receipt-target"
            receipt_target.write_text("{}", encoding="utf-8")
            receipt.symlink_to(receipt_target)
            with self.assertRaisesRegex(RuntimeError, "unsafe receipt"):
                MODULE.verify_existing_archive(archive, source, receipt_dir)

            output_target = base / "inventory-target"
            output_target.write_text("keep", encoding="utf-8")
            inventory_output = base / "inventory.json"
            inventory_output.symlink_to(output_target)
            with self.assertRaisesRegex(RuntimeError, "unsafe JSON output"):
                MODULE.write_json_atomic(inventory_output, {"archive": archive.name})
            self.assertEqual(output_target.read_text(encoding="utf-8"), "keep")

            regular_output = base / "regular-inventory.json"
            regular_output.write_text("old", encoding="utf-8")
            with mock.patch.object(
                MODULE.os, "replace", wraps=MODULE.os.replace
            ) as replace:
                MODULE.write_json_atomic(regular_output, {"archive": archive.name})
            replace.assert_called_once()
            self.assertEqual(
                json.loads(regular_output.read_text(encoding="utf-8")),
                {"archive": archive.name},
            )

            archive.unlink()
            archive.symlink_to(output_target)
            with self.assertRaisesRegex(RuntimeError, "unsafe archive"):
                MODULE.verify_existing_archive(archive, source, base / "other-receipts")

    def test_exact_zenodo_pins(self):
        selected = {
            name: source
            for name, source in MODULE.SOURCES.items()
            if source["group"] == "rf-fingerprinting"
        }
        self.assertEqual(set(selected), set(EXPECTED))
        for name, (record_id, filename, size, md5, record) in EXPECTED.items():
            source = selected[name]
            self.assertEqual(
                source["url"],
                f"https://zenodo.org/api/records/{record_id}/files/{filename}/content",
            )
            self.assertEqual((source["bytes"], source["md5"]), (size, md5))
            self.assertEqual(source["doi"], f"10.5281/zenodo.{record_id}")
            self.assertEqual(
                (source["record"], source["record_bytes"]), (record, TOTALS[record])
            )
            self.assertEqual(source["license"], "CC BY 4.0")

    def test_record_totals_and_ruff_npy_slice(self):
        selected = [
            source
            for source in MODULE.SOURCES.values()
            if source["group"] == "rf-fingerprinting"
        ]
        sums = {
            record: sum(
                source["bytes"] for source in selected if source["record"] == record
            )
            for record in TOTALS
        }
        for record in {"gnss-rff", "mmwave-5g-rff", "inria-pla-rff", "wlan-rff"}:
            self.assertEqual(sums[record], TOTALS[record])
        self.assertEqual(sums["ruff-uwb-rff"], 2_517_940_303)
        ruff = [source for source in selected if source["record"] == "ruff-uwb-rff"]
        self.assertEqual(len(ruff), 2)
        self.assertTrue(all(source["representation"] == "npy" for source in ruff))
        self.assertTrue(all("csv_format" not in source["url"] for source in ruff))

    def test_group_and_ignored_payload_contract(self):
        self.assertIn("rf-fingerprinting", MODULE.GROUPS)
        self.assertIn("rfid-exsim", MODULE.GROUPS)
        self.assertIn("matter-traces", MODULE.GROUPS)
        ignores = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertTrue(
            {"/data/raw/", "/data/derived/", "/data/receipts/"}.issubset(ignores)
        )

    def test_rfid_exsim_zenodo_pin(self):
        source = MODULE.SOURCES["rfid-exsim-v1"]
        self.assertEqual(
            source["url"],
            "https://zenodo.org/api/records/17854328/files/"
            "yasserhmimou9/RFID-ExSim-Dataset-v1.0.zip/content",
        )
        self.assertEqual(
            (source["filename"], source["source_filename"]),
            (
                "RFID-ExSim-Dataset-v1.0.zip",
                "yasserhmimou9/RFID-ExSim-Dataset-v1.0.zip",
            ),
        )
        self.assertEqual((source["bytes"], source["record_bytes"]), (299_566, 299_566))
        self.assertEqual(source["md5"], "1e0f4712a158c7dde5d2d31aaa84c071")
        self.assertEqual(
            source["sha256"],
            "aaa39788d4c757bb9b0f6ce46f2e976be6ce650d4f28161f52e885bb41c24c20",
        )
        self.assertEqual(
            source["sha256_provenance"], "computed_from_zenodo_api_content"
        )
        self.assertEqual(source["doi"], "10.5281/zenodo.17854328")
        self.assertIn("unspecified on the Zenodo record", source["license"])

    def test_matter_trace_record_v2_pins(self):
        selected = {
            name: source
            for name, source in MODULE.SOURCES.items()
            if source["group"] == "matter-traces"
        }
        self.assertEqual(len(selected), 16)
        self.assertEqual(
            sum(source["bytes"] for source in selected.values()),
            MODULE.MATTER_TRACE_RECORD_BYTES,
        )
        self.assertTrue(
            all(source["doi"] == "10.34810/DATA1813" for source in selected.values())
        )
        self.assertTrue(
            all(
                source["record"] == "matter-protocol-traces-v2"
                and source["record_bytes"] == MODULE.MATTER_TRACE_RECORD_BYTES
                and source["license"] == "CC BY 4.0"
                and source["url"].startswith(
                    "https://dataverse.csuc.cat/api/access/datafile/"
                )
                for source in selected.values()
            )
        )
        self.assertEqual(
            selected["matter-trace-wifi-e8"]["md5"],
            "0b82acb65e11596a7696d9298e6e2ca9",
        )

    def test_rfid_exsim_sha256_pin_is_enforced_hermetically(self):
        payload = b"synthetic RFID JSONL bundle"
        spec = {
            "filename": "rfid-exsim.zip",
            "bytes": len(payload),
            "md5": hashlib.md5(payload, usedforsecurity=False).hexdigest(),
            "sha256": "0" * 64,
        }
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / spec["filename"]
            archive.write_bytes(payload)
            with self.assertRaisesRegex(
                RuntimeError, "existing archive failed verification"
            ):
                MODULE.verify_existing_archive(
                    archive, spec, Path(directory) / "receipts"
                )

    def test_catalog_axes_are_separate(self):
        entries = {
            entry["id"]: entry
            for entry in json.loads(
                (ROOT / "data/catalog/research-leads-v1.json").read_text()
            )["entries"]
        }
        expected = {
            "zenodo-13846381-gnss-rff": {
                "physical_source_relation_eval",
                "spoofing_cause_eval",
                "day_shift_eval",
            },
            "zenodo-18481702-mmwave-5g-rff": {
                "physical_source_relation_eval",
                "transmitter_feature_eval",
            },
            "zenodo-18268648-inria-pla": {
                "physical_source_relation_eval",
                "open_set_eval",
                "rogue_source_eval",
            },
            "zenodo-11083153-ruff-uwb": {
                "physical_source_relation_eval",
                "location_shift_eval",
                "source_location_split_eval",
            },
            "zenodo-18515187-wlan-rff": {
                "layout_profile",
                "domain_shift_candidate",
            },
            "zenodo-17854328-rfid-exsim": {
                "controlled_baseline_eval",
                "collision_eval",
                "uid_cloning_eval",
                "replay_software_injection_eval",
                "flooding_eval",
            },
        }
        for entry_id, roles in expected.items():
            self.assertEqual(set(entries[entry_id]["roles"]), roles)
        rfid_exsim = entries["zenodo-17854328-rfid-exsim"]
        self.assertEqual(
            set(rfid_exsim["modalities"]),
            {"rfid_read_event", "scenario_observation"},
        )
        self.assertNotIn("rf_iq", rfid_exsim["modalities"])
        self.assertIn(
            "do not establish production intent",
            rfid_exsim["note"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
