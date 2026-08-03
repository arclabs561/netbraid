#!/usr/bin/env python3
"""Hermetic tests for the bounded mmWave jamming oracle compiler."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
COMPILER = HERE / "compile-mmwave-jamming-oracles.py"
SPEC = importlib.util.spec_from_file_location(
    "compile_mmwave_jamming_oracles", COMPILER
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

TARGET_NAMES = {
    1: "one_target",
    2: "two_targets",
    3: "three_targets",
    4: "four_targets",
    5: "five_targets",
}
REGIME_NAMES = {
    "short_range_radar": "SRR",
    "ultra_short_range_radar": "USRR",
}
CAUSE_NAMES = {
    "controlled_jammer_present": "with",
    "controlled_jammer_absent": "without",
}
NOT_A_MAT_PAYLOAD = b"arbitrary bytes: integrity-only admission; not MATLAB data\x00"


def filename_for(cell) -> str:
    return (
        f"Receiver_{cell.receiver_element}_{REGIME_NAMES[cell.radar_regime]}_"
        f"{CAUSE_NAMES[cell.controlled_jamming_cause]}_jammer_"
        f"{TARGET_NAMES[cell.target_count]}.mat"
    )


def pinset_digest(artifacts) -> str:
    encoded = json.dumps(
        sorted(artifacts, key=lambda item: item["filename"]),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class Fixture:
    def __init__(self, case: unittest.TestCase) -> None:
        temporary = tempfile.TemporaryDirectory()
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.raw = self.root / "raw"
        self.receipts = self.root / "receipts"
        self.manifest = self.root / "manifest.json"
        self.raw.mkdir()
        self.receipts.mkdir()
        self.artifacts = []
        digest_md5 = hashlib.md5(NOT_A_MAT_PAYLOAD, usedforsecurity=False).hexdigest()
        digest_sha256 = hashlib.sha256(NOT_A_MAT_PAYLOAD).hexdigest()
        for cell in sorted(MODULE.expected_cells()):
            filename = filename_for(cell)
            content_url = (
                f"https://zenodo.org/api/records/{MODULE.SELECTED_RECORD_ID}/files/"
                f"{filename}/content"
            )
            artifact = {
                "filename": filename,
                "content_url": content_url,
                "bytes": len(NOT_A_MAT_PAYLOAD),
                "md5": digest_md5,
            }
            self.artifacts.append(artifact)
            (self.raw / filename).write_bytes(NOT_A_MAT_PAYLOAD)
            receipt = {
                "schema": MODULE.RECEIPT_SCHEMA,
                "source": {
                    "record_id": MODULE.SELECTED_RECORD_ID,
                    "doi": f"10.5281/zenodo.{MODULE.SELECTED_RECORD_ID}",
                    "license": "CC BY 4.0",
                    "license_id": "cc-by-4.0",
                    **artifact,
                },
                "integrity": {
                    "bytes": len(NOT_A_MAT_PAYLOAD),
                    "md5": digest_md5,
                    "sha256": digest_sha256,
                },
            }
            (self.receipts / f"{filename}.json").write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        self.total_bytes = len(NOT_A_MAT_PAYLOAD) * 80
        self.pins = self.pins_for(self.artifacts)
        self.write_manifest()

    def pins_for(self, artifacts) -> object:
        total_bytes = sum(item["bytes"] for item in artifacts)
        return MODULE.CatalogPins(
            record_count=1,
            artifact_count=len(artifacts),
            total_bytes=total_bytes,
            records=(
                MODULE.RecordPin(
                    record_id=MODULE.SELECTED_RECORD_ID,
                    artifact_count=len(artifacts),
                    total_bytes=total_bytes,
                    artifact_pinset_sha256=pinset_digest(artifacts),
                ),
            ),
        )

    def document(self, artifacts=None) -> dict[str, object]:
        if artifacts is None:
            artifacts = self.artifacts
        return {
            "schema": MODULE.MANIFEST_SCHEMA,
            "publisher": "Zenodo",
            "expected_record_count": self.pins.record_count,
            "expected_artifact_count": self.pins.artifact_count,
            "expected_total_bytes": self.pins.total_bytes,
            "records": [
                {
                    "record_id": MODULE.SELECTED_RECORD_ID,
                    "api_url": (
                        f"https://zenodo.org/api/records/{MODULE.SELECTED_RECORD_ID}"
                    ),
                    "doi": f"10.5281/zenodo.{MODULE.SELECTED_RECORD_ID}",
                    "license": "CC BY 4.0",
                    "license_id": "cc-by-4.0",
                    "expected_artifact_count": self.pins.artifact_count,
                    "expected_total_bytes": self.pins.total_bytes,
                    "artifacts": artifacts,
                }
            ],
        }

    def write_manifest(self, document=None) -> None:
        if document is None:
            document = self.document()
        self.manifest.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def compile(self, *, mmap_min_bytes=MODULE.MMAP_MIN_BYTES):
        return MODULE.compile_inventory(
            self.manifest,
            self.raw,
            self.receipts,
            pins=self.pins,
            mmap_min_bytes=mmap_min_bytes,
        )


class MmwaveJammingOracleCompilerTests(unittest.TestCase):
    def assert_compile_error(self, expected: str, callback) -> None:
        with self.assertRaisesRegex(MODULE.OracleCompileError, expected):
            callback()

    def test_exact_80_cell_grammar_counts_and_safe_pairing(self):
        fixture = Fixture(self)
        inventory = fixture.compile()

        self.assertEqual(len(MODULE.expected_cells()), 80)
        self.assertEqual(len(inventory["observations"]), 80)
        self.assertEqual(inventory["counts"]["paired_cells"], 40)
        self.assertEqual(inventory["counts"]["receiver_elements"], 4)
        self.assertEqual(inventory["counts"]["radar_regimes"], 2)
        self.assertEqual(inventory["counts"]["radar_configurations"], 8)
        self.assertEqual(inventory["counts"]["target_counts"], 5)
        self.assertEqual(
            inventory["counts"]["controlled_jamming_causes"],
            {
                "controlled_jammer_absent": 40,
                "controlled_jammer_present": 40,
            },
        )
        self.assertEqual(
            inventory["required_split_groups"],
            [
                "paired_cell_group",
                "receiver_group",
                "radar_regime_group",
                "radar_configuration_group",
                "target_count_group",
            ],
        )
        self.assertEqual(
            inventory["assignment"],
            {"partitions_assigned": 0, "train_test_assignment": "not_assigned"},
        )

        pairs = {}
        for observation in inventory["observations"]:
            self.assertRegex(observation["observation_id"], r"^[0-9a-f]{64}$")
            pair_id = observation["paired_cell_group"]["group_id"]
            pairs.setdefault(pair_id, []).append(observation)
            for group_name in inventory["required_split_groups"]:
                group = observation[group_name]
                self.assertEqual(group["state"], "known")
                self.assertRegex(group["group_id"], r"^[0-9a-f]{64}$")
            for axis, state in MODULE.ABSTENTION_STATES.items():
                self.assertEqual(observation[axis], {"state": state})
        self.assertEqual(len(pairs), 40)
        for pair in pairs.values():
            self.assertEqual(len(pair), 2)
            self.assertEqual(
                {item["controlled_jamming_cause"] for item in pair},
                {
                    "controlled_jammer_absent",
                    "controlled_jammer_present",
                },
            )
            self.assertEqual(
                {
                    (
                        item["receiver_element"],
                        item["radar_regime"],
                        item["target_count"],
                    )
                    for item in pair
                },
                {
                    (
                        pair[0]["receiver_element"],
                        pair[0]["radar_regime"],
                        pair[0]["target_count"],
                    )
                },
            )

    def test_determinism_and_manifest_order_invariance(self):
        fixture = Fixture(self)
        first = fixture.compile()
        first_bytes = MODULE.render_inventory(first)

        document = fixture.document(list(reversed(fixture.artifacts)))
        fixture.write_manifest(document)
        second = fixture.compile()
        second_bytes = MODULE.render_inventory(second)

        self.assertEqual(first, second)
        self.assertEqual(first_bytes, second_bytes)
        output = fixture.root / "output" / "inventory.json"
        MODULE.write_inventory(output, first)
        written_once = output.read_bytes()
        MODULE.write_inventory(output, second)
        self.assertEqual(written_once, output.read_bytes())

    def test_no_mat_parser_and_no_raw_labels_paths_or_digests_in_output(self):
        fixture = Fixture(self)
        inventory = fixture.compile(mmap_min_bytes=1)
        encoded = MODULE.render_inventory(inventory).decode("ascii")

        tree = ast.parse(COMPILER.read_text(encoding="utf-8"))
        imported_roots = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            imported_roots.isdisjoint(
                {"h5py", "mat4py", "mat73", "numpy", "scipy", "tables"}
            )
        )
        self.assertEqual(inventory["privacy"]["mat_payloads_parsed"], 0)
        self.assertEqual(inventory["privacy"]["mat_payloads_deserialized"], 0)
        self.assertEqual(inventory["privacy"]["mat_payload_bytes_interpreted"], 0)
        self.assertEqual(
            inventory["privacy"]["integrity_bytes_hashed"], fixture.total_bytes
        )
        forbidden = [
            *(item["filename"] for item in fixture.artifacts),
            *(item["md5"] for item in fixture.artifacts),
            hashlib.sha256(NOT_A_MAT_PAYLOAD).hexdigest(),
            str(fixture.root),
            "Receiver_",
            "_with_jammer_",
            "_without_jammer_",
            ".mat",
            "SRR",
            "USRR",
        ]
        for value in forbidden:
            self.assertNotIn(value, encoded)

    def test_read_only_mmap_and_streaming_fallback_are_equivalent(self):
        fixture = Fixture(self)
        expected = fixture.compile(mmap_min_bytes=1)
        real_mmap = MODULE.mmap.mmap
        accesses = []

        def mmap_spy(*args, **kwargs):
            accesses.append(kwargs.get("access"))
            return real_mmap(*args, **kwargs)

        with mock.patch.object(MODULE.mmap, "mmap", side_effect=mmap_spy):
            mapped = fixture.compile(mmap_min_bytes=1)
        self.assertEqual(mapped, expected)
        self.assertEqual(len(accesses), 80)
        self.assertEqual(set(accesses), {MODULE.mmap.ACCESS_READ})

        with mock.patch.object(MODULE.mmap, "mmap", side_effect=OSError("no mmap")):
            streamed = fixture.compile(mmap_min_bytes=1)
        self.assertEqual(streamed, expected)

    def test_mmap_fallback_failure_and_toctou_change_fail_closed(self):
        fixture = Fixture(self)
        artifacts = MODULE.load_artifacts(fixture.manifest, pins=fixture.pins)
        with (
            mock.patch.object(MODULE.mmap, "mmap", side_effect=OSError("no mmap")),
            mock.patch.object(MODULE.os, "read", side_effect=OSError("read failed")),
        ):
            self.assert_compile_error(
                "artifact_read_failed",
                lambda: MODULE.admit_artifacts(
                    artifacts,
                    fixture.raw,
                    fixture.receipts,
                    mmap_min_bytes=1,
                ),
            )

        raw_descriptor = MODULE._open_directory(
            fixture.raw, "raw_directory_missing_or_unsafe"
        )
        descriptor, before = MODULE._open_artifact_at(raw_descriptor, artifacts[0])
        self.addCleanup(os.close, raw_descriptor)
        self.addCleanup(os.close, descriptor)
        changed = replace(before, changed_ns=before.changed_ns + 1)
        with mock.patch.object(MODULE, "_identity", return_value=changed):
            self.assert_compile_error(
                "artifact_changed_during_verification",
                lambda: MODULE._digest_artifact(descriptor, before, mmap_min_bytes=1),
            )

    def test_malformed_duplicate_and_missing_filename_cells_fail_closed(self):
        malformed = Fixture(self)
        malformed_artifacts = [dict(item) for item in malformed.artifacts]
        malformed_artifacts[0]["filename"] = "Receiver_1_SRR_one_target.mat"
        malformed_artifacts[0]["content_url"] = (
            f"https://zenodo.org/api/records/{MODULE.SELECTED_RECORD_ID}/files/"
            "Receiver_1_SRR_one_target.mat/content"
        )
        malformed.write_manifest(malformed.document(malformed_artifacts))
        self.assert_compile_error("malformed_filename_cell", malformed.compile)

        duplicate = Fixture(self)
        duplicate_artifacts = [dict(item) for item in duplicate.artifacts]
        duplicate_artifacts[-1] = dict(duplicate_artifacts[0])
        duplicate.write_manifest(duplicate.document(duplicate_artifacts))
        self.assert_compile_error("duplicate_artifact_filename", duplicate.compile)

        missing = Fixture(self)
        missing.write_manifest(missing.document(missing.artifacts[:-1]))
        self.assert_compile_error("record_artifact_pin_mismatch", missing.compile)

    def test_duplicate_json_keys_and_manifest_pin_drift_fail_closed(self):
        duplicate_keys = Fixture(self)
        duplicate_keys.manifest.write_text(
            '{"schema":"netbraid.controlled_jamming_artifacts.v1",'
            '"schema":"duplicate","publisher":"Zenodo"}',
            encoding="utf-8",
        )
        self.assert_compile_error("duplicate_json_key", duplicate_keys.compile)

        aggregate = Fixture(self)
        document = aggregate.document()
        document["expected_total_bytes"] = aggregate.total_bytes + 1
        aggregate.write_manifest(document)
        self.assert_compile_error("manifest_aggregate_pin_mismatch", aggregate.compile)

        pinset = Fixture(self)
        artifacts = [dict(item) for item in pinset.artifacts]
        artifacts[0]["md5"] = "0" * 32
        pinset.write_manifest(pinset.document(artifacts))
        self.assert_compile_error("record_artifact_pinset_mismatch", pinset.compile)

    def test_missing_malformed_and_mismatched_receipts_fail_closed(self):
        missing = Fixture(self)
        first_name = missing.artifacts[0]["filename"]
        (missing.receipts / f"{first_name}.json").unlink()
        self.assert_compile_error("receipt_directory_cell_mismatch", missing.compile)

        duplicate_key = Fixture(self)
        first_name = duplicate_key.artifacts[0]["filename"]
        (duplicate_key.receipts / f"{first_name}.json").write_text(
            '{"schema":"local.netbraid_controlled_jamming_artifact.v1",'
            '"schema":"duplicate","source":{},"integrity":{}}',
            encoding="utf-8",
        )
        self.assert_compile_error("duplicate_json_key", duplicate_key.compile)

        digest = Fixture(self)
        first_name = digest.artifacts[0]["filename"]
        receipt_path = digest.receipts / f"{first_name}.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["integrity"]["sha256"] = "0" * 64
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        self.assert_compile_error("local_receipt_verification_failed", digest.compile)

    def test_artifact_digest_regular_file_and_file_collisions_fail_closed(self):
        digest = Fixture(self)
        first_name = digest.artifacts[0]["filename"]
        payload = bytearray((digest.raw / first_name).read_bytes())
        payload[0] ^= 0xFF
        (digest.raw / first_name).write_bytes(payload)
        self.assert_compile_error("artifact_md5_mismatch", digest.compile)

        symlink = Fixture(self)
        first_name = symlink.artifacts[0]["filename"]
        first_path = symlink.raw / first_name
        first_path.unlink()
        first_path.symlink_to(symlink.raw / symlink.artifacts[1]["filename"])
        self.assert_compile_error("artifact_missing_or_unsafe", symlink.compile)

        hardlink = Fixture(self)
        first_path = hardlink.raw / hardlink.artifacts[0]["filename"]
        second_path = hardlink.raw / hardlink.artifacts[1]["filename"]
        second_path.unlink()
        os.link(first_path, second_path)
        self.assert_compile_error("artifact_file_collision", hardlink.compile)

    def test_directory_inventory_change_during_admission_fails_closed(self):
        fixture = Fixture(self)
        artifacts = MODULE.load_artifacts(fixture.manifest, pins=fixture.pins)
        expected_names = frozenset(item.filename for item in artifacts)
        expected_receipts = frozenset(f"{name}.json" for name in expected_names)
        with mock.patch.object(
            MODULE,
            "_directory_names",
            side_effect=(
                expected_names,
                expected_receipts,
                expected_names | {"PRIVATE_EXTRA.mat"},
                expected_receipts,
            ),
        ):
            self.assert_compile_error(
                "raw_directory_changed_during_admission",
                lambda: MODULE.admit_artifacts(
                    artifacts,
                    fixture.raw,
                    fixture.receipts,
                ),
            )

    def test_id_output_bounds_and_output_path_collisions_fail_closed(self):
        fixture = Fixture(self)
        with mock.patch.object(MODULE, "_opaque_id", return_value="a" * 64):
            self.assert_compile_error("opaque_id_collision", fixture.compile)

        inventory = fixture.compile()
        with mock.patch.object(MODULE, "MAX_OUTPUT_BYTES", 32):
            self.assert_compile_error(
                "inventory_output_size_limit",
                lambda: MODULE.render_inventory(inventory),
            )

        output_dir = fixture.root / "output"
        output_dir.mkdir()
        destination = output_dir / "inventory.json"
        destination.symlink_to(fixture.manifest)
        self.assert_compile_error(
            "unsafe_output_path",
            lambda: MODULE.write_inventory(destination, inventory),
        )

        real_parent = fixture.root / "real-parent"
        real_parent.mkdir()
        linked_parent = fixture.root / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        self.assert_compile_error(
            "unsafe_output_directory",
            lambda: MODULE.write_inventory(linked_parent / "inventory.json", inventory),
        )


if __name__ == "__main__":
    unittest.main()
