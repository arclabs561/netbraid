#!/usr/bin/env python3
"""Hermetic tests for the bounded OSU LoRa SigMF metadata profiler."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "profile_osu_lora_sigmf", HERE / "profile-osu-lora-sigmf.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

PRIVATE_MARKERS = (
    "PRIVATE_AUTHOR",
    "PRIVATE_DESCRIPTION",
    "PRIVATE_RECEIVER",
    "PRIVATE_TRANSMITTER",
    "PRIVATE_ANTENNA",
    "PRIVATE_PATH",
    "PRIVATE_SOURCE",
)


def antenna(seed: str) -> dict[str, object]:
    return {
        "gain": 1,
        "model": f"{PRIVATE_MARKERS[4]}_{seed}",
        "type": "omnidirectional",
    }


def annotation(seed: int, sample_count: int) -> dict[str, object]:
    return {
        "core:sample_count": sample_count,
        "core:sample_start": seed,
        "wines:reciever": {
            "antenna": antenna(f"receiver-{seed}"),
            "model": f"{PRIVATE_MARKERS[2]}_{seed}",
        },
        "wines:transmitter": {
            "ID": {
                "Transmission ID": seed,
                "Transmitter ID": f"{PRIVATE_MARKERS[3]}_{seed}",
            },
            "antenna": antenna(f"transmitter-{seed}"),
            "model": f"{PRIVATE_MARKERS[3]}_MODEL_{seed}",
        },
    }


def metadata_document(stem: str = PRIVATE_MARKERS[5]) -> dict[str, object]:
    return {
        "version": "1.0.0",
        "schema": {"global": {}, "captures": {}, "annotations": {}},
        "_metadata": {
            "global": {
                "core:author": PRIVATE_MARKERS[0],
                "core:datatype": "cf32",
                "core:description": PRIVATE_MARKERS[1],
                "core:sample_rate": "1 MS/s",
            },
            "captures": [
                {
                    "core:date": "2023-01-01T00:00:00Z",
                    "core:sample_start": 0,
                    "frequency": "915 MHz",
                }
            ],
            "annotations": [annotation(0, 2), annotation(2, 3)],
        },
        "data_file": (
            f"https://example.invalid/{PRIVATE_MARKERS[6]}/{stem}.sigmf-meta"
        ),
    }


class OsuLoraSigmfProfileTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def build_tree(
        self,
        *,
        document: dict[str, object] | None = None,
        data_bytes: int = 40,
        stem: str = PRIVATE_MARKERS[5],
        relative_directory: str = "distances/5m",
    ) -> tuple[Path, Path, Path]:
        root = self.temporary_directory() / "root"
        directory = root / relative_directory
        directory.mkdir(parents=True)
        metadata_path = directory / f"{stem}.sigmf-meta"
        metadata_path.write_text(
            json.dumps(document or metadata_document(stem)), encoding="utf-8"
        )
        data_path = directory / f"{stem}.dat"
        data_path.write_bytes(b"\0" * data_bytes)
        return root, metadata_path, data_path

    def test_profiles_deterministically_without_label_path_or_source_leakage(self):
        root, metadata_path, _data_path = self.build_tree()

        first = MODULE.profile_tree(root)
        second = MODULE.profile_tree(root)
        first_rendered = MODULE.render_report(first)

        self.assertEqual(first, second)
        self.assertEqual(first_rendered, MODULE.render_report(second))
        self.assertEqual(first["status"], "pass")
        self.assertEqual(first["inventory"]["metadata_files"], 1)
        self.assertEqual(first["inventory"]["data_files"], 1)
        self.assertEqual(first["aggregate_metadata"]["core_sample_count"], 5)
        self.assertEqual(first["aggregate_metadata"]["datatypes"], ["cf32"])
        self.assertEqual(first["aggregate_metadata"]["sample_rates"], ["1 MS/s"])
        self.assertEqual(
            first["aggregate_metadata"]["receiver_labels"]["distinct_composite_labels"],
            2,
        )
        self.assertEqual(
            first["aggregate_metadata"]["transmitter_labels"][
                "distinct_composite_labels"
            ],
            2,
        )
        self.assertEqual(first["setup"]["tokens"], ["distances"])
        self.assertEqual(first["setup"]["distance_tokens"], ["5m"])
        self.assertEqual(first["cf32_extent_validation"]["checked"], 1)
        self.assertEqual(first["cf32_extent_validation"]["matched"], 1)
        self.assertEqual(first["cf32_extent_validation"]["iq_payload_bytes_read"], 0)
        self.assertEqual(first["validation"]["total_failures"], 0)

        text = first_rendered.decode("utf-8")
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)
        self.assertNotIn(str(root), text)
        self.assertNotIn(metadata_path.name, text)
        self.assertNotIn("https://", text)

    def test_duplicate_keys_fail_closed(self):
        root, metadata_path, _data_path = self.build_tree()
        encoded = json.dumps(metadata_document())
        metadata_path.write_text(
            encoded.replace('"version": "1.0.0"', '"version":"1","version":"2"'),
            encoding="utf-8",
        )

        with self.assertRaisesRegex(MODULE.ProfileError, "duplicate_json_key"):
            MODULE.profile_tree(root)

    def test_source_erratum_pins_match_embedded_source_evidence(self):
        # Embedded source-evidence fixtures keep the canonical gate independent
        # of the ignored data/receipts tree, which is absent in a fresh clone.
        source_evidence_fixtures = (
            (
                "receivers/Diff_Receivers_Setup_Indoor_SameTx/"
                "RX2/Device1_FFT.sigmf-meta",
                4_057,
                "afaec1310788dc79cc84dff736e247fa92284e6b87cf60441e7726c5d84d9b2c",
            ),
            (
                "receivers/Diff_Receivers_Setup_Outdoor_DiffTx/"
                "RX2/Device1_FFT.sigmf-meta",
                4_065,
                "8f9ded39bc5374fb03d97cef42e3003fdf064194dc95b7af3fd9c8e97392b9be",
            ),
            (
                "receivers/Diff_Receivers_Setup_Outdoor_SameTx/"
                "RX2/Device1_FFT.sigmf-meta",
                4_059,
                "55a76bb1b15c50834619245ba739a930d07c14f80cfaf3ca47eb0803e03d7018",
            ),
        )
        expected = {
            path: (source_bytes, source_sha256)
            for path, source_bytes, source_sha256 in source_evidence_fixtures
        }
        actual = {
            path: (erratum.source_bytes, erratum.source_sha256)
            for path, erratum in MODULE.SOURCE_ERRATA.items()
        }

        self.assertEqual(actual, expected)

    def test_exact_source_erratum_is_repaired_without_path_leakage(self):
        relative_directory = "receivers/Diff_Receivers_Setup_Indoor_SameTx/RX2"
        root, metadata_path, _data_path = self.build_tree(
            stem="Device1_FFT",
            relative_directory=relative_directory,
        )
        malformed = metadata_path.read_bytes()[1:]
        metadata_path.write_bytes(malformed)
        relative = metadata_path.relative_to(root).as_posix()
        erratum = MODULE.SourceErratum(
            source_bytes=len(malformed),
            source_sha256=hashlib.sha256(malformed).hexdigest(),
        )

        with mock.patch.object(MODULE, "SOURCE_ERRATA", {relative: erratum}):
            report = MODULE.profile_tree(root)
            inventory = MODULE.inventory_tree(root)
            metadata_record = next(
                record for record in inventory.files if record.kind == "metadata"
            )
            document = MODULE._read_metadata(metadata_record)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(document["version"], "1.0.0")
        self.assertEqual(report["source_errata"]["normalized_metadata_files"], 1)
        self.assertEqual(
            report["source_errata"]["repair_receipt"],
            {
                "algorithm": "sha256",
                "domain": "netbraid.osu_lora_sigmf.source_errata.v0",
                "digest": MODULE._source_errata_receipt([erratum]),
            },
        )
        self.assertEqual(
            report["source_errata"]["repository_relative_paths_retained"], 0
        )

        rendered = MODULE.render_report(report).decode("utf-8")
        for path_fragment in (
            relative,
            "Diff_Receivers_Setup_Indoor_SameTx",
            "RX2",
            "Device1_FFT.sigmf-meta",
        ):
            self.assertNotIn(path_fragment, rendered)

    def test_source_erratum_hash_drift_is_rejected(self):
        relative_directory = "receivers/Diff_Receivers_Setup_Indoor_SameTx/RX2"
        root, metadata_path, _data_path = self.build_tree(
            stem="Device1_FFT",
            relative_directory=relative_directory,
        )
        malformed = metadata_path.read_bytes()[1:]
        relative = metadata_path.relative_to(root).as_posix()
        erratum = MODULE.SourceErratum(
            source_bytes=len(malformed),
            source_sha256=hashlib.sha256(malformed).hexdigest(),
        )
        drifted = bytearray(malformed)
        drifted[drifted.index(PRIVATE_MARKERS[0].encode("ascii"))] = ord("X")
        metadata_path.write_bytes(drifted)

        with mock.patch.object(MODULE, "SOURCE_ERRATA", {relative: erratum}):
            with self.assertRaisesRegex(
                MODULE.ProfileError, "source_erratum_pin_mismatch"
            ):
                MODULE.profile_tree(root)

    def test_unpinned_malformed_metadata_is_rejected(self):
        root, metadata_path, _data_path = self.build_tree()
        metadata_path.write_bytes(metadata_path.read_bytes()[1:])

        with mock.patch.object(MODULE, "SOURCE_ERRATA", {}):
            with self.assertRaisesRegex(MODULE.ProfileError, "invalid_metadata_json"):
                MODULE.profile_tree(root)

    def test_traversal_rejects_and_safe_data_file_mismatch_fails_report(self):
        traversal = metadata_document()
        traversal["data_file"] = "https://example.invalid/path/%2e%2e/PRIVATE_PATH.dat"
        root, _metadata_path, _data_path = self.build_tree(document=traversal)
        with self.assertRaisesRegex(
            MODULE.ProfileError, "unsafe_data_file_declaration"
        ):
            MODULE.profile_tree(root)

        mismatch = metadata_document()
        mismatch["data_file"] = "https://example.invalid/path/OTHER.dat"
        root, _metadata_path, _data_path = self.build_tree(document=mismatch)
        report = MODULE.profile_tree(root)
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["validation"]["failures"]["data_file_mismatches"], 1)
        self.assertNotIn("OTHER", MODULE.render_report(report).decode("utf-8"))

    def test_symlink_and_non_regular_entries_are_rejected(self):
        root, _metadata_path, data_path = self.build_tree()
        data_path.unlink()
        data_path.symlink_to(root / "outside.dat")
        with self.assertRaisesRegex(MODULE.ProfileError, "symlink_rejected"):
            MODULE.profile_tree(root)

        if hasattr(os, "mkfifo"):
            root, _metadata_path, _data_path = self.build_tree()
            os.mkfifo(root / "distances" / "5m" / "pipe")
            with self.assertRaisesRegex(
                MODULE.ProfileError, "non_regular_entry_rejected"
            ):
                MODULE.profile_tree(root)

    def test_cf32_extent_mismatch_forces_failure(self):
        root, _metadata_path, _data_path = self.build_tree(data_bytes=39)

        report = MODULE.profile_tree(root)

        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["cf32_extent_validation"]["checked"], 1)
        self.assertEqual(report["cf32_extent_validation"]["matched"], 0)
        self.assertEqual(report["validation"]["failures"]["extent_mismatches"], 1)

    def test_file_and_metadata_limits_fail_closed(self):
        root, metadata_path, data_path = self.build_tree()
        cases = (
            ("MAX_FILES", 1, "file_count_limit_exceeded"),
            (
                "MAX_FILE_BYTES",
                data_path.stat().st_size - 1,
                "file_byte_limit_exceeded",
            ),
            (
                "MAX_METADATA_FILE_BYTES",
                metadata_path.stat().st_size - 1,
                "metadata_file_byte_limit_exceeded",
            ),
            (
                "MAX_TOTAL_METADATA_BYTES",
                metadata_path.stat().st_size - 1,
                "metadata_total_byte_limit_exceeded",
            ),
        )
        for name, limit, error in cases:
            with self.subTest(limit=name), mock.patch.object(MODULE, name, limit):
                with self.assertRaisesRegex(MODULE.ProfileError, error):
                    MODULE.profile_tree(root)

    def test_configurable_total_tree_bound_rejects_and_accepts(self):
        root, metadata_path, data_path = self.build_tree()
        total_bytes = metadata_path.stat().st_size + data_path.stat().st_size

        with self.assertRaisesRegex(
            MODULE.ProfileError, "tree_total_byte_limit_exceeded"
        ):
            MODULE.profile_tree(root, max_total_bytes=total_bytes - 1)

        report = MODULE.profile_tree(root, max_total_bytes=total_bytes)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["limits"]["total_tree_bytes"], total_bytes)
        self.assertEqual(
            report["limits"]["total_tree_bytes_hard_ceiling"],
            MODULE.HARD_MAX_TOTAL_TREE_BYTES,
        )

    def test_total_tree_default_and_cli_preserve_the_hard_ceiling(self):
        self.assertGreaterEqual(
            MODULE.DEFAULT_MAX_TOTAL_TREE_BYTES,
            273 * MODULE.GIB,
        )
        self.assertLessEqual(
            MODULE.DEFAULT_MAX_TOTAL_TREE_BYTES,
            MODULE.HARD_MAX_TOTAL_TREE_BYTES,
        )
        self.assertEqual(
            MODULE.parse_args([]).max_total_bytes,
            MODULE.DEFAULT_MAX_TOTAL_TREE_BYTES,
        )
        self.assertEqual(
            MODULE.parse_args(["--max-total-bytes", "123"]).max_total_bytes,
            123,
        )

        with mock.patch.object(sys, "stderr", io.StringIO()):
            with self.assertRaises(SystemExit):
                MODULE.parse_args(
                    [
                        "--max-total-bytes",
                        str(MODULE.HARD_MAX_TOTAL_TREE_BYTES + 1),
                    ]
                )

        with self.assertRaisesRegex(
            MODULE.ProfileError,
            "total_tree_byte_limit_exceeds_hard_ceiling",
        ):
            MODULE.profile_tree(
                Path("unused"),
                max_total_bytes=MODULE.HARD_MAX_TOTAL_TREE_BYTES + 1,
            )

    def test_iq_data_file_is_never_opened(self):
        root, _metadata_path, _data_path = self.build_tree()
        real_open = MODULE.os.open
        opened: list[str] = []

        def guarded_open(path, flags, *args, **kwargs):
            opened.append(os.fspath(path))
            if os.fspath(path).endswith(".dat"):
                raise AssertionError("IQ payload was opened")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(MODULE.os, "open", side_effect=guarded_open):
            report = MODULE.profile_tree(root)
        self.assertEqual(report["status"], "pass")
        self.assertFalse(any(path.endswith(".dat") for path in opened))

    def test_missing_and_orphan_pairs_are_aggregate_failures(self):
        root, _metadata_path, data_path = self.build_tree()
        data_path.unlink()
        orphan = data_path.with_name("ORPHAN.dat")
        orphan.write_bytes(b"\0" * 8)

        report = MODULE.profile_tree(root)

        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["validation"]["failures"]["missing_data_files"], 1)
        self.assertEqual(report["validation"]["failures"]["orphan_data_files"], 1)
        self.assertNotIn("ORPHAN", MODULE.render_report(report).decode("utf-8"))

    def test_report_is_written_atomically_with_private_mode(self):
        root, _metadata_path, _data_path = self.build_tree()
        report = MODULE.profile_tree(root)
        rendered = MODULE.render_report(report)
        output = self.temporary_directory() / "reports" / "profile.json"

        MODULE.write_report(output, rendered)

        self.assertEqual(output.read_bytes(), rendered)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(list(output.parent.glob(f".{output.name}.*")), [])
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
