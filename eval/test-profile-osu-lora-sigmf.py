#!/usr/bin/env python3
"""Hermetic tests for the bounded OSU LoRa SigMF metadata profiler."""

from __future__ import annotations

import importlib.util
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
    ) -> tuple[Path, Path, Path]:
        root = self.temporary_directory() / "root"
        directory = root / "distances" / "5m"
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

    def test_file_metadata_and_total_limits_fail_closed(self):
        root, metadata_path, data_path = self.build_tree()
        total_bytes = metadata_path.stat().st_size + data_path.stat().st_size
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
            ("MAX_TOTAL_BYTES", total_bytes - 1, "tree_total_byte_limit_exceeded"),
        )
        for name, limit, error in cases:
            with self.subTest(limit=name), mock.patch.object(MODULE, name, limit):
                with self.assertRaisesRegex(MODULE.ProfileError, error):
                    MODULE.profile_tree(root)

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
