#!/usr/bin/env python3
"""Hermetic tests for the bounded OPERAnet layout profiler."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "profile_operanet_layout", HERE / "profile-operanet-layout.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def fixed_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def observation(
    experiment_ids: set[int],
    *,
    variants: dict[int, list[str]] | None = None,
) -> object:
    return MODULE.ArchiveObservation(
        report={},
        experiment_ids=experiment_ids,
        normalized_member_keys={f"{value:03d}" for value in experiment_ids},
        extensions={".fixture"},
        variant_ids=variants or {},
        unmatched_names=[],
    )


class OperanetLayoutTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_profiles_locked_member_family_without_payload_reads(self) -> None:
        path = self.temporary_directory() / "fixture.zip"
        members = {
            "fixture_001.bin": b"one",
            "fixture_002.bin": b"two",
            "fixture_002b.bin": b"three",
        }
        with zipfile.ZipFile(path, "w") as archive:
            for name, payload in members.items():
                archive.writestr(fixed_info(name), payload)
        expected_uncompressed = sum(map(len, members.values()))
        archive_bytes = path.stat().st_size
        spec = MODULE.ArchiveSpec(
            key="fixture",
            filename=path.name,
            modality="fixture",
            archive_bytes=archive_bytes,
            md5="0" * 32,
            sha256="0" * 64,
            doi="fixture-doi",
            url="https://example.invalid/fixture",
            expected_members=3,
            expected_uncompressed_bytes=expected_uncompressed,
            member_prefix="fixture_",
            member_extension=".bin",
            member_pattern=MODULE.experiment_pattern("fixture_", ".bin", "b?"),
        )

        with zipfile.ZipFile(path) as archive:
            result = MODULE.inspect_central_directory(archive, spec)

        self.assertEqual(result.experiment_ids, {1, 2})
        self.assertEqual(result.normalized_member_keys, {"001", "002", "002b"})
        self.assertEqual(result.variant_ids, {2: ["", "b"]})
        self.assertEqual(
            result.report["central_directory"]["payload_members_opened"], 0
        )
        self.assertFalse(result.report["central_directory"]["crc_payloads_verified"])

    def test_rejects_unsafe_member_name(self) -> None:
        path = self.temporary_directory() / "unsafe.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(fixed_info("../fixture_001.bin"), b"one")
        spec = MODULE.ArchiveSpec(
            key="fixture",
            filename=path.name,
            modality="fixture",
            archive_bytes=path.stat().st_size,
            md5="0" * 32,
            sha256="0" * 64,
            doi="fixture-doi",
            url="https://example.invalid/fixture",
            expected_members=1,
            expected_uncompressed_bytes=3,
        )
        with zipfile.ZipFile(path) as archive:
            with self.assertRaisesRegex(RuntimeError, "unsafe"):
                MODULE.inspect_central_directory(archive, spec)

    def test_reports_partial_filename_overlap_without_semantic_claim(self) -> None:
        observations = {
            "codes": observation(set()),
            "kinect": observation({2}),
            "pwr": observation({2}),
            "uwb1": observation({1, 2}),
            "uwb2": observation({1, 2}),
            "wificsi1": observation({1, 2}),
            "wificsi2": observation({1, 2, 3}, variants={2: ["", "b"]}),
        }

        report = MODULE.overlap_report(observations)

        self.assertEqual(report["common_experiment_ids"], [2])
        self.assertEqual(
            report["claim_status"], "blocked_as_universal_or_semantic_alignment"
        )
        self.assertFalse(report["all_sensing_modalities_same_experiment_id_set"])
        blocker_codes = {item["code"] for item in report["blockers"]}
        self.assertEqual(
            blocker_codes,
            {
                "code_archive_has_no_experiment_ids",
                "filename_tokens_are_not_capture_metadata",
                "incomplete_cross_modality_coverage",
                "variant_suffix_semantics_unknown",
            },
        )

    def test_receipt_is_strict_and_bound_to_source(self) -> None:
        directory = self.temporary_directory()
        path = directory / "fixture.zip.json"
        spec = MODULE.ArchiveSpec(
            key="fixture",
            filename="fixture.zip",
            modality="fixture",
            archive_bytes=3,
            md5=hashlib.md5(b"one", usedforsecurity=False).hexdigest(),
            sha256=hashlib.sha256(b"one").hexdigest(),
            doi="fixture-doi",
            url="https://example.invalid/fixture",
            expected_members=1,
            expected_uncompressed_bytes=3,
        )
        source = {
            "bytes": spec.archive_bytes,
            "doi": spec.doi,
            "filename": spec.filename,
            "group": "motivating",
            "license": "CC0",
            "md5": spec.md5,
            "url": spec.url,
        }
        receipt = {
            "archive": spec.filename,
            "bytes": spec.archive_bytes,
            "md5": spec.md5,
            "schema": MODULE.RECEIPT_SCHEMA,
            "sha256": spec.sha256,
            "source": source,
        }
        path.write_text(json.dumps(receipt), encoding="utf-8")
        MODULE.read_receipt(path, spec)

        receipt["source"]["doi"] = "wrong"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "locked source"):
            MODULE.read_receipt(path, spec)

    def test_report_write_is_private_and_rejects_symlink(self) -> None:
        directory = self.temporary_directory()
        report = directory / "report.json"
        MODULE.write_report(report, b"{}\n")
        self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)

        alias = directory / "alias.json"
        alias.symlink_to(report)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            MODULE.write_report(alias, b"{}\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
