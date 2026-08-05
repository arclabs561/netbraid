#!/usr/bin/env python3
"""Hermetic tests for the bounded RoboLoc-G structural profiler."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import stat
import sys
import tempfile
import unittest
import zipfile
from dataclasses import dataclass
from pathlib import Path
from unittest import mock


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "profile_robolocg_structural_alignment",
    HERE / "profile-robolocg-structural-alignment.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


LOCKED_MARKER = "locked_payload_must_remain_unread"
FRAME_MARKER = "fixture_frame_identifier"
ANCHOR_MARKER = "fixture_anchor_reference"
COORDINATE_MARKER = "123.125"
FIRST_CLOCK_MARKER = "1000000000001"


@dataclass(frozen=True)
class Bundle:
    root: Path
    manifest: Path
    raw: Path
    receipts: Path
    contract: object


def fixed_info(name: str, *, directory: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_STORED if directory else zipfile.ZIP_DEFLATED
    if directory:
        info.external_attr = (stat.S_IFDIR | 0o700) << 16 | 0x10
    else:
        info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def take_index(take) -> int:
    return MODULE.policy.TAKE_ORDER.index(take)


def csv_payload(
    plan,
    *,
    wrong_header: bool = False,
    oversized_field: bool = False,
    oversized_row: bool = False,
) -> bytes:
    header = list(plan.header.columns)
    if wrong_header:
        header[-1] = "wrong_column"
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(header)
    for row_index in range(2):
        base_seconds = 1000 + take_index(plan.take) * 10 + row_index
        outer_ns = base_seconds * MODULE.policy.NANOSECONDS_PER_SECOND + 1
        embedded_ns = outer_ns - 100
        values = []
        for column in plan.header.columns:
            if column == "timestamp":
                value = str(outer_ns)
            elif column == "time":
                value = f"{base_seconds}.000000001"
            elif column == "header.stamp.sec":
                value = str(embedded_ns // MODULE.policy.NANOSECONDS_PER_SECOND)
            elif column == "header.stamp.nanosec":
                value = str(embedded_ns % MODULE.policy.NANOSECONDS_PER_SECOND)
            elif column == "header.frame_id":
                value = FRAME_MARKER
            elif plan.modality == "ftm" and column == "anchor_id":
                value = (
                    f"{ANCHOR_MARKER}_different"
                    if plan.take is MODULE.policy.Take.STILL
                    else ANCHOR_MARKER
                )
            elif column == "header.seq":
                value = ""
            elif column in {"is_bigendian", "is_dense"}:
                value = "False"
            elif column == "frames.rssi":
                value = "-42"
            elif column == "range" and plan.modality == "uwb":
                value = "1500" if row_index == 0 else "2500"
            elif column in MODULE.UNSIGNED_COLUMNS:
                value = "1"
            else:
                value = COORDINATE_MARKER
            values.append(value)
        if plan.take in {
            MODULE.policy.Take.RANDOM1,
            MODULE.policy.Take.RANDOM2,
        }:
            values[-1] = LOCKED_MARKER
        if oversized_field:
            values[-1] = "9" * (MODULE.MAX_FIELD_BYTES + 1)
        if oversized_row:
            values[-1] = "9" * MODULE.MAX_CSV_ROW_BYTES
        writer.writerow(values)
    return output.getvalue().encode("utf-8")


def archive_entries(spec, *, mutation: str | None = None):
    entries = []
    plans = MODULE.expected_members(spec)
    target = "SENSORS_MEASUREMENTS_CSV/AOP/zigzag1/radar_scan.csv"
    for name, plan in plans.items():
        if mutation == "missing_member" and name == target:
            continue
        output_name = (
            "../escape.csv" if mutation == "unsafe_member" and name == target else name
        )
        payload = (
            b""
            if plan.directory
            else csv_payload(
                plan,
                wrong_header=mutation == "wrong_header" and name == target,
                oversized_field=mutation == "oversized_field" and name == target,
                oversized_row=mutation == "oversized_row" and name == target,
            )
        )
        entries.append((output_name, plan.directory, payload))
    return entries


def write_archive(path: Path, spec, *, mutation: str | None = None) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, directory, payload in archive_entries(spec, mutation=mutation):
            archive.writestr(fixed_info(name, directory=directory), payload)
    path.chmod(0o600)


def build_bundle(
    root: Path,
    *,
    archive_mutation: tuple[str, str] | None = None,
) -> Bundle:
    raw = root / "raw"
    receipts = root / "receipts"
    raw.mkdir(mode=0o700)
    receipts.mkdir(mode=0o700)
    specs = MODULE.PRODUCTION_CONTRACT.archives
    artifacts = []
    payload_digests = {}
    for spec in specs:
        path = raw / spec.filename
        mutation = (
            archive_mutation[1]
            if archive_mutation is not None and archive_mutation[0] == spec.kind
            else None
        )
        write_archive(path, spec, mutation=mutation)
        payload = path.read_bytes()
        md5 = hashlib.md5(payload, usedforsecurity=False).hexdigest()
        sha256 = hashlib.sha256(payload).hexdigest()
        payload_digests[spec.filename] = sha256
        artifacts.append(
            {
                "bytes": len(payload),
                "content_url": f"https://example.invalid/{spec.filename}",
                "filename": spec.filename,
                "md5": md5,
            }
        )
    record = {
        "api_updated": "2025-01-01T00:00:00+00:00",
        "api_url": "https://example.invalid/api/record",
        "artifacts": artifacts,
        "difficulty_rationale": "fixture",
        "doi": "10.0000/fixture",
        "expected_artifact_count": len(artifacts),
        "expected_total_bytes": sum(item["bytes"] for item in artifacts),
        "grouping_warning": "fixture",
        "license": "fixture",
        "license_id": "fixture",
        "record_id": MODULE.RECORD_ID,
        "record_url": "https://example.invalid/record",
        "task_rationale": "fixture",
        "title": "RoboLoc-G fixture",
        "version": None,
    }
    manifest_value = {
        "expected_artifact_count": len(artifacts),
        "expected_record_count": 1,
        "expected_total_bytes": record["expected_total_bytes"],
        "publisher": "fixture",
        "records": [record],
        "schema": "netbraid.curated_eval_artifacts.v1",
    }
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps(manifest_value), encoding="utf-8")
    manifest.chmod(0o600)
    for artifact in artifacts:
        receipt = {
            "integrity": {
                "bytes": artifact["bytes"],
                "md5": artifact["md5"],
                "sha256": payload_digests[artifact["filename"]],
            },
            "schema": "local.netbraid_curated_eval_artifact.v1",
            "source": MODULE._source_for(record, artifact),
        }
        receipt_path = receipts / f"{artifact['filename']}.json"
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        receipt_path.chmod(0o600)
    contract = MODULE.ProfileContract(
        MODULE.RECORD_ID,
        hashlib.sha256(MODULE._canonical_bytes(record)).hexdigest(),
        specs,
    )
    return Bundle(root, manifest, raw, receipts, contract)


class RoboLocGStructuralProfilerTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def assert_profile_error(self, code: str, function, *args) -> None:
        with self.assertRaises(MODULE.RoboLocGProfileError) as raised:
            function(*args)
        self.assertEqual(raised.exception.code, code)

    def profile(self, bundle: Bundle):
        return MODULE.profile_record(
            bundle.manifest,
            bundle.raw,
            bundle.receipts,
            bundle.contract,
        )

    def test_profiles_only_permitted_takes_deterministically(self):
        bundle = build_bundle(self.temporary_directory())
        original_open = MODULE.zipfile.ZipFile.open

        def reject_locked(archive, member, *args, **kwargs):
            name = member.filename if isinstance(member, zipfile.ZipInfo) else member
            if "random1" in name or "random2" in name:
                raise AssertionError("locked-test payload member was opened")
            return original_open(archive, member, *args, **kwargs)

        with mock.patch.object(MODULE.zipfile.ZipFile, "open", new=reject_locked):
            first = self.profile(bundle)
            second = self.profile(bundle)

        self.assertEqual(first, second)
        self.assertEqual(MODULE.render_report(first), MODULE.render_report(second))
        self.assertEqual(first["status"], "blocked")
        self.assertEqual(first["locked_test"]["payload_members_opened"], 0)
        self.assertTrue(first["locked_test"]["gate_enforced"])
        self.assertFalse(first["gate"]["fusion_capable"])
        self.assertFalse(first["gate"]["scoring_allowed"])
        self.assertEqual([item["take_count"] for item in first["roles"]], [4, 1, 1])

    def test_locked_test_read_attempt_fails_before_archive_open(self):
        spec = MODULE.PRODUCTION_CONTRACT.archives[0]
        name, plan = next(
            (name, plan)
            for name, plan in MODULE.expected_members(spec).items()
            if plan.take is MODULE.policy.Take.RANDOM1 and not plan.directory
        )
        archive = mock.Mock()
        self.assert_profile_error(
            "locked_test_payload_read_forbidden",
            MODULE.profile_member,
            archive,
            mock.Mock(filename=name),
            plan,
        )
        archive.open.assert_not_called()

    def test_manifest_receipt_and_raw_tamper_fail_closed(self):
        manifest_bundle = build_bundle(self.temporary_directory())
        manifest = json.loads(manifest_bundle.manifest.read_text(encoding="utf-8"))
        manifest["records"][0]["title"] = "tampered"
        manifest_bundle.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        self.assert_profile_error(
            "record_manifest_digest_mismatch", self.profile, manifest_bundle
        )

        receipt_bundle = build_bundle(self.temporary_directory())
        receipt_path = receipt_bundle.receipts / "SENSORS_MEASUREMENTS_CSV.zip.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["integrity"]["sha256"] = "0" * 64
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        receipt_path.chmod(0o600)
        self.assert_profile_error(
            "raw_archive_digest_mismatch", self.profile, receipt_bundle
        )

        raw_bundle = build_bundle(self.temporary_directory())
        raw_path = raw_bundle.raw / "SENSORS_MEASUREMENTS_CSV.zip"
        payload = bytearray(raw_path.read_bytes())
        payload[len(payload) // 2] ^= 1
        raw_path.write_bytes(payload)
        self.assert_profile_error(
            "raw_archive_digest_mismatch", self.profile, raw_bundle
        )

    def test_symlink_and_unsafe_zip_member_paths_fail_closed(self):
        bundle = build_bundle(self.temporary_directory())
        archive_path = bundle.raw / "SENSORS_MEASUREMENTS_CSV.zip"
        outside = bundle.root / "outside.zip"
        archive_path.replace(outside)
        archive_path.symlink_to(outside)
        self.assert_profile_error("unsafe_raw_archive", self.profile, bundle)

        unsafe = build_bundle(
            self.temporary_directory(),
            archive_mutation=("sensor_measurements_csv", "unsafe_member"),
        )
        self.assert_profile_error("unsafe_zip_member_path", self.profile, unsafe)

    def test_wrong_header_and_count_row_field_limits_fail_closed(self):
        wrong_header = build_bundle(
            self.temporary_directory(),
            archive_mutation=("sensor_measurements_csv", "wrong_header"),
        )
        self.assert_profile_error("csv_header_mismatch", self.profile, wrong_header)

        missing = build_bundle(
            self.temporary_directory(),
            archive_mutation=("sensor_measurements_csv", "missing_member"),
        )
        self.assert_profile_error("zip_entry_count_mismatch", self.profile, missing)

        oversized_row = build_bundle(
            self.temporary_directory(),
            archive_mutation=("sensor_measurements_csv", "oversized_row"),
        )
        self.assert_profile_error("csv_row_size_limit", self.profile, oversized_row)

        oversized_field = build_bundle(
            self.temporary_directory(),
            archive_mutation=("sensor_measurements_csv", "oversized_field"),
        )
        self.assert_profile_error("csv_field_size_limit", self.profile, oversized_field)

        total_limit = build_bundle(self.temporary_directory())
        with mock.patch.object(MODULE, "MAX_TOTAL_ROWS", 1):
            self.assert_profile_error("csv_total_row_limit", self.profile, total_limit)

    def test_report_is_metadata_only_and_published_privately(self):
        bundle = build_bundle(self.temporary_directory())
        report = self.profile(bundle)
        rendered = MODULE.render_report(report)
        text = rendered.decode("utf-8")
        for forbidden in (
            str(bundle.root),
            "SENSORS_MEASUREMENTS_CSV.zip",
            "radar_scan.csv",
            FRAME_MARKER,
            ANCHOR_MARKER,
            COORDINATE_MARKER,
            FIRST_CLOCK_MARKER,
            LOCKED_MARKER,
        ):
            self.assertNotIn(forbidden, text)
        self.assertTrue(report["metadata_only"])
        self.assertEqual(report["claims"]["ground_truth_role"], "sole_oracle")
        self.assertEqual(
            report["claims"]["gantry_evidence_role"],
            "dependent_consistency_only",
        )
        self.assertFalse(report["claims"]["localization_scores_computed"])
        self.assertFalse(report["claims"]["radar_associations_or_extrinsics_claimed"])

        report_path = bundle.root / "derived" / "report.json"
        report_path.parent.mkdir(mode=0o700)
        MODULE.write_report(report_path, rendered)
        self.assertEqual(report_path.read_bytes(), rendered)
        self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)

        outside = bundle.root / "outside-report.json"
        outside.write_text("unchanged", encoding="utf-8")
        linked = bundle.root / "linked-report.json"
        linked.symlink_to(outside)
        self.assert_profile_error(
            "unsafe_report_path", MODULE.write_report, linked, rendered
        )
        self.assertEqual(outside.read_text(encoding="utf-8"), "unchanged")

    def test_diagnostics_are_aggregate_and_blocker_states_are_explicit(self):
        report = self.profile(build_bundle(self.temporary_directory()))
        diagnostics = report["diagnostics"]
        self.assertTrue(diagnostics["ftm_anchor_sets"]["train_reference_available"])
        calibration = diagnostics["ftm_anchor_sets"]["roles"][1]
        self.assertEqual(calibration["mismatch_take_count_vs_train_reference"], 1)
        self.assertTrue(
            all(
                item["minimum_ns"] == 100 and item["maximum_ns"] == 100
                for item in diagnostics["outer_vs_header_clock_delta_ns"]
            )
        )
        self.assertTrue(
            all(
                item["bucket_counts"]["at_least_1000"] == item["count"]
                for item in diagnostics["uwb_range_magnitude"]
            )
        )
        states = {item["blocker"]: item["state"] for item in report["blockers"]}
        self.assertEqual(
            states["outer_vs_header_deltas_diagnostic"],
            "closed",
        )
        self.assertEqual(states["uwb_unit_conflict"], "open")
        self.assertEqual(states["ftm_anchor_id_mismatch"], "open")


if __name__ == "__main__":
    unittest.main(verbosity=2)
