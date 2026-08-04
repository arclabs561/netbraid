#!/usr/bin/env python3
"""Hermetic tests for the SDR4IoT layer-alignment evaluator."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "evaluate_sdr4iot_layer_alignment",
    HERE / "evaluate-sdr4iot-layer-alignment.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FIXED_ZIP_TIME = (2020, 1, 2, 3, 4, 6)
BASE_SECONDS = 1_600_000_000
FREQUENCY = 2_426_000_000
SAMPLE_RATE = 5_000_000


@dataclass(frozen=True)
class GroupFixture:
    modality: str
    scenario: int
    count: int
    csv_clock_offset_seconds: int = 0
    csv_frequency: int = FREQUENCY
    malformed_development_pcap: bool = False
    unsafe_tar_member: bool = False


def artifact_name(group: GroupFixture, extension: str) -> str:
    return (
        f"{group.modality}/scenario{group.scenario}/scene1/20200102_0304/"
        f"S{group.scenario}_s1_2020-01-02_03-04_server41_mobile73.{extension}"
    )


def zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    return info


def pcap_bytes(count: int, *, trailing: bool = False) -> bytes:
    payload = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 256))
    for index in range(count):
        seconds = BASE_SECONDS + index // 10
        microseconds = 100_000 + (index % 10) * 100_000
        packet = bytes((index + 1, index + 2, index + 3, index + 4))
        payload.extend(
            struct.pack("<IIII", seconds, microseconds, len(packet), len(packet))
        )
        payload.extend(packet)
    if trailing:
        payload.extend(b"unsafe-trailer")
    return bytes(payload)


def csv_bytes(group: GroupFixture) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        (
            "Time",
            "Start_trame",
            "End_trame",
            "Channel_frequency",
            "Sample_rate",
            "Robot_node",
            "X",
            "Y",
        )
    )
    epoch = datetime(1970, 1, 1)
    for index in range(group.count):
        packet_time = epoch + timedelta(
            seconds=BASE_SECONDS + index // 10,
            microseconds=100_000 + (index % 10) * 100_000,
        )
        table_time = packet_time + timedelta(seconds=group.csv_clock_offset_seconds)
        start = 20_000 + index * 2
        writer.writerow(
            (
                table_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
                start,
                start + 2,
                group.csv_frequency,
                SAMPLE_RATE,
                73,
                5429,
                454,
            )
        )
    return output.getvalue().encode("utf-8")


def add_tar_file(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = 0o600
    member.mtime = 0
    archive.addfile(member, io.BytesIO(payload))


def sigmf_bytes(group: GroupFixture) -> bytes:
    signal_data = bytes(index % 251 for index in range(group.count * 2 * 8))
    digest = hashlib.sha512(signal_data).hexdigest()
    metadata = {
        "global": {
            "core:datatype": "cf32",
            "core:description": "Synthetic packet detections.",
            "core:sha512": digest,
            "core:version": "0.0.1",
        },
        "captures": [
            {
                "core:frequency": FREQUENCY,
                "core:sample_start": index * 2,
                "core:sampling_rate": SAMPLE_RATE,
                "core:time": f"2020-01-02T03:04:{index % 60:02d}.000000Z",
            }
            for index in range(group.count)
        ],
        "annotations": [
            {
                "core:comment": "Synthetic packet detection.",
                "core:latitude": 5429,
                "core:longitude": 454,
                "core:sample_count": 2,
                "core:sample_start": index * 2,
            }
            for index in range(group.count)
        ],
    }
    metadata_payload = json.dumps(metadata, sort_keys=True).encode("utf-8")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        data_name = (
            "../private-record.sigmf-data"
            if group.unsafe_tar_member
            else ("private-record.sigmf-data")
        )
        add_tar_file(archive, data_name, signal_data)
        add_tar_file(archive, "private-record.sigmf-meta", metadata_payload)
    return output.getvalue()


def write_archive(
    path: Path, groups: list[GroupFixture], *, reverse: bool = False
) -> None:
    members: list[tuple[str, bytes]] = []
    for group in groups:
        members.extend(
            (
                (
                    artifact_name(group, "cap"),
                    pcap_bytes(group.count, trailing=group.malformed_development_pcap),
                ),
                (artifact_name(group, "csv"), csv_bytes(group)),
                (artifact_name(group, "sigmf"), sigmf_bytes(group)),
            )
        )
    if reverse:
        members.reverse()
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in members:
            archive.writestr(zip_info(name), payload)


class Sdr4iotLayerAlignmentTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def fixture_archive(
        self,
        root: Path,
        *,
        evaluation: GroupFixture | None = None,
        development: GroupFixture | None = None,
        reverse: bool = False,
    ) -> Path:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if development is None:
            development = GroupFixture("ble", 41, 4)
        if evaluation is None:
            evaluation = GroupFixture("zigbee", 73, 2)
        path = root / "publisher-private-token.zip"
        write_archive(path, [development, evaluation], reverse=reverse)
        return path

    def test_aligned_evaluation_group_passes_all_registered_checks(self):
        archive = self.fixture_archive(self.temporary_directory())

        report = MODULE.evaluate_archive(archive, verify_publisher_digest=False)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["counts"]["complete_groups"], 2)
        self.assertEqual(report["counts"]["development_groups"], 1)
        self.assertEqual(report["counts"]["evaluation_groups_passed"], 1)
        self.assertEqual(report["counts"]["packets"], 2)
        self.assertEqual(report["counts"]["csv_records"], 2)
        self.assertEqual(report["counts"]["sigmf_captures"], 2)
        self.assertEqual(report["counts"]["sigmf_annotations"], 2)
        self.assertEqual(report["max_timing_residual_ns"], 0)
        self.assertEqual(report["failure_reason_counts"], {})
        self.assertEqual(
            report["descriptive_capability_by_modality"],
            {
                "zigbee": {
                    "evaluation_groups": 1,
                    "groups_failed": 0,
                    "groups_parsed": 1,
                    "groups_passed_all_checks": 1,
                    "groups_with_clock_residual_within_2ms": 1,
                    "groups_with_populated_equal_counts": 1,
                    "groups_with_representation_structure_alignment": 1,
                }
            },
        )

    def test_frequency_mismatch_has_one_stable_failure_reason(self):
        root = self.temporary_directory()
        evaluation = GroupFixture("zigbee", 73, 2, csv_frequency=2_480_000_000)
        archive = self.fixture_archive(root, evaluation=evaluation)

        report = MODULE.evaluate_archive(archive, verify_publisher_digest=False)

        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["counts"]["evaluation_groups_failed"], 1)
        self.assertEqual(report["failure_reason_counts"], {"frequency_mismatch": 1})
        capability = report["descriptive_capability_by_modality"]["zigbee"]
        self.assertEqual(capability["groups_with_populated_equal_counts"], 1)
        self.assertEqual(
            capability["groups_with_representation_structure_alignment"], 0
        )

    def test_group_clock_offset_does_not_change_timing_residual(self):
        root = self.temporary_directory()
        baseline = self.fixture_archive(root / "baseline")
        shifted_root = root / "shifted"
        shifted_root.mkdir()
        shifted = self.fixture_archive(
            shifted_root,
            evaluation=GroupFixture("zigbee", 73, 2, csv_clock_offset_seconds=25_200),
        )

        baseline_report = MODULE.evaluate_archive(
            baseline, verify_publisher_digest=False
        )
        shifted_report = MODULE.evaluate_archive(shifted, verify_publisher_digest=False)

        self.assertEqual(baseline_report["status"], "pass")
        self.assertEqual(shifted_report["status"], "pass")
        self.assertEqual(
            baseline_report["max_timing_residual_ns"],
            shifted_report["max_timing_residual_ns"],
        )
        self.assertEqual(
            baseline_report["failure_reason_counts"],
            shifted_report["failure_reason_counts"],
        )

    def test_largest_group_is_partitioned_before_its_payload_is_read(self):
        development = GroupFixture("ble", 41, 5, malformed_development_pcap=True)
        archive = self.fixture_archive(
            self.temporary_directory(), development=development
        )

        report = MODULE.evaluate_archive(archive, verify_publisher_digest=False)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["counts"]["evaluation_groups"], 1)
        self.assertEqual(report["counts"]["packets"], 2)
        self.assertEqual(report["failure_reason_counts"], {})

    def test_report_is_deterministic_and_contains_only_aggregates(self):
        root = self.temporary_directory()
        archive = self.fixture_archive(root)

        first = MODULE.render_report(
            MODULE.evaluate_archive(archive, verify_publisher_digest=False)
        )
        second = MODULE.render_report(
            MODULE.evaluate_archive(archive, verify_publisher_digest=False)
        )

        self.assertEqual(first, second)
        for forbidden in (
            str(root).encode(),
            b"publisher-private-token",
            b"server41",
            b"mobile73",
            b"scenario41",
            b"2020-",
            b"2426000000",
            b"5429",
            b"private-record",
        ):
            self.assertNotIn(forbidden, first)

    def test_unsafe_tar_member_fails_closed_without_leaking_its_name(self):
        evaluation = GroupFixture("zigbee", 73, 2, unsafe_tar_member=True)
        archive = self.fixture_archive(
            self.temporary_directory(), evaluation=evaluation
        )

        report = MODULE.evaluate_archive(archive, verify_publisher_digest=False)
        encoded = MODULE.render_report(report)

        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["failure_reason_counts"], {"unsafe_tar_member": 1})
        self.assertNotIn(b"private-record", encoded)
        self.assertNotIn(b"..", encoded)

    def test_report_writer_rejects_symlink_and_source_alias(self):
        root = self.temporary_directory()
        archive = self.fixture_archive(root)
        target = root / "target.json"
        target.write_text("keep", encoding="utf-8")
        link = root / "report.json"
        link.symlink_to(target)

        with self.assertRaises(MODULE.AlignmentEvaluationError) as raised:
            MODULE.write_report(link, b"{}\n", source_path=archive)
        self.assertEqual(raised.exception.code, "unsafe_report_path")
        self.assertEqual(target.read_text(encoding="utf-8"), "keep")

        with self.assertRaises(MODULE.AlignmentEvaluationError) as raised:
            MODULE.write_report(archive, b"{}\n", source_path=archive)
        self.assertEqual(raised.exception.code, "report_aliases_source")

    def test_failed_hypothesis_is_a_successful_cli_run(self):
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            archive = directory / "source.zip"
            archive.write_bytes(b"source")
            report_path = directory / "report.json"
            report = {
                "schema": MODULE.SCHEMA,
                "status": "fail",
                "source_digests": {"md5": "0" * 32, "sha256": "0" * 64},
                "counts": {},
                "max_timing_residual_ns": None,
                "failure_reason_counts": {"timing_residual_exceeded": 1},
            }
            with (
                mock.patch.object(MODULE, "evaluate_archive", return_value=report),
                mock.patch.object(
                    MODULE,
                    "parse_args",
                    return_value=SimpleNamespace(
                        archive=archive,
                        report=report_path,
                    ),
                ),
                mock.patch("sys.stdout", io.StringIO()),
            ):
                result = MODULE.main()

        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
