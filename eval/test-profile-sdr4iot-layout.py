#!/usr/bin/env python3
"""Hermetic tests for the SDR4IoT BLE/Zigbee layout profiler."""

import importlib.util
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "profile_sdr4iot_layout", HERE / "profile-sdr4iot-layout.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def standard_name(modality, scenario, scene, receiver, mobile, extension):
    mobile_suffix = "" if mobile is None else f"_mobile{mobile}"
    return (
        f"{modality}/scenario{scenario}/scene{scene}/20260102_0304/"
        f"S{scenario}_s{scene}_2026-01-02_03-04_server{receiver}"
        f"{mobile_suffix}.{extension}"
    )


def alternate_name(extension):
    tag = "-tag" if extension == "sigmf" else ""
    return (
        "zigbee/scenario6/scene38/20260102_0304/"
        f"S6_s38_server9-mobile11-2026-01-02_03-04-05{tag}.{extension}"
    )


def write_archive(path, names, *, reverse=False):
    ordered = list(names)
    if reverse:
        ordered.reverse()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in ordered:
            archive.writestr(name, b"payload-not-read-by-profiler")


def complete_fixture_names():
    names = []
    for extension in ("cap", "csv", "sigmf"):
        names.append(standard_name("ble", "2", "3", "9", "5", extension))
        names.append(alternate_name(extension))
    names.extend(
        [
            "ble/scenario2/scene3/20260102_0304/"
            "extract_S2_s3_2026-01-02_03-04_server9_mobile5.csv",
            "ble/.DS_Store",
        ]
    )
    return names


class Sdr4iotLayoutProfileTests(unittest.TestCase):
    def test_profiles_distinct_modalities_and_candidate_layer_pairing(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "dataset.zip"
            write_archive(archive, complete_fixture_names())
            report = MODULE.profile_archive(archive, verify_publisher_digest=False)

        by_modality = {item["modality"]: item for item in report["modalities"]}
        self.assertEqual(report["status"], "pass")
        self.assertEqual(set(by_modality), {"ble", "zigbee"})
        self.assertEqual(by_modality["ble"]["complete_three_layer_groups"], 1)
        self.assertEqual(by_modality["zigbee"]["complete_three_layer_groups"], 1)
        self.assertEqual(by_modality["ble"]["mobile_tokens"], 1)
        self.assertEqual(report["cross_modality"]["shared_receiver_tokens"], 1)
        self.assertEqual(report["privacy"]["payload_bytes_read"], 0)
        self.assertEqual(
            report["supplemental_member_counts"],
            {"additional_tabular_extract": 1, "archive_metadata": 1},
        )

    def test_member_order_does_not_change_aggregate_report(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.zip"
            second = Path(directory) / "second.zip"
            names = complete_fixture_names()
            write_archive(first, names)
            write_archive(second, names, reverse=True)
            left = MODULE.profile_archive(first, verify_publisher_digest=False)
            right = MODULE.profile_archive(second, verify_publisher_digest=False)

        for report in (left, right):
            report["source"].pop("archive")
            report["source"].pop("md5")
            report["source"].pop("sha256")
        self.assertEqual(left, right)

    def test_path_filename_mismatch_and_unknown_layout_fail_closed(self):
        cases = (
            (
                "ble/scenario2/scene3/20260102_0304/"
                "S2_s4_2026-01-02_03-04_server9_mobile5.cap",
                "path_filename_group_mismatch",
            ),
            (
                "ble/scenario2/scene3/20260102_0304/unknown.bin",
                "unsupported_member_layout",
            ),
        )
        for name, reason in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "bad.zip"
                names = complete_fixture_names() + [name]
                write_archive(archive, names)
                with self.assertRaises(MODULE.LayoutProfileError) as raised:
                    MODULE.profile_archive(archive, verify_publisher_digest=False)
                self.assertEqual(str(raised.exception), reason)

    def test_duplicate_layer_in_one_observation_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "duplicate.zip"
            names = complete_fixture_names()
            names.append(
                "ble/scenario2/scene3/20260102_0304/"
                "S2b_s3_2026-01-02_03-04_server9_mobile5.cap"
            )
            write_archive(archive, names)
            with self.assertRaises(MODULE.LayoutProfileError) as raised:
                MODULE.profile_archive(archive, verify_publisher_digest=False)
        self.assertEqual(str(raised.exception), "duplicate_observation_layer")

    def test_report_retains_no_publisher_token_values_or_member_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "dataset.zip"
            output = root / "derived" / "report.json"
            write_archive(archive, complete_fixture_names())
            report = MODULE.profile_archive(archive, verify_publisher_digest=False)
            MODULE._write_report(output, report)
            encoded = output.read_text()

        self.assertEqual(json.loads(encoded), report)
        for forbidden in ("server9", "mobile5", "scenario2/scene3", "20260102_0304"):
            self.assertNotIn(forbidden, encoded)


if __name__ == "__main__":
    unittest.main()
