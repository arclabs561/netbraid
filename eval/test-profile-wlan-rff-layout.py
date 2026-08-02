#!/usr/bin/env python3
"""Hermetic tests for the WLAN RFF archive-layout profiler."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "profile_wlan_rff_layout", HERE / "profile-wlan-rff-layout.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def member(device, session, segment, environment):
    return f"{device}_{session}_{segment}_{environment}.npz"


def write_archive(path, environment, devices, *, reverse=False):
    names = [
        member(device, "2026_01_02_03_04_05", segment, environment)
        for device in devices
        for segment in range(3)
    ]
    if reverse:
        names.reverse()
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in names:
            archive.writestr(name, b"not-an-npz-payload")


class WlanRffLayoutProfileTests(unittest.TestCase):
    def test_profiles_shared_tokens_without_reading_npz_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            anechoic = root / "anechoic.zip"
            office = root / "office.zip"
            write_archive(anechoic, "anechoic_chamber", ("001", "002", "003"))
            write_archive(office, "office_room", ("001", "002", "004"))
            report = MODULE.profile_archives(
                anechoic, office, verify_publisher_digests=False
            )

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["cross_environment"]["shared_device_tokens"], 2)
        self.assertEqual(report["cross_environment"]["device_tokens_in_union"], 4)
        self.assertFalse(report["cross_environment"]["same_token_set"])
        self.assertEqual(report["privacy"]["npz_payload_bytes_read"], 0)
        self.assertEqual(
            report["interpretation"]["not_established"],
            [
                "physical_device_identity",
                "physical_source_identity",
                "event_identity",
                "malicious_intent",
            ],
        )

    def test_member_order_does_not_change_aggregate_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.zip"
            second = root / "second.zip"
            office = root / "office.zip"
            write_archive(first, "anechoic_chamber", ("001", "002"))
            write_archive(second, "anechoic_chamber", ("001", "002"), reverse=True)
            write_archive(office, "office_room", ("001", "002"))
            left = MODULE.profile_archives(
                first, office, verify_publisher_digests=False
            )
            right = MODULE.profile_archives(
                second, office, verify_publisher_digests=False
            )

        for report in (left, right):
            for archive in report["archives"]:
                archive.pop("archive_md5")
                archive.pop("archive_sha256")
                archive.pop("archive_bytes")
                archive.pop("compressed_member_bytes")
        self.assertEqual(left, right)

    def test_unsafe_malformed_and_mixed_environment_members_fail_closed(self):
        cases = (
            ("nested/value.npz", "unsafe_member_name"),
            ("device.npz", "unsupported_member_name"),
            (
                member("001", "2026_01_02_03_04_05", 0, "office_room"),
                "unsupported_member_name",
            ),
        )
        for name, code in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                archive_path = Path(directory) / "bad.zip"
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr(name, b"payload")
                with self.assertRaises(MODULE.LayoutProfileError) as raised:
                    MODULE.profile_archive(archive_path, "anechoic_chamber")
                self.assertEqual(str(raised.exception), code)

    def test_cli_rejects_unpinned_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            anechoic = root / "anechoic.zip"
            office = root / "office.zip"
            report_path = root / "report.json"
            write_archive(anechoic, "anechoic_chamber", ("001", "002"))
            write_archive(office, "office_room", ("001", "002"))
            process = subprocess.run(
                [
                    sys.executable,
                    str(HERE / "profile-wlan-rff-layout.py"),
                    "--anechoic",
                    str(anechoic),
                    "--office",
                    str(office),
                    "--report",
                    str(report_path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, "")
        self.assertEqual(process.stderr.strip(), "archive_digest_mismatch")

    def test_canonical_report_is_json_serializable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            anechoic = root / "anechoic.zip"
            office = root / "office.zip"
            write_archive(anechoic, "anechoic_chamber", ("001",))
            write_archive(office, "office_room", ("001",))
            report = MODULE.profile_archives(
                anechoic, office, verify_publisher_digests=False
            )
            report_path = root / "derived" / "report.json"
            MODULE._write_report(report_path, report)
            written = json.loads(report_path.read_text())
        encoded = json.dumps(report, separators=(",", ":"), sort_keys=True)
        self.assertEqual(written, report)
        self.assertNotIn("2026_01_02_03_04_05", encoded)
        self.assertNotIn('"001"', encoded)


if __name__ == "__main__":
    unittest.main()
