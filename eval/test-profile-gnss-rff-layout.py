#!/usr/bin/env python3
"""Hermetic tests for the central-directory-only GNSS RFF profiler."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import json
import stat
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "profile_gnss_rff_layout", HERE / "profile-gnss-rff-layout.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FIXED_TIME = (2024, 9, 25, 0, 0, 0)


def data_member(day, scenario, category, sequence):
    prefix = "SS" if scenario == "spoof" else "S"
    return f"data/{day}/{prefix}{category}_{sequence}.mat"


def model_member(day, category):
    numeric_day = day.removeprefix("oct_")
    return (
        f"models/Fully_connected{numeric_day}_C{category}_"
        "SS20000_same_samples_lr001_red_1_samplemean.h5"
    )


def zip_info(name, compression):
    info = zipfile.ZipInfo(name, FIXED_TIME)
    info.compress_type = compression
    info.create_system = 3
    mode = (stat.S_IFDIR | 0o755) if name.endswith("/") else (stat.S_IFREG | 0o600)
    info.external_attr = mode << 16
    return info


def default_sequences():
    return {
        (day, category, scenario): [10_000 + category]
        for day in MODULE.DAYS
        for category in MODULE.CATEGORIES
        for scenario in MODULE.SCENARIOS
    }


def write_archive(
    path,
    *,
    sequences=None,
    reverse=False,
    extra_members=(),
    omit=(),
    compression_overrides=None,
):
    sequences = sequences or default_sequences()
    compression_overrides = compression_overrides or {}
    omitted = set(omit)
    entries = []
    for directory in sorted(MODULE.EXPECTED_DIRECTORIES):
        entries.append((directory, b"", zipfile.ZIP_STORED))
    for day in MODULE.DAYS:
        for category in MODULE.CATEGORIES:
            for scenario in MODULE.SCENARIOS:
                for sequence in sequences.get((day, category, scenario), []):
                    name = data_member(day, scenario, category, sequence)
                    compression = compression_overrides.get(name, zipfile.ZIP_DEFLATED)
                    entries.append((name, b"synthetic-mat-payload", compression))
    for day in MODULE.DAYS:
        for category in MODULE.CATEGORIES:
            name = model_member(day, category)
            entries.append((name, b"synthetic-h5-payload", zipfile.ZIP_DEFLATED))
    entries.append(("demo.py", b"print('synthetic demo')\n", zipfile.ZIP_DEFLATED))
    entries.extend(extra_members)
    entries = [entry for entry in entries if entry[0] not in omitted]
    if reverse:
        entries.reverse()

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
            for name, payload, compression in entries:
                archive.writestr(zip_info(name, compression), payload)


def archive_md5(path):
    digest = hashlib.md5(usedforsecurity=False)
    digest.update(path.read_bytes())
    return digest.hexdigest()


def profile(path):
    return MODULE.profile_archive(
        path,
        expected_md5=archive_md5(path),
        expected_bytes=path.stat().st_size,
    )


def patch_member_flags(path, predicate, added_flags):
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        central_offset = archive.start_dir
    encoded = bytearray(path.read_bytes())
    offset = central_offset
    for member in members:
        if encoded[offset : offset + 4] != b"PK\x01\x02":
            raise AssertionError("missing central-directory signature")
        name_length, extra_length, comment_length = struct.unpack_from(
            "<HHH", encoded, offset + 28
        )
        if predicate(member.filename):
            central_flags = struct.unpack_from("<H", encoded, offset + 8)[0]
            local_flags = struct.unpack_from("<H", encoded, member.header_offset + 6)[0]
            struct.pack_into("<H", encoded, offset + 8, central_flags | added_flags)
            struct.pack_into(
                "<H", encoded, member.header_offset + 6, local_flags | added_flags
            )
        offset += 46 + name_length + extra_length + comment_length
    path.write_bytes(encoded)


def patch_member_name(path, target, replacement):
    target_bytes = target.encode("ascii")
    replacement_bytes = replacement.encode("ascii")
    if len(target_bytes) != len(replacement_bytes):
        raise AssertionError("replacement must preserve ZIP record lengths")

    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        central_offset = archive.start_dir
    encoded = bytearray(path.read_bytes())
    offset = central_offset
    replaced = 0
    for member in members:
        if encoded[offset : offset + 4] != b"PK\x01\x02":
            raise AssertionError("missing central-directory signature")
        name_length, extra_length, comment_length = struct.unpack_from(
            "<HHH", encoded, offset + 28
        )
        central_name = bytes(encoded[offset + 46 : offset + 46 + name_length])
        if central_name == target_bytes:
            local_name_length = struct.unpack_from(
                "<H", encoded, member.header_offset + 26
            )[0]
            local_start = member.header_offset + 30
            if (
                bytes(encoded[local_start : local_start + local_name_length])
                != target_bytes
            ):
                raise AssertionError("local and central member names differ")
            encoded[offset + 46 : offset + 46 + name_length] = replacement_bytes
            encoded[local_start : local_start + local_name_length] = replacement_bytes
            replaced += 1
        offset += 46 + name_length + extra_length + comment_length
    if replaced != 1:
        raise AssertionError("expected exactly one member-name replacement")
    path.write_bytes(encoded)


class GnssRffLayoutProfileTests(unittest.TestCase):
    def temporary_path(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name) / "synthetic.zip"

    def test_strict_grammar_counts_cross_day_coverage_and_privacy(self):
        path = self.temporary_path()
        sequences = default_sequences()
        sequences[("oct_18", 1, "clean")] = [111_111_111, 987_654_321]
        sequences[("oct_19", 1, "clean")] = [987_654_321, 222_222_222]
        sequences[("oct_19", 3, "spoof")] = []
        sequences[("oct_19", 4, "spoof")] = []
        write_archive(path, sequences=sequences)

        report = profile(path)
        rendered = MODULE.render_report(report).decode("utf-8")

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["layout"]["data_members"]["total"], 16)
        oct_19 = report["layout"]["data_members"]["by_day"][1]
        self.assertEqual(oct_19["controlled_scenarios"], {"clean": 5, "spoof": 2})
        coverage = report["layout"]["cross_day_coverage"]
        self.assertEqual(coverage["pairs_covered_on_both_days"], 6)
        baseline_clean = next(
            row
            for row in coverage["category_scenario_pairs"]
            if row["category"] == 1 and row["controlled_scenario"] == "clean"
        )
        self.assertEqual(baseline_clean["shared_sequence_token_count"], 1)
        self.assertEqual(report["layout"]["model_members"]["total"], 8)
        self.assertEqual(report["layout"]["demo_members"], 1)
        self.assertEqual(report["privacy"]["member_paths_emitted"], 0)
        self.assertEqual(report["privacy"]["sequence_values_emitted"], 0)
        self.assertEqual(report["privacy"]["member_payload_streams_opened"], 0)
        self.assertNotIn("987654321", rendered)
        self.assertNotIn("data/oct_", rendered)
        self.assertNotIn("models/", rendered)
        self.assertNotIn(".mat", rendered)
        self.assertNotIn(".h5", rendered)
        self.assertNotIn("demo.py", rendered)

    def test_same_archive_and_order_independent_layout_are_deterministic(self):
        first_path = self.temporary_path()
        second_path = first_path.with_name("reversed.zip")
        write_archive(first_path)
        write_archive(second_path, reverse=True)

        first = profile(first_path)
        repeated = profile(first_path)
        reversed_report = profile(second_path)

        self.assertEqual(first, repeated)
        self.assertEqual(MODULE.render_report(first), MODULE.render_report(repeated))
        for key in (
            "layout",
            "encryption",
            "compression",
            "observed_bounds",
            "privacy",
            "interpretation",
            "limits",
        ):
            self.assertEqual(first[key], reversed_report[key])

    def test_member_payload_apis_are_never_used(self):
        path = self.temporary_path()
        write_archive(path)

        forbidden = AssertionError("member payload API was called")
        with contextlib.ExitStack() as stack:
            for method in ("open", "read", "extract", "extractall"):
                stack.enter_context(
                    mock.patch.object(
                        MODULE.zipfile.ZipFile, method, side_effect=forbidden
                    )
                )
            report = profile(path)

        self.assertEqual(report["privacy"]["mat_payload_bytes_decompressed"], 0)
        self.assertEqual(report["privacy"]["h5_payload_bytes_decompressed"], 0)
        self.assertEqual(report["privacy"]["password_values_used"], 0)

    def test_traditional_encryption_is_counted_and_strong_encryption_rejected(self):
        path = self.temporary_path()
        write_archive(path)
        patch_member_flags(path, lambda name: not name.endswith("/"), 0x0001)

        report = profile(path)

        self.assertEqual(report["encryption"]["encrypted_members"], 25)
        self.assertEqual(report["encryption"]["by_kind"]["data_mat"], 16)
        self.assertEqual(report["encryption"]["by_kind"]["model_h5"], 8)
        self.assertEqual(report["encryption"]["by_kind"]["demo_python"], 1)
        self.assertEqual(report["encryption"]["by_kind"]["directory"], 0)

        strong_path = path.with_name("strong.zip")
        write_archive(strong_path)
        patch_member_flags(
            strong_path,
            lambda name: name.endswith(".h5"),
            MODULE.STRONG_ENCRYPTION_FLAG,
        )
        with self.assertRaisesRegex(
            MODULE.LayoutProfileError, "unsupported_encryption"
        ):
            profile(strong_path)

    def test_unsafe_duplicate_and_unsupported_members_fail_closed(self):
        cases = (
            ("../escape.mat", "unsafe_member_name"),
            ("/absolute.mat", "unsafe_member_name"),
            ("data//oct_18/S1_1.mat", "unsafe_member_name"),
            ("data\\oct_18\\S1_1.mat", "unsafe_member_name"),
            ("README.txt", "unsupported_member_name"),
        )
        for name, error in cases:
            with self.subTest(name=name):
                path = self.temporary_path()
                write_archive(
                    path,
                    extra_members=((name, b"synthetic", zipfile.ZIP_DEFLATED),),
                )
                with self.assertRaisesRegex(MODULE.LayoutProfileError, error):
                    profile(path)

        path = self.temporary_path()
        duplicate = data_member("oct_18", "clean", 1, 10_001)
        write_archive(
            path,
            extra_members=((duplicate, b"duplicate", zipfile.ZIP_DEFLATED),),
        )
        with self.assertRaisesRegex(MODULE.LayoutProfileError, "duplicate_member_name"):
            profile(path)

        path = self.temporary_path()
        target = data_member("oct_18", "clean", 1, 10_001)
        write_archive(path)
        patch_member_name(path, target, target.replace("oct_18", "oct\x0018"))
        with self.assertRaisesRegex(MODULE.LayoutProfileError, "unsafe_member_name"):
            profile(path)

    def test_unsupported_compression_and_incomplete_support_files_fail_closed(self):
        path = self.temporary_path()
        target = data_member("oct_18", "clean", 1, 10_001)
        write_archive(path, compression_overrides={target: zipfile.ZIP_BZIP2})
        with self.assertRaisesRegex(
            MODULE.LayoutProfileError, "unsupported_compression"
        ):
            profile(path)

        path = self.temporary_path()
        write_archive(path, omit={model_member("oct_19", 4)})
        with self.assertRaisesRegex(
            MODULE.LayoutProfileError, "incomplete_model_member_set"
        ):
            profile(path)

        path = self.temporary_path()
        write_archive(path, omit={"demo.py"})
        with self.assertRaisesRegex(
            MODULE.LayoutProfileError, "incomplete_demo_member_set"
        ):
            profile(path)

    def test_bounds_fail_closed(self):
        path = self.temporary_path()
        write_archive(path)
        member_count = 4 + 16 + 8 + 1
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(MODULE, "MAX_MEMBERS", member_count - 1)
            )
            stack.enter_context(
                self.assertRaisesRegex(
                    MODULE.LayoutProfileError, "archive_member_count_limit"
                )
            )
            profile(path)

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(MODULE, "MAX_MEMBER_BYTES", 8))
            stack.enter_context(
                self.assertRaisesRegex(MODULE.LayoutProfileError, "member_size_limit")
            )
            profile(path)

    def test_digest_and_size_mismatches_fail_before_layout_admission(self):
        path = self.temporary_path()
        write_archive(path)

        with self.assertRaisesRegex(
            MODULE.LayoutProfileError, "archive_digest_mismatch"
        ):
            MODULE.profile_archive(
                path,
                expected_md5="0" * 32,
                expected_bytes=path.stat().st_size,
            )
        with self.assertRaisesRegex(MODULE.LayoutProfileError, "archive_size_mismatch"):
            MODULE.profile_archive(
                path,
                expected_md5=archive_md5(path),
                expected_bytes=path.stat().st_size + 1,
            )

    def test_interpretation_scopes_are_explicit_and_json_round_trips(self):
        path = self.temporary_path()
        write_archive(path)
        report = profile(path)
        rendered = MODULE.render_report(report)
        interpretation = report["interpretation"]

        self.assertIn(
            "controlled-scenario oracles only", interpretation["spoof_label_scope"]
        )
        for claim in (
            "physical-source identity",
            "tamper",
            "actor identity",
            "malicious intent",
        ):
            self.assertIn(claim, interpretation["spoof_label_scope"])
        self.assertIn("transfer integrity only", interpretation["archive_digest_scope"])
        self.assertEqual(json.loads(rendered), report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
