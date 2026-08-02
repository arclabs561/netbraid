#!/usr/bin/env python3
"""Hermetic tests for the bounded CAEZ alignment profiler."""

import importlib.util
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "profile_caez_alignment", HERE / "profile-caez-alignment.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def add_member(archive, name, data):
    member = tarfile.TarInfo(name)
    member.size = len(data)
    archive.addfile(member, io.BytesIO(data))


def metadata(timestamp, psdu_hash):
    return json.dumps(
        {"timestamp": timestamp, "psdu_hash": psdu_hash, "psdu_length": 42}
    ).encode()


class CaezAlignmentTests(unittest.TestCase):
    def build_archive(self, position_rows, duplicate_hash=False):
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name) / "fixture.tar"
        positions = position_rows.encode()
        with tarfile.open(path, "w") as archive:
            add_member(
                archive,
                f"{MODULE.BASE.ROOT_MEMBER}/gt-positions.csv",
                positions,
            )
            add_member(
                archive,
                f"{MODULE.BASE.ROOT_MEMBER}/ap1/take1/frame0_metadata.json",
                metadata("10.25", "a" * 64),
            )
            add_member(
                archive,
                f"{MODULE.BASE.ROOT_MEMBER}/ap2/take1/frame0_metadata.json",
                metadata("11", ("a" if duplicate_hash else "b") * 64),
            )
        return temporary, path, positions

    def test_profiles_candidate_axis_without_inventing_semantics(self):
        temporary, path, positions = self.build_archive(
            "10,1,2,3\n10.25,2,3,4\n11,3,4,5\n"
        )
        self.addCleanup(temporary.cleanup)
        report = MODULE.profile_alignment(
            path,
            stems=("ap1/take1/frame0", "ap2/take1/frame0"),
            expected_ground_truth_bytes=len(positions),
        )
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["position_candidate_axis"]["rows"], 3)
        self.assertEqual(
            report["position_candidate_axis"]["exact_candidate_axis_matches"], 2
        )
        self.assertEqual(report["frame_metadata_sample"]["distinct_psdu_hashes"], 2)
        self.assertEqual(report["limits"]["position_rows_retained"], 0)
        self.assertIn("timestamp_unit_or_clock_domain", report["not_established"])

    def test_rejects_malformed_position_rows(self):
        temporary, path, positions = self.build_archive("10,1,2\n")
        self.addCleanup(temporary.cleanup)
        with self.assertRaisesRegex(RuntimeError, "four columns"):
            MODULE.profile_alignment(
                path,
                stems=("ap1/take1/frame0", "ap2/take1/frame0"),
                expected_ground_truth_bytes=len(positions),
            )

    def test_reports_hash_uniqueness_without_retaining_hashes(self):
        temporary, path, positions = self.build_archive(
            "10.25,1,2,3\n11,2,3,4\n", duplicate_hash=True
        )
        self.addCleanup(temporary.cleanup)
        report = MODULE.profile_alignment(
            path,
            stems=("ap1/take1/frame0", "ap2/take1/frame0"),
            expected_ground_truth_bytes=len(positions),
        )
        self.assertEqual(report["frame_metadata_sample"]["distinct_psdu_hashes"], 1)
        rendered = json.dumps(report)
        self.assertNotIn("a" * 64, rendered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
