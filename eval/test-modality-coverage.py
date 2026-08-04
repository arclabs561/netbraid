#!/usr/bin/env python3
"""Hermetic tests for the eval-facing modality registry."""

from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "eval" / "audit-modality-coverage.py"
SPEC = importlib.util.spec_from_file_location("modality_coverage", SCRIPT)
assert SPEC and SPEC.loader
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


class ModalityCoverageTests(unittest.TestCase):
    def test_registry_separates_technology_representation_and_level(self):
        surfaces, _ = AUDIT.validate_registry()
        by_id = {surface["id"]: surface for surface in surfaces}

        self.assertEqual(by_id["bluetooth-le-packet"]["readiness"], "evaluated")
        self.assertEqual(
            by_id["sub-ghz-technology-recognition"]["technologies"],
            ["ieee80211ah", "ieee802154g", "lora", "sigfox"],
        )
        self.assertEqual(
            by_id["sub-ghz-technology-recognition"]["readiness"], "candidate"
        )
        self.assertEqual(by_id["xrf55-event-fusion"]["scope"], "multimodal_fusion")

    def test_report_is_aggregate_deterministic_and_names_admission_gaps(self):
        first = AUDIT.canonical_json(AUDIT.build_report())
        second = AUDIT.canonical_json(AUDIT.build_report())
        report = json.loads(first)

        self.assertEqual(first, second)
        self.assertEqual(report["surfaces"], 11)
        self.assertEqual(report["readiness"]["candidate"], 2)
        self.assertIn("ieee80211ah", report["technologies"])
        self.assertIn("signal_iq", report["representations"])
        self.assertEqual(report["fusion_surfaces"], ["xrf55-event-fusion"])

    def test_duplicate_keys_and_unbound_candidate_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            duplicate = directory / "duplicate.json"
            duplicate.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
            with self.assertRaisesRegex(AUDIT.CoverageError, "duplicate_json_key"):
                AUDIT.read_json(duplicate)

            document = json.loads(AUDIT.DEFAULT_REGISTRY.read_text(encoding="utf-8"))
            candidate = next(
                surface
                for surface in document["surfaces"]
                if surface["readiness"] == "candidate"
            )
            candidate["source_lead"] = None
            invalid = directory / "invalid.json"
            invalid.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(AUDIT.CoverageError, "candidate_boundary"):
                AUDIT.validate_registry(invalid)

    def test_report_write_is_private(self):
        with tempfile.TemporaryDirectory() as directory_name:
            report_path = Path(directory_name) / "report.json"
            payload = AUDIT.canonical_json(AUDIT.build_report())

            AUDIT.write_private(report_path, payload)

            self.assertEqual(report_path.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
