#!/usr/bin/env python3
"""Hermetic tests for the indoor-jamming experiment result verifier."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "verify_indoor_jamming_experiment",
    HERE / "verify-indoor-jamming-experiment.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def summary() -> dict:
    return {
        "schema": MODULE.SUMMARY_SCHEMA,
        "status": "validation_failed",
        "attempted_reads": 60,
        "completed_reads": 60,
        "failed_reader_calls": 0,
        "verified_selected_windows": 60,
        "verified_completed_selected_bytes": 62_914_560,
        "validation": {
            "observations": 6,
            "coverage_numerator": 1,
            "coverage_denominator": 6,
            "balanced_accuracy": 0.166666666667,
            "macro_f1": 0.222222222222,
            "complete_triplets_succeeded": 0,
            "abstentions": 5,
        },
        "test_evaluated": False,
    }


def report() -> dict:
    expected = summary()
    return {
        "schema": MODULE.REPORT_SCHEMA,
        "status": expected["status"],
        "window_policy": {
            "attempted_reads": expected["attempted_reads"],
            "completed_reads": expected["completed_reads"],
            "failed_reader_calls": expected["failed_reader_calls"],
            "verified_selected_windows": expected["verified_selected_windows"],
            "verified_completed_selected_bytes": expected[
                "verified_completed_selected_bytes"
            ],
        },
        "validation": {
            "metrics": {
                "observations": 6,
                "coverage": {"numerator": 1, "denominator": 6},
                "balanced_accuracy": 0.166666666667,
                "macro_f1": 0.222222222222,
                "complete_triplets": [
                    {"success": False},
                    {"success": False},
                ],
            }
        },
        "abstentions": {"validation": {"count": 5}},
        "test_metrics": None,
    }


class IndoorJammingExperimentVerifierTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.experiment = self.root / "experiment.md"
        self.report = self.root / "report.json"

    def write_inputs(self, expected: dict | None = None, actual: dict | None = None):
        self.experiment.write_text(
            "# Result\n\n```json\n"
            + json.dumps(expected or summary(), indent=2, sort_keys=True)
            + "\n```\n",
            encoding="utf-8",
        )
        self.report.write_text(
            json.dumps(actual or report(), sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def test_exact_summary_matches_report(self):
        self.write_inputs()

        self.assertEqual(MODULE.verify(self.experiment, self.report), summary())

    def test_metric_drift_fails_closed(self):
        expected = summary()
        expected["validation"]["abstentions"] = 4
        self.write_inputs(expected=expected)

        with self.assertRaisesRegex(
            MODULE.VerificationError, "result_summary_mismatch"
        ):
            MODULE.verify(self.experiment, self.report)

    def test_duplicate_summary_and_duplicate_json_key_fail_closed(self):
        self.write_inputs()
        block = self.experiment.read_text(encoding="utf-8").split("# Result\n\n", 1)[1]
        self.experiment.write_text(f"# Result\n\n{block}\n{block}", encoding="utf-8")
        with self.assertRaisesRegex(MODULE.VerificationError, "result_summary_count"):
            MODULE.load_summary(self.experiment)

        self.experiment.write_text(
            '```json\n{"schema":"'
            + MODULE.SUMMARY_SCHEMA
            + '","schema":"duplicate"}\n```\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MODULE.VerificationError, "invalid_result_summary"):
            MODULE.load_summary(self.experiment)


if __name__ == "__main__":
    unittest.main()
