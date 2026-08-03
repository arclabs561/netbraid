#!/usr/bin/env python3
"""Hermetic checks for the RUFF-UWB transfer result verifier."""

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
    "verify_ruff_uwb_cross_campaign_experiment",
    HERE / "verify-ruff-uwb-cross-campaign-experiment.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def summary() -> dict:
    role = {
        "locations": 10,
        "atomic_groups": 20,
        "source_rows": 200,
        "sampled_rows": 20,
        "feature_rows": 20,
    }
    unused = {**role, "sampled_rows": 0, "feature_rows": 0}
    return {
        "schema": MODULE.SUMMARY_SCHEMA,
        "status": "pass",
        "selected_prototype_mode": "centroid",
        "roles": {
            "source_train": role,
            "source_validation": role,
            "source_test_unused": unused,
            "target_test": role,
        },
        "validation_candidates": {
            "centroid": {
                "balanced_accuracy": 0.75,
                "evaluated_rows": 20,
                "macro_f1": 0.7,
            }
        },
        "target_metrics": {
            "balanced_accuracy": 0.25,
            "macro_f1": 0.2,
            "uniform_chance_balanced_accuracy": 0.125,
            "evaluated_rows": 20,
            "per_device_recall": {"device-001": 0.5, "device-002": 0.0},
        },
        "leakage_checks": {
            "source_test_feature_rows": 0,
            "target_configuration_candidates": 0,
            "source_train_validation_row_overlap": 0,
            "source_test_target_row_overlap": 0,
            "all_checks_passed": True,
        },
        "privacy": {
            "corpus_rows_retained": 0,
            "input_paths_retained": 0,
            "raw_source_identifiers_retained": 0,
        },
    }


def report() -> dict:
    expected = summary()
    roles = {
        name: {
            "location_count": value["locations"],
            "atomic_group_count": value["atomic_groups"],
            "source_row_count": value["source_rows"],
            "sampled_row_count": value["sampled_rows"],
            "feature_row_count": value["feature_rows"],
        }
        for name, value in expected["roles"].items()
    }
    return {
        "schema": MODULE.REPORT_SCHEMA,
        "status": expected["status"],
        "configuration": {
            "selected_prototype_mode": expected["selected_prototype_mode"]
        },
        "role_receipts": roles,
        "validation_selection": {
            "candidate_metrics": expected["validation_candidates"]
        },
        "target_metrics": expected["target_metrics"],
        "leakage_checks": expected["leakage_checks"],
        "privacy": expected["privacy"],
    }


class RuffUwbExperimentVerifierTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.experiment = root / "experiment.md"
        self.report = root / "report.json"

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
        expected["target_metrics"]["balanced_accuracy"] = 0.5
        self.write_inputs(expected=expected)

        with self.assertRaisesRegex(
            MODULE.VerificationError, "result_summary_mismatch"
        ):
            MODULE.verify(self.experiment, self.report)

    def test_missing_report_boundary_fails_closed(self):
        self.write_inputs()
        actual = report()
        del actual["leakage_checks"]["source_test_feature_rows"]
        self.report.write_text(json.dumps(actual), encoding="utf-8")

        with self.assertRaisesRegex(MODULE.VerificationError, "report_schema"):
            MODULE.verify(self.experiment, self.report)


if __name__ == "__main__":
    unittest.main()
