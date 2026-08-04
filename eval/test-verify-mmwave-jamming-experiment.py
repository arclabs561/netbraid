#!/usr/bin/env python3
"""Hermetic tests for the mmWave experiment result verifier."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "verify_mmwave_jamming_experiment",
    HERE / "verify-mmwave-jamming-experiment.py",
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("verifier_import_failed")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def summary() -> dict[str, object]:
    return {
        "schema": MODULE.SUMMARY_SCHEMA,
        "status": "inference_blocked",
        "heldout_balanced_accuracy": 0.625,
        "heldout_macro_f1": 0.624765478424,
        "fold_balanced_accuracies": [0.5, 0.65, 0.65, 0.7],
        "paired_ranking": {
            "both_members_correct_pairs": 10,
            "losses": 12,
            "nominal_one_sided_exact_p_value": 0.008294501687,
            "ties": 0,
            "wins": 28,
        },
    }


def report() -> dict[str, object]:
    value = summary()
    return {
        "schema": MODULE.REPORT_SCHEMA,
        "status": value["status"],
        "heldout_metrics": {
            "balanced_accuracy": value["heldout_balanced_accuracy"],
            "macro_f1": value["heldout_macro_f1"],
        },
        "paired_ranking": value["paired_ranking"],
        "per_fold_metrics_without_group_identifiers": [
            {"balanced_accuracy": score}
            for score in reversed(value["fold_balanced_accuracies"])
        ],
    }


class MmwaveExperimentVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.experiment = self.root / "experiment.md"
        self.report = self.root / "report.json"

    def write_inputs(
        self,
        expected: dict[str, object] | None = None,
        actual: dict[str, object] | None = None,
    ) -> None:
        self.experiment.write_text(
            "# Result\n\n```json\n"
            + json.dumps(expected or summary(), indent=2, sort_keys=True)
            + "\n```\n"
        )
        self.report.write_text(json.dumps(actual or report()) + "\n")

    def test_exact_summary_matches_report(self) -> None:
        self.write_inputs()
        self.assertEqual(MODULE.verify(self.experiment, self.report), summary())

    def test_metric_drift_fails_closed(self) -> None:
        expected = summary()
        expected["paired_ranking"]["wins"] = 29
        self.write_inputs(expected=expected)
        with self.assertRaisesRegex(
            MODULE.VerificationError, "result_summary_mismatch"
        ):
            MODULE.verify(self.experiment, self.report)

    def test_schema_and_fold_count_fail_closed(self) -> None:
        actual = report()
        actual["schema"] = "wrong"
        with self.assertRaisesRegex(MODULE.VerificationError, "report_schema"):
            MODULE.report_summary(actual)

        actual = report()
        actual["per_fold_metrics_without_group_identifiers"] = []
        with self.assertRaisesRegex(MODULE.VerificationError, "report_schema"):
            MODULE.report_summary(actual)


if __name__ == "__main__":
    unittest.main()
