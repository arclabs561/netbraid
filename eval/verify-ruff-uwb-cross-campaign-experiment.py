#!/usr/bin/env python3
"""Verify the tracked RUFF-UWB transfer summary against its ignored report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import experiment_result_verifier as COMMON

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPERIMENT = (
    ROOT / "eval" / "experiments" / "0018-ruff-uwb-cross-campaign-transfer-v0.md"
)
DEFAULT_REPORT = (
    ROOT / "data" / "derived" / "eval" / "ruff-uwb-cross-distance-report.json"
)
SUMMARY_SCHEMA = "netbraid.ruff_uwb_cross_campaign_result_summary.v0"
REPORT_SCHEMA = "netbraid.ruff_uwb_cross_distance_eval.v0"
VerificationError = COMMON.VerificationError


def _role_summary(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "locations": value["location_count"],
        "atomic_groups": value["atomic_group_count"],
        "source_rows": value["source_row_count"],
        "sampled_rows": value["sampled_row_count"],
        "feature_rows": value["feature_row_count"],
    }


def report_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    try:
        if report["schema"] != REPORT_SCHEMA:
            raise VerificationError("report_schema")
        roles = report["role_receipts"]
        selection = report["validation_selection"]
        metrics = report["target_metrics"]
        leakage = report["leakage_checks"]
        return {
            "schema": SUMMARY_SCHEMA,
            "status": report["status"],
            "selected_prototype_mode": report["configuration"][
                "selected_prototype_mode"
            ],
            "roles": {
                role: _role_summary(roles[role])
                for role in (
                    "source_train",
                    "source_validation",
                    "source_test_unused",
                    "target_test",
                )
            },
            "validation_candidates": selection["candidate_metrics"],
            "target_metrics": {
                "balanced_accuracy": metrics["balanced_accuracy"],
                "macro_f1": metrics["macro_f1"],
                "uniform_chance_balanced_accuracy": metrics[
                    "uniform_chance_balanced_accuracy"
                ],
                "evaluated_rows": metrics["evaluated_rows"],
                "per_device_recall": metrics["per_device_recall"],
            },
            "leakage_checks": {
                field: leakage[field]
                for field in (
                    "source_test_feature_rows",
                    "target_configuration_candidates",
                    "source_train_validation_row_overlap",
                    "source_test_target_row_overlap",
                    "all_checks_passed",
                )
            },
            "privacy": report["privacy"],
        }
    except (KeyError, TypeError, VerificationError) as error:
        if isinstance(error, VerificationError):
            raise
        raise VerificationError("report_schema") from error


def verify(experiment_path: Path, report_path: Path) -> dict[str, Any]:
    return COMMON.verify(experiment_path, report_path, SUMMARY_SCHEMA, report_summary)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment", type=Path, default=DEFAULT_EXPERIMENT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        summary = verify(arguments.experiment, arguments.report)
    except VerificationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "schema": summary["schema"],
                "status": "verified",
                "target_evaluated_rows": summary["target_metrics"]["evaluated_rows"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
