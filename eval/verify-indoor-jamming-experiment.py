#!/usr/bin/env python3
"""Verify the tracked indoor-jamming result summary against its report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

import experiment_result_verifier as COMMON

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPERIMENT = (
    ROOT / "eval" / "experiments" / "0007-indoor-jamming-controlled-cause-v0.md"
)
DEFAULT_REPORT = (
    ROOT / "data" / "derived" / "eval" / "indoor-jamming-controlled-cause-report.json"
)
SUMMARY_SCHEMA = "netbraid.indoor_jamming_controlled_cause_result_summary.v0"
REPORT_SCHEMA = "netbraid.indoor_jamming_controlled_cause_eval.v0"
VerificationError = COMMON.VerificationError


def load_summary(path: Path) -> Mapping[str, Any]:
    return COMMON.load_summary(path, SUMMARY_SCHEMA)


def load_report(path: Path) -> Mapping[str, Any]:
    return COMMON.load_report(path)


def report_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    try:
        if report["schema"] != REPORT_SCHEMA:
            raise VerificationError("report_schema")
        window = report["window_policy"]
        validation = report["validation"]["metrics"]
        abstentions = report["abstentions"]["validation"]
        triplets = validation["complete_triplets"]
        return {
            "schema": SUMMARY_SCHEMA,
            "status": report["status"],
            "attempted_reads": window["attempted_reads"],
            "completed_reads": window["completed_reads"],
            "failed_reader_calls": window["failed_reader_calls"],
            "verified_selected_windows": window["verified_selected_windows"],
            "verified_completed_selected_bytes": window[
                "verified_completed_selected_bytes"
            ],
            "validation": {
                "observations": validation["observations"],
                "coverage_numerator": validation["coverage"]["numerator"],
                "coverage_denominator": validation["coverage"]["denominator"],
                "balanced_accuracy": validation["balanced_accuracy"],
                "macro_f1": validation["macro_f1"],
                "complete_triplets_succeeded": sum(
                    item["success"] is True for item in triplets
                ),
                "abstentions": abstentions["count"],
            },
            "test_evaluated": report["test_metrics"] is not None,
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
                "test_evaluated": summary["test_evaluated"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
