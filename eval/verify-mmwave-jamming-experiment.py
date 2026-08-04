#!/usr/bin/env python3
"""Verify the tracked mmWave result summary against its ignored report."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import experiment_result_verifier as COMMON

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPERIMENT = (
    ROOT / "eval/experiments/0028-mmwave-jamming-receiver-crossfit-v0.md"
)
DEFAULT_REPORT = ROOT / "data/derived/eval/mmwave-jamming-receiver-crossfit-report.json"
SUMMARY_SCHEMA = "netbraid.mmwave_jamming_receiver_crossfit_result_summary.v0"
REPORT_SCHEMA = "netbraid.mmwave_jamming_receiver_crossfit_eval.v0"
VerificationError = COMMON.VerificationError


def report_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    try:
        if report["schema"] != REPORT_SCHEMA:
            raise VerificationError("report_schema")
        heldout = report["heldout_metrics"]
        paired = report["paired_ranking"]
        folds = report["per_fold_metrics_without_group_identifiers"]
        if not isinstance(folds, list) or len(folds) != 4:
            raise VerificationError("report_schema")
        return {
            "schema": SUMMARY_SCHEMA,
            "status": report["status"],
            "heldout_balanced_accuracy": heldout["balanced_accuracy"],
            "heldout_macro_f1": heldout["macro_f1"],
            "fold_balanced_accuracies": sorted(
                item["balanced_accuracy"] for item in folds
            ),
            "paired_ranking": {
                "both_members_correct_pairs": paired["both_members_correct_pairs"],
                "losses": paired["losses"],
                "one_sided_exact_p_value": paired["one_sided_exact_p_value"],
                "ties": paired["ties"],
                "wins": paired["wins"],
            },
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
            {"schema": summary["schema"], "status": "verified"},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
