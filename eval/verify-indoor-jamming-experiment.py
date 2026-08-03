#!/usr/bin/env python3
"""Verify the tracked indoor-jamming result summary against its report."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPERIMENT = (
    ROOT / "eval" / "experiments" / "0007-indoor-jamming-controlled-cause-v0.md"
)
DEFAULT_REPORT = (
    ROOT / "data" / "derived" / "eval" / "indoor-jamming-controlled-cause-report.json"
)
SUMMARY_SCHEMA = "netbraid.indoor_jamming_controlled_cause_result_summary.v0"
REPORT_SCHEMA = "netbraid.indoor_jamming_controlled_cause_eval.v0"
MAX_EXPERIMENT_BYTES = 256 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
JSON_BLOCK = re.compile(r"```json\n(?P<payload>.*?)\n```", re.DOTALL)


class VerificationError(ValueError):
    """Stable, path-free result-summary verification failure."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("duplicate_json_key")
        result[key] = value
    return result


def _read_text(path: Path, limit: int, error_code: str) -> str:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            raise VerificationError(error_code)
        payload = path.read_bytes()
    except OSError as error:
        raise VerificationError(error_code) from error
    if len(payload) > limit:
        raise VerificationError(error_code)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(error_code) from error


def _load_json_text(payload: str, error_code: str) -> Mapping[str, Any]:
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, VerificationError) as error:
        raise VerificationError(error_code) from error
    if not isinstance(value, Mapping):
        raise VerificationError(error_code)
    return value


def load_summary(path: Path) -> Mapping[str, Any]:
    document = _read_text(path, MAX_EXPERIMENT_BYTES, "experiment_unavailable")
    matches: list[Mapping[str, Any]] = []
    for match in JSON_BLOCK.finditer(document):
        value = _load_json_text(match.group("payload"), "invalid_result_summary")
        if value.get("schema") == SUMMARY_SCHEMA:
            matches.append(value)
    if len(matches) != 1:
        raise VerificationError("result_summary_count")
    return matches[0]


def load_report(path: Path) -> Mapping[str, Any]:
    return _load_json_text(
        _read_text(path, MAX_REPORT_BYTES, "report_unavailable"),
        "invalid_report",
    )


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
    expected = load_summary(experiment_path)
    actual = report_summary(load_report(report_path))
    if expected != actual:
        raise VerificationError("result_summary_mismatch")
    return actual


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
