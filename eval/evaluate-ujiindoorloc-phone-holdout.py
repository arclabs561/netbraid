#!/usr/bin/env python3
"""Evaluate a deterministic phone-disjoint UJIIndoorLoc centroid baseline."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import ujiindoorloc as uji

SCHEMA = "netbraid.ujiindoorloc_phone_holdout_baseline.v0"
DEFAULT_REPORT = (
    uji.ROOT
    / "data"
    / "derived"
    / "eval"
    / "ujiindoorloc-phone-holdout-baseline-v0.json"
)
MISSING_RSSI_DBM = -105.0
MIN_CALIBRATION_COVERAGE = Fraction(4, 5)
MIN_VALIDATION_COVERAGE = Fraction(4, 5)
MAX_VALIDATION_SELECTIVE_ERROR = Fraction(1, 2)
MIN_VALIDATION_MACRO_RECALL = Fraction(1, 5)
TARGET_CLASSES = tuple(
    (building, floor)
    for building, floor_count in ((0, 4), (1, 4), (2, 5))
    for floor in range(floor_count)
)


class BaselineError(RuntimeError):
    """Stable fail-closed protocol error."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Fit:
    feature_indices: tuple[int, ...]
    means: tuple[float, ...]
    scales: tuple[float, ...]
    centroids: Mapping[tuple[int, int], tuple[float, ...]]
    train_rows: int
    observed_feature_count: int


@dataclass(frozen=True)
class Prediction:
    target: tuple[int, int] | None
    margin: float


def _rounded(value: float) -> float:
    return round(value, 12)


def _encoded(row: uji.ModelRow, feature_indices: Sequence[int]) -> tuple[float, ...]:
    if len(row.rssi) != len(uji.WAP_FIELDS):
        raise BaselineError("invalid_rssi_width")
    return tuple(
        MISSING_RSSI_DBM if row.rssi[index] is None else float(row.rssi[index])
        for index in feature_indices
    )


def fit_centroids(rows: Sequence[uji.ModelRow]) -> Fit:
    if not rows:
        raise BaselineError("empty_training_role")
    unknown = {row.target for row in rows} - set(TARGET_CLASSES)
    if unknown:
        raise BaselineError("unexpected_target_class")
    if {row.target for row in rows} != set(TARGET_CLASSES):
        raise BaselineError("incomplete_training_class_coverage")
    if any(len(row.rssi) != len(uji.WAP_FIELDS) for row in rows):
        raise BaselineError("invalid_rssi_width")

    observed = tuple(
        index
        for index in range(len(uji.WAP_FIELDS))
        if any(row.rssi[index] is not None for row in rows)
    )
    if not observed:
        raise BaselineError("no_observed_training_features")
    encoded = tuple(_encoded(row, observed) for row in rows)
    means = tuple(math.fsum(sorted(values)) / len(values) for values in zip(*encoded))
    scales = tuple(
        math.sqrt(
            math.fsum(sorted((value - mean) ** 2 for value in values)) / len(values)
        )
        for values, mean in zip(zip(*encoded), means)
    )
    retained_positions = tuple(index for index, scale in enumerate(scales) if scale > 0)
    if not retained_positions:
        raise BaselineError("no_variable_training_features")
    feature_indices = tuple(observed[index] for index in retained_positions)
    retained_means = tuple(means[index] for index in retained_positions)
    retained_scales = tuple(scales[index] for index in retained_positions)

    by_class: dict[tuple[int, int], list[tuple[float, ...]]] = defaultdict(list)
    for row in rows:
        values = _encoded(row, feature_indices)
        by_class[row.target].append(
            tuple(
                (value - mean) / scale
                for value, mean, scale in zip(values, retained_means, retained_scales)
            )
        )
    centroids = {
        target: tuple(
            math.fsum(sorted(values)) / len(values) for values in zip(*by_class[target])
        )
        for target in TARGET_CLASSES
    }
    return Fit(
        feature_indices,
        retained_means,
        retained_scales,
        centroids,
        len(rows),
        len(observed),
    )


def predict_unthresholded(row: uji.ModelRow, fit: Fit) -> Prediction:
    values = _encoded(row, fit.feature_indices)
    standardized = tuple(
        (value - mean) / scale
        for value, mean, scale in zip(values, fit.means, fit.scales)
    )
    distances = sorted(
        (
            math.fsum(
                (value - centroid_value) ** 2
                for value, centroid_value in zip(standardized, centroid)
            )
            / len(standardized),
            target,
        )
        for target, centroid in fit.centroids.items()
    )
    nearest, second = distances[0], distances[1]
    margin = max(0.0, second[0] - nearest[0])
    if nearest[0] == second[0]:
        return Prediction(None, margin)
    return Prediction(nearest[1], margin)


def apply_threshold(prediction: Prediction, threshold: float) -> tuple[int, int] | None:
    if prediction.target is None or prediction.margin < threshold:
        return None
    return prediction.target


def select_threshold(
    rows: Sequence[uji.ModelRow], predictions: Sequence[Prediction]
) -> tuple[float, dict[str, Any]]:
    if len(rows) != len(predictions) or not rows:
        raise BaselineError("invalid_calibration_rows")
    candidates = sorted({0.0, *(prediction.margin for prediction in predictions)})
    eligible = []
    for threshold in candidates:
        decided = [
            (row, apply_threshold(prediction, threshold))
            for row, prediction in zip(rows, predictions)
            if apply_threshold(prediction, threshold) is not None
        ]
        if len(decided) * MIN_CALIBRATION_COVERAGE.denominator < (
            len(rows) * MIN_CALIBRATION_COVERAGE.numerator
        ):
            continue
        errors = sum(row.target != target for row, target in decided)
        eligible.append((Fraction(errors, len(decided)), -len(decided), threshold))
    if not eligible:
        raise BaselineError("calibration_coverage_below_minimum")
    _, _, threshold = min(eligible)
    decided = sum(
        apply_threshold(prediction, threshold) is not None for prediction in predictions
    )
    errors = sum(
        target is not None and row.target != target
        for row, prediction in zip(rows, predictions)
        for target in (apply_threshold(prediction, threshold),)
    )
    return threshold, {
        "candidate_count": len(candidates),
        "minimum_coverage": {
            "numerator": MIN_CALIBRATION_COVERAGE.numerator,
            "denominator": MIN_CALIBRATION_COVERAGE.denominator,
        },
        "selected_threshold": _rounded(threshold),
        "selected_decided_rows": decided,
        "selected_error_rows": errors,
    }


def _fraction(numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": None if denominator == 0 else _rounded(numerator / denominator),
    }


def _metric_core(
    rows: Sequence[uji.ModelRow], predictions: Sequence[tuple[int, int] | None]
) -> dict[str, Any]:
    if len(rows) != len(predictions) or not rows:
        raise BaselineError("invalid_metric_rows")
    class_reports = []
    recalls = []
    f1s = []
    for target in TARGET_CLASSES:
        support = sum(row.target == target for row in rows)
        true_positive = sum(
            row.target == target and prediction == target
            for row, prediction in zip(rows, predictions)
        )
        false_positive = sum(
            row.target != target and prediction == target
            for row, prediction in zip(rows, predictions)
        )
        predicted = true_positive + false_positive
        decided = sum(
            row.target == target and prediction is not None
            for row, prediction in zip(rows, predictions)
        )
        incorrect = decided - true_positive
        abstained = support - decided
        recall = true_positive / support if support else 0.0
        denominator = 2 * true_positive + false_positive + support - true_positive
        f1 = 2 * true_positive / denominator if denominator else 0.0
        recalls.append(recall)
        f1s.append(f1)
        class_reports.append(
            {
                "building": target[0],
                "floor": target[1],
                "support": support,
                "decided": decided,
                "correct": true_positive,
                "incorrect": incorrect,
                "abstained": abstained,
                "predicted": predicted,
                "false_positive": false_positive,
                "recall": _rounded(recall),
                "f1": _rounded(f1),
            }
        )
    decided_total = sum(prediction is not None for prediction in predictions)
    correct = sum(
        row.target == prediction for row, prediction in zip(rows, predictions)
    )
    errors = decided_total - correct
    abstained = len(rows) - decided_total
    return {
        "rows": len(rows),
        "outcomes": {
            "correct": correct,
            "incorrect": errors,
            "abstained": abstained,
            "reconciled_total": correct + errors + abstained,
        },
        "coverage": _fraction(decided_total, len(rows)),
        "selective_error": _fraction(errors, decided_total),
        "macro_recall": _rounded(math.fsum(recalls) / len(TARGET_CLASSES)),
        "macro_f1": _rounded(math.fsum(f1s) / len(TARGET_CLASSES)),
        "per_class": class_reports,
    }


def metric_report(
    rows: Sequence[uji.ModelRow], predictions: Sequence[tuple[int, int] | None]
) -> dict[str, Any]:
    report = _metric_core(rows, predictions)
    grouped: dict[int, list[tuple[uji.ModelRow, tuple[int, int] | None]]] = defaultdict(
        list
    )
    for row, prediction in zip(rows, predictions):
        grouped[row.phone].append((row, prediction))
    anonymous = []
    for pairs in grouped.values():
        phone_rows, phone_predictions = zip(*pairs)
        summary = _metric_core(phone_rows, phone_predictions)
        summary.pop("per_class")
        anonymous.append(summary)
    report["per_phone"] = sorted(
        anonymous,
        key=lambda item: json.dumps(item, allow_nan=False, sort_keys=True),
    )
    return report


def validation_gate(metrics: Mapping[str, Any]) -> dict[str, Any]:
    coverage = metrics["coverage"]
    selective = metrics["selective_error"]
    coverage_passed = coverage["numerator"] * MIN_VALIDATION_COVERAGE.denominator >= (
        coverage["denominator"] * MIN_VALIDATION_COVERAGE.numerator
    )
    selective_passed = selective["denominator"] > 0 and (
        selective["numerator"] * MAX_VALIDATION_SELECTIVE_ERROR.denominator
        <= selective["denominator"] * MAX_VALIDATION_SELECTIVE_ERROR.numerator
    )
    class_support_passed = all(item["support"] > 0 for item in metrics["per_class"])
    macro_recall = sum(
        Fraction(item["correct"], item["support"])
        for item in metrics["per_class"]
        if item["support"] > 0
    ) / len(TARGET_CLASSES)
    macro_passed = class_support_passed and macro_recall >= MIN_VALIDATION_MACRO_RECALL
    return {
        "coverage_at_least": 0.8,
        "coverage_passed": coverage_passed,
        "selective_error_at_most": 0.5,
        "selective_error_passed": selective_passed,
        "macro_recall_at_least": _rounded(float(MIN_VALIDATION_MACRO_RECALL)),
        "macro_recall_passed": macro_passed,
        "complete_class_support_passed": class_support_passed,
        "passed": coverage_passed
        and selective_passed
        and macro_passed
        and class_support_passed,
    }


RoleReader = Callable[[str], Sequence[uji.ModelRow]]


def evaluate_protocol(
    role_reader: RoleReader,
    *,
    integrity: tuple[int, str, str],
    publisher_rows: Mapping[str, int],
    role_rows: Mapping[str, int],
    role_phones: Mapping[str, int],
    role_targets: Mapping[str, int],
) -> dict[str, Any]:
    read_counts = {role: 0 for role in uji.ROLES}

    def read(role: str) -> tuple[uji.ModelRow, ...]:
        rows = tuple(role_reader(role))
        read_counts[role] += len(rows)
        if len(rows) != role_rows[role]:
            raise BaselineError("role_read_reconciliation_failed")
        return rows

    train = read("train")
    fit = fit_centroids(train)
    calibration = read("calibration")
    calibration_raw = tuple(predict_unthresholded(row, fit) for row in calibration)
    threshold, selection = select_threshold(calibration, calibration_raw)
    calibration_predictions = tuple(
        apply_threshold(prediction, threshold) for prediction in calibration_raw
    )
    validation = read("validation")
    validation_predictions = tuple(
        apply_threshold(predict_unthresholded(row, fit), threshold)
        for row in validation
    )
    calibration_metrics = metric_report(calibration, calibration_predictions)
    validation_metrics = metric_report(validation, validation_predictions)
    gate = validation_gate(validation_metrics)
    test_metrics = None
    if gate["passed"]:
        test = read("test")
        test_predictions = tuple(
            apply_threshold(predict_unthresholded(row, fit), threshold) for row in test
        )
        test_metrics = metric_report(test, test_predictions)

    raw_total = sum(publisher_rows.values())
    assigned_total = sum(role_rows.values())
    if raw_total != assigned_total:
        raise BaselineError("raw_role_reconciliation_failed")
    return {
        "schema": SCHEMA,
        "status": "pass" if gate["passed"] else "validation_gate_failed",
        "integrity": {
            "bytes": integrity[0],
            "md5": integrity[1],
            "sha256": integrity[2],
        },
        "target": {
            "kind": "building_floor",
            "class_count": len(TARGET_CLASSES),
        },
        "split": {
            "unit": "phone",
            "roles": list(uji.ROLES),
            "disjoint_unit_overlap_count": 0,
            "role_row_counts": dict(role_rows),
            "role_phone_counts": dict(role_phones),
            "role_target_counts": dict(role_targets),
        },
        "reconciliation": {
            "publisher_row_counts": dict(publisher_rows),
            "raw_row_total": raw_total,
            "assigned_row_total": assigned_total,
            "all_raw_rows_assigned_once": raw_total == assigned_total,
            "model_row_read_counts": read_counts,
        },
        "fit": {
            "train_rows": fit.train_rows,
            "input_rssi_columns": len(uji.WAP_FIELDS),
            "train_observed_feature_count": fit.observed_feature_count,
            "retained_variable_feature_count": len(fit.feature_indices),
            "class_centroid_count": len(fit.centroids),
            "missing_rssi_encoding_dbm": int(MISSING_RSSI_DBM),
            "feature_fit_split": "train",
            "centroid_fit_split": "train",
        },
        "calibration": {
            "threshold_fit_split": "calibration",
            "selection": selection,
            "metrics": calibration_metrics,
        },
        "validation": {"metrics": validation_metrics, "gate": gate},
        "test": {
            "read": read_counts["test"] > 0,
            "evaluated": test_metrics is not None,
            "metrics": test_metrics,
        },
        "privacy": {
            "phone_values_retained": 0,
            "user_values_retained": 0,
            "rows_retained": 0,
            "rssi_fingerprints_retained": 0,
            "coordinate_values_retained": 0,
            "timestamp_values_retained": 0,
            "member_paths_retained": 0,
            "local_paths_retained": 0,
        },
    }


def evaluate_archive(
    archive_path: Path,
    receipt_path: Path,
    contract: uji.ArtifactContract = uji.DEFAULT_CONTRACT,
) -> dict[str, Any]:
    scan = uji.scan_archive(archive_path, receipt_path, contract)
    plan = uji.build_phone_role_plan(scan)

    def reader(role: str) -> Sequence[uji.ModelRow]:
        return uji.read_roles(archive_path, receipt_path, plan, (role,), contract)[role]

    return evaluate_protocol(
        reader,
        integrity=scan.integrity,
        publisher_rows=scan.publisher_rows,
        role_rows=plan.row_counts,
        role_phones=plan.phone_counts,
        role_targets=plan.target_counts,
    )


def render_report(report: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                report, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise BaselineError("report_not_json_serializable") from error


def write_report(path: Path, payload: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    except OSError as error:
        raise BaselineError("report_io_error") from error


def reject_output_aliases(archive: Path, receipt: Path, report: Path) -> None:
    try:
        inputs = {archive.resolve(strict=False), receipt.resolve(strict=False)}
        report_resolved = report.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise BaselineError("unsafe_input_or_report_path") from error
    if report_resolved in inputs:
        raise BaselineError("report_aliases_input")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=uji.DEFAULT_ARCHIVE)
    parser.add_argument("--receipt", type=Path, default=uji.DEFAULT_RECEIPT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        reject_output_aliases(arguments.archive, arguments.receipt, arguments.report)
        report = evaluate_archive(
            arguments.archive.expanduser().absolute(),
            arguments.receipt.expanduser().absolute(),
        )
        payload = render_report(report)
        write_report(arguments.report.expanduser().absolute(), payload)
    except (BaselineError, uji.UjiIndoorLocError) as error:
        print(error.code, file=sys.stderr)
        return 2
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
