#!/usr/bin/env python3
"""Deterministic aggregate metrics for qualified hypothesis-frame relations.

The input contract contains only opaque frame identifiers, relation labels, and
bounded opaque stratum labels. It cannot carry observations, paths, addresses,
device identifiers, scores, intent, or tamper conclusions.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Optional, TextIO, Tuple

from hypothesis_frame import FRAME_ID_PATTERN, MAX_FRAMES, RELATION_STATES

SCHEMA = "netbraid.hypothesis_metrics_manifest.v1"
REPORT_SCHEMA = "netbraid.hypothesis_metrics_report.v1"
ABSTAIN = "abstain"
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_STRATA_PER_ROW = 8
MAX_STRATUM_DIMENSIONS = 8
MAX_STRATUM_VALUES_PER_DIMENSION = 32
MAX_STRATUM_CELLS = 128
STRATUM_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
OPAQUE_STRATUM_VALUE_PATTERN = re.compile(r"[a-f0-9]{16,64}\Z")

RELATION_AXES = tuple(sorted(RELATION_STATES))
ROW_FIELDS = ("frame_id", "references", "predictions", "strata")


class HypothesisMetricsError(ValueError):
    """Stable fail-closed reason for an invalid metrics manifest."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class EvaluationRowV1:
    frame_id: str
    references: Tuple[Tuple[str, str], ...]
    predictions: Tuple[Tuple[str, str], ...]
    strata: Tuple[Tuple[str, str], ...]

    def reference(self, axis: str) -> str:
        return dict(self.references)[axis]

    def prediction(self, axis: str) -> str:
        return dict(self.predictions)[axis]


def _expect_fields(value: Mapping[str, Any], fields: Sequence[str], code: str) -> None:
    if set(value) != set(fields):
        raise HypothesisMetricsError(code)


def _parse_axis_labels(value: Any, *, predictions: bool) -> Tuple[Tuple[str, str], ...]:
    code = "invalid_predictions_schema" if predictions else "invalid_references_schema"
    if not isinstance(value, Mapping):
        raise HypothesisMetricsError(code)
    _expect_fields(value, RELATION_AXES, code)

    parsed = []
    for axis in RELATION_AXES:
        label = value[axis]
        allowed = RELATION_STATES[axis]
        if predictions:
            allowed = frozenset((allowed - {"unknown"}) | {ABSTAIN})
        if not isinstance(label, str) or label not in allowed:
            kind = "prediction" if predictions else "reference"
            raise HypothesisMetricsError(f"invalid_{axis}_{kind}")
        parsed.append((axis, label))
    return tuple(parsed)


def _parse_strata(value: Any) -> Tuple[Tuple[str, str], ...]:
    if not isinstance(value, Mapping) or len(value) > MAX_STRATA_PER_ROW:
        raise HypothesisMetricsError("invalid_strata_schema")
    parsed = []
    for name, label in value.items():
        if not isinstance(name, str) or STRATUM_NAME_PATTERN.fullmatch(name) is None:
            raise HypothesisMetricsError("invalid_stratum_name")
        if (
            not isinstance(label, str)
            or OPAQUE_STRATUM_VALUE_PATTERN.fullmatch(label) is None
        ):
            raise HypothesisMetricsError("invalid_stratum_value")
        parsed.append((name, label))
    return tuple(sorted(parsed))


def parse_row(value: Any) -> EvaluationRowV1:
    if not isinstance(value, Mapping):
        raise HypothesisMetricsError("invalid_row_schema")
    _expect_fields(value, ROW_FIELDS, "invalid_row_schema")
    frame_id = value["frame_id"]
    if not isinstance(frame_id, str) or FRAME_ID_PATTERN.fullmatch(frame_id) is None:
        raise HypothesisMetricsError("invalid_frame_id")
    return EvaluationRowV1(
        frame_id=frame_id,
        references=_parse_axis_labels(value["references"], predictions=False),
        predictions=_parse_axis_labels(value["predictions"], predictions=True),
        strata=_parse_strata(value["strata"]),
    )


def _check_strata_bounds(rows: Sequence[EvaluationRowV1]) -> None:
    values_by_dimension = defaultdict(set)  # type: dict[str, set[str]]
    cells = set()  # type: set[Tuple[str, str]]
    for row in rows:
        for name, value in row.strata:
            values_by_dimension[name].add(value)
            cells.add((name, value))
    if len(values_by_dimension) > MAX_STRATUM_DIMENSIONS:
        raise HypothesisMetricsError("too_many_stratum_dimensions")
    if any(
        len(values) > MAX_STRATUM_VALUES_PER_DIMENSION
        for values in values_by_dimension.values()
    ):
        raise HypothesisMetricsError("too_many_stratum_values")
    if len(cells) > MAX_STRATUM_CELLS:
        raise HypothesisMetricsError("too_many_stratum_cells")


def parse_manifest(value: Any) -> Tuple[EvaluationRowV1, ...]:
    if not isinstance(value, Mapping):
        raise HypothesisMetricsError("invalid_manifest_schema")
    _expect_fields(value, ("schema", "rows"), "invalid_manifest_schema")
    if value["schema"] != SCHEMA:
        raise HypothesisMetricsError("unsupported_manifest_schema")
    raw_rows = value["rows"]
    if not isinstance(raw_rows, list) or not 1 <= len(raw_rows) <= MAX_FRAMES:
        raise HypothesisMetricsError("invalid_manifest_row_count")
    rows = tuple(parse_row(row) for row in raw_rows)
    if len({row.frame_id for row in rows}) != len(rows):
        raise HypothesisMetricsError("duplicate_frame_id")
    _check_strata_bounds(rows)
    return rows


def _fraction(numerator: int, denominator: int) -> dict[str, int]:
    return {"numerator": numerator, "denominator": denominator}


def _axis_metrics(rows: Sequence[EvaluationRowV1], axis: str) -> dict[str, Any]:
    pairs = [(row.reference(axis), row.prediction(axis)) for row in rows]
    confusion = Counter(pairs)
    support = Counter(reference for reference, _ in pairs)
    abstentions = sum(prediction == ABSTAIN for _, prediction in pairs)
    decided_known = [
        (reference, prediction)
        for reference, prediction in pairs
        if reference != "unknown" and prediction != ABSTAIN
    ]
    errors = sum(reference != prediction for reference, prediction in decided_known)
    decided_known_count = len(decided_known)

    report = {
        "row_count": len(rows),
        "confusion": [
            {"reference": reference, "prediction": prediction, "count": count}
            for (reference, prediction), count in sorted(confusion.items())
        ],
        "support": [
            {"reference": label, "count": support[label]}
            for label in sorted(RELATION_STATES[axis])
        ],
        "abstention": _fraction(abstentions, len(rows)),
        "coverage": _fraction(len(rows) - abstentions, len(rows)),
        "decided_known_references": {
            "count": decided_known_count,
            "correct_count": decided_known_count - errors,
            "error_count": errors,
            "risk": _fraction(errors, decided_known_count),
        },
    }
    if axis == "physical_source_relation":
        report["physical_source_counts"] = {
            "false_match": confusion[("different", "same")],
            "false_nonmatch": confusion[("same", "different")],
            "unknown_forced_decision": sum(
                confusion[("unknown", prediction)]
                for prediction in ("different", "same")
            ),
            "same_source_true_accept": confusion[("same", "same")],
        }
    return report


def _metrics_for_rows(rows: Sequence[EvaluationRowV1]) -> dict[str, Any]:
    return {axis: _axis_metrics(rows, axis) for axis in RELATION_AXES}


def evaluate(rows: Sequence[EvaluationRowV1]) -> dict[str, Any]:
    """Return deterministic raw aggregate counts for parsed evaluation rows."""

    if not 1 <= len(rows) <= MAX_FRAMES:
        raise HypothesisMetricsError("invalid_manifest_row_count")
    if len({row.frame_id for row in rows}) != len(rows):
        raise HypothesisMetricsError("duplicate_frame_id")
    _check_strata_bounds(rows)

    stratum_rows = defaultdict(list)  # type: dict[Tuple[str, str], list[EvaluationRowV1]]
    for row in rows:
        for stratum in row.strata:
            stratum_rows[stratum].append(row)

    return {
        "schema": REPORT_SCHEMA,
        "input_schema": SCHEMA,
        "row_count": len(rows),
        "axes": _metrics_for_rows(rows),
        "strata": [
            {
                "name": name,
                "value": value,
                "row_count": len(stratum_rows[(name, value)]),
                "axes": _metrics_for_rows(stratum_rows[(name, value)]),
            }
            for name, value in sorted(stratum_rows)
        ],
    }


def evaluate_manifest(value: Any) -> dict[str, Any]:
    return evaluate(parse_manifest(value))


def _object_without_duplicate_keys(
    pairs: Sequence[Tuple[str, Any]],
) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise HypothesisMetricsError("duplicate_json_key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise HypothesisMetricsError("invalid_json")


def parse_json_bytes(data: bytes) -> Any:
    if len(data) > MAX_INPUT_BYTES:
        raise HypothesisMetricsError("manifest_too_large")
    try:
        text = data.decode("utf-8")
        return json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HypothesisMetricsError("invalid_json") from error


def main(
    stdin: Optional[TextIO] = None,
    stdout: Optional[TextIO] = None,
    stderr: Optional[TextIO] = None,
) -> int:
    input_stream = stdin if stdin is not None else sys.stdin
    output_stream = stdout if stdout is not None else sys.stdout
    error_stream = stderr if stderr is not None else sys.stderr
    try:
        binary_input = getattr(input_stream, "buffer", input_stream)
        data = binary_input.read(MAX_INPUT_BYTES + 1)
        if isinstance(data, str):
            data = data.encode("utf-8")
        report = evaluate_manifest(parse_json_bytes(data))
        json.dump(report, output_stream, sort_keys=True, separators=(",", ":"))
        output_stream.write("\n")
        return 0
    except HypothesisMetricsError as error:
        print(error.code, file=error_stream)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
