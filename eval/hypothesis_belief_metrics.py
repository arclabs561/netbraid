#!/usr/bin/env python3
"""Proper-score and diagnostic metrics for finite relation beliefs.

The evaluator joins content-bound model profile metadata and relation-only
predictions to validated hypothesis frames. Reports are aggregate and retain no
frame identifiers or source observations.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Optional, TextIO

from hypothesis_frame import (
    FRAME_ID_PATTERN,
    RELATION_STATES,
    HypothesisFrameError,
    HypothesisFrameV0,
    parse_manifest as parse_frame_manifest,
)

SCHEMA = "netbraid.hypothesis_belief_metrics_manifest.v0"
REPORT_SCHEMA = "netbraid.hypothesis_belief_metrics_report.v0"
PPB = 1_000_000_000
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ROWS = 100_000
MAX_STRATA_PER_ROW = 8
MAX_STRATUM_DIMENSIONS = 8
MAX_STRATUM_VALUES_PER_DIMENSION = 32
MAX_STRATUM_CELLS = 128
PROFILE_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
DIGEST_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
STRATUM_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,31}\Z")
OPAQUE_STRATUM_VALUE_PATTERN = re.compile(r"[a-f0-9]{16,64}\Z")
BELIEF_SEMANTICS = frozenset(("heuristic_relative", "model_posterior"))
ABSTENTION_REASONS = frozenset(
    (
        "component_limit",
        "assignment_budget",
        "insufficient_evidence",
        "unmodeled_dependence",
        "other_declared",
    )
)


class HypothesisBeliefMetricsError(ValueError):
    """Stable fail-closed reason for an invalid belief evaluation."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ProfileRefV0:
    profile_id: str
    profile_sha256: str
    belief_semantics: str

    def document(self) -> dict[str, str]:
        return {
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "belief_semantics": self.belief_semantics,
        }


@dataclass(frozen=True)
class BeliefRowV0:
    frame_id: str
    axis: str
    outcome: str
    beliefs_ppb: tuple[tuple[str, int], ...]
    abstention_reason: Optional[str]
    strata: tuple[tuple[str, str], ...]


def _expect_fields(value: Mapping[str, Any], fields: Sequence[str], code: str) -> None:
    if set(value) != set(fields):
        raise HypothesisBeliefMetricsError(code)


def _parse_profile(value: Any) -> ProfileRefV0:
    if not isinstance(value, Mapping):
        raise HypothesisBeliefMetricsError("invalid_profile_schema")
    _expect_fields(
        value,
        ("profile_id", "profile_sha256", "belief_semantics"),
        "invalid_profile_schema",
    )
    profile_id = value["profile_id"]
    profile_sha256 = value["profile_sha256"]
    belief_semantics = value["belief_semantics"]
    if (
        not isinstance(profile_id, str)
        or PROFILE_ID_PATTERN.fullmatch(profile_id) is None
    ):
        raise HypothesisBeliefMetricsError("invalid_profile_id")
    if (
        not isinstance(profile_sha256, str)
        or DIGEST_PATTERN.fullmatch(profile_sha256) is None
    ):
        raise HypothesisBeliefMetricsError("invalid_profile_sha256")
    if (
        not isinstance(belief_semantics, str)
        or belief_semantics not in BELIEF_SEMANTICS
    ):
        raise HypothesisBeliefMetricsError("invalid_belief_semantics")
    return ProfileRefV0(profile_id, profile_sha256, belief_semantics)


def _parse_strata(value: Any) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping) or len(value) > MAX_STRATA_PER_ROW:
        raise HypothesisBeliefMetricsError("invalid_strata_schema")
    parsed = []
    for name, label in value.items():
        if not isinstance(name, str) or STRATUM_NAME_PATTERN.fullmatch(name) is None:
            raise HypothesisBeliefMetricsError("invalid_stratum_name")
        if (
            not isinstance(label, str)
            or OPAQUE_STRATUM_VALUE_PATTERN.fullmatch(label) is None
        ):
            raise HypothesisBeliefMetricsError("invalid_stratum_value")
        parsed.append((name, label))
    return tuple(sorted(parsed))


def _parse_exact_beliefs(axis: str, value: Any) -> tuple[tuple[str, int], ...]:
    if not isinstance(value, Mapping):
        raise HypothesisBeliefMetricsError("invalid_beliefs_schema")
    states = tuple(sorted(RELATION_STATES[axis] - {"unknown"}))
    if set(value) != set(states):
        raise HypothesisBeliefMetricsError("invalid_belief_states")
    parsed = []
    total = 0
    for state in states:
        probability = value[state]
        if type(probability) is not int or not 0 <= probability <= PPB:
            raise HypothesisBeliefMetricsError("invalid_belief_probability")
        total += probability
        parsed.append((state, probability))
    if total != PPB:
        raise HypothesisBeliefMetricsError("belief_probability_sum_mismatch")
    return tuple(parsed)


def _parse_outcome(
    axis: str, value: Any
) -> tuple[str, tuple[tuple[str, int], ...], Optional[str]]:
    if not isinstance(value, Mapping) or not isinstance(value.get("state"), str):
        raise HypothesisBeliefMetricsError("invalid_outcome_schema")
    state = value["state"]
    if state == "exact":
        _expect_fields(value, ("state", "beliefs_ppb"), "invalid_outcome_schema")
        return state, _parse_exact_beliefs(axis, value["beliefs_ppb"]), None
    if state == "abstained":
        _expect_fields(value, ("state", "reason"), "invalid_outcome_schema")
        reason = value["reason"]
        if not isinstance(reason, str) or reason not in ABSTENTION_REASONS:
            raise HypothesisBeliefMetricsError("invalid_abstention_reason")
        return state, (), reason
    if state == "no_feasible_assignment":
        _expect_fields(value, ("state",), "invalid_outcome_schema")
        return state, (), None
    raise HypothesisBeliefMetricsError("invalid_outcome_state")


def _parse_row(value: Any) -> BeliefRowV0:
    if not isinstance(value, Mapping):
        raise HypothesisBeliefMetricsError("invalid_row_schema")
    _expect_fields(
        value,
        ("frame_id", "axis", "outcome", "strata"),
        "invalid_row_schema",
    )
    frame_id = value["frame_id"]
    axis = value["axis"]
    if not isinstance(frame_id, str) or FRAME_ID_PATTERN.fullmatch(frame_id) is None:
        raise HypothesisBeliefMetricsError("invalid_frame_id")
    if not isinstance(axis, str) or axis not in RELATION_STATES:
        raise HypothesisBeliefMetricsError("invalid_relation_axis")
    outcome, beliefs, reason = _parse_outcome(axis, value["outcome"])
    return BeliefRowV0(
        frame_id=frame_id,
        axis=axis,
        outcome=outcome,
        beliefs_ppb=beliefs,
        abstention_reason=reason,
        strata=_parse_strata(value["strata"]),
    )


def _check_strata_bounds(rows: Sequence[BeliefRowV0]) -> None:
    values_by_dimension: dict[str, set[str]] = defaultdict(set)
    cells = set()
    for row in rows:
        for name, value in row.strata:
            values_by_dimension[name].add(value)
            cells.add((name, value))
    if len(values_by_dimension) > MAX_STRATUM_DIMENSIONS:
        raise HypothesisBeliefMetricsError("too_many_stratum_dimensions")
    if any(
        len(values) > MAX_STRATUM_VALUES_PER_DIMENSION
        for values in values_by_dimension.values()
    ):
        raise HypothesisBeliefMetricsError("too_many_stratum_values")
    if len(cells) > MAX_STRATUM_CELLS:
        raise HypothesisBeliefMetricsError("too_many_stratum_cells")


def parse_manifest(
    value: Any,
) -> tuple[ProfileRefV0, tuple[HypothesisFrameV0, ...], tuple[BeliefRowV0, ...]]:
    if not isinstance(value, Mapping):
        raise HypothesisBeliefMetricsError("invalid_manifest_schema")
    _expect_fields(
        value,
        ("schema", "profile", "frame_manifest", "rows"),
        "invalid_manifest_schema",
    )
    if value["schema"] != SCHEMA:
        raise HypothesisBeliefMetricsError("unsupported_manifest_schema")
    profile = _parse_profile(value["profile"])
    try:
        frames = parse_frame_manifest(value["frame_manifest"])
    except HypothesisFrameError as error:
        raise HypothesisBeliefMetricsError("invalid_frame_manifest") from error
    raw_rows = value["rows"]
    if not isinstance(raw_rows, list) or not 1 <= len(raw_rows) <= MAX_ROWS:
        raise HypothesisBeliefMetricsError("invalid_manifest_row_count")
    rows = tuple(_parse_row(row) for row in raw_rows)
    slots = [(row.frame_id, row.axis) for row in rows]
    if len(set(slots)) != len(slots):
        raise HypothesisBeliefMetricsError("duplicate_frame_axis")
    frame_ids = {frame.frame_id for frame in frames}
    if any(row.frame_id not in frame_ids for row in rows):
        raise HypothesisBeliefMetricsError("unknown_prediction_frame")
    _check_strata_bounds(rows)
    return (
        profile,
        frames,
        tuple(sorted(rows, key=lambda row: (row.axis, row.frame_id))),
    )


def _fraction(numerator: int, denominator: int) -> dict[str, int]:
    return {"numerator": numerator, "denominator": denominator}


def _confidence_bins() -> list[dict[str, Any]]:
    return [
        {
            "lower_ppb": index * (PPB // 10),
            "upper_ppb": (index + 1) * (PPB // 10),
            "upper_inclusive": index == 9,
            "count": 0,
            "confidence_ppb_sum": 0,
            "correct_count": 0,
        }
        for index in range(10)
    ]


def _axis_metrics(
    rows: Sequence[BeliefRowV0], frames_by_id: Mapping[str, HypothesisFrameV0]
) -> dict[str, Any]:
    axis = rows[0].axis
    if any(row.axis != axis for row in rows):
        raise HypothesisBeliefMetricsError("mixed_axis_metric_input")
    outcome_counts = Counter(row.outcome for row in rows)
    abstention_counts = Counter(
        row.abstention_reason for row in rows if row.abstention_reason is not None
    )
    references = Counter(getattr(frames_by_id[row.frame_id], axis) for row in rows)
    brier_numerator = 0
    scored_count = 0
    unique_map_count = 0
    unique_map_correct = 0
    tied_map_count = 0
    tied_map_contains_reference = 0
    unknown_reference_exact = 0
    bins = _confidence_bins()

    for row in rows:
        if row.outcome != "exact":
            continue
        reference = getattr(frames_by_id[row.frame_id], axis)
        if reference == "unknown":
            unknown_reference_exact += 1
            continue
        beliefs = dict(row.beliefs_ppb)
        scored_count += 1
        brier_numerator += sum(
            (probability - (PPB if state == reference else 0)) ** 2
            for state, probability in row.beliefs_ppb
        )
        confidence = max(beliefs.values())
        map_states = tuple(
            state for state, probability in row.beliefs_ppb if probability == confidence
        )
        if len(map_states) != 1:
            tied_map_count += 1
            tied_map_contains_reference += reference in map_states
            continue
        unique_map_count += 1
        correct = map_states[0] == reference
        unique_map_correct += correct
        bin_index = min(9, (confidence * 10) // PPB)
        bins[bin_index]["count"] += 1
        bins[bin_index]["confidence_ppb_sum"] += confidence
        bins[bin_index]["correct_count"] += correct

    return {
        "row_count": len(rows),
        "outcomes": {
            state: outcome_counts[state]
            for state in ("exact", "abstained", "no_feasible_assignment")
        },
        "abstention_reasons": [
            {"reason": reason, "count": abstention_counts[reason]}
            for reason in sorted(ABSTENTION_REASONS)
        ],
        "reference_support": [
            {"reference": state, "count": references[state]}
            for state in sorted(RELATION_STATES[axis])
        ],
        "proper_score": {
            "name": "multiclass_brier",
            "scored_count": scored_count,
            "unknown_reference_exact_count": unknown_reference_exact,
            "mean": _fraction(brier_numerator, scored_count * PPB * PPB),
        },
        "maximum_state": {
            "unique_count": unique_map_count,
            "unique_correct_count": unique_map_correct,
            "unique_error_count": unique_map_count - unique_map_correct,
            "tied_count": tied_map_count,
            "tied_contains_reference_count": tied_map_contains_reference,
        },
        "confidence_diagnostic": {
            "kind": "fixed_top_state_bins",
            "excludes_tied_and_unknown_reference_rows": True,
            "bins": bins,
        },
    }


def evaluate(
    profile: ProfileRefV0,
    frames: Sequence[HypothesisFrameV0],
    rows: Sequence[BeliefRowV0],
) -> dict[str, Any]:
    if not rows:
        raise HypothesisBeliefMetricsError("invalid_manifest_row_count")
    frames_by_id = {frame.frame_id: frame for frame in frames}
    rows_by_axis: dict[str, list[BeliefRowV0]] = defaultdict(list)
    stratum_rows: dict[tuple[str, str], list[BeliefRowV0]] = defaultdict(list)
    for row in rows:
        rows_by_axis[row.axis].append(row)
        for stratum in row.strata:
            stratum_rows[stratum].append(row)

    return {
        "schema": REPORT_SCHEMA,
        "input_schema": SCHEMA,
        "profile": profile.document(),
        "row_count": len(rows),
        "axes": {
            axis: _axis_metrics(rows_by_axis[axis], frames_by_id)
            for axis in sorted(rows_by_axis)
        },
        "strata": [
            {
                "name": name,
                "value": value,
                "row_count": len(stratum_rows[(name, value)]),
                "axes": {
                    axis: _axis_metrics(axis_rows, frames_by_id)
                    for axis, axis_rows in _group_by_axis(stratum_rows[(name, value)])
                },
            }
            for name, value in sorted(stratum_rows)
        ],
    }


def _group_by_axis(
    rows: Sequence[BeliefRowV0],
) -> tuple[tuple[str, list[BeliefRowV0]], ...]:
    grouped: dict[str, list[BeliefRowV0]] = defaultdict(list)
    for row in rows:
        grouped[row.axis].append(row)
    return tuple((axis, grouped[axis]) for axis in sorted(grouped))


def evaluate_manifest(value: Any) -> dict[str, Any]:
    return evaluate(*parse_manifest(value))


def _object_without_duplicate_keys(
    pairs: Sequence[tuple[str, Any]],
) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise HypothesisBeliefMetricsError("duplicate_json_key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise HypothesisBeliefMetricsError("invalid_json")


def parse_json_bytes(data: bytes) -> Any:
    if len(data) > MAX_INPUT_BYTES:
        raise HypothesisBeliefMetricsError("manifest_too_large")
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HypothesisBeliefMetricsError("invalid_json") from error


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
    except HypothesisBeliefMetricsError as error:
        print(error.code, file=error_stream)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
