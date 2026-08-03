#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Evaluate selective Wi-Fi/RFID event relation on the private XRF55 cache."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import stat
import sys
import tempfile
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
DEFAULT_INPUT_DIR = ROOT / "data" / "derived" / "eval"
DEFAULT_ADAPTER = DEFAULT_INPUT_DIR / "xrf55-feature-cache-adapter.json"
DEFAULT_WIFI_MATRIX = DEFAULT_INPUT_DIR / "xrf55-feature-cache-wifi.npy"
DEFAULT_RFID_MATRIX = DEFAULT_INPUT_DIR / "xrf55-feature-cache-rfid.npy"
DEFAULT_REPORT = DEFAULT_INPUT_DIR / "xrf55-calibrated-event-relation-report.json"
REPORT_SCHEMA = "netbraid.xrf55_calibrated_event_relation_eval.v0"

FIT_REPETITIONS = frozenset(range(1, 9))
CALIBRATION_REPETITIONS = frozenset(range(9, 12))
VALIDATION_REPETITIONS = frozenset(range(12, 15))
TEST_REPETITIONS = frozenset(range(15, 21))
ROLE_REPETITIONS = {
    "fit": FIT_REPETITIONS,
    "calibration": CALIBRATION_REPETITIONS,
    "validation": VALIDATION_REPETITIONS,
    "test": TEST_REPETITIONS,
}
SOURCE_MODALITY = "wifi"
TARGET_MODALITY = "rfid"


class Xrf55EventRelationError(RuntimeError):
    """Stable failure at the calibrated event-relation boundary."""


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Xrf55EventRelationError("module_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RETRIEVAL = _load_module(
    "xrf55_calibrated_retrieval_dependency",
    HERE / "evaluate-xrf55-cross-modal-retrieval.py",
)
CONTRACT = _load_module(
    "xrf55_calibrated_event_relation_contract",
    HERE / "calibrated_event_relation.py",
)
METRICS = _load_module(
    "xrf55_calibrated_hypothesis_metrics", HERE / "hypothesis_metrics.py"
)


@dataclass(frozen=True)
class DirectionModel:
    source: str
    target: str
    source_policy: Any
    target_policy: Any
    weights: np.ndarray


@dataclass(frozen=True)
class PairScores:
    frame_id: str
    group_id: str
    reference: str
    forward: float
    reverse: float
    unaligned_forward: float
    unaligned_reverse: float


def load_pair_cache(adapter_path: Path, wifi_path: Path, rfid_path: Path) -> Any:
    adapter, events = RETRIEVAL._validate_adapter(RETRIEVAL._load_json(adapter_path))
    artifacts = RETRIEVAL._require_fields(
        adapter["integrity"]["artifacts"],
        set(RETRIEVAL.FEATURES.MODALITIES),
        "artifact_set_mismatch",
    )
    matrices = {
        SOURCE_MODALITY: RETRIEVAL._load_matrix(wifi_path, artifacts[SOURCE_MODALITY]),
        TARGET_MODALITY: RETRIEVAL._load_matrix(rfid_path, artifacts[TARGET_MODALITY]),
    }
    return RETRIEVAL.LoadedCache(adapter, events, matrices)


def _events_for(cache: Any, repetitions: frozenset[int]) -> tuple[Any, ...]:
    events = tuple(event for event in cache.events if event.repetition in repetitions)
    expected = 8 * len(repetitions)
    if len(events) != expected:
        raise Xrf55EventRelationError("role_event_count_mismatch")
    if len({event.event_id for event in events}) != expected:
        raise Xrf55EventRelationError("role_event_id_collision")
    return events


def _fit_direction(cache: Any, source: str, target: str) -> DirectionModel:
    fit_events = _events_for(cache, FIT_REPETITIONS)
    rows = [event.row for event in fit_events]
    source_fit = np.asarray(cache.matrices[source][rows], dtype=np.float64)
    target_fit = np.asarray(cache.matrices[target][rows], dtype=np.float64)
    source_policy = RETRIEVAL._fit_standardizer(source_fit)
    target_policy = RETRIEVAL._fit_standardizer(target_fit)
    weights = RETRIEVAL._ridge_weights(
        RETRIEVAL._standardize(source_fit, source_policy),
        RETRIEVAL._standardize(target_fit, target_policy),
    )
    return DirectionModel(source, target, source_policy, target_policy, weights)


def _learned_distance(
    cache: Any, model: DirectionModel, source_row: int, target_row: int
) -> float:
    source = np.asarray(cache.matrices[model.source][[source_row]], dtype=np.float64)
    target = np.asarray(cache.matrices[model.target][[target_row]], dtype=np.float64)
    prediction = RETRIEVAL._standardize(source, model.source_policy) @ model.weights
    observed = RETRIEVAL._standardize(target, model.target_policy)
    difference = prediction[0] - observed[0]
    distance = float((difference @ difference) / difference.size)
    if not math.isfinite(distance) or distance < 0.0:
        raise Xrf55EventRelationError("nonfinite_learned_distance")
    return distance


def _unaligned_distance(
    cache: Any,
    source_model: DirectionModel,
    target_model: DirectionModel,
    source_row: int,
    target_row: int,
) -> float:
    source = np.asarray(
        cache.matrices[source_model.source][[source_row]], dtype=np.float64
    )
    target = np.asarray(
        cache.matrices[target_model.source][[target_row]], dtype=np.float64
    )
    left = RETRIEVAL._standardize_full(source, source_model.source_policy)[0]
    right = RETRIEVAL._standardize_full(target, target_model.source_policy)[0]
    difference = left - right
    distance = float((difference @ difference) / difference.size)
    if not math.isfinite(distance) or distance < 0.0:
        raise Xrf55EventRelationError("nonfinite_unaligned_distance")
    return distance


def _frame_id(left_event_id: str, right_event_id: str) -> str:
    digest = hashlib.sha256(
        b"netbraid.xrf55-wifi-rfid-event-pair.v0\x00"
        + left_event_id.encode("ascii")
        + b"\x00"
        + right_event_id.encode("ascii")
    ).hexdigest()
    return f"xrf55-event-pair-{digest}"


def _pair_scores(
    cache: Any,
    repetitions: frozenset[int],
    forward: DirectionModel,
    reverse: DirectionModel,
) -> tuple[PairScores, ...]:
    by_group: defaultdict[str, list[Any]] = defaultdict(list)
    for event in _events_for(cache, repetitions):
        by_group[event.group_id].append(event)
    if len(by_group) != 8 or any(
        len(events) != len(repetitions) for events in by_group.values()
    ):
        raise Xrf55EventRelationError("role_group_contract_mismatch")

    pairs = []
    for group_id in sorted(by_group):
        events = sorted(by_group[group_id], key=lambda event: event.repetition)
        for left in events:
            for right in events:
                pairs.append(
                    PairScores(
                        frame_id=_frame_id(left.event_id, right.event_id),
                        group_id=group_id,
                        reference="same"
                        if left.repetition == right.repetition
                        else "different",
                        forward=_learned_distance(cache, forward, left.row, right.row),
                        reverse=_learned_distance(cache, reverse, right.row, left.row),
                        unaligned_forward=_unaligned_distance(
                            cache, forward, reverse, left.row, right.row
                        ),
                        unaligned_reverse=_unaligned_distance(
                            cache, reverse, forward, right.row, left.row
                        ),
                    )
                )
    return tuple(pairs)


def _quantile(values: Sequence[float], quantile: float) -> float:
    if not values:
        raise Xrf55EventRelationError("empty_calibration_class")
    result = float(np.quantile(np.asarray(values, dtype=np.float64), quantile))
    if not math.isfinite(result) or result < 0.0:
        raise Xrf55EventRelationError("invalid_calibration_quantile")
    return result


def _thresholds(
    rows: Sequence[PairScores], forward_field: str, reverse_field: str
) -> tuple[float, float, float, float]:
    same = [row for row in rows if row.reference == "same"]
    different = [row for row in rows if row.reference == "different"]
    return (
        _quantile([getattr(row, forward_field) for row in same], 0.9),
        _quantile([getattr(row, forward_field) for row in different], 0.1),
        _quantile([getattr(row, reverse_field) for row in same], 0.9),
        _quantile([getattr(row, reverse_field) for row in different], 0.1),
    )


def _thresholds_ordered(values: tuple[float, float, float, float]) -> bool:
    return values[0] < values[1] and values[2] < values[3]


def _json_digest(domain: bytes, value: Any) -> str:
    encoded = json.dumps(
        value, allow_nan=False, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(domain + encoded).hexdigest()


def _partition_digest(events: Sequence[Any], role: str) -> str:
    rows = [
        {
            "event_id": event.event_id,
            "group_id": event.group_id,
            "repetition": event.repetition,
            "row": event.row,
        }
        for event in sorted(events, key=lambda item: item.event_id)
    ]
    return _json_digest(f"netbraid.xrf55-{role}-partition.v0\x00".encode(), rows)


def _model_digest(models: Sequence[DirectionModel], kind: str) -> str:
    digest = hashlib.sha256(f"netbraid.xrf55-{kind}-models.v0\x00".encode())
    for model in models:
        digest.update(model.source.encode("ascii"))
        digest.update(b"\x00")
        digest.update(model.target.encode("ascii"))
        digest.update(b"\x00")
        for value in (
            model.source_policy.means,
            model.source_policy.scales,
            model.source_policy.active,
            model.target_policy.means,
            model.target_policy.scales,
            model.target_policy.active,
        ):
            array = np.ascontiguousarray(value)
            digest.update(array.dtype.str.encode("ascii"))
            digest.update(str(array.shape).encode("ascii"))
            digest.update(array.tobytes())
        if kind == "learned":
            weights = np.ascontiguousarray(model.weights)
            digest.update(weights.dtype.str.encode("ascii"))
            digest.update(str(weights.shape).encode("ascii"))
            digest.update(weights.tobytes())
    return digest.hexdigest()


def _profile(
    cache: Any,
    models: Sequence[DirectionModel],
    thresholds: tuple[float, float, float, float],
    *,
    kind: str,
) -> Any:
    artifacts = cache.adapter["integrity"]["artifacts"]
    input_digest = _json_digest(
        b"netbraid.xrf55-wifi-rfid-inputs.v0\x00",
        {
            modality: artifacts[modality]["sha256"]
            for modality in (SOURCE_MODALITY, TARGET_MODALITY)
        },
    )
    feature_digest = _json_digest(
        b"netbraid.xrf55-feature-policy.v0\x00", cache.adapter["feature_policy"]
    )
    return CONTRACT.CalibratedEventRelationProfileV0(
        profile_id=f"xrf55-wifi-rfid-{kind}-v0",
        reducer_revision="bidirectional-ridge-distance-v0",
        model_revision=(
            f"ridge-alpha-{RETRIEVAL.RIDGE_ALPHA.hex()}-v0"
            if kind == "learned"
            else "unaligned-standardization-v0"
        ),
        feature_policy_digest=feature_digest,
        input_matrix_digest=input_digest,
        model_digest=_model_digest(models, kind),
        fit_partition_digest=_partition_digest(
            _events_for(cache, FIT_REPETITIONS), "fit"
        ),
        calibration_partition_digest=_partition_digest(
            _events_for(cache, CALIBRATION_REPETITIONS), "calibration"
        ),
        forward_same_threshold=thresholds[0].hex(),
        forward_different_threshold=thresholds[1].hex(),
        reverse_same_threshold=thresholds[2].hex(),
        reverse_different_threshold=thresholds[3].hex(),
    )


def _prediction(row: PairScores, profile: Any, kind: str) -> Any:
    if kind == "learned":
        forward_score, reverse_score = row.forward, row.reverse
    elif kind == "unaligned":
        forward_score, reverse_score = (
            row.unaligned_forward,
            row.unaligned_reverse,
        )
    else:
        raise Xrf55EventRelationError("unsupported_prediction_kind")
    decision, reason = CONTRACT.expected_decision(
        profile, forward_score.hex(), reverse_score.hex()
    )
    return CONTRACT.EventRelationPredictionV0(
        frame_id=row.frame_id,
        profile_digest=profile.content_digest(),
        forward_score=forward_score.hex(),
        reverse_score=reverse_score.hex(),
        decision=decision,
        abstain_reason=reason,
        profile=profile,
    )


def qualified_prediction_row(prediction: Any) -> dict[str, Any]:
    return METRICS.compose_prediction_row(
        prediction.frame_id,
        ({"event_relation": prediction.decision},),
    )


def _summary(rows: Sequence[PairScores], predictions: Sequence[Any]) -> dict[str, Any]:
    if len(rows) != len(predictions) or any(
        row.frame_id != prediction.frame_id
        for row, prediction in zip(rows, predictions)
    ):
        raise Xrf55EventRelationError("prediction_row_mismatch")
    confusion = Counter(
        (row.reference, prediction.decision)
        for row, prediction in zip(rows, predictions)
    )
    references = Counter(row.reference for row in rows)
    decisions = Counter(prediction.decision for prediction in predictions)
    reasons = Counter(
        prediction.abstain_reason
        for prediction in predictions
        if prediction.abstain_reason is not None
    )
    false_links = confusion[("different", "same")]
    false_nonmatches = confusion[("same", "different")]
    decided = decisions["same"] + decisions["different"]
    errors = false_links + false_nonmatches
    return {
        "rows": len(rows),
        "reference_support": dict(sorted(references.items())),
        "prediction_counts": {
            decision: decisions[decision]
            for decision in ("same", "different", "abstain")
        },
        "abstain_reasons": {
            reason: reasons[reason]
            for reason in ("score_gap", "direction_disagreement")
        },
        "confusion": [
            {
                "reference": reference,
                "prediction": prediction,
                "count": confusion[(reference, prediction)],
            }
            for reference in ("same", "different")
            for prediction in ("same", "different", "abstain")
        ],
        "coverage": {"numerator": decided, "denominator": len(rows)},
        "selective_risk": {"numerator": errors, "denominator": decided},
        "false_links": false_links,
        "false_nonmatches": false_nonmatches,
    }


def _all_abstain_summary(rows: Sequence[PairScores]) -> dict[str, Any]:
    references = Counter(row.reference for row in rows)
    return {
        "rows": len(rows),
        "reference_support": dict(sorted(references.items())),
        "prediction_counts": {"same": 0, "different": 0, "abstain": len(rows)},
        "coverage": {"numerator": 0, "denominator": len(rows)},
        "selective_risk": {"numerator": 0, "denominator": 0},
        "false_links": 0,
        "false_nonmatches": 0,
    }


def _per_group(
    rows: Sequence[PairScores], predictions: Sequence[Any]
) -> list[dict[str, Any]]:
    by_group_rows: defaultdict[str, list[PairScores]] = defaultdict(list)
    by_group_predictions: defaultdict[str, list[Any]] = defaultdict(list)
    for row, prediction in zip(rows, predictions):
        by_group_rows[row.group_id].append(row)
        by_group_predictions[row.group_id].append(prediction)
    return [
        {
            "group_id": group_id,
            "metrics": _summary(
                by_group_rows[group_id], by_group_predictions[group_id]
            ),
        }
        for group_id in sorted(by_group_rows)
    ]


def _lower_risk(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    left_risk = left["selective_risk"]
    right_risk = right["selective_risk"]
    if left_risk["denominator"] == 0 or right_risk["denominator"] == 0:
        return False
    return (
        left_risk["numerator"] * right_risk["denominator"]
        < right_risk["numerator"] * left_risk["denominator"]
    )


def _validation_gate(
    learned: Mapping[str, Any], unaligned: Mapping[str, Any]
) -> dict[str, Any]:
    checks = {
        "coverage_at_least_half": 2 * learned["coverage"]["numerator"]
        >= learned["coverage"]["denominator"],
        "false_links_at_most_two": learned["false_links"] <= 2,
        "false_nonmatches_at_most_two": learned["false_nonmatches"] <= 2,
        "coverage_not_below_unaligned": learned["coverage"]["numerator"]
        >= unaligned["coverage"]["numerator"],
        "selective_risk_below_unaligned": _lower_risk(learned, unaligned),
    }
    return {"checks": checks, "passed": all(checks.values())}


def evaluate(cache: Any) -> dict[str, Any]:
    forward = _fit_direction(cache, SOURCE_MODALITY, TARGET_MODALITY)
    reverse = _fit_direction(cache, TARGET_MODALITY, SOURCE_MODALITY)
    calibration = _pair_scores(cache, CALIBRATION_REPETITIONS, forward, reverse)
    learned_thresholds = _thresholds(calibration, "forward", "reverse")
    unaligned_thresholds = _thresholds(
        calibration, "unaligned_forward", "unaligned_reverse"
    )
    learned_profile = _profile(
        cache, (forward, reverse), learned_thresholds, kind="learned"
    )
    unaligned_profile = (
        _profile(cache, (forward, reverse), unaligned_thresholds, kind="unaligned")
        if _thresholds_ordered(unaligned_thresholds)
        else None
    )

    validation = _pair_scores(cache, VALIDATION_REPETITIONS, forward, reverse)
    validation_learned_predictions = tuple(
        _prediction(row, learned_profile, "learned") for row in validation
    )
    validation_learned = _summary(validation, validation_learned_predictions)
    if unaligned_profile is None:
        validation_unaligned_predictions = ()
        validation_unaligned = _all_abstain_summary(validation)
    else:
        validation_unaligned_predictions = tuple(
            _prediction(row, unaligned_profile, "unaligned") for row in validation
        )
        validation_unaligned = _summary(validation, validation_unaligned_predictions)
    gate = _validation_gate(validation_learned, validation_unaligned)

    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "validation_pass" if gate["passed"] else "validation_failed",
        "task": {
            "relation_axis": "event_relation",
            "modality_pair": [SOURCE_MODALITY, TARGET_MODALITY],
            "ridge_alpha": RETRIEVAL.RIDGE_ALPHA.hex(),
            "score": "mean_squared_residual_in_fit_standardized_target_space",
            "roles": {
                role: [min(repetitions), max(repetitions)]
                for role, repetitions in ROLE_REPETITIONS.items()
            },
            "session_separation": "unbounded_session_axis",
        },
        "profiles": {
            "learned": {
                "digest": learned_profile.content_digest(),
                "document": learned_profile.document(),
            },
            "unaligned": {
                "status": "valid"
                if unaligned_profile is not None
                else "invalid_threshold_order",
                "digest": unaligned_profile.content_digest()
                if unaligned_profile is not None
                else None,
                "document": unaligned_profile.document()
                if unaligned_profile is not None
                else None,
                "thresholds": [value.hex() for value in unaligned_thresholds],
            },
        },
        "calibration": {
            "reference_support": dict(
                sorted(Counter(row.reference for row in calibration).items())
            ),
            "rows": len(calibration),
        },
        "validation": {
            "all_abstain": _all_abstain_summary(validation),
            "learned": validation_learned,
            "learned_per_group": _per_group(validation, validation_learned_predictions),
            "unaligned": validation_unaligned,
            "gate": gate,
        },
        "test": None,
        "privacy": dict(cache.adapter["privacy"]),
        "limitations": [
            "pair outcomes reuse observations and are not independent",
            "acquisition-session separation is not observed",
            "same event does not imply same performer device source or identity",
            "pairwise same-event predictions are not transitively merged",
        ],
    }
    if gate["passed"]:
        test = _pair_scores(cache, TEST_REPETITIONS, forward, reverse)
        test_predictions = tuple(
            _prediction(row, learned_profile, "learned") for row in test
        )
        report["test"] = {
            "learned": _summary(test, test_predictions),
            "learned_per_group": _per_group(test, test_predictions),
        }
        report["status"] = "pass"
    return report


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise Xrf55EventRelationError("unsafe_report_directory")
    if os.path.lexists(path):
        target = path.lstat()
        if stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode):
            raise Xrf55EventRelationError("unsafe_report_path")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", type=Path, default=DEFAULT_ADAPTER)
    parser.add_argument("--wifi-matrix", type=Path, default=DEFAULT_WIFI_MATRIX)
    parser.add_argument("--rfid-matrix", type=Path, default=DEFAULT_RFID_MATRIX)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        cache = load_pair_cache(
            arguments.adapter, arguments.wifi_matrix, arguments.rfid_matrix
        )
        report = evaluate(cache)
        _write_report(arguments.report, report)
    except (OSError, ValueError, Xrf55EventRelationError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps({"status": report["status"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
