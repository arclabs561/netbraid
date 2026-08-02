#!/usr/bin/env python3
"""Evaluate a finite counter-to-capture campaign from derived window metadata.

The manifest contains campaign-local run IDs and already-derived TrafficWindow
values only. It deliberately has no collection, packet, address, interface, or
source-path surface.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Optional, TextIO

import counter_capture_eval as core

MANIFEST_SCHEMA_VERSION = 1
RESULT_SCHEMA_VERSION = 1
DEFAULT_RESULT_SCHEMA = "netbraid.counter_capture_campaign_evaluation"
REGIMES = ("idle", "download", "upload", "bidirectional")
WINDOW_FIELDS = (
    "duration_ms",
    "received_bytes",
    "transmitted_bytes",
    "received_packets",
    "transmitted_packets",
)
CALIBRATION_FIELDS = (
    "run_id",
    "regime",
    "counter_window",
    "capture_window",
)
HELDOUT_FIELDS = CALIBRATION_FIELDS + (
    "true_candidate_index",
    "candidate_run_ids",
)
RUN_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
EXCLUSION_REASONS = ("candidate_excluded", "minimum_distance_tie")


class CampaignError(ValueError):
    """A stable fail-closed reason for an invalid campaign manifest."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CampaignRun:
    run_id: str
    regime: str
    counter_window: core.TrafficWindow
    capture_window: core.TrafficWindow
    candidate_run_ids: tuple[str, ...] = ()


def _expect_fields(value: Mapping[str, Any], fields: Sequence[str], code: str) -> None:
    if set(value) != set(fields):
        raise CampaignError(code)


def _parse_window(value: Any) -> core.TrafficWindow:
    if not isinstance(value, Mapping):
        raise CampaignError("invalid_traffic_window_schema")
    _expect_fields(value, WINDOW_FIELDS, "invalid_traffic_window_schema")
    return core.TrafficWindow(**{name: value[name] for name in WINDOW_FIELDS})


def _parse_run(value: Any, *, heldout: bool) -> CampaignRun:
    if not isinstance(value, Mapping):
        raise CampaignError("invalid_run_schema")
    _expect_fields(
        value,
        HELDOUT_FIELDS if heldout else CALIBRATION_FIELDS,
        "invalid_run_schema",
    )
    run_id = value["run_id"]
    if not isinstance(run_id, str) or RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise CampaignError("invalid_run_id")
    regime = value["regime"]
    if regime not in REGIMES:
        raise CampaignError("invalid_regime")

    candidate_run_ids: tuple[str, ...] = ()
    if heldout:
        true_index = value["true_candidate_index"]
        if (
            isinstance(true_index, bool)
            or not isinstance(true_index, int)
            or true_index != 0
        ):
            raise CampaignError("true_candidate_index_must_be_zero")
        candidates = value["candidate_run_ids"]
        if not isinstance(candidates, list) or len(candidates) != 4:
            raise CampaignError("heldout_requires_four_candidates")
        if any(
            not isinstance(candidate, str)
            or RUN_ID_PATTERN.fullmatch(candidate) is None
            for candidate in candidates
        ):
            raise CampaignError("invalid_candidate_run_id")
        candidate_run_ids = tuple(candidates)

    return CampaignRun(
        run_id=run_id,
        regime=regime,
        counter_window=_parse_window(value["counter_window"]),
        capture_window=_parse_window(value["capture_window"]),
        candidate_run_ids=candidate_run_ids,
    )


def _parse_run_list(value: Any, *, heldout: bool) -> list[CampaignRun]:
    if not isinstance(value, list):
        raise CampaignError("invalid_run_list")
    return [_parse_run(item, heldout=heldout) for item in value]


def _regime_order(run: CampaignRun) -> tuple[int, str]:
    return REGIMES.index(run.regime), run.run_id


def _parse_manifest(
    manifest: Mapping[str, Any],
) -> tuple[list[CampaignRun], list[CampaignRun]]:
    _expect_fields(
        manifest,
        ("schema_version", "calibration_runs", "heldout_runs"),
        "invalid_manifest_schema",
    )
    schema_version = manifest["schema_version"]
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version != MANIFEST_SCHEMA_VERSION
    ):
        raise CampaignError("unsupported_manifest_schema_version")

    calibration = _parse_run_list(manifest["calibration_runs"], heldout=False)
    heldout = _parse_run_list(manifest["heldout_runs"], heldout=True)
    if len(calibration) + len(heldout) != 24:
        raise CampaignError("campaign_requires_twenty_four_runs")
    if len(calibration) != 8 or len(heldout) != 16:
        raise CampaignError("campaign_requires_eight_calibration_and_sixteen_heldout")

    calibration_ids = [run.run_id for run in calibration]
    heldout_ids = [run.run_id for run in heldout]
    if len(set(calibration_ids)) != len(calibration_ids) or len(
        set(heldout_ids)
    ) != len(heldout_ids):
        raise CampaignError("duplicate_run_id")
    if set(calibration_ids) & set(heldout_ids):
        raise CampaignError("calibration_heldout_overlap")

    all_counts = Counter(run.regime for run in calibration + heldout)
    calibration_counts = Counter(run.regime for run in calibration)
    heldout_counts = Counter(run.regime for run in heldout)
    if any(all_counts[regime] != 6 for regime in REGIMES):
        raise CampaignError("each_regime_requires_six_runs")
    if any(calibration_counts[regime] != 2 for regime in REGIMES) or any(
        heldout_counts[regime] != 4 for regime in REGIMES
    ):
        raise CampaignError("each_regime_requires_two_calibration_four_heldout")

    heldout_by_id = {run.run_id: run for run in heldout}
    for run in heldout:
        if run.candidate_run_ids[0] != run.run_id:
            raise CampaignError("true_candidate_must_reference_self")
        decoy_ids = run.candidate_run_ids[1:]
        if len(set(decoy_ids)) != 3 or run.run_id in decoy_ids:
            raise CampaignError("decoys_must_reference_distinct_runs")
        if tuple(sorted(decoy_ids)) != decoy_ids:
            raise CampaignError("decoys_must_be_canonically_ordered")
        for decoy_id in decoy_ids:
            decoy = heldout_by_id.get(decoy_id)
            if decoy is None:
                raise CampaignError("decoy_must_reference_heldout_run")
            if decoy.regime != run.regime:
                raise CampaignError("decoy_regime_mismatch")

    return sorted(calibration, key=_regime_order), sorted(heldout, key=_regime_order)


def _exclusion_counts(outcomes: Sequence[core.RankOutcome]) -> dict[str, int]:
    counts = Counter(
        outcome.reason for outcome in outcomes if outcome.status == "unknown"
    )
    if any(reason not in EXCLUSION_REASONS for reason in counts):
        raise CampaignError("unexpected_ranking_exclusion")
    return {
        "total": sum(counts.values()),
        **{reason: counts[reason] for reason in EXCLUSION_REASONS},
    }


def _holdout_metrics(outcomes: Sequence[core.RankOutcome]) -> dict[str, Any]:
    successes = sum(
        outcome.status == "ranked" and outcome.winner_index == 0 for outcome in outcomes
    )
    ranked_incorrect = sum(
        outcome.status == "ranked" and outcome.winner_index != 0 for outcome in outcomes
    )
    lower, upper = core.clopper_pearson(successes, len(outcomes))
    exclusions = _exclusion_counts(outcomes)
    return {
        "recall_at_1": {"numerator": successes, "denominator": len(outcomes)},
        "exact_95_percent_interval": {"lower": lower, "upper": upper},
        "ranked_incorrect": ranked_incorrect,
        "abstentions": exclusions["total"],
        "exclusion_counts": exclusions,
    }


def _score_text(score: Optional[Decimal]) -> Optional[str]:
    return None if score is None else format(score, "f")


def evaluate_manifest(
    manifest: Mapping[str, Any], *, result_schema: str = DEFAULT_RESULT_SCHEMA
) -> dict[str, Any]:
    """Validate and deterministically evaluate one complete campaign manifest."""

    if not isinstance(manifest, Mapping):
        raise CampaignError("manifest_must_be_object")
    if (
        not isinstance(result_schema, str)
        or RUN_ID_PATTERN.fullmatch(result_schema) is None
    ):
        raise CampaignError("invalid_result_schema")
    calibration, heldout = _parse_manifest(manifest)
    scales = core.calibration_scales(
        [core.residuals(run.counter_window, run.capture_window) for run in calibration]
    )
    heldout_by_id = {run.run_id: run for run in heldout}
    outcomes: list[tuple[CampaignRun, core.RankOutcome]] = []
    for run in heldout:
        captures = [
            heldout_by_id[candidate_id].capture_window
            for candidate_id in run.candidate_run_ids
        ]
        outcomes.append(
            (run, core.rank_candidates(run.counter_window, captures, scales))
        )

    outcome_values = [outcome for _, outcome in outcomes]
    aggregate = core.summarize_holdout(outcome_values)
    aggregate["ranked_incorrect"] = sum(
        outcome.status == "ranked" and outcome.winner_index != 0
        for outcome in outcome_values
    )
    aggregate["exclusion_counts"] = _exclusion_counts(outcome_values)

    regime_results = []
    for regime in REGIMES:
        regime_outcomes = [outcome for run, outcome in outcomes if run.regime == regime]
        regime_results.append(
            {
                "regime": regime,
                "run_counts": {"total": 6, "calibration": 2, "heldout": 4},
                **_holdout_metrics(regime_outcomes),
            }
        )

    return {
        "schema": result_schema,
        "schema_version": RESULT_SCHEMA_VERSION,
        "run_counts": {"total": 24, "calibration": 8, "heldout": 16},
        "regimes": regime_results,
        "heldout_outcomes": [
            {
                "run_id": run.run_id,
                "regime": run.regime,
                "candidate_run_ids": list(run.candidate_run_ids),
                "status": outcome.status,
                "winner_index": outcome.winner_index,
                "candidate_scores": [
                    _score_text(score) for score in outcome.candidate_scores
                ],
                "reason": outcome.reason,
            }
            for run, outcome in outcomes
        ],
        "aggregate_holdout": aggregate,
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CampaignError("duplicate_json_key")
        value[key] = item
    return value


def load_manifest(source: TextIO) -> Mapping[str, Any]:
    value = json.load(source, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, Mapping):
        raise CampaignError("manifest_must_be_object")
    return value


def _arguments(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate derived counter/capture TrafficWindow metadata."
    )
    parser.add_argument(
        "manifest",
        nargs="?",
        default="-",
        help="JSON manifest path, or -/omitted for stdin",
    )
    parser.add_argument(
        "--result-schema",
        default=DEFAULT_RESULT_SCHEMA,
        help="stable output schema token",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        if arguments.manifest == "-":
            manifest = load_manifest(sys.stdin)
        else:
            with Path(arguments.manifest).open(encoding="utf-8") as source:
                manifest = load_manifest(source)
        result = evaluate_manifest(manifest, result_schema=arguments.result_schema)
    except CampaignError as error:
        print(error.code, file=sys.stderr)
        return 2
    except core.CandidateError as error:
        print(error.code, file=sys.stderr)
        return 2
    except json.JSONDecodeError:
        print("invalid_json", file=sys.stderr)
        return 2
    except OSError:
        print("manifest_io_error", file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
