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

LEGACY_MANIFEST_SCHEMA_VERSION = 1
POLICY_MANIFEST_SCHEMA_VERSION = 2
# Kept for callers that imported the original single-version constant.
MANIFEST_SCHEMA_VERSION = LEGACY_MANIFEST_SCHEMA_VERSION
RESULT_SCHEMA_VERSION = 1
POLICY_RESULT_SCHEMA_VERSION = 2
DEFAULT_RESULT_SCHEMA = "netbraid.counter_capture_campaign_evaluation"
REGIMES = ("idle", "download", "upload", "bidirectional")
POLICY_FIELDS = (
    "regimes",
    "calibration_runs_per_regime",
    "heldout_runs_per_regime",
    "candidate_count",
    "minimum_successes",
)
MAX_CAMPAIGN_RUNS = 10_000
MAX_CANDIDATES = 256
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
POLICY_CALIBRATION_FIELDS = CALIBRATION_FIELDS + ("split_group_id",)
POLICY_HELDOUT_FIELDS = POLICY_CALIBRATION_FIELDS + (
    "true_candidate_index",
    "candidate_run_ids",
)
RUN_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
EXCLUSION_REASONS = ("candidate_excluded", "minimum_distance_tie")
DEPENDENT_OUTCOMES_REASON = "shared_calibration_and_reused_candidate_windows"


class CampaignError(ValueError):
    """A stable fail-closed reason for an invalid campaign manifest."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CampaignPolicy:
    regimes: tuple[str, ...]
    calibration_runs_per_regime: int
    heldout_runs_per_regime: int
    candidate_count: int
    minimum_successes: int

    @property
    def calibration_runs(self) -> int:
        return len(self.regimes) * self.calibration_runs_per_regime

    @property
    def heldout_runs(self) -> int:
        return len(self.regimes) * self.heldout_runs_per_regime

    @property
    def total_runs(self) -> int:
        return self.calibration_runs + self.heldout_runs

    def document(self) -> dict[str, Any]:
        return {
            "regimes": list(self.regimes),
            "calibration_runs_per_regime": self.calibration_runs_per_regime,
            "heldout_runs_per_regime": self.heldout_runs_per_regime,
            "candidate_count": self.candidate_count,
            "minimum_successes": self.minimum_successes,
        }


LEGACY_POLICY = CampaignPolicy(
    regimes=REGIMES,
    calibration_runs_per_regime=2,
    heldout_runs_per_regime=4,
    candidate_count=4,
    minimum_successes=12,
)


@dataclass(frozen=True)
class CampaignRun:
    run_id: str
    regime: str
    counter_window: core.TrafficWindow
    capture_window: core.TrafficWindow
    split_group_id: Optional[str] = None
    true_candidate_index: Optional[int] = None
    candidate_run_ids: tuple[str, ...] = ()


def _expect_fields(value: Mapping[str, Any], fields: Sequence[str], code: str) -> None:
    if set(value) != set(fields):
        raise CampaignError(code)


def _parse_window(value: Any) -> core.TrafficWindow:
    if not isinstance(value, Mapping):
        raise CampaignError("invalid_traffic_window_schema")
    _expect_fields(value, WINDOW_FIELDS, "invalid_traffic_window_schema")
    return core.TrafficWindow(**{name: value[name] for name in WINDOW_FIELDS})


def _bounded_integer(value: Any, *, minimum: int, maximum: int, code: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise CampaignError(code)
    return value


def _parse_policy(value: Any) -> CampaignPolicy:
    if not isinstance(value, Mapping):
        raise CampaignError("invalid_campaign_policy")
    _expect_fields(value, POLICY_FIELDS, "invalid_campaign_policy")
    regimes = value["regimes"]
    if (
        not isinstance(regimes, list)
        or not regimes
        or any(
            not isinstance(regime, str) or RUN_ID_PATTERN.fullmatch(regime) is None
            for regime in regimes
        )
        or len(set(regimes)) != len(regimes)
    ):
        raise CampaignError("invalid_policy_regimes")
    calibration_per_regime = _bounded_integer(
        value["calibration_runs_per_regime"],
        minimum=1,
        maximum=MAX_CAMPAIGN_RUNS,
        code="invalid_policy_calibration_runs_per_regime",
    )
    heldout_per_regime = _bounded_integer(
        value["heldout_runs_per_regime"],
        minimum=2,
        maximum=MAX_CAMPAIGN_RUNS,
        code="invalid_policy_heldout_runs_per_regime",
    )
    candidate_count = _bounded_integer(
        value["candidate_count"],
        minimum=2,
        maximum=MAX_CANDIDATES,
        code="invalid_policy_candidate_count",
    )
    if candidate_count > heldout_per_regime:
        raise CampaignError("policy_candidates_exceed_regime_holdout")
    heldout_runs = len(regimes) * heldout_per_regime
    total_runs = len(regimes) * (calibration_per_regime + heldout_per_regime)
    if total_runs > MAX_CAMPAIGN_RUNS:
        raise CampaignError("campaign_policy_exceeds_run_limit")
    minimum_successes = _bounded_integer(
        value["minimum_successes"],
        minimum=1,
        maximum=heldout_runs,
        code="invalid_policy_minimum_successes",
    )
    if minimum_successes <= heldout_runs // candidate_count:
        raise CampaignError("policy_gate_not_above_random_expectation")
    return CampaignPolicy(
        regimes=tuple(regimes),
        calibration_runs_per_regime=calibration_per_regime,
        heldout_runs_per_regime=heldout_per_regime,
        candidate_count=candidate_count,
        minimum_successes=minimum_successes,
    )


def _parse_run(
    value: Any,
    *,
    heldout: bool,
    policy: CampaignPolicy,
    legacy_schema: bool,
) -> CampaignRun:
    if not isinstance(value, Mapping):
        raise CampaignError("invalid_run_schema")
    _expect_fields(
        value,
        (
            HELDOUT_FIELDS
            if legacy_schema and heldout
            else CALIBRATION_FIELDS
            if legacy_schema
            else POLICY_HELDOUT_FIELDS
            if heldout
            else POLICY_CALIBRATION_FIELDS
        ),
        "invalid_run_schema",
    )
    run_id = value["run_id"]
    if not isinstance(run_id, str) or RUN_ID_PATTERN.fullmatch(run_id) is None:
        raise CampaignError("invalid_run_id")
    regime = value["regime"]
    if regime not in policy.regimes:
        raise CampaignError("invalid_regime")

    split_group_id: Optional[str] = None
    if not legacy_schema:
        group = value["split_group_id"]
        if not isinstance(group, str) or RUN_ID_PATTERN.fullmatch(group) is None:
            raise CampaignError("invalid_split_group_id")
        split_group_id = group

    true_candidate_index: Optional[int] = None
    candidate_run_ids: tuple[str, ...] = ()
    if heldout:
        true_index = value["true_candidate_index"]
        if legacy_schema:
            if (
                isinstance(true_index, bool)
                or not isinstance(true_index, int)
                or true_index != 0
            ):
                raise CampaignError("true_candidate_index_must_be_zero")
        else:
            true_index = _bounded_integer(
                true_index,
                minimum=0,
                maximum=policy.candidate_count - 1,
                code="invalid_true_candidate_index",
            )
        candidates = value["candidate_run_ids"]
        if (
            not isinstance(candidates, list)
            or len(candidates) != policy.candidate_count
        ):
            raise CampaignError(
                "heldout_requires_four_candidates"
                if legacy_schema
                else "heldout_candidate_count_mismatch"
            )
        if any(
            not isinstance(candidate, str)
            or RUN_ID_PATTERN.fullmatch(candidate) is None
            for candidate in candidates
        ):
            raise CampaignError("invalid_candidate_run_id")
        true_candidate_index = true_index
        candidate_run_ids = tuple(candidates)

    return CampaignRun(
        run_id=run_id,
        regime=regime,
        counter_window=_parse_window(value["counter_window"]),
        capture_window=_parse_window(value["capture_window"]),
        split_group_id=split_group_id,
        true_candidate_index=true_candidate_index,
        candidate_run_ids=candidate_run_ids,
    )


def _parse_run_list(
    value: Any,
    *,
    heldout: bool,
    policy: CampaignPolicy,
    legacy_schema: bool,
) -> list[CampaignRun]:
    if not isinstance(value, list):
        raise CampaignError("invalid_run_list")
    return [
        _parse_run(
            item,
            heldout=heldout,
            policy=policy,
            legacy_schema=legacy_schema,
        )
        for item in value
    ]


def _regime_order(run: CampaignRun, policy: CampaignPolicy) -> tuple[int, str]:
    return policy.regimes.index(run.regime), run.run_id


def _parse_manifest(
    manifest: Mapping[str, Any],
) -> tuple[int, CampaignPolicy, list[CampaignRun], list[CampaignRun]]:
    if "schema_version" not in manifest:
        raise CampaignError("invalid_manifest_schema")
    schema_version = manifest["schema_version"]
    if (
        isinstance(schema_version, bool)
        or not isinstance(schema_version, int)
        or schema_version
        not in (LEGACY_MANIFEST_SCHEMA_VERSION, POLICY_MANIFEST_SCHEMA_VERSION)
    ):
        raise CampaignError("unsupported_manifest_schema_version")
    legacy_schema = schema_version == LEGACY_MANIFEST_SCHEMA_VERSION
    _expect_fields(
        manifest,
        (
            ("schema_version", "calibration_runs", "heldout_runs")
            if legacy_schema
            else ("schema_version", "policy", "calibration_runs", "heldout_runs")
        ),
        "invalid_manifest_schema",
    )
    policy = LEGACY_POLICY if legacy_schema else _parse_policy(manifest["policy"])

    calibration = _parse_run_list(
        manifest["calibration_runs"],
        heldout=False,
        policy=policy,
        legacy_schema=legacy_schema,
    )
    heldout = _parse_run_list(
        manifest["heldout_runs"],
        heldout=True,
        policy=policy,
        legacy_schema=legacy_schema,
    )
    if len(calibration) + len(heldout) != policy.total_runs:
        raise CampaignError(
            "campaign_requires_twenty_four_runs"
            if legacy_schema
            else "campaign_run_count_mismatch"
        )
    if (
        len(calibration) != policy.calibration_runs
        or len(heldout) != policy.heldout_runs
    ):
        raise CampaignError(
            "campaign_requires_eight_calibration_and_sixteen_heldout"
            if legacy_schema
            else "campaign_split_count_mismatch"
        )

    calibration_ids = [run.run_id for run in calibration]
    heldout_ids = [run.run_id for run in heldout]
    if len(set(calibration_ids)) != len(calibration_ids) or len(
        set(heldout_ids)
    ) != len(heldout_ids):
        raise CampaignError("duplicate_run_id")
    if set(calibration_ids) & set(heldout_ids):
        raise CampaignError("calibration_heldout_overlap")
    if not legacy_schema:
        calibration_groups = {run.split_group_id for run in calibration}
        heldout_groups = {run.split_group_id for run in heldout}
        if calibration_groups & heldout_groups:
            raise CampaignError("calibration_heldout_group_overlap")

    all_counts = Counter(run.regime for run in calibration + heldout)
    calibration_counts = Counter(run.regime for run in calibration)
    heldout_counts = Counter(run.regime for run in heldout)
    if any(
        all_counts[regime]
        != policy.calibration_runs_per_regime + policy.heldout_runs_per_regime
        for regime in policy.regimes
    ):
        raise CampaignError(
            "each_regime_requires_six_runs"
            if legacy_schema
            else "each_regime_run_count_mismatch"
        )
    if any(
        calibration_counts[regime] != policy.calibration_runs_per_regime
        for regime in policy.regimes
    ) or any(
        heldout_counts[regime] != policy.heldout_runs_per_regime
        for regime in policy.regimes
    ):
        raise CampaignError(
            "each_regime_requires_two_calibration_four_heldout"
            if legacy_schema
            else "each_regime_split_count_mismatch"
        )

    heldout_by_id = {run.run_id: run for run in heldout}
    for run in heldout:
        true_index = run.true_candidate_index
        if true_index is None or run.candidate_run_ids[true_index] != run.run_id:
            raise CampaignError("true_candidate_must_reference_self")
        decoy_ids = tuple(
            candidate_id
            for index, candidate_id in enumerate(run.candidate_run_ids)
            if index != true_index
        )
        if len(set(decoy_ids)) != policy.candidate_count - 1 or run.run_id in decoy_ids:
            raise CampaignError("decoys_must_reference_distinct_runs")
        if tuple(sorted(decoy_ids)) != decoy_ids:
            raise CampaignError("decoys_must_be_canonically_ordered")
        for decoy_id in decoy_ids:
            decoy = heldout_by_id.get(decoy_id)
            if decoy is None:
                raise CampaignError("decoy_must_reference_heldout_run")
            if decoy.regime != run.regime:
                raise CampaignError("decoy_regime_mismatch")

    return (
        schema_version,
        policy,
        sorted(calibration, key=lambda run: _regime_order(run, policy)),
        sorted(heldout, key=lambda run: _regime_order(run, policy)),
    )


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


def _holdout_metrics(
    outcomes: Sequence[tuple[CampaignRun, core.RankOutcome]],
    *,
    report_exact_interval: bool,
) -> dict[str, Any]:
    successes = sum(
        outcome.status == "ranked" and outcome.winner_index == run.true_candidate_index
        for run, outcome in outcomes
    )
    ranked_incorrect = sum(
        outcome.status == "ranked" and outcome.winner_index != run.true_candidate_index
        for run, outcome in outcomes
    )
    exclusions = _exclusion_counts([outcome for _, outcome in outcomes])
    result = {
        "recall_at_1": {"numerator": successes, "denominator": len(outcomes)},
        "ranked_incorrect": ranked_incorrect,
        "abstentions": exclusions["total"],
        "exclusion_counts": exclusions,
    }
    if report_exact_interval:
        lower, upper = core.clopper_pearson(successes, len(outcomes))
        result["exact_95_percent_interval"] = {"lower": lower, "upper": upper}
    else:
        result["uncertainty"] = {
            "status": "not_reported",
            "reason": DEPENDENT_OUTCOMES_REASON,
        }
    return result


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
    manifest_schema_version, policy, calibration, heldout = _parse_manifest(manifest)
    scales = core.calibration_scales(
        [core.residuals(run.counter_window, run.capture_window) for run in calibration],
        expected_runs=policy.calibration_runs,
    )
    heldout_by_id = {run.run_id: run for run in heldout}
    outcomes: list[tuple[CampaignRun, core.RankOutcome]] = []
    for run in heldout:
        captures = [
            heldout_by_id[candidate_id].capture_window
            for candidate_id in run.candidate_run_ids
        ]
        outcomes.append(
            (
                run,
                core.rank_candidates(
                    run.counter_window,
                    captures,
                    scales,
                    expected_candidates=policy.candidate_count,
                ),
            )
        )

    outcome_values = [outcome for _, outcome in outcomes]
    aggregate = core.summarize_holdout(
        outcome_values,
        expected_winner_indices=[run.true_candidate_index for run, _ in outcomes],
        expected_runs=policy.heldout_runs,
        minimum_successes=policy.minimum_successes,
    )
    aggregate["ranked_incorrect"] = sum(
        outcome.status == "ranked" and outcome.winner_index != run.true_candidate_index
        for run, outcome in outcomes
    )
    aggregate["exclusion_counts"] = _exclusion_counts(outcome_values)
    if manifest_schema_version == POLICY_MANIFEST_SCHEMA_VERSION:
        aggregate["acceptance_gate"] = aggregate.pop("gate")
        aggregate.pop("exact_95_percent_interval")
        aggregate["uncertainty"] = {
            "status": "not_reported",
            "reason": DEPENDENT_OUTCOMES_REASON,
        }

    regime_results = []
    for regime in policy.regimes:
        regime_outcomes = [item for item in outcomes if item[0].regime == regime]
        regime_results.append(
            {
                "regime": regime,
                "run_counts": {
                    "total": policy.calibration_runs_per_regime
                    + policy.heldout_runs_per_regime,
                    "calibration": policy.calibration_runs_per_regime,
                    "heldout": policy.heldout_runs_per_regime,
                },
                **_holdout_metrics(
                    regime_outcomes,
                    report_exact_interval=(
                        manifest_schema_version == LEGACY_MANIFEST_SCHEMA_VERSION
                    ),
                ),
            }
        )

    result = {
        "schema": result_schema,
        "schema_version": (
            RESULT_SCHEMA_VERSION
            if manifest_schema_version == LEGACY_MANIFEST_SCHEMA_VERSION
            else POLICY_RESULT_SCHEMA_VERSION
        ),
        "run_counts": {
            "total": policy.total_runs,
            "calibration": policy.calibration_runs,
            "heldout": policy.heldout_runs,
        },
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
    if manifest_schema_version == POLICY_MANIFEST_SCHEMA_VERSION:
        result["policy"] = policy.document()
        for item, (run, _) in zip(result["heldout_outcomes"], outcomes):
            item["true_candidate_index"] = run.true_candidate_index
            item["split_group_id"] = run.split_group_id
    return result


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
