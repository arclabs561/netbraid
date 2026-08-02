#!/usr/bin/env python3
"""Finite evaluator primitives for paired counter and capture windows.

This module derives bounded, identifier-free traffic windows and provides
deterministic calibration, ranking, and holdout summaries.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Iterable, Mapping, Optional, Sequence

FEATURE_NAMES = (
    "received_bytes",
    "transmitted_bytes",
    "received_packets",
    "transmitted_packets",
    "received_share",
    "transmitted_share",
    "mean_received_packet_bytes",
    "mean_transmitted_packet_bytes",
    "mean_received_bits_per_second",
    "mean_transmitted_bits_per_second",
)
SCALE_FLOOR = Decimal("0.05")


class CandidateError(ValueError):
    """A stable exclusion reason for one inadmissible source window."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class TrafficWindow:
    duration_ms: int
    received_bytes: int
    transmitted_bytes: int
    received_packets: int
    transmitted_packets: int

    def __post_init__(self) -> None:
        values = (
            self.duration_ms,
            self.received_bytes,
            self.transmitted_bytes,
            self.received_packets,
            self.transmitted_packets,
        )
        if any(
            isinstance(value, bool) or not isinstance(value, int) for value in values
        ):
            raise CandidateError("non_integer_window_value")
        if self.duration_ms <= 0 or any(value < 0 for value in values[1:]):
            raise CandidateError("invalid_window_extent")

    def features(self) -> dict[str, Optional[Decimal]]:
        packet_total = self.received_packets + self.transmitted_packets
        return {
            "received_bytes": Decimal(self.received_bytes),
            "transmitted_bytes": Decimal(self.transmitted_bytes),
            "received_packets": Decimal(self.received_packets),
            "transmitted_packets": Decimal(self.transmitted_packets),
            "received_share": _ratio(self.received_packets, packet_total),
            "transmitted_share": _ratio(self.transmitted_packets, packet_total),
            "mean_received_packet_bytes": _ratio(
                self.received_bytes, self.received_packets
            ),
            "mean_transmitted_packet_bytes": _ratio(
                self.transmitted_bytes, self.transmitted_packets
            ),
            "mean_received_bits_per_second": Decimal(self.received_bytes)
            * Decimal(8000)
            / Decimal(self.duration_ms),
            "mean_transmitted_bits_per_second": Decimal(self.transmitted_bytes)
            * Decimal(8000)
            / Decimal(self.duration_ms),
        }


@dataclass(frozen=True)
class CaptureCandidate:
    window: TrafficWindow
    packets_seen: int
    packets_oriented: int
    packets_excluded: int


@dataclass(frozen=True)
class RankOutcome:
    status: str
    winner_index: Optional[int]
    candidate_scores: tuple[Optional[Decimal], ...]
    reason: Optional[str] = None


def _counter_value(document: Mapping[str, Any], name: str) -> int:
    value = document.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CandidateError("invalid_counter_value")
    return value


def _nonnegative_integer(value: Any, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise CandidateError(code)
    return value


def counter_window(
    first: Mapping[str, Any],
    last: Mapping[str, Any],
    *,
    first_generation: int,
    last_generation: int,
    duration_ms: int,
) -> TrafficWindow:
    """Derive one compatible counter delta without retaining identity."""

    first_generation = _nonnegative_integer(first_generation, "invalid_path_generation")
    last_generation = _nonnegative_integer(last_generation, "invalid_path_generation")
    if first_generation != last_generation:
        raise CandidateError("path_generation_changed")
    first_interface = first.get("interface")
    last_interface = last.get("interface")
    if (
        not isinstance(first_interface, str)
        or not first_interface
        or first_interface != last_interface
    ):
        raise CandidateError("interface_changed_or_missing")
    names = (
        "received_bytes",
        "transmitted_bytes",
        "received_packets",
        "transmitted_packets",
    )
    before = {name: _counter_value(first, name) for name in names}
    after = {name: _counter_value(last, name) for name in names}
    if any(after[name] < before[name] for name in names):
        raise CandidateError("counter_reset")
    return TrafficWindow(
        duration_ms=duration_ms,
        received_bytes=after["received_bytes"] - before["received_bytes"],
        transmitted_bytes=after["transmitted_bytes"] - before["transmitted_bytes"],
        received_packets=after["received_packets"] - before["received_packets"],
        transmitted_packets=(
            after["transmitted_packets"] - before["transmitted_packets"]
        ),
    )


def _packet_endpoints(packet: Mapping[str, Any]) -> Optional[tuple[str, str]]:
    for family in ("ipv4", "ipv6", "ethernet", "ieee80211"):
        value = packet.get(family)
        if not isinstance(value, Mapping):
            continue
        source = value.get("source")
        destination = value.get("destination")
        if (
            isinstance(source, str)
            and source
            and isinstance(destination, str)
            and destination
        ):
            return source.casefold(), destination.casefold()
    return None


def capture_window(
    manifest: Mapping[str, Any],
    packets: Sequence[Mapping[str, Any]],
    *,
    local_addresses: Iterable[str],
    duration_ms: int,
) -> CaptureCandidate:
    """Aggregate a complete normalized capture, discarding orientation addresses."""

    normalization = manifest.get("normalization")
    if not isinstance(normalization, Mapping):
        raise CandidateError("capture_normalization_missing")
    if normalization.get("state") != "complete":
        raise CandidateError("capture_partial")
    if normalization.get("packet_limit_reached") is not False:
        raise CandidateError("capture_packet_limit_reached")
    quarantined = _nonnegative_integer(
        normalization.get("packet_rows_quarantined"),
        "invalid_capture_quarantine_count",
    )
    emitted = _nonnegative_integer(
        normalization.get("packet_rows_emitted"), "invalid_capture_packet_count"
    )
    if quarantined != 0:
        raise CandidateError("capture_quarantined")
    if emitted != len(packets):
        raise CandidateError("capture_packet_count_mismatch")

    addresses = {
        value.casefold()
        for value in local_addresses
        if isinstance(value, str) and value
    }
    if not addresses:
        raise CandidateError("orientation_addresses_missing")

    received_bytes = transmitted_bytes = 0
    received_packets = transmitted_packets = 0
    excluded = 0
    for packet in packets:
        frame = packet.get("frame")
        original_len = frame.get("original_len") if isinstance(frame, Mapping) else None
        if (
            isinstance(original_len, bool)
            or not isinstance(original_len, int)
            or original_len < 0
        ):
            raise CandidateError("invalid_packet_extent")
        endpoints = _packet_endpoints(packet)
        if endpoints is None:
            excluded += 1
            continue
        source, destination = endpoints
        source_local = source in addresses
        destination_local = destination in addresses
        if source_local == destination_local:
            excluded += 1
        elif source_local:
            transmitted_packets += 1
            transmitted_bytes += original_len
        else:
            received_packets += 1
            received_bytes += original_len
    oriented = received_packets + transmitted_packets
    if oriented == 0:
        raise CandidateError("no_oriented_packets")
    return CaptureCandidate(
        window=TrafficWindow(
            duration_ms=duration_ms,
            received_bytes=received_bytes,
            transmitted_bytes=transmitted_bytes,
            received_packets=received_packets,
            transmitted_packets=transmitted_packets,
        ),
        packets_seen=len(packets),
        packets_oriented=oriented,
        packets_excluded=excluded,
    )


def _ratio(numerator: int, denominator: int) -> Optional[Decimal]:
    if denominator == 0:
        return None
    return Decimal(numerator) / Decimal(denominator)


def residuals(counter: TrafficWindow, capture: TrafficWindow) -> dict[str, Decimal]:
    counter_features = counter.features()
    capture_features = capture.features()
    result: dict[str, Decimal] = {}
    for name in FEATURE_NAMES:
        expected = counter_features[name]
        observed = capture_features[name]
        if expected is None or observed is None:
            if expected is observed:
                result[name] = Decimal(0)
                continue
            raise CandidateError("incomparable_sparse_feature")
        result[name] = abs(expected - observed) / max(abs(expected), Decimal(1))
    return result


def calibration_scales(
    calibration_residuals: Sequence[Mapping[str, Decimal]],
    *,
    expected_runs: int = 8,
) -> dict[str, Decimal]:
    """Lock one robust feature scale from a declared calibration split."""

    if expected_runs <= 0 or len(calibration_residuals) != expected_runs:
        code = (
            "calibration_requires_eight_runs"
            if expected_runs == 8
            else "calibration_run_count_mismatch"
        )
        raise CandidateError(code)
    scales = {}
    for name in FEATURE_NAMES:
        values = sorted(item[name] for item in calibration_residuals)
        midpoint = len(values) // 2
        if len(values) % 2 == 0:
            median = (values[midpoint - 1] + values[midpoint]) / Decimal(2)
        else:
            median = values[midpoint]
        scales[name] = max(median, SCALE_FLOOR)
    return scales


def distance(
    counter: TrafficWindow, capture: TrafficWindow, scales: Mapping[str, Decimal]
) -> Decimal:
    if set(scales) != set(FEATURE_NAMES) or any(
        value <= 0 for value in scales.values()
    ):
        raise CandidateError("invalid_calibration_scales")
    values = residuals(counter, capture)
    return sum((values[name] / scales[name] for name in FEATURE_NAMES), Decimal(0))


def rank_candidates(
    counter: TrafficWindow,
    captures: Sequence[Optional[TrafficWindow]],
    scales: Mapping[str, Decimal],
    *,
    expected_candidates: int = 4,
) -> RankOutcome:
    """Rank a declared candidate set; ties and exclusions abstain."""

    if expected_candidates < 2 or len(captures) != expected_candidates:
        code = (
            "ranking_requires_four_candidates"
            if expected_candidates == 4
            else "ranking_candidate_count_mismatch"
        )
        raise CandidateError(code)
    scores: list[Optional[Decimal]] = []
    for capture in captures:
        if capture is None:
            scores.append(None)
            continue
        try:
            scores.append(distance(counter, capture, scales))
        except CandidateError:
            scores.append(None)
    if any(score is None for score in scores):
        return RankOutcome("unknown", None, tuple(scores), "candidate_excluded")
    admissible = [
        (score, index) for index, score in enumerate(scores) if score is not None
    ]
    best = min(score for score, _ in admissible)
    winners = [index for score, index in admissible if score == best]
    if len(winners) != 1:
        return RankOutcome("unknown", None, tuple(scores), "minimum_distance_tie")
    return RankOutcome("ranked", winners[0], tuple(scores))


def _binomial_cdf(k: int, n: int, probability: float) -> float:
    return sum(
        math.comb(n, index) * probability**index * (1.0 - probability) ** (n - index)
        for index in range(k + 1)
    )


def clopper_pearson(
    successes: int, trials: int, alpha: float = 0.05
) -> tuple[float, float]:
    """Return the equal-tailed exact binomial interval by bounded bisection."""

    if not 0 <= successes <= trials or trials <= 0 or not 0.0 < alpha < 1.0:
        raise CandidateError("invalid_binomial_interval_input")
    if successes == 0:
        lower = 0.0
    else:
        lo, hi = 0.0, successes / trials
        for _ in range(80):
            midpoint = (lo + hi) / 2.0
            survival = 1.0 - _binomial_cdf(successes - 1, trials, midpoint)
            if survival < alpha / 2.0:
                lo = midpoint
            else:
                hi = midpoint
        lower = (lo + hi) / 2.0
    if successes == trials:
        upper = 1.0
    else:
        lo, hi = successes / trials, 1.0
        for _ in range(80):
            midpoint = (lo + hi) / 2.0
            if _binomial_cdf(successes, trials, midpoint) > alpha / 2.0:
                lo = midpoint
            else:
                hi = midpoint
        upper = (lo + hi) / 2.0
    return lower, upper


def summarize_holdout(
    outcomes: Sequence[RankOutcome],
    *,
    expected_winner_indices: Optional[Sequence[int]] = None,
    expected_runs: int = 16,
    minimum_successes: int = 12,
) -> dict[str, Any]:
    if expected_runs <= 0 or len(outcomes) != expected_runs:
        code = (
            "holdout_requires_sixteen_runs"
            if expected_runs == 16
            else "holdout_run_count_mismatch"
        )
        raise CandidateError(code)
    if expected_winner_indices is None:
        expected_winner_indices = (0,) * len(outcomes)
    if len(expected_winner_indices) != len(outcomes) or any(
        isinstance(index, bool) or not isinstance(index, int) or index < 0
        for index in expected_winner_indices
    ):
        raise CandidateError("invalid_expected_winner_indices")
    if not 0 <= minimum_successes <= len(outcomes):
        raise CandidateError("invalid_minimum_successes")
    successes = sum(
        outcome.status == "ranked" and outcome.winner_index == expected_index
        for outcome, expected_index in zip(outcomes, expected_winner_indices)
    )
    abstentions = sum(outcome.status == "unknown" for outcome in outcomes)
    lower, upper = clopper_pearson(successes, len(outcomes))
    return {
        "recall_at_1": {"numerator": successes, "denominator": len(outcomes)},
        "exact_95_percent_interval": {"lower": lower, "upper": upper},
        "abstentions": abstentions,
        "gate": "pass" if successes >= minimum_successes else "fail",
    }
