#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Compare XRF55 joint reduction with and without discarded marginals."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections.abc import Callable, Sequence
from typing import Any

import numpy as np

import xrf55_features as FEATURES
import xrf55_joint_features as JOINT


def _publisher_array(modality: str) -> np.ndarray:
    layout = FEATURES.OFFICIAL_LAYOUTS[modality]
    return np.ones(
        layout.shape,
        dtype=layout.dtype,
        order="F" if layout.fortran_order else "C",
    )


def _duration(function: Callable[[], np.ndarray]) -> float:
    started = time.perf_counter()
    result = function()
    elapsed = time.perf_counter() - started
    if result.shape != (JOINT.FEATURE_COUNT,) or not bool(np.isfinite(result).all()):
        raise RuntimeError("invalid benchmark reduction output")
    return elapsed


def _summary(samples: Sequence[float]) -> dict[str, Any]:
    return {
        "median_seconds": statistics.median(samples).hex(),
        "minimum_seconds": min(samples).hex(),
        "samples_seconds": [sample.hex() for sample in samples],
    }


def benchmark(modality: str, rounds: int) -> dict[str, Any]:
    array = _publisher_array(modality)

    def optimized() -> np.ndarray:
        return JOINT.feature_vector(modality, array)

    def discarded_marginal() -> np.ndarray:
        FEATURES.feature_vector(modality, array)
        return JOINT.feature_vector(modality, array)

    expected = optimized()
    np.testing.assert_array_equal(discarded_marginal(), expected)
    optimized_samples = []
    discarded_samples = []
    for index in range(rounds):
        first, second = (
            (optimized_samples, discarded_samples)
            if index % 2 == 0
            else (discarded_samples, optimized_samples)
        )
        first_function, second_function = (
            (optimized, discarded_marginal)
            if index % 2 == 0
            else (discarded_marginal, optimized)
        )
        first.append(_duration(first_function))
        second.append(_duration(second_function))

    optimized_median = statistics.median(optimized_samples)
    discarded_median = statistics.median(discarded_samples)
    return {
        "modality": modality,
        "optimized": _summary(optimized_samples),
        "with_discarded_marginal": _summary(discarded_samples),
        "median_speedup_ratio": (discarded_median / optimized_median).hex(),
        "median_reduction_fraction": (
            (discarded_median - optimized_median) / discarded_median
        ).hex(),
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--rounds",
        type=int,
        default=3,
        help="timed rounds per implementation and modality (default: 3)",
    )
    parser.add_argument(
        "--modality",
        action="append",
        choices=FEATURES.MODALITIES,
        dest="modalities",
        help="modality to benchmark; repeat to select several (default: all)",
    )
    args = parser.parse_args(argv)
    if not 1 <= args.rounds <= 20:
        parser.error("--rounds must be between 1 and 20")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    modalities = tuple(dict.fromkeys(args.modalities or FEATURES.MODALITIES))
    report = {
        "schema": "netbraid.xrf55_joint_feature_benchmark.v0",
        "rounds": args.rounds,
        "modalities": [benchmark(modality, args.rounds) for modality in modalities],
    }
    json.dump(report, fp=sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
