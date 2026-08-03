#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9,<3.10"
# dependencies = ["numpy==2.0.2"]
# ///

"""Benchmark expanded versus compact RUFF-UWB metadata sampling."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from time import perf_counter


ROOT = Path(__file__).resolve().parents[1]
CROSS_PATH = Path(__file__).with_name("evaluate-ruff-uwb-cross-distance.py")
CROSS_SPEC = importlib.util.spec_from_file_location(
    "netbraid_benchmark_ruff_uwb_cross_distance", CROSS_PATH
)
if CROSS_SPEC is None or CROSS_SPEC.loader is None:
    raise RuntimeError("cross_distance_evaluator_import_unavailable")
CROSS = importlib.util.module_from_spec(CROSS_SPEC)
sys.modules[CROSS_SPEC.name] = CROSS
CROSS_SPEC.loader.exec_module(CROSS)
BASE = CROSS.BASE


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("compact", "expanded"), required=True)
    parser.add_argument(
        "--row-adapter",
        type=Path,
        default=(
            ROOT / "data" / "derived" / "eval" / "ruff-uwb-one-meter-row-adapter.json"
        ),
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-rows-per-atomic-group", type=int, default=8)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = CROSS.TransferConfig(
        seed=args.seed,
        max_rows_per_atomic_group=args.max_rows_per_atomic_group,
    )
    started = perf_counter()
    if args.mode == "compact":
        adapter = BASE.load_row_span_adapter(
            args.row_adapter, CROSS.PINNED_SOURCE_BINDING
        )
        selections = BASE.partition_and_sample_row_spans(adapter.spans, config.base())
        sampled = {role: selections[role].sampled for role in BASE.SPLITS}
        source_rows = sum(selections[role].source_row_count for role in BASE.SPLITS)
    else:
        adapter = BASE.load_row_adapter(args.row_adapter, CROSS.PINNED_SOURCE_BINDING)
        assigned = BASE.partition_rows(adapter.rows, config.seed)
        sampled = BASE.sample_rows(assigned, config.base())
        source_rows = sum(len(assigned[role]) for role in BASE.SPLITS)
    elapsed = perf_counter() - started
    sampled_receipt = BASE._digest_values(
        "row-sampling-benchmark",
        (f"{role}:{row.row_index}" for role in BASE.SPLITS for row in sampled[role]),
    )
    print(
        json.dumps(
            {
                "elapsed_seconds": round(elapsed, 6),
                "mode": args.mode,
                "sampled_receipt": sampled_receipt,
                "sampled_rows": sum(len(sampled[role]) for role in BASE.SPLITS),
                "source_rows": source_rows,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
