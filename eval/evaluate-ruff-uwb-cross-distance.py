#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9,<3.10"
# dependencies = ["numpy==2.0.2"]
# ///

"""Evaluate frozen one-meter RUFF-UWB rules on the two-meter campaign.

The evaluator selects between two simple prototype rules using only one-meter
train and validation locations. It never featurizes the one-meter test split.
All two-meter locations are assigned to the final target role before bounded
row sampling. Both waveform arrays remain read-only NumPy memory maps.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


ROOT = Path(__file__).resolve().parents[1]
BASE_PATH = Path(__file__).with_name("evaluate-ruff-uwb-heldout-location.py")
BASE_SPEC = importlib.util.spec_from_file_location(
    "netbraid_evaluate_ruff_uwb_heldout_location", BASE_PATH
)
if BASE_SPEC is None or BASE_SPEC.loader is None:
    raise RuntimeError("heldout_evaluator_import_unavailable")
BASE = importlib.util.module_from_spec(BASE_SPEC)
sys.modules[BASE_SPEC.name] = BASE
BASE_SPEC.loader.exec_module(BASE)

COMPILER_PATH = Path(__file__).with_name("compile-ruff-uwb-row-adapter.py")
COMPILER_SPEC = importlib.util.spec_from_file_location(
    "netbraid_compile_ruff_uwb_row_adapter", COMPILER_PATH
)
if COMPILER_SPEC is None or COMPILER_SPEC.loader is None:
    raise RuntimeError("row_adapter_compiler_import_unavailable")
COMPILER = importlib.util.module_from_spec(COMPILER_SPEC)
sys.modules[COMPILER_SPEC.name] = COMPILER
COMPILER_SPEC.loader.exec_module(COMPILER)

np = BASE.np
REPORT_SCHEMA = "netbraid.ruff_uwb_cross_distance_eval.v0"
PROJECTION = "magnitude_gradient_peak_align_common_crop_center_l2_v0"


def binding_from_contract(contract: Any) -> Any:
    """Project the compiler's immutable archive contract into evaluator form."""

    def member(value: Any, *, include_sha256: bool) -> Dict[str, Any]:
        projected = {
            "member_bytes": value.file_bytes,
            "compressed_bytes": value.compressed_bytes,
            "crc32": f"{value.crc32:08x}",
            "compression": value.compression,
            "flags": value.flags,
            "header_offset": value.header_offset,
            "npy_version": [1, 0],
            "dtype": value.dtype,
            "fortran_order": False,
            "shape": list(value.shape),
        }
        if include_sha256:
            projected["sha256"] = value.sha256
        return projected

    if contract.label.sha256 is None:
        raise BASE.EvaluationInputError("label_contract_digest_missing")
    return BASE.RowAdapterBinding(
        archive={
            "archive_bytes": contract.archive_bytes,
            "archive_md5": contract.archive_md5,
            "archive_sha256": contract.archive_sha256,
            "receipt_schema": COMPILER.RECEIPT_SCHEMA,
        },
        label_member=member(contract.label, include_sha256=True),
        waveform_member=member(contract.waveform, include_sha256=False),
    )


PINNED_SOURCE_BINDING = binding_from_contract(
    COMPILER.PRODUCTION_CONTRACTS["distance-1"]
)
PINNED_TARGET_BINDING = binding_from_contract(
    COMPILER.PRODUCTION_CONTRACTS["distance-2"]
)


@dataclass(frozen=True)
class TransferConfig:
    seed: int = 0
    max_rows_per_atomic_group: int = 8
    window_length: int = 128
    windows_per_row: int = 4
    common_signal_length: int = 200
    alignment_index: int = 40

    def base(self) -> Any:
        config = BASE.EvaluationConfig(
            seed=self.seed,
            max_rows_per_atomic_group=self.max_rows_per_atomic_group,
            window_length=self.window_length,
            windows_per_row=self.windows_per_row,
        )
        config.validate()
        if (
            type(self.common_signal_length) is not int
            or not self.window_length
            <= self.common_signal_length
            <= BASE.MAX_SIGNAL_SAMPLES
        ):
            raise BASE.EvaluationInputError("invalid_common_signal_length")
        if (
            type(self.alignment_index) is not int
            or not 0 <= self.alignment_index < self.common_signal_length
        ):
            raise BASE.EvaluationInputError("invalid_alignment_index")
        return config


def _device_map(rows: Sequence[Any]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for row in rows:
        prior = mapping.setdefault(row.physical_source, row.physical_device)
        if prior != row.physical_device:
            raise BASE.EvaluationInputError("physical_source_device_not_bijective")
    return mapping


def _validate_transfer_adapters(source: Any, target: Any) -> None:
    source_map = _device_map(source.rows)
    target_map = _device_map(target.rows)
    if source_map != target_map:
        raise BASE.EvaluationInputError("cross_distance_identity_mismatch")
    source_collections = {row.distance_collection for row in source.rows}
    target_collections = {row.distance_collection for row in target.rows}
    if len(source_collections) != 1 or len(target_collections) != 1:
        raise BASE.EvaluationInputError("cross_distance_collection_count")
    if source_collections == target_collections:
        raise BASE.EvaluationInputError("cross_distance_collection_alias")


def _sample_target_rows(
    rows: Sequence[Any], adapter_id: str, config: TransferConfig
) -> Tuple[Any, ...]:
    base = config.base()
    groups: Dict[Tuple[str, str, str, str], List[Any]] = defaultdict(list)
    for row in rows:
        groups[row.atomic_group()].append(row)
    selected: List[Any] = []
    for group, candidates in sorted(groups.items()):
        ranked = sorted(
            candidates,
            key=lambda row: (
                BASE._hash_parts(
                    base.seed,
                    "cross-distance-target-row-sample",
                    adapter_id,
                    *group,
                    row.row_index,
                ),
                row.row_index,
            ),
        )
        selected.extend(ranked[: base.max_rows_per_atomic_group])
    return tuple(sorted(selected, key=lambda row: (row.atomic_group(), row.row_index)))


def _project_row(waveforms: Any, row: Any, config: TransferConfig) -> Any:
    base = config.base()
    signal = np.asarray(waveforms[row.row_index])
    if signal.ndim != 1 or len(signal) < config.common_signal_length:
        raise BASE.EvaluationInputError("signal_shorter_than_common_projection")
    magnitude = np.asarray(np.abs(signal), dtype=np.float64)
    if not np.all(np.isfinite(magnitude)):
        raise BASE.EvaluationInputError("selected_window_not_finite")
    peak = int(np.argmax(np.gradient(magnitude)))
    aligned = np.roll(magnitude, config.alignment_index - peak)
    common = aligned[: config.common_signal_length]
    features = []
    for start in BASE._window_starts(len(common), base):
        window = common[start : start + base.window_length]
        centered = window - np.mean(window)
        amplitude = float(np.sqrt(np.sum(centered**2)))
        if not np.isfinite(amplitude) or amplitude <= np.finfo(np.float64).eps:
            raise BASE.EvaluationInputError("selected_window_zero_amplitude")
        features.append(centered / amplitude)
    return BASE.RowFeatures(metadata=row, windows=np.stack(features, axis=0))


def _project_rows(
    waveforms: Any, rows: Sequence[Any], config: TransferConfig
) -> Tuple[Any, ...]:
    return tuple(_project_row(waveforms, row, config) for row in rows)


def _qualified_row_receipt(adapter_id: str, rows: Sequence[Any]) -> str:
    return BASE._digest_values(
        "source-qualified-rows",
        (f"{adapter_id}:{row.row_index}" for row in rows),
    )


def _source_receipt(loaded: Any, contract: Any, adapter_id: str) -> Dict[str, Any]:
    return {
        "adapter_id": adapter_id,
        "array_rows": loaded.array.shape[0],
        "samples_per_row": loaded.array.shape[1],
        "dtype": loaded.array.dtype.str,
        "file_bytes": loaded.file_bytes,
        "sha256": contract.sha256,
        "numpy_mmap": loaded.mmap_used,
        "mmap_writeable": bool(loaded.array.flags.writeable),
        "input_path_retained": False,
    }


def _role_receipt(
    adapter_id: str,
    assigned: Sequence[Any],
    sampled: Sequence[Any],
    features: Sequence[Any],
) -> Dict[str, Any]:
    return {
        "location_count": len({row.location for row in assigned}),
        "atomic_group_count": len({row.atomic_group() for row in assigned}),
        "source_row_count": len(assigned),
        "sampled_row_count": len(sampled),
        "feature_row_count": len(features),
        "window_count": sum(len(row.windows) for row in features),
        "sampled_row_receipt": _qualified_row_receipt(adapter_id, sampled),
    }


def _identity_overlap(
    left_adapter: str,
    left: Sequence[Any],
    right_adapter: str,
    right: Sequence[Any],
) -> int:
    left_ids = {(left_adapter, row.row_index) for row in left}
    right_ids = {(right_adapter, row.row_index) for row in right}
    return len(left_ids & right_ids)


def evaluate_transfer(
    source_adapter: Any,
    source_waveform_path: Path,
    target_adapter: Any,
    target_waveform_path: Path,
    config: Optional[TransferConfig] = None,
) -> Dict[str, Any]:
    """Fit/select on one meter and evaluate once on all two-meter locations."""

    selected = config or TransferConfig()
    base = selected.base()
    _validate_transfer_adapters(source_adapter, target_adapter)
    if (
        source_adapter.source_contract.samples_per_row < selected.common_signal_length
        or target_adapter.source_contract.samples_per_row
        < selected.common_signal_length
    ):
        raise BASE.EvaluationInputError("signal_shorter_than_common_projection")

    # The operation order is a leakage contract: roles and bounded samples are
    # fixed before either waveform source is opened.
    source_assigned = BASE.partition_rows(source_adapter.rows, base.seed)
    source_sampled = BASE.sample_rows(source_assigned, base)
    target_sampled = _sample_target_rows(
        target_adapter.rows, target_adapter.adapter_id, selected
    )
    feature_values = (
        (
            len(source_sampled["train"])
            + len(source_sampled["validation"])
            + len(target_sampled)
        )
        * base.windows_per_row
        * base.window_length
    )
    if feature_values > BASE.MAX_FEATURE_VALUES:
        raise BASE.EvaluationInputError("feature_memory_bound")

    source_loaded = BASE.load_waveforms(
        source_waveform_path, source_adapter.source_contract
    )
    target_loaded = BASE.load_waveforms(
        target_waveform_path, target_adapter.source_contract
    )
    source_train = _project_rows(source_loaded.array, source_sampled["train"], selected)
    source_validation = _project_rows(
        source_loaded.array, source_sampled["validation"], selected
    )
    target_test = _project_rows(target_loaded.array, target_sampled, selected)

    expected_devices = set(_device_map(source_adapter.rows).values())
    for role, features in (
        ("source_train", source_train),
        ("source_validation", source_validation),
        ("target_test", target_test),
    ):
        if {row.metadata.physical_device for row in features} != expected_devices:
            raise BASE.EvaluationInputError(f"{role}_missing_device")

    candidates: Dict[str, Dict[str, Any]] = {}
    prototype_sets: Dict[str, Any] = {}
    for mode in BASE.PROTOTYPE_MODES:
        prototypes = BASE.fit_prototypes(source_train, mode)
        truths, predictions = BASE.predict_rows(source_validation, prototypes)
        metrics = BASE._metric_summary(truths, predictions, prototypes.labels)
        prototype_sets[mode] = prototypes
        candidates[mode] = {
            "macro_f1": metrics["macro_f1"],
            "balanced_accuracy": metrics["balanced_accuracy"],
            "evaluated_rows": metrics["evaluated_rows"],
        }
    chosen_mode = min(
        BASE.PROTOTYPE_MODES,
        key=lambda mode: (
            -candidates[mode]["macro_f1"],
            -candidates[mode]["balanced_accuracy"],
            BASE.PROTOTYPE_MODES.index(mode),
        ),
    )
    chosen = prototype_sets[chosen_mode]
    truths, predictions = BASE.predict_rows(target_test, chosen)
    target_metrics = BASE._metric_summary(truths, predictions, chosen.labels)
    aliases = {
        label: f"device-{index + 1:03d}" for index, label in enumerate(chosen.labels)
    }

    source_test = source_assigned["test"]
    receipts = {
        "source_train": _role_receipt(
            source_adapter.adapter_id,
            source_assigned["train"],
            source_sampled["train"],
            source_train,
        ),
        "source_validation": _role_receipt(
            source_adapter.adapter_id,
            source_assigned["validation"],
            source_sampled["validation"],
            source_validation,
        ),
        "source_test_unused": _role_receipt(
            source_adapter.adapter_id, source_test, (), ()
        ),
        "target_test": _role_receipt(
            target_adapter.adapter_id,
            target_adapter.rows,
            target_sampled,
            target_test,
        ),
    }
    report = {
        "schema": REPORT_SCHEMA,
        "status": "pass",
        "task": "closed_set_physical_device_classification_cross_campaign_transfer",
        "operation_order": [
            "source_location_partition_80_10_10",
            "source_bounded_sampling_within_assigned_roles",
            "target_all_locations_assigned_to_test",
            "target_bounded_sampling_within_test_role",
            "read_only_source_and_target_mmap",
            "common_magnitude_peak_aligned_projection",
            "source_train_only_prototype_fit",
            "source_validation_only_configuration_selection",
            "target_test_only_final_evaluation",
        ],
        "configuration": {
            "seed": selected.seed,
            "source_location_split_percentages": BASE.SPLIT_PERCENTAGES,
            "max_rows_per_atomic_group": selected.max_rows_per_atomic_group,
            "window_length": selected.window_length,
            "windows_per_row": selected.windows_per_row,
            "common_signal_length": selected.common_signal_length,
            "alignment_index": selected.alignment_index,
            "projection": PROJECTION,
            "selected_prototype_mode": chosen_mode,
            "closed_set_rejection_threshold": None,
        },
        "sources": {
            "source": _source_receipt(
                source_loaded,
                source_adapter.source_contract,
                source_adapter.adapter_id,
            ),
            "target": _source_receipt(
                target_loaded,
                target_adapter.source_contract,
                target_adapter.adapter_id,
            ),
        },
        "role_receipts": receipts,
        "leakage_checks": {
            "source_test_feature_rows": 0,
            "target_configuration_candidates": 0,
            "source_train_validation_row_overlap": _identity_overlap(
                source_adapter.adapter_id,
                source_sampled["train"],
                source_adapter.adapter_id,
                source_sampled["validation"],
            ),
            "source_test_target_row_overlap": _identity_overlap(
                source_adapter.adapter_id,
                source_test,
                target_adapter.adapter_id,
                target_adapter.rows,
            ),
            "row_identity": "adapter_id_plus_row_index",
            "prototype_fit_role": "source_train",
            "configuration_selection_role": "source_validation",
            "final_evaluation_role": "target_test",
            "all_checks_passed": True,
        },
        "fit_receipt": {
            "role": "source_train",
            "sampled_row_receipt": receipts["source_train"]["sampled_row_receipt"],
            "device_count": len(chosen.labels),
        },
        "validation_selection": {
            "role": "source_validation",
            "candidate_metrics": candidates,
            "selected_prototype_mode": chosen_mode,
        },
        "target_metrics": {
            "macro_f1": target_metrics["macro_f1"],
            "balanced_accuracy": target_metrics["balanced_accuracy"],
            "uniform_chance_balanced_accuracy": round(1 / len(chosen.labels), 12),
            "per_device_recall": {
                aliases[label]: target_metrics["recalls"][index]
                for index, label in enumerate(chosen.labels)
            },
            "confusion_matrix": {
                "labels": [aliases[label] for label in chosen.labels],
                "rows_true_columns_predicted": target_metrics["confusion_matrix"],
            },
            "evaluated_rows": target_metrics["evaluated_rows"],
        },
        "limitations": [
            "The source and target campaigns differ in distance, day, and room position.",
            (
                "The common magnitude projection reconciles publisher NPY dtype and "
                "length differences but cannot prove the representations are equivalent."
            ),
            (
                "Shared opaque source aliases assume publisher device labels identify "
                "the same physical boards across campaigns."
            ),
            "Results are closed-set and do not measure unseen-device rejection.",
            "No uncertainty interval or population-level claim is produced.",
        ],
        "privacy": {
            "corpus_rows_retained": 0,
            "input_paths_retained": 0,
            "raw_source_identifiers_retained": 0,
        },
    }
    BASE.render_report(report)
    return report


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-row-adapter",
        type=Path,
        default=(
            ROOT / "data" / "derived" / "eval" / "ruff-uwb-one-meter-row-adapter.json"
        ),
    )
    parser.add_argument(
        "--source-waveforms",
        type=Path,
        default=(
            ROOT / "data" / "derived" / "eval" / "ruff-uwb-one-meter-waveforms.npy"
        ),
    )
    parser.add_argument(
        "--target-row-adapter",
        type=Path,
        default=(
            ROOT / "data" / "derived" / "eval" / "ruff-uwb-two-meter-row-adapter.json"
        ),
    )
    parser.add_argument(
        "--target-waveforms",
        type=Path,
        default=(
            ROOT / "data" / "derived" / "eval" / "ruff-uwb-two-meter-waveforms.npy"
        ),
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=(
            ROOT / "data" / "derived" / "eval" / "ruff-uwb-cross-distance-report.json"
        ),
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--max-rows-per-atomic-group", type=int, default=8)
    parser.add_argument("--window-length", type=int, default=128)
    parser.add_argument("--windows-per-row", type=int, default=4)
    parser.add_argument("--common-signal-length", type=int, default=200)
    parser.add_argument("--alignment-index", type=int, default=40)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        source = BASE.load_row_adapter(args.source_row_adapter, PINNED_SOURCE_BINDING)
        target = BASE.load_row_adapter(args.target_row_adapter, PINNED_TARGET_BINDING)
        report = evaluate_transfer(
            source,
            args.source_waveforms,
            target,
            args.target_waveforms,
            TransferConfig(
                seed=args.seed,
                max_rows_per_atomic_group=args.max_rows_per_atomic_group,
                window_length=args.window_length,
                windows_per_row=args.windows_per_row,
                common_signal_length=args.common_signal_length,
                alignment_index=args.alignment_index,
            ),
        )
        BASE.write_report(args.report, report)
    except BASE.EvaluationInputError as error:
        print(error.code, file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "pass",
                "schema": REPORT_SCHEMA,
                "macro_f1": report["target_metrics"]["macro_f1"],
                "balanced_accuracy": report["target_metrics"]["balanced_accuracy"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
