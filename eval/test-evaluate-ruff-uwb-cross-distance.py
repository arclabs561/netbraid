#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9,<3.10"
# dependencies = ["numpy==2.0.2"]
# ///

"""Hermetic tests for the RUFF-UWB cross-distance evaluator."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

import numpy as np


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"module_unavailable:{name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CROSS = load_module(
    "evaluate_ruff_uwb_cross_distance",
    HERE / "evaluate-ruff-uwb-cross-distance.py",
)
SUPPORT = load_module(
    "evaluate_ruff_uwb_heldout_test_support",
    HERE / "test-evaluate-ruff-uwb-heldout-location.py",
)


def config():
    return CROSS.TransferConfig(
        seed=17,
        max_rows_per_atomic_group=1,
        window_length=8,
        windows_per_row=1,
        common_signal_length=16,
        alignment_index=4,
    )


def binding_for_cross(binding):
    return CROSS.BASE.RowAdapterBinding(
        archive=binding.archive,
        label_member=binding.label_member,
        waveform_member=binding.waveform_member,
    )


def load_adapter(adapter, binding):
    return CROSS.BASE.validate_row_adapter(adapter, binding_for_cross(binding))


def hash_parts_oracle(seed, domain, *parts):
    digest = hashlib.sha256()
    namespace = b"netbraid.ruff-uwb-heldout-location.v0"
    for value in (namespace, seed.to_bytes(8, "big"), domain.encode("utf-8")):
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    for part in parts:
        encoded = str(part).encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.digest()


def target_aliases_are_collection_scoped(adapter):
    locations = {}
    for span in adapter["spans"]:
        prior = span["location"]
        if prior not in locations:
            locations[prior] = SUPPORT.opaque(10_000 + len(locations))
        span["location"] = locations[prior]
        span["distance_collection"] = SUPPORT.opaque(9_000)
    SUPPORT.resign_adapter(adapter)


class TransferFixture:
    def __init__(self, case):
        temporary = tempfile.TemporaryDirectory()
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        rows, _, generated = SUPPORT.synthetic_dataset(self.root)
        generated.unlink()

        patterns = {
            "device-0": np.asarray(
                [0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                dtype=np.float64,
            ),
            "device-1": np.asarray(
                [0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                dtype=np.float64,
            ),
        }
        source_magnitude = np.stack(
            [patterns[row.physical_device] for row in rows], axis=0
        )
        phase = np.linspace(0.0, np.pi / 3.0, source_magnitude.shape[1])
        self.source_waveforms = np.asarray(
            source_magnitude * np.exp(1j * phase), dtype=np.complex128
        )
        self.target_waveforms = np.asarray(
            np.abs(self.source_waveforms[:, :16]), dtype=np.float64
        )
        self.source_path = self.root / "source.npy"
        self.target_path = self.root / "target.npy"
        np.save(self.source_path, self.source_waveforms, allow_pickle=False)
        np.save(self.target_path, self.target_waveforms, allow_pickle=False)

        target_rows = tuple(
            SUPPORT.MODULE.RowMetadata(
                row_index=row.row_index,
                distance_collection="distance-2m",
                physical_source=row.physical_source,
                physical_device=row.physical_device,
                location=f"target-{row.location}",
            )
            for row in rows
        )
        source_adapter, source_binding = SUPPORT.row_adapter(
            rows, self.source_path, self.source_waveforms
        )
        target_adapter, target_binding = SUPPORT.row_adapter(
            target_rows, self.target_path, self.target_waveforms
        )
        target_aliases_are_collection_scoped(target_adapter)
        self.source_document = source_adapter
        self.target_document = target_adapter
        self.source_binding = binding_for_cross(source_binding)
        self.target_binding = binding_for_cross(target_binding)
        self.source = CROSS.BASE.validate_row_adapter(
            source_adapter, self.source_binding
        )
        self.target = CROSS.BASE.validate_row_adapter(
            target_adapter, self.target_binding
        )
        self.source_compact = CROSS.BASE.validate_row_span_adapter(
            source_adapter, self.source_binding
        )
        self.target_compact = CROSS.BASE.validate_row_span_adapter(
            target_adapter, self.target_binding
        )

    def evaluate(self, source=None, source_path=None, target=None, target_path=None):
        return CROSS.evaluate_transfer(
            source or self.source,
            source_path or self.source_path,
            target or self.target,
            target_path or self.target_path,
            config(),
        )

    def changed_target(self):
        changed = self.target_waveforms.copy()
        rows_by_group = {
            (row.location, row.physical_device, row.row_index % 2): row.row_index
            for row in self.target.rows
        }
        devices = sorted({row.physical_device for row in self.target.rows})
        for row in self.target.rows:
            other = devices[1 - devices.index(row.physical_device)]
            changed[row.row_index] = self.target_waveforms[
                rows_by_group[(row.location, other, row.row_index % 2)]
            ]
        path = self.root / "changed-target.npy"
        np.save(path, changed, allow_pickle=False)
        document, binding = SUPPORT.row_adapter(
            tuple(
                SUPPORT.MODULE.RowMetadata(
                    row_index=row.row_index,
                    distance_collection="distance-2m",
                    physical_source=f"source-{devices.index(row.physical_device)}",
                    physical_device=f"device-{devices.index(row.physical_device)}",
                    location=f"target-location-{index // 4:02d}",
                )
                for index, row in enumerate(self.target.rows)
            ),
            path,
            changed,
        )
        target_aliases_are_collection_scoped(document)
        return load_adapter(document, binding), path


class RuffUwbCrossDistanceTests(unittest.TestCase):
    def test_compiler_contracts_are_the_only_production_binding_source(self):
        self.assertEqual(
            CROSS.PINNED_SOURCE_BINDING,
            CROSS.BASE.PRODUCTION_ROW_ADAPTER_BINDING,
        )
        target = CROSS.COMPILER.PRODUCTION_CONTRACTS["distance-2"]
        self.assertEqual(
            CROSS.PINNED_TARGET_BINDING.archive["archive_sha256"],
            target.archive_sha256,
        )
        self.assertEqual(
            CROSS.PINNED_TARGET_BINDING.waveform_member["shape"],
            list(target.waveform.shape),
        )

    def test_transfer_is_deterministic_with_source_scoped_row_indices(self):
        fixture = TransferFixture(self)

        first = fixture.evaluate()
        reversed_source = replace(
            fixture.source, rows=tuple(reversed(fixture.source.rows))
        )
        reversed_target = replace(
            fixture.target, rows=tuple(reversed(fixture.target.rows))
        )
        second = fixture.evaluate(source=reversed_source, target=reversed_target)

        self.assertEqual(
            CROSS.BASE.render_report(first), CROSS.BASE.render_report(second)
        )
        self.assertEqual(first["status"], "pass")
        self.assertEqual(first["target_metrics"]["macro_f1"], 1.0)
        self.assertEqual(first["target_metrics"]["balanced_accuracy"], 1.0)
        self.assertEqual(first["leakage_checks"]["source_test_target_row_overlap"], 0)
        self.assertEqual(
            first["leakage_checks"]["row_identity"],
            "adapter_id_plus_row_index",
        )

    def test_compact_and_expanded_adapters_produce_identical_report(self):
        fixture = TransferFixture(self)

        expanded = fixture.evaluate()
        compact = fixture.evaluate(
            source=fixture.source_compact, target=fixture.target_compact
        )

        self.assertEqual(
            CROSS.BASE.render_report(expanded), CROSS.BASE.render_report(compact)
        )

    def test_compact_source_sampling_matches_expanded_oracle_across_split_spans(self):
        fixture = TransferFixture(self)
        document = copy.deepcopy(fixture.source_document)
        first, second = document["spans"][:2]
        self.assertEqual((first["row_start"], first["row_stop"]), (0, 2))
        self.assertEqual((second["row_start"], second["row_stop"]), (2, 4))
        document["spans"][:2] = [
            {**first, "row_start": 0, "row_stop": 1},
            {**second, "row_start": 1, "row_stop": 2},
            {**first, "row_start": 2, "row_stop": 3},
            {**second, "row_start": 3, "row_stop": 4},
        ]
        document["counts"]["spans"] = len(document["spans"])
        SUPPORT.resign_adapter(document)
        expanded = CROSS.BASE.validate_row_adapter(document, fixture.source_binding)
        compact = CROSS.BASE.validate_row_span_adapter(document, fixture.source_binding)

        assigned = CROSS.BASE.partition_rows(expanded.rows, config().seed)
        oracle = CROSS.BASE.sample_rows(assigned, config().base())
        actual = CROSS.BASE.partition_and_sample_row_spans(
            compact.spans, config().base()
        )

        for role in CROSS.BASE.SPLITS:
            self.assertEqual(actual[role].sampled, oracle[role])
            self.assertEqual(actual[role].source_row_count, len(assigned[role]))
            self.assertEqual(
                actual[role].location_count,
                len({row.location for row in assigned[role]}),
            )
            self.assertEqual(
                actual[role].atomic_group_count,
                len({row.atomic_group() for row in assigned[role]}),
            )

    def test_compact_target_sampling_matches_full_sort_oracle(self):
        fixture = TransferFixture(self)
        grouped = {}
        for row in fixture.target.rows:
            grouped.setdefault(row.atomic_group(), []).append(row)
        selected = []
        for group, candidates in sorted(grouped.items()):
            ranked = sorted(
                candidates,
                key=lambda row: (
                    hash_parts_oracle(
                        config().seed,
                        "cross-distance-target-row-sample",
                        fixture.target.adapter_id,
                        *group,
                        row.row_index,
                    ),
                    row.row_index,
                ),
            )
            selected.extend(ranked[: config().max_rows_per_atomic_group])
        oracle = tuple(
            sorted(selected, key=lambda row: (row.atomic_group(), row.row_index))
        )

        actual = CROSS._sample_target_rows(
            fixture.target_compact.spans, fixture.target.adapter_id, config()
        )

        self.assertEqual(actual.sampled, oracle)

    def test_source_test_rows_never_affect_selection_or_target_metrics(self):
        fixture = TransferFixture(self)
        baseline = fixture.evaluate()
        source_partitions = CROSS.BASE.partition_rows(
            fixture.source.rows, config().seed
        )
        changed = fixture.source_waveforms.copy()
        for row in source_partitions["test"]:
            changed[row.row_index] = complex(row.row_index + 1, row.row_index + 2)
        path = fixture.root / "changed-source-test.npy"
        np.save(path, changed, allow_pickle=False)
        fixture_devices = sorted({item.physical_device for item in fixture.source.rows})
        document, binding = SUPPORT.row_adapter(
            # Reconstruct only the raw fixture names expected by the helper;
            # production reports and adapters retain neither mapping.
            tuple(
                SUPPORT.MODULE.RowMetadata(
                    row_index=row.row_index,
                    distance_collection="distance-1m",
                    physical_source=(
                        f"source-{fixture_devices.index(row.physical_device)}"
                    ),
                    physical_device=(
                        f"device-{fixture_devices.index(row.physical_device)}"
                    ),
                    location=row.location,
                )
                for row in fixture.source.rows
            ),
            path,
            changed,
        )
        modified_source = load_adapter(document, binding)

        modified = fixture.evaluate(source=modified_source, source_path=path)

        self.assertEqual(
            baseline["validation_selection"], modified["validation_selection"]
        )
        self.assertEqual(baseline["target_metrics"], modified["target_metrics"])
        self.assertEqual(
            modified["role_receipts"]["source_test_unused"]["feature_row_count"],
            0,
        )

    def test_target_changes_cannot_change_fit_or_validation_selection(self):
        fixture = TransferFixture(self)
        baseline = fixture.evaluate()
        changed_target, changed_path = fixture.changed_target()

        modified = fixture.evaluate(target=changed_target, target_path=changed_path)

        self.assertEqual(baseline["fit_receipt"], modified["fit_receipt"])
        self.assertEqual(
            baseline["validation_selection"], modified["validation_selection"]
        )
        self.assertNotEqual(baseline["target_metrics"], modified["target_metrics"])

    def test_identity_mismatch_fails_before_waveform_open(self):
        fixture = TransferFixture(self)
        document = copy.deepcopy(fixture.target_document)
        old_device = document["spans"][0]["physical_device"]
        for span in document["spans"]:
            if span["physical_device"] == old_device:
                span["physical_device"] = SUPPORT.opaque(12_000)
        SUPPORT.resign_adapter(document)
        target = CROSS.BASE.validate_row_adapter(document, fixture.target_binding)

        with mock.patch.object(CROSS.BASE, "load_waveforms") as load:
            with self.assertRaises(CROSS.BASE.EvaluationInputError) as raised:
                fixture.evaluate(target=target)

        self.assertEqual(raised.exception.code, "cross_distance_identity_mismatch")
        load.assert_not_called()

    def test_adapter_alias_fails_before_waveform_open(self):
        fixture = TransferFixture(self)
        target = replace(fixture.target, adapter_id=fixture.source.adapter_id)

        with mock.patch.object(CROSS.BASE, "load_waveforms") as load:
            with self.assertRaises(CROSS.BASE.EvaluationInputError) as raised:
                fixture.evaluate(target=target)

        self.assertEqual(raised.exception.code, "cross_distance_adapter_alias")
        load.assert_not_called()

    def test_feature_bound_fails_before_waveform_open(self):
        fixture = TransferFixture(self)

        with (
            mock.patch.object(CROSS.BASE, "MAX_FEATURE_VALUES", 1),
            mock.patch.object(CROSS.BASE, "load_waveforms") as load,
            self.assertRaises(CROSS.BASE.EvaluationInputError) as raised,
        ):
            fixture.evaluate()

        self.assertEqual(raised.exception.code, "feature_memory_bound")
        load.assert_not_called()

    def test_report_is_path_free_and_both_arrays_are_read_only_mmaps(self):
        fixture = TransferFixture(self)

        report = fixture.evaluate()

        self.assertTrue(report["sources"]["source"]["numpy_mmap"])
        self.assertTrue(report["sources"]["target"]["numpy_mmap"])
        self.assertFalse(report["sources"]["source"]["mmap_writeable"])
        self.assertFalse(report["sources"]["target"]["mmap_writeable"])
        encoded = CROSS.BASE.render_report(report).decode("utf-8")
        for private in (
            str(fixture.root),
            '"source-0"',
            '"device-0"',
            '"target-location',
            '"distance-1m"',
            '"distance-2m"',
        ):
            self.assertNotIn(private, encoded)


if __name__ == "__main__":
    unittest.main()
