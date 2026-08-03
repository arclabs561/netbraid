#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9,<3.10"
# dependencies = ["numpy==2.0.2"]
# ///
"""Hermetic tests for the RUFF-UWB held-out-location eval harness."""

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "evaluate_ruff_uwb_heldout_location",
    HERE / "evaluate-ruff-uwb-heldout-location.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def opaque(seed):
    return f"{seed:064x}"


def known(seed):
    return {"state": "known", "group_id": opaque(seed)}


def current_observation(seed):
    groups = {
        "event_group": {"state": "not_observed", "group_id": None},
        "physical_source_group": known(seed * 100 + 1),
        "physical_device_group": known(seed * 100 + 2),
        "variant_group": known(seed * 100 + 3),
        "session_group": {"state": "not_observed", "group_id": None},
        "domain_group": known(seed * 100 + 4),
        "day_group": known(seed * 100 + 5),
        "receiver_group": known(seed * 100 + 6),
        "location_group": known(seed * 100 + 7),
        "channel_group": known(seed * 100 + 8),
        "configuration_group": known(seed * 100 + 9),
        "source_location_group": known(seed * 100 + 10),
        "campaign_group": known(seed * 100 + 11),
    }
    return {
        "observation_id": opaque(seed),
        "observation_count": 1,
        **groups,
    }


def current_archive(seed, sha256):
    return {
        "archive_id": opaque(seed * 100 + 1),
        "campaign_group_id": opaque(seed * 100 + 2),
        "configuration_group_id": opaque(seed * 100 + 3),
        "archive_bytes": 1000 + seed,
        "archive_md5": f"{seed:032x}",
        "archive_sha256": sha256,
        "label_rows": 1,
        "oracle_records": 1,
        "distinct_sources": 1,
        "distinct_locations": 1,
    }


def current_oracle():
    return {
        "schema": MODULE.CURRENT_ORACLE_SCHEMA,
        "inventory_id": opaque(1),
        "status": "pass",
        "provenance": {},
        "manifest": {
            "local_ignored_manifest": True,
            "partitions_assigned": 0,
            "train_test_splits_assigned": False,
        },
        "publisher_claims": {},
        "required_split_groups": list(MODULE.REQUIRED_SPLIT_GROUPS),
        "archives": [
            current_archive(1, MODULE.PINNED_ONE_METER_ARCHIVE_SHA256),
            current_archive(2, "b" * 64),
        ],
        "counts": {"label_rows": 2, "observations": 2},
        "privacy": {
            "absolute_paths_retained": 0,
            "relative_paths_retained": 0,
            "filenames_retained": 0,
            "source_urls_retained": 0,
            "raw_label_values_emitted": 0,
            "waveform_members_opened": 0,
            "waveform_payload_bytes_read": 0,
        },
        "observations": [current_observation(1), current_observation(2)],
    }


def class_pattern(device_index):
    if device_index == 0:
        return np.tile(np.array([1.0, -1.0]), 8)
    return np.tile(np.array([1.0, 1.0, -1.0, -1.0]), 4)


def synthetic_dataset(root, location_count=10, repeats=2):
    rows = []
    waveforms = []
    for location_index in range(location_count):
        for device_index in range(2):
            for repeat in range(repeats):
                row_index = len(rows)
                pattern = class_pattern(device_index)
                scale = 1.0 + location_index / 20.0 + repeat / 10.0
                offset = 5.0 + location_index + repeat
                waveforms.append(offset + scale * pattern)
                rows.append(
                    MODULE.RowMetadata(
                        row_index=row_index,
                        distance_collection="distance-1m",
                        physical_source=f"source-{device_index}",
                        physical_device=f"device-{device_index}",
                        location=f"location-{location_index:02d}",
                    )
                )
    path = root / "synthetic-waveforms.npy"
    array = np.asarray(waveforms, dtype=np.float32)
    np.save(path, array, allow_pickle=False)
    return tuple(rows), array, path


def waveform_contract(path, array, rows=None, samples_per_row=None):
    encoded = path.read_bytes()
    return MODULE.WaveformSourceContract(
        file_bytes=len(encoded),
        sha256=hashlib.sha256(encoded).hexdigest(),
        rows=array.shape[0] if rows is None else rows,
        samples_per_row=(
            array.shape[1] if samples_per_row is None else samples_per_row
        ),
        dtype=array.dtype.str,
    )


def config():
    return MODULE.EvaluationConfig(
        seed=17,
        max_rows_per_atomic_group=1,
        window_length=8,
        windows_per_row=2,
    )


def assert_code(test, code, function, *args):
    with test.assertRaises(MODULE.EvaluationInputError) as raised:
        function(*args)
    test.assertEqual(raised.exception.code, code)


class RuffUwbHeldoutLocationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_current_oracle_fails_closed_before_opening_waveforms(self):
        oracle_path = self.root / "oracle.json"
        report_path = self.root / "blocker.json"
        oracle_path.write_text(json.dumps(current_oracle()), encoding="utf-8")

        with mock.patch.object(MODULE.np, "load") as load:
            return_code = MODULE.main(
                [
                    "--oracle",
                    str(oracle_path),
                    "--waveforms",
                    str(self.root / "absent.npy"),
                    "--report",
                    str(report_path),
                ]
            )

        self.assertEqual(return_code, 2)
        load.assert_not_called()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["code"], "oracle_row_mapping_unavailable")
        self.assertFalse(report["observed_contract"]["row_indices"])
        self.assertFalse(report["observed_contract"]["row_order_contract"])
        encoded = MODULE.render_report(report).decode("utf-8")
        self.assertNotIn(str(self.root), encoded)

        expected_return_code = MODULE.main(
            [
                "--oracle",
                str(oracle_path),
                "--waveforms",
                str(self.root / "absent.npy"),
                "--report",
                str(report_path),
                "--expect-blocked",
            ]
        )
        self.assertEqual(expected_return_code, 0)

    def test_strict_oracle_parser_rejects_duplicate_keys_and_bad_counts(self):
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"schema":"first","schema":"second"}', encoding="utf-8")
        assert_code(
            self,
            "oracle_invalid_json",
            MODULE.load_current_oracle,
            duplicate,
        )

        bad = current_oracle()
        bad["counts"]["label_rows"] = 3
        assert_code(
            self,
            "oracle_count_mismatch",
            MODULE.validate_current_oracle,
            bad,
        )

    def test_synthetic_eval_is_deterministic_and_reports_exact_metrics(self):
        rows, waveforms, path = synthetic_dataset(self.root)
        contract = waveform_contract(path, waveforms)

        first = MODULE.evaluate_rows(rows, path, contract, config())
        second = MODULE.evaluate_rows(tuple(reversed(rows)), path, contract, config())

        self.assertEqual(MODULE.render_report(first), MODULE.render_report(second))
        self.assertEqual(first["status"], "pass")
        self.assertEqual(first["configuration"]["selected_prototype_mode"], "centroid")
        self.assertEqual(first["test_metrics"]["macro_f1"], 1.0)
        self.assertEqual(first["test_metrics"]["balanced_accuracy"], 1.0)
        self.assertEqual(
            first["test_metrics"]["per_device_recall"],
            {"device-001": 1.0, "device-002": 1.0},
        )
        self.assertEqual(
            first["test_metrics"]["confusion_matrix"]["rows_true_columns_predicted"],
            [[1, 0], [0, 1]],
        )
        self.assertEqual(
            {
                role: first["split_receipts"][role]["location_count"]
                for role in MODULE.SPLITS
            },
            {"train": 8, "validation": 1, "test": 1},
        )
        self.assertTrue(first["source_receipt"]["numpy_mmap"])
        encoded = MODULE.render_report(first).decode("utf-8")
        for private_value in (
            str(self.root),
            "source-0",
            "source-1",
            "location-00",
            "distance-1m",
        ):
            self.assertNotIn(private_value, encoded)

    def test_locations_atomic_groups_and_rows_never_cross_splits(self):
        rows, _, _ = synthetic_dataset(self.root)
        partitions = MODULE.partition_rows(rows, config().seed)

        for left, right in MODULE.combinations(MODULE.SPLITS, 2):
            self.assertFalse(
                {row.location for row in partitions[left]}
                & {row.location for row in partitions[right]}
            )
            self.assertFalse(
                {row.atomic_group() for row in partitions[left]}
                & {row.atomic_group() for row in partitions[right]}
            )
            self.assertFalse(
                {row.row_index for row in partitions[left]}
                & {row.row_index for row in partitions[right]}
            )
        for location in {row.location for row in rows}:
            roles = {
                role
                for role in MODULE.SPLITS
                if any(row.location == location for row in partitions[role])
            }
            self.assertEqual(len(roles), 1)

        sparse = MODULE.sample_rows(partitions, config())
        dense_config = MODULE.EvaluationConfig(
            seed=config().seed,
            max_rows_per_atomic_group=2,
            window_length=8,
            windows_per_row=2,
        )
        dense = MODULE.sample_rows(partitions, dense_config)
        for role in MODULE.SPLITS:
            self.assertEqual(
                {row.location for row in sparse[role]},
                {row.location for row in dense[role]},
            )

    def test_test_data_cannot_change_train_fit_or_validation_selection(self):
        rows, waveforms, first_path = synthetic_dataset(self.root)
        baseline = MODULE.evaluate_rows(
            rows,
            first_path,
            waveform_contract(first_path, waveforms),
            config(),
        )
        partitions = MODULE.partition_rows(rows, config().seed)

        changed = waveforms.copy()
        for row in partitions["test"]:
            device_index = int(row.physical_device.rsplit("-", 1)[1])
            changed[row.row_index] = 7.0 + class_pattern(1 - device_index)
        changed_path = self.root / "changed-test-only.npy"
        np.save(changed_path, changed, allow_pickle=False)
        modified = MODULE.evaluate_rows(
            rows,
            changed_path,
            waveform_contract(changed_path, changed),
            config(),
        )

        self.assertEqual(baseline["fit_receipt"], modified["fit_receipt"])
        self.assertEqual(
            baseline["validation_selection"], modified["validation_selection"]
        )
        self.assertEqual(baseline["split_receipts"], modified["split_receipts"])
        self.assertNotEqual(baseline["test_metrics"], modified["test_metrics"])

    def test_npy_is_memory_mapped_read_only(self):
        _, waveforms, path = synthetic_dataset(self.root)

        loaded = MODULE.load_waveforms(path, waveform_contract(path, waveforms))

        self.assertTrue(loaded.mmap_used)
        self.assertIsInstance(loaded.array, np.memmap)
        self.assertEqual(loaded.array.mode, "r")
        self.assertFalse(loaded.array.flags.writeable)

    def test_classification_metrics_match_hand_computed_confusion(self):
        metrics = MODULE._metric_summary(
            ("a", "a", "b", "b", "c", "c"),
            ("a", "b", "b", "b", "a", "c"),
            ("a", "b", "c"),
        )

        self.assertEqual(
            metrics["confusion_matrix"],
            [[1, 1, 0], [0, 2, 0], [1, 0, 1]],
        )
        self.assertEqual(metrics["recalls"], (0.5, 1.0, 0.5))
        self.assertEqual(metrics["balanced_accuracy"], 0.666666666667)
        self.assertEqual(metrics["macro_f1"], 0.655555555556)

    def test_malformed_row_metadata_fails_closed(self):
        rows, _, _ = synthetic_dataset(self.root)
        duplicate = list(rows)
        duplicate[1] = MODULE.RowMetadata(
            row_index=duplicate[0].row_index,
            distance_collection=duplicate[1].distance_collection,
            physical_source=duplicate[1].physical_source,
            physical_device=duplicate[1].physical_device,
            location=duplicate[1].location,
        )
        assert_code(
            self,
            "duplicate_or_invalid_row_index",
            MODULE.partition_rows,
            duplicate,
            config().seed,
        )

        inconsistent = list(rows)
        first = inconsistent[0]
        inconsistent[0] = MODULE.RowMetadata(
            row_index=first.row_index,
            distance_collection=first.distance_collection,
            physical_source=first.physical_source,
            physical_device="device-conflict",
            location=first.location,
        )
        assert_code(
            self,
            "physical_source_device_not_bijective",
            MODULE.partition_rows,
            inconsistent,
            config().seed,
        )

        too_few_locations = tuple(row for row in rows if row.location != "location-09")
        assert_code(
            self,
            "location_count_outside_split_bound",
            MODULE.partition_rows,
            too_few_locations,
            config().seed,
        )

        second_collection = list(rows)
        first = second_collection[0]
        second_collection[0] = MODULE.RowMetadata(
            row_index=first.row_index,
            distance_collection="distance-2m",
            physical_source=first.physical_source,
            physical_device=first.physical_device,
            location=first.location,
        )
        assert_code(
            self,
            "one_npy_requires_one_distance_collection",
            MODULE.partition_rows,
            second_collection,
            config().seed,
        )

    def test_malformed_waveforms_and_selected_windows_fail_closed(self):
        rows, waveforms, path = synthetic_dataset(self.root)
        valid_contract = waveform_contract(path, waveforms)
        assert_code(
            self,
            "waveform_source_digest_mismatch",
            MODULE.load_waveforms,
            path,
            MODULE.WaveformSourceContract(
                file_bytes=valid_contract.file_bytes,
                sha256="0" * 64,
                rows=valid_contract.rows,
                samples_per_row=valid_contract.samples_per_row,
                dtype=valid_contract.dtype,
            ),
        )

        one_dimensional = self.root / "one-dimensional.npy"
        np.save(one_dimensional, np.ones(16, dtype=np.float32), allow_pickle=False)
        one_dimensional_array = np.ones(16, dtype=np.float32)
        assert_code(
            self,
            "waveform_array_must_be_2d",
            MODULE.load_waveforms,
            one_dimensional,
            waveform_contract(
                one_dimensional,
                one_dimensional_array,
                rows=1,
                samples_per_row=16,
            ),
        )

        archive_path = self.root / "waveforms.zip"
        archive_path.write_bytes(b"not-an-npy")
        assert_code(
            self,
            "waveform_source_must_be_standalone_npy",
            MODULE.load_waveforms,
            archive_path,
            MODULE.WaveformSourceContract(
                file_bytes=archive_path.stat().st_size,
                sha256=hashlib.sha256(archive_path.read_bytes()).hexdigest(),
                rows=1,
                samples_per_row=2,
                dtype="<f4",
            ),
        )

        out_of_range = list(rows)
        last = out_of_range[-1]
        out_of_range[-1] = MODULE.RowMetadata(
            row_index=len(waveforms),
            distance_collection=last.distance_collection,
            physical_source=last.physical_source,
            physical_device=last.physical_device,
            location=last.location,
        )
        assert_code(
            self,
            "row_index_outside_waveform_array",
            MODULE.evaluate_rows,
            out_of_range,
            path,
            waveform_contract(path, waveforms),
            config(),
        )

        constant_path = self.root / "constant.npy"
        np.save(
            constant_path,
            np.ones_like(waveforms, dtype=np.float32),
            allow_pickle=False,
        )
        assert_code(
            self,
            "selected_window_zero_amplitude",
            MODULE.evaluate_rows,
            rows,
            constant_path,
            waveform_contract(
                constant_path,
                np.ones_like(waveforms, dtype=np.float32),
            ),
            config(),
        )

    def test_report_renderer_rejects_non_finite_metric(self):
        value = copy.deepcopy(MODULE.current_oracle_blocker(current_oracle()))
        value["unexpected"] = float("nan")

        assert_code(
            self,
            "report_not_json_serializable",
            MODULE.render_report,
            value,
        )


if __name__ == "__main__":
    unittest.main()
