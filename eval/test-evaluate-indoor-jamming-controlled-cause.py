#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["h5py==3.16.0", "xlrd==2.0.2"]
# ///

"""Hermetic tests for the indoor controlled-cause smoke evaluator."""

from __future__ import annotations

import copy
import importlib.util
import math
import os
import sys
import tempfile
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "evaluate_indoor_jamming_controlled_cause",
    HERE / "evaluate-indoor-jamming-controlled-cause.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

MINIMUM_EXTENT = 145_920_978
WINDOW_COLUMNS = 65_536
JAMMER_REPETITIONS = (1, 1, 1, 2, 3)


def opaque(index: int) -> str:
    return f"{index:064x}"


def policy():
    return MODULE._expected_policy()


def oracle():
    return {
        "schema": MODULE.COMPILER.OUTPUT_SCHEMA,
        "inventory_id": opaque(90_000),
        "provenance": {
            "integrity_basis": "full_local_md5_sha256_rehash_and_exact_fetch_receipts"
        },
    }


def synthetic_observations(root: Path):
    observations = []
    file_index = 0
    for jammer_index, repetitions in enumerate(JAMMER_REPETITIONS):
        for _repeat in range(repetitions):
            groups = {
                "file_session_group": opaque(1_000 + file_index),
                "paired_condition_group": opaque(2_000 + file_index),
                "tx_rx_setup_group": opaque(3_000),
                "assigned_jammer_setup_group": opaque(4_000 + jammer_index),
                "power_setup_group": opaque(5_000),
                "distance_setup_group": opaque(6_000),
                "combined_setup_group": opaque(7_000 + jammer_index),
            }
            for cause_index, cause in enumerate(MODULE.CAUSES):
                sample_count = MINIMUM_EXTENT + file_index * 100 + cause_index
                observations.append(
                    MODULE.BoundObservation(
                        observation_id=opaque(10_000 + file_index * 3 + cause_index),
                        controlled_cause=cause,
                        sample_count=sample_count,
                        assigned_power=0.5,
                        distance_meters=10.0,
                        groups=groups,
                        source_path=root / f"private-w{file_index + 1}.mat",
                        dataset_path=f"private-{cause}",
                    )
                )
            file_index += 1
    return tuple(observations)


def feature_values(cause: str, file_index: int, start: int):
    variation = (-0.1, 0.0, 0.1)[file_index % 3]
    starts = policy()["window_policy"]["expected_starts"]
    window_variation = (-0.015, -0.005, 0.005, 0.015)[starts.index(start)]
    if cause == "silent":
        return (
            0.0 + variation + window_variation,
            1.5 + variation + window_variation,
            0.5,
            0.0 - variation + window_variation,
            1.8 + variation + window_variation,
            0.5,
        )
    if cause == "sine":
        return (
            2.0 + variation + window_variation,
            3.2 + variation + window_variation,
            0.0,
            -2.0 + variation + window_variation,
            3.4 + variation + window_variation,
            0.0,
        )
    return (
        0.5 + variation + window_variation,
        5.0 + variation + window_variation,
        0.1,
        -0.5 - variation + window_variation,
        5.4 + variation + window_variation,
        0.1,
    )


def summary_from_features(vector, start, stop):
    rows = []
    for row_index in range(2):
        mean, rms, zero_rate = vector[row_index * 3 : row_index * 3 + 3]
        rows.append(
            {
                "finite": stop - start,
                "nonfinite": 0,
                "zero": round(zero_rate * (stop - start)),
                "sum": mean * (stop - start),
                "sumsq": rms * rms * (stop - start),
            }
        )
    return {
        "dataset": {
            "rank": 2,
            "shape": [2, MINIMUM_EXTENT + 10_000],
            "dtype": "float64",
            "chunks": [2, 1_024],
            "compression": "gzip",
        },
        "requested_interval": {"start": start, "stop": stop},
        "selected_interval": {"start": start, "stop": stop},
        "selected_bytes": 2 * (stop - start) * 8,
        "truncated": False,
        "rows": rows,
    }


class SyntheticReader:
    def __init__(self, *, mutate_paths=()):
        self.calls = []
        self.mutate_paths = {str(path) for path in mutate_paths}

    def __call__(self, source_path, dataset_path, start, stop):
        self.calls.append((str(source_path), dataset_path, start, stop))
        file_index = int(Path(source_path).stem.removeprefix("private-w")) - 1
        cause = dataset_path.removeprefix("private-")
        vector = feature_values(cause, file_index, start)
        if str(source_path) in self.mutate_paths:
            vector = tuple(value + 50.0 for value in vector)
        return summary_from_features(vector, start, stop)


def evaluate(observations, reader):
    return MODULE.evaluate_bound_observations(
        observations,
        policy(),
        "a" * 64,
        oracle(),
        reader,
    )


class IndoorJammingControlledCauseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.observations = synthetic_observations(self.root)

    def test_current_slice_and_split_counts_are_exact(self):
        partitions, _intervals = MODULE.preflight(self.observations, policy())

        self.assertEqual(
            {role: len(items) for role, items in partitions.items()},
            {"train": 9, "validation": 6, "test": 9},
        )
        self.assertEqual(
            {
                role: Counter(item.controlled_cause for item in items)
                for role, items in partitions.items()
            },
            {
                "train": Counter({cause: 3 for cause in MODULE.CAUSES}),
                "validation": Counter({cause: 2 for cause in MODULE.CAUSES}),
                "test": Counter({cause: 3 for cause in MODULE.CAUSES}),
            },
        )
        self.assertEqual(
            {
                role: len({item.groups["file_session_group"] for item in items})
                for role, items in partitions.items()
            },
            {"train": 3, "validation": 2, "test": 3},
        )

    def test_file_pair_combined_and_jammer_groups_never_cross_roles(self):
        partitions, _intervals = MODULE.preflight(self.observations, policy())

        for field in MODULE.ATOMIC_GROUPS:
            memberships = {
                role: {item.groups[field] for item in items}
                for role, items in partitions.items()
            }
            for left_index, left in enumerate(MODULE.SPLITS):
                for right in MODULE.SPLITS[left_index + 1 :]:
                    self.assertFalse(memberships[left] & memberships[right])
        for field in MODULE.CONDITIONING_GROUPS:
            self.assertEqual(len({item.groups[field] for item in self.observations}), 1)

        validation_jammer = partitions["validation"][0].groups[
            "assigned_jammer_setup_group"
        ]
        train_combined = partitions["train"][0].groups["combined_setup_group"]
        crossed = tuple(
            replace(
                item,
                groups={**item.groups, "combined_setup_group": train_combined},
            )
            if item.groups["assigned_jammer_setup_group"] == validation_jammer
            else item
            for item in self.observations
        )
        with self.assertRaisesRegex(
            MODULE.EvaluationInputError, "atomic_group_crosses_roles"
        ):
            MODULE.preflight(crossed, policy())

    def test_preflight_failure_occurs_before_hyperslab_reads(self):
        malformed = self.observations[:-1]
        reader = mock.Mock()

        with self.assertRaisesRegex(
            MODULE.EvaluationInputError, "slice_observation_count"
        ):
            evaluate(malformed, reader)

        reader.assert_not_called()

    def test_window_plan_is_deterministic_disjoint_and_untruncated(self):
        _partitions, intervals = MODULE.preflight(self.observations, policy())

        self.assertEqual(
            [start for start, _stop in intervals],
            [29_151_427, 58_335_623, 87_519_818, 116_704_014],
        )
        self.assertTrue(
            all(stop - start == WINDOW_COLUMNS for start, stop in intervals)
        )
        self.assertTrue(
            all(left[1] <= right[0] for left, right in zip(intervals, intervals[1:]))
        )
        reader = SyntheticReader()
        outcome = MODULE.extract_features(self.observations[0], intervals, reader)
        self.assertIsNotNone(outcome.vector)
        self.assertIsNone(outcome.reason)
        self.assertEqual(len(reader.calls), 4)

    def test_feature_vector_matches_hand_computed_aggregates(self):
        _partitions, intervals = MODULE.preflight(self.observations, policy())
        outcome = MODULE.extract_features(
            self.observations[0], intervals, SyntheticReader()
        )

        self.assertEqual(
            outcome.vector,
            (-0.1, 1.4, 0.5, 0.1, 1.7, 0.5),
        )

    def test_metadata_fields_never_enter_features(self):
        _partitions, intervals = MODULE.preflight(self.observations, policy())
        original = self.observations[0]
        changed = MODULE.BoundObservation(
            observation_id=opaque(99_001),
            controlled_cause=original.controlled_cause,
            sample_count=original.sample_count + 9_999,
            assigned_power=0.9,
            distance_meters=77.0,
            groups={
                field: opaque(99_100 + index)
                for index, field in enumerate(original.groups)
            },
            source_path=original.source_path,
            dataset_path=original.dataset_path,
        )

        first = MODULE.extract_features(original, intervals, SyntheticReader())
        second = MODULE.extract_features(changed, intervals, SyntheticReader())

        self.assertEqual(first.vector, second.vector)
        self.assertEqual(
            tuple(policy()["feature_policy"]["features"]), MODULE.FEATURE_NAMES
        )
        self.assertFalse(policy()["feature_policy"]["metadata_features"])

    def test_nonfinite_overflow_truncation_and_zero_variance_abstain(self):
        _partitions, intervals = MODULE.preflight(self.observations, policy())
        valid = SyntheticReader()(
            self.observations[0].source_path,
            self.observations[0].dataset_path,
            *intervals[0],
        )

        cases = []
        nonfinite = copy.deepcopy(valid)
        nonfinite["rows"][0]["finite"] -= 1
        nonfinite["rows"][0]["nonfinite"] = 1
        cases.append(("window_invalid_aggregate", nonfinite))
        overflow = copy.deepcopy(valid)
        overflow["rows"][0]["sum"] = math.inf
        cases.append(("window_invalid_aggregate", overflow))
        truncated = copy.deepcopy(valid)
        truncated["truncated"] = True
        truncated["selected_interval"]["stop"] -= 1
        cases.append(("window_truncated", truncated))
        invalid_rms = copy.deepcopy(valid)
        invalid_rms["rows"][0]["sumsq"] = -1.0
        cases.append(("window_invalid_aggregate", invalid_rms))

        for reason, summary in cases:
            with self.subTest(reason=reason):
                outcome = MODULE.extract_features(
                    self.observations[0],
                    intervals,
                    lambda *_args, selected=summary: selected,
                )
                self.assertIsNone(outcome.vector)
                self.assertEqual(outcome.reason, reason)

        partitions, _intervals = MODULE.preflight(self.observations, policy())
        constant = {
            item.observation_id: MODULE.FeatureOutcome((1.0,) * 6, None)
            for item in partitions["train"]
        }
        with self.assertRaisesRegex(
            MODULE.EvaluationInputError, "no_nonzero_variance_features"
        ):
            MODULE.fit_model(partitions["train"], constant)

    def test_test_mutation_cannot_change_train_fit_or_validation_gate(self):
        partitions, _intervals = MODULE.preflight(self.observations, policy())
        baseline = evaluate(self.observations, SyntheticReader())
        test_paths = {item.source_path for item in partitions["test"]}
        mutated = evaluate(self.observations, SyntheticReader(mutate_paths=test_paths))

        self.assertEqual(baseline["model"], mutated["model"])
        self.assertEqual(baseline["validation"], mutated["validation"])
        self.assertEqual(baseline["split_receipts"], mutated["split_receipts"])
        self.assertNotEqual(baseline["test_metrics"], mutated["test_metrics"])

    def test_execution_receipt_excludes_test_after_validation_failure(self):
        partitions, _intervals = MODULE.preflight(self.observations, policy())
        validation_paths = {item.source_path for item in partitions["validation"]}
        reader = SyntheticReader(mutate_paths=validation_paths)

        report = evaluate(self.observations, reader)

        self.assertEqual(report["status"], "validation_failed")
        self.assertIsNone(report["test_metrics"])
        test_paths = {str(item.source_path) for item in partitions["test"]}
        self.assertTrue(
            all(source_path not in test_paths for source_path, *_rest in reader.calls)
        )
        self.assertEqual(report["window_policy"]["planned_reads"], 96)
        self.assertEqual(report["window_policy"]["attempted_reads"], len(reader.calls))
        self.assertEqual(report["window_policy"]["completed_reads"], len(reader.calls))
        self.assertEqual(report["window_policy"]["failed_reader_calls"], 0)
        self.assertEqual(
            report["window_policy"]["verified_completed_selected_bytes"],
            len(reader.calls) * MODULE.WINDOW_BYTE_BUDGET,
        )

    def test_read_receipt_separates_attempted_and_completed_calls(self):
        partitions, _intervals = MODULE.preflight(self.observations, policy())
        failing_path = partitions["validation"][0].source_path
        synthetic = SyntheticReader()
        calls = 0
        failed = False

        def fail_one_reader(source_path, dataset_path, start, stop):
            nonlocal calls, failed
            calls += 1
            if source_path == failing_path and not failed:
                failed = True
                raise ValueError("synthetic read failure")
            return synthetic(source_path, dataset_path, start, stop)

        report = evaluate(self.observations, fail_one_reader)

        self.assertEqual(report["window_policy"]["attempted_reads"], calls)
        self.assertEqual(report["window_policy"]["completed_reads"], calls - 1)
        self.assertEqual(report["window_policy"]["failed_reader_calls"], 1)
        self.assertEqual(
            report["window_policy"]["verified_completed_selected_bytes"],
            (calls - 1) * MODULE.WINDOW_BYTE_BUDGET,
        )

    def test_source_identity_violation_is_fatal_during_evaluation(self):
        for source_path in {item.source_path for item in self.observations}:
            source_path.write_bytes(b"source-before")
        bound = tuple(
            replace(item, source_identity=MODULE._source_identity(item.source_path))
            for item in self.observations
        )
        synthetic = SyntheticReader()
        mutated = False

        def mutate_during_read(source_path, dataset_path, start, stop):
            nonlocal mutated
            result = synthetic(source_path, dataset_path, start, stop)
            if not mutated:
                mutated = True
                Path(source_path).write_bytes(b"source-after!")
            return result

        with self.assertRaisesRegex(
            MODULE.EvaluationInputError, "source_changed_since_full_digest"
        ):
            evaluate(
                bound,
                MODULE.identity_bound_reader(bound, mutate_during_read),
            )

    def test_metrics_count_abstentions_as_errors(self):
        selected = self.observations[:6]
        predictions = {
            selected[0].observation_id: "silent",
            selected[1].observation_id: "abstain",
            selected[2].observation_id: "gaussian",
            selected[3].observation_id: "abstain",
            selected[4].observation_id: "sine",
            selected[5].observation_id: "abstain",
        }

        metrics = MODULE.metric_summary(selected, predictions)

        self.assertEqual(
            metrics["confusion"]["rows_true_columns_predicted"],
            [[1, 0, 0, 1], [0, 1, 0, 1], [0, 0, 1, 1]],
        )
        self.assertEqual(
            metrics["coverage"], {"numerator": 3, "denominator": 6, "value": 0.5}
        )
        self.assertEqual(metrics["balanced_accuracy"], 0.5)
        self.assertEqual(metrics["macro_f1"], 0.666666666667)
        for cause in MODULE.CAUSES:
            self.assertEqual(metrics["per_class"][cause]["fn"], 1)
            self.assertEqual(metrics["per_class"][cause]["recall"]["denominator"], 2)

    def test_validation_gate_boundaries_are_exact(self):
        gate_policy = policy()["validation_gate"]
        boundary = MODULE._validation_gate(
            {
                "coverage": {"value": gate_policy["coverage_at_least"]},
                "balanced_accuracy": gate_policy[
                    "balanced_accuracy_strictly_greater_than"
                ],
            },
            gate_policy,
        )
        self.assertTrue(boundary["coverage_passed"])
        self.assertFalse(boundary["balanced_accuracy_passed"])
        self.assertFalse(boundary["passed"])

        above = MODULE._validation_gate(
            {
                "coverage": {"value": gate_policy["coverage_at_least"]},
                "balanced_accuracy": math.nextafter(
                    gate_policy["balanced_accuracy_strictly_greater_than"], math.inf
                ),
            },
            gate_policy,
        )
        self.assertTrue(above["passed"])
        below = MODULE._validation_gate(
            {
                "coverage": {
                    "value": math.nextafter(gate_policy["coverage_at_least"], -math.inf)
                },
                "balanced_accuracy": 1.0,
            },
            gate_policy,
        )
        self.assertFalse(below["coverage_passed"])
        self.assertFalse(below["passed"])

    def test_full_digest_identity_is_fenced_across_reads(self):
        source = self.root / "bound.mat"
        source.write_bytes(b"first-version")
        observation = replace(
            self.observations[0],
            source_path=source,
            source_identity=MODULE._source_identity(source),
        )
        reader = MODULE.identity_bound_reader(
            (observation,),
            lambda _source, _dataset, start, stop: summary_from_features(
                feature_values("silent", 0, start), start, stop
            ),
        )
        start = policy()["window_policy"]["expected_starts"][0]
        reader(source, observation.dataset_path, start, start + WINDOW_COLUMNS)

        source.write_bytes(b"other-version")
        with self.assertRaisesRegex(
            MODULE.EvaluationInputError, "source_changed_since_full_digest"
        ):
            reader(source, observation.dataset_path, start, start + WINDOW_COLUMNS)

    def test_report_is_canonical_path_free_and_input_preserving(self):
        for item in self.observations:
            item.source_path.write_bytes(b"private unchanged bytes")
        before = {
            item.source_path: item.source_path.read_bytes()
            for item in self.observations
        }
        report = evaluate(self.observations, SyntheticReader())
        report_path = self.root / "private" / "report.json"

        MODULE.write_report(report_path, report)

        encoded = report_path.read_bytes()
        self.assertEqual(encoded, MODULE.render_report(report))
        reordered = {key: report[key] for key in reversed(tuple(report))}
        self.assertEqual(encoded, MODULE.render_report(reordered))
        self.assertTrue(encoded.startswith(b'{"abstentions":'))
        self.assertEqual(set(report), MODULE.TOP_LEVEL_FIELDS)
        self.assertEqual(stat_mode(report_path), 0o600)
        for private_value in (
            str(self.root),
            "private-w1.mat",
            "private-silent",
            "Nojamming",
            "Sine",
            "Gaussian",
        ):
            self.assertNotIn(private_value, encoded.decode("utf-8"))
        encoded_text = encoded.decode("utf-8")
        for item in self.observations:
            self.assertNotIn(item.observation_id, encoded_text)
            for group_id in item.groups.values():
                self.assertNotIn(group_id, encoded_text)
        self.assertEqual(
            before,
            {path: path.read_bytes() for path in before},
        )

    def test_report_is_invariant_to_opaque_identifier_values(self):
        baseline = evaluate(self.observations, SyntheticReader())
        all_identifiers = sorted(
            {
                identifier
                for item in self.observations
                for identifier in (item.observation_id, *item.groups.values())
            }
        )
        relabel = {
            identifier: opaque(900_000 - index)
            for index, identifier in enumerate(all_identifiers)
        }
        relabeled = tuple(
            replace(
                item,
                observation_id=relabel[item.observation_id],
                groups={field: relabel[value] for field, value in item.groups.items()},
            )
            for item in self.observations
        )

        self.assertEqual(
            MODULE.render_report(evaluate(relabeled, SyntheticReader())),
            MODULE.render_report(baseline),
        )

    def test_only_controlled_cause_is_predicted(self):
        report = evaluate(self.observations, SyntheticReader())

        self.assertEqual(report["scope"]["target"], "controlled_cause")
        self.assertEqual(
            report["test_metrics"]["confusion"]["predicted_labels"],
            ["silent", "sine", "gaussian", "abstain"],
        )
        encoded = MODULE.render_report(report).decode("utf-8")
        for forbidden in (
            '"target":"identity"',
            '"target":"tamper"',
            '"target":"malicious_intent"',
        ):
            self.assertNotIn(forbidden, encoded)
        predictions = {
            item.observation_id: "malicious" for item in self.observations[:3]
        }
        with self.assertRaisesRegex(
            MODULE.EvaluationInputError, "prediction_outside_controlled_cause"
        ):
            MODULE.metric_summary(self.observations[:3], predictions)


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777


if __name__ == "__main__":
    unittest.main()
