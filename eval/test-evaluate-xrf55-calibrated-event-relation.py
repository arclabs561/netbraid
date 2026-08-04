#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Hermetic checks for calibrated XRF55 event-relation evaluation."""

from __future__ import annotations

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


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = load_module(
    "evaluate_xrf55_calibrated_event_relation",
    HERE / "evaluate-xrf55-calibrated-event-relation.py",
)
FIXTURE = load_module(
    "xrf55_calibrated_fixture_source",
    HERE / "test-evaluate-xrf55-cross-modal-retrieval.py",
)


def load_fixture(root, *, matrices=None):
    adapter_path, matrix_paths, _ = FIXTURE._write_fixture(root, matrices=matrices)
    return MODULE.load_pair_cache(
        adapter_path, matrix_paths["wifi"], matrix_paths["rfid"]
    )


def models_and_pairs(cache, repetitions):
    forward = MODULE._fit_direction(cache, "wifi", "rfid")
    reverse = MODULE._fit_direction(cache, "rfid", "wifi")
    return forward, reverse, MODULE._pair_scores(cache, repetitions, forward, reverse)


class Xrf55CalibratedEventRelationTests(unittest.TestCase):
    def test_role_pair_counts_and_calibration_profile_are_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = load_fixture(Path(directory))
            forward, reverse, calibration = models_and_pairs(
                cache, MODULE.CALIBRATION_REPETITIONS
            )
            validation = MODULE._pair_scores(
                cache, MODULE.VALIDATION_REPETITIONS, forward, reverse
            )
            test = MODULE._pair_scores(cache, MODULE.TEST_REPETITIONS, forward, reverse)

        for rows, total, same, different in (
            (calibration, 72, 24, 48),
            (validation, 72, 24, 48),
            (test, 288, 48, 240),
        ):
            with self.subTest(total=total):
                self.assertEqual(len(rows), total)
                self.assertEqual(sum(row.reference == "same" for row in rows), same)
                self.assertEqual(
                    sum(row.reference == "different" for row in rows), different
                )
                self.assertEqual(len({row.frame_id for row in rows}), total)

        thresholds = MODULE._thresholds(calibration, "forward", "reverse")
        profile = MODULE._profile(cache, (forward, reverse), thresholds, kind="learned")
        self.assertLess(
            float.fromhex(profile.forward_same_threshold),
            float.fromhex(profile.forward_different_threshold),
        )
        self.assertLess(
            float.fromhex(profile.reverse_same_threshold),
            float.fromhex(profile.reverse_different_threshold),
        )

    def test_locked_test_rows_do_not_affect_fit_or_calibration(self):
        events = FIXTURE._events()
        baseline = FIXTURE._matrices(events)
        changed = {name: matrix.copy() for name, matrix in baseline.items()}
        test_rows = [
            index
            for index, event in enumerate(events)
            if event.repetition in MODULE.TEST_REPETITIONS
        ]
        for modality in ("wifi", "rfid"):
            changed[modality][test_rows] += 10_000.0

        with tempfile.TemporaryDirectory() as first_directory:
            first = load_fixture(Path(first_directory), matrices=baseline)
            first_forward, first_reverse, first_calibration = models_and_pairs(
                first, MODULE.CALIBRATION_REPETITIONS
            )
            first_thresholds = MODULE._thresholds(
                first_calibration, "forward", "reverse"
            )
            first_profile = MODULE._profile(
                first,
                (first_forward, first_reverse),
                first_thresholds,
                kind="learned",
            )
        with tempfile.TemporaryDirectory() as second_directory:
            second = load_fixture(Path(second_directory), matrices=changed)
            second_forward, second_reverse, second_calibration = models_and_pairs(
                second, MODULE.CALIBRATION_REPETITIONS
            )
            second_thresholds = MODULE._thresholds(
                second_calibration, "forward", "reverse"
            )
            second_profile = MODULE._profile(
                second,
                (second_forward, second_reverse),
                second_thresholds,
                kind="learned",
            )

        self.assertEqual(first_thresholds, second_thresholds)
        first_document = first_profile.document()
        second_document = second_profile.document()
        for field in (
            "model_digest",
            "fit_partition_digest",
            "calibration_partition_digest",
            "forward_same_threshold",
            "forward_different_threshold",
            "reverse_same_threshold",
            "reverse_different_threshold",
        ):
            self.assertEqual(first_document[field], second_document[field])
        self.assertNotEqual(
            first_document["input_matrix_digest"],
            second_document["input_matrix_digest"],
        )

    def test_qualified_projection_changes_only_event_relation(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = load_fixture(Path(directory))
            forward, reverse, calibration = models_and_pairs(
                cache, MODULE.CALIBRATION_REPETITIONS
            )
            profile = MODULE._profile(
                cache,
                (forward, reverse),
                MODULE._thresholds(calibration, "forward", "reverse"),
                kind="learned",
            )
            prediction = MODULE._prediction(calibration[0], profile, "learned")
            row = MODULE.qualified_prediction_row(prediction)

        self.assertEqual(row["frame_id"], prediction.frame_id)
        self.assertEqual(row["predictions"]["event_relation"], prediction.decision)
        self.assertTrue(
            all(
                value == "abstain"
                for axis, value in row["predictions"].items()
                if axis != "event_relation"
            )
        )
        forbidden = {
            "identity",
            "performer",
            "device",
            "source",
            "principal",
            "intent",
            "tamper",
        }
        self.assertTrue(forbidden.isdisjoint(row))

    def test_validation_failure_never_scores_test_role(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = load_fixture(Path(directory))
            original = MODULE._pair_scores
            roles = []

            def recording_pair_scores(cache, repetitions, forward, reverse):
                roles.append(repetitions)
                return original(cache, repetitions, forward, reverse)

            with mock.patch.object(MODULE, "_pair_scores", recording_pair_scores):
                with mock.patch.object(
                    MODULE,
                    "_validation_gate",
                    return_value={"checks": {"forced": False}, "passed": False},
                ):
                    report = MODULE.evaluate(cache)

        self.assertEqual(report["status"], "validation_failed")
        self.assertIsNone(report["test"])
        self.assertNotIn(MODULE.TEST_REPETITIONS, roles)

    def test_calibration_failure_never_scores_validation_or_test_roles(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = load_fixture(Path(directory))
            original = MODULE._pair_scores
            roles = []

            def recording_pair_scores(cache, repetitions, forward, reverse):
                roles.append(repetitions)
                return original(cache, repetitions, forward, reverse)

            invalid = (0.75, 0.25, 0.8, 0.2)
            ordered = (0.25, 0.75, 0.2, 0.8)
            with mock.patch.object(MODULE, "_pair_scores", recording_pair_scores):
                with mock.patch.object(
                    MODULE, "_thresholds", side_effect=(invalid, ordered)
                ):
                    report = MODULE.evaluate(cache)

        self.assertEqual(report["status"], "calibration_failed")
        self.assertEqual(
            report["profiles"]["learned"]["status"], "invalid_threshold_order"
        )
        self.assertEqual(
            report["profiles"]["learned"]["thresholds"],
            [value.hex() for value in invalid],
        )
        self.assertEqual(
            report["profiles"]["unaligned"]["status"], "thresholds_ordered"
        )
        self.assertIsNone(report["validation"])
        self.assertIsNone(report["test"])
        self.assertEqual(roles, [MODULE.CALIBRATION_REPETITIONS])

    def test_report_is_deterministic_private_and_mmap_backed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = load_fixture(root)
            report = MODULE.evaluate(cache)
            first = root / "first.json"
            second = root / "second.json"
            MODULE._write_report(first, report)
            MODULE._write_report(second, report)
            first_bytes = first.read_bytes()
            second_bytes = second.read_bytes()

        self.assertEqual(first_bytes, second_bytes)
        for matrix in cache.matrices.values():
            self.assertIsInstance(matrix, np.memmap)
            self.assertEqual(matrix.mode, "r")
        encoded = first_bytes.decode()
        for forbidden in (str(root), "synthetic-test", "example.invalid"):
            self.assertNotIn(forbidden, encoded)
        document = json.loads(first_bytes)

        def keys(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    yield key
                    yield from keys(item)
            elif isinstance(value, list):
                for item in value:
                    yield from keys(item)

        self.assertTrue(
            {"performer_id", "device_id", "source_id"}.isdisjoint(keys(document))
        )
        self.assertEqual(document["schema"], MODULE.REPORT_SCHEMA)
        self.assertEqual(document["status"], "validation_failed")
        self.assertIsNone(document["test"])
        self.assertEqual(document["calibration"]["rows"], 72)


if __name__ == "__main__":
    unittest.main(verbosity=2)
