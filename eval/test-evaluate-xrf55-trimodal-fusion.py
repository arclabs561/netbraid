#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Hermetic checks for preregistered XRF55 trimodal-fusion evaluation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "evaluate_xrf55_trimodal_fusion",
    HERE / "evaluate-xrf55-trimodal-fusion.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _opaque(text):
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024**2):
            digest.update(chunk)
    return digest.hexdigest()


def _latent(group_index, repetition):
    group = group_index / 16.0
    event = repetition / 20.0
    return np.array(
        [
            1.0,
            group,
            group**2,
            event,
            event**2,
            event**3,
            np.sin(np.pi * event),
            np.cos(np.pi * event),
        ],
        dtype=np.float64,
    )


def _role_matrices(role, events, role_group_indices):
    matrices = {}
    group_index_by_id = {
        _opaque(f"group-{group_index}"): group_index
        for group_index in role_group_indices
    }
    for modality_index, modality in enumerate(MODULE.MODALITIES):
        random = np.random.default_rng(3100 + modality_index)
        transform = random.normal(size=(8, 12))
        offset = random.normal(size=12)
        matrix = np.zeros((len(events), MODULE.FEATURE_COUNT), dtype="<f8")
        for event in events:
            group_index = group_index_by_id[event["group_id"]]
            repetition = event["row"] % MODULE.EVENTS_PER_GROUP + 1
            noise = 1e-3 * np.sin(
                np.arange(12, dtype=np.float64) + event["row"] * 0.37 + modality_index
            )
            matrix[event["row"], :12] = (
                _latent(group_index, repetition) @ transform + offset + noise
            )
            matrix[event["row"], 12:] = modality_index
        matrices[modality] = matrix
    return matrices


def _events_for_role(role):
    first, last = MODULE.ROLE_GROUP_RANKS[role]
    events = []
    for group_index in range(first, last + 1):
        group_id = _opaque(f"group-{group_index}")
        for repetition in range(1, MODULE.EVENTS_PER_GROUP + 1):
            events.append(
                {
                    "event_id": _opaque(f"event-{group_index}-{repetition}"),
                    "group_id": group_id,
                    "role": role,
                    "row": len(events),
                }
            )
    return events


def _adapter(role, events, artifacts):
    first, last = MODULE.ROLE_GROUP_RANKS[role]
    return {
        "schema": MODULE.ROLE_CACHE_SCHEMA,
        "provenance": {
            "dataset": "XRF55 processed RF arrays",
            "publisher_implementation_revision": (
                MODULE.PUBLISHER_IMPLEMENTATION_REVISION
            ),
            "publisher_project": "https://aiotgroup.github.io/XRF55/",
        },
        "integrity": {
            "all_archive_bytes_freshly_rehashed": False,
            "basis": "exact_size_and_fetch_receipt_metadata_plus_selected_member_crc",
            "artifacts": artifacts,
        },
        "feature_policy": MODULE.FEATURES.feature_policy_document(),
        "role_policy": {
            "assignment": "complete_opaque_performer_action_group_rank",
            "first_group_rank": first,
            "last_group_rank": last,
            "modalities_colocated": list(MODULE.MODALITIES),
            "role": role,
            "whole_groups_disjoint": True,
        },
        "events": events,
        "counts": {
            "archives": 2,
            "events": MODULE.ROLE_EVENT_COUNTS[role],
            "features_per_modality": MODULE.FEATURE_COUNT,
            "groups": MODULE.ROLE_GROUP_COUNTS[role],
            "modalities": len(MODULE.MODALITIES),
        },
        "privacy": {
            "archive_names_retained": 0,
            "local_paths_retained": 0,
            "member_names_retained": 0,
            "raw_action_identifiers_retained": 0,
            "raw_labels_retained": 0,
            "raw_performer_identifiers_retained": 0,
            "raw_repetition_identifiers_retained": 0,
            "raw_scene_identifiers_retained": 0,
            "raw_source_values_retained": 0,
        },
    }


def _write_role(root, role, *, mutate=None):
    paths = MODULE.role_paths(root, role)
    events = _events_for_role(role)
    first, last = MODULE.ROLE_GROUP_RANKS[role]
    matrices = _role_matrices(role, events, range(first, last + 1))
    if mutate is not None:
        mutate(matrices)
    artifacts = {}
    for modality in MODULE.MODALITIES:
        path = paths.matrices[modality]
        with path.open("wb") as output:
            np.save(output, matrices[modality], allow_pickle=False)
        path.chmod(0o600)
        artifacts[modality] = {
            "bytes": path.stat().st_size,
            "dtype": "<f8",
            "sha256": _sha256(path),
            "shape": [MODULE.ROLE_EVENT_COUNTS[role], MODULE.FEATURE_COUNT],
        }
    document = _adapter(role, events, artifacts)
    paths.adapter.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    paths.adapter.chmod(0o600)
    return paths


def _write_fixture(root, mutations=None):
    mutations = {} if mutations is None else mutations
    return {
        role: _write_role(root, role, mutate=mutations.get(role))
        for role in MODULE.ROLE_ORDER
    }


def _read_adapter(path):
    return json.loads(path.read_text())


def _write_adapter(path, document):
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def _force_pass(_summary):
    return {"comparisons": {}, "passed": True, "quality": {}}


def _boundary_metrics(*, coverage=50, false_links=4, false_nonmatches=2, risk=6):
    return {
        "support": {"different": 80, "same": 20, "total": 100},
        "coverage": MODULE._rate(coverage, 100),
        "abstention": MODULE._rate(100 - coverage, 100),
        "selective_risk": MODULE._rate(risk, coverage),
        "false_link": MODULE._rate(false_links, 80),
        "false_nonmatch": MODULE._rate(false_nonmatches, 20),
    }


def _gate_summary():
    result = {}
    fused = _boundary_metrics()
    for method in MODULE.METHODS:
        candidate = fused if method == "fusion" else _boundary_metrics(risk=7)
        result[method] = {
            "overall": candidate,
            "by_group": {"group_01": candidate, "group_02": candidate},
        }
    return result


class Xrf55TrimodalFusionOracleTests(unittest.TestCase):
    def test_vectorized_scores_match_independent_naive_oracle_for_all_pairs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = _write_fixture(root)
            roles = MODULE.load_pre_gate_roles(
                {role: paths[role] for role in MODULE.PRE_GATE_ROLES}
            )
            fit = MODULE.fit_train_role(roles["train"])
            scored = MODULE.score_role(roles["validation"], fit)
            role = roles["validation"]
            standardized = {
                modality: MODULE._standardize(
                    role.matrices[modality], fit.standardizers[modality]
                )
                for modality in MODULE.MODALITIES
            }
            first_group = scored.groups[0]
            events = sorted(
                (
                    event
                    for event in role.adapter.events
                    if event.group_id == first_group.group_id
                ),
                key=lambda event: event.event_id,
            )

            for method in MODULE.PAIR_METHODS:
                left, right = MODULE.PAIR_MODALITIES[method]
                forward = fit.directions[(left, right)]
                reverse = fit.directions[(right, left)]
                expected = []
                for left_event in events:
                    for right_event in events:
                        left_vector = standardized[left][left_event.row]
                        right_vector = standardized[right][right_event.row]
                        forward_difference = (
                            left_vector @ forward.weights - right_vector
                        )
                        reverse_difference = (
                            right_vector @ reverse.weights - left_vector
                        )
                        forward_score = float(
                            np.mean(forward_difference * forward_difference)
                            / forward.normalizer
                        )
                        reverse_score = float(
                            np.mean(reverse_difference * reverse_difference)
                            / reverse.normalizer
                        )
                        expected.append((forward_score + reverse_score) / 2.0)
                np.testing.assert_allclose(
                    first_group.methods[method],
                    np.asarray(expected),
                    rtol=1e-12,
                    atol=1e-12,
                )

            expected_fusion = np.mean(
                np.stack(
                    [first_group.methods[method] for method in MODULE.PAIR_METHODS]
                ),
                axis=0,
            )
            np.testing.assert_array_equal(
                first_group.methods["fusion"], expected_fusion
            )

    def test_hand_scored_confusion_metrics_are_exact(self):
        observed = MODULE.metrics(
            np.array([0.1, 0.2, 0.5, 0.7, 0.8, 0.9]),
            np.array([True, False, True, False, True, False]),
            MODULE.Thresholds(0.25, 0.75),
        )

        self.assertEqual(observed["support"], {"different": 3, "same": 3, "total": 6})
        self.assertEqual(observed["coverage"], MODULE._rate(4, 6))
        self.assertEqual(observed["abstention"], MODULE._rate(2, 6))
        self.assertEqual(observed["selective_risk"], MODULE._rate(2, 4))
        self.assertEqual(observed["false_link"], MODULE._rate(1, 3))
        self.assertEqual(observed["false_nonmatch"], MODULE._rate(1, 3))

    def test_linear_quantiles_and_strict_order_are_fixed(self):
        same = np.arange(10, dtype=np.float64)
        different = np.arange(10, 20, dtype=np.float64)
        group = MODULE.GroupScores(
            "opaque",
            np.array([True] * 10 + [False] * 10),
            {method: np.concatenate((same, different)) for method in MODULE.METHODS},
        )
        thresholds = MODULE.calibrate(MODULE.ScoredRole((group,)))

        for method in MODULE.METHODS:
            self.assertEqual(thresholds[method], MODULE.Thresholds(8.1, 10.9))


class Xrf55TrimodalFusionIsolationTests(unittest.TestCase):
    def test_later_roles_cannot_change_earlier_fit_or_calibration(self):
        def offset(amount):
            def mutate(matrices):
                for matrix in matrices.values():
                    matrix[:, :12] += amount

            return mutate

        with tempfile.TemporaryDirectory() as baseline_directory:
            baseline_root = Path(baseline_directory)
            baseline_paths = _write_fixture(baseline_root)
            baseline_roles = MODULE.load_pre_gate_roles(
                {role: baseline_paths[role] for role in MODULE.PRE_GATE_ROLES}
            )
            baseline_fit = MODULE.fit_train_role(baseline_roles["train"])
            baseline_thresholds = MODULE.calibrate(
                MODULE.score_role(baseline_roles["calibration"], baseline_fit)
            )
            baseline_report, _ = MODULE.evaluate_validation_roles(baseline_roles)

        with tempfile.TemporaryDirectory() as calibration_directory:
            calibration_paths = _write_fixture(
                Path(calibration_directory), {"calibration": offset(1000.0)}
            )
            calibration_roles = MODULE.load_pre_gate_roles(
                {role: calibration_paths[role] for role in MODULE.PRE_GATE_ROLES}
            )
            calibration_fit = MODULE.fit_train_role(calibration_roles["train"])

        with tempfile.TemporaryDirectory() as validation_directory:
            validation_paths = _write_fixture(
                Path(validation_directory), {"validation": offset(2000.0)}
            )
            validation_roles = MODULE.load_pre_gate_roles(
                {role: validation_paths[role] for role in MODULE.PRE_GATE_ROLES}
            )
            validation_fit = MODULE.fit_train_role(validation_roles["train"])
            validation_thresholds = MODULE.calibrate(
                MODULE.score_role(validation_roles["calibration"], validation_fit)
            )

        with tempfile.TemporaryDirectory() as locked_directory:
            locked_paths = _write_fixture(
                Path(locked_directory), {"locked_test": offset(3000.0)}
            )
            locked_report, _ = MODULE.run_validation(
                {role: locked_paths[role] for role in MODULE.PRE_GATE_ROLES}
            )

        self.assertEqual(baseline_fit.digest, calibration_fit.digest)
        self.assertEqual(baseline_fit.digest, validation_fit.digest)
        self.assertNotEqual(
            baseline_thresholds,
            MODULE.calibrate(
                MODULE.score_role(calibration_roles["calibration"], calibration_fit)
            ),
        )
        self.assertEqual(baseline_thresholds, validation_thresholds)
        self.assertEqual(baseline_report, locked_report)

    def test_validation_reports_fusion_and_all_three_pair_baselines(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = _write_fixture(Path(directory))
            report, _ = MODULE.run_validation(
                {role: paths[role] for role in MODULE.PRE_GATE_ROLES}
            )

        self.assertEqual(tuple(report["calibration"]["thresholds"]), MODULE.METHODS)
        self.assertIsNotNone(report["validation"])
        self.assertEqual(tuple(report["validation"]["metrics"]), MODULE.METHODS)
        for method in MODULE.METHODS:
            self.assertEqual(
                set(report["validation"]["metrics"][method]),
                {"overall", "by_group"},
            )

    def test_validation_gate_accepts_exact_boundaries_and_rejects_each_overstep(self):
        self.assertTrue(MODULE.validation_gate(_gate_summary())["passed"])

        mutations = {
            "coverage": {"coverage": MODULE._rate(49, 100)},
            "false_link": {"false_link": MODULE._rate(5, 80)},
            "false_nonmatch": {"false_nonmatch": MODULE._rate(3, 20)},
        }
        for name, change in mutations.items():
            with self.subTest(name=name):
                summary = _gate_summary()
                summary["fusion"]["overall"] = {
                    **summary["fusion"]["overall"],
                    **change,
                }
                self.assertFalse(MODULE.validation_gate(summary)["passed"])

        for name, change in (
            ("equal_risk", {"selective_risk": MODULE._rate(6, 50)}),
            ("higher_coverage", {"coverage": MODULE._rate(51, 100)}),
        ):
            with self.subTest(name=name):
                summary = _gate_summary()
                summary["wifi_rfid"]["by_group"]["group_01"] = {
                    **summary["wifi_rfid"]["by_group"]["group_01"],
                    **change,
                }
                self.assertFalse(MODULE.validation_gate(summary)["passed"])


class Xrf55TrimodalFusionBoundaryTests(unittest.TestCase):
    def test_failed_validation_receipt_never_opens_locked_adapter_or_matrix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = _write_fixture(root)
            receipt, _ = MODULE.run_validation(
                {role: paths[role] for role in MODULE.PRE_GATE_ROLES}
            )
            receipt["status"] = "validation_failed"
            receipt_path = root / "receipt.json"
            MODULE._write_atomic(receipt_path, receipt)
            opened_roles = []
            original = MODULE._load_role_adapter

            def recording_load(role, selected_paths):
                opened_roles.append(role)
                return original(role, selected_paths)

            with mock.patch.object(MODULE, "_load_role_adapter", recording_load):
                with self.assertRaisesRegex(
                    MODULE.Xrf55TrimodalFusionError,
                    "validation_receipt_not_passed",
                ):
                    MODULE.run_locked_test(paths, receipt_path, root / "locked.used")

        self.assertNotIn("locked_test", opened_roles)

    def test_passed_receipt_is_content_bound_and_locked_test_is_single_use(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = _write_fixture(root)
            receipt_path = root / "receipt.json"
            marker = root / "receipt.used"
            with mock.patch.object(MODULE, "validation_gate", _force_pass):
                receipt, _ = MODULE.run_validation(
                    {role: paths[role] for role in MODULE.PRE_GATE_ROLES}
                )
                MODULE._write_atomic(receipt_path, receipt)
                locked = MODULE.run_locked_test(paths, receipt_path, marker)

            self.assertEqual(locked["model"]["digest"], receipt["model"]["digest"])
            self.assertEqual(locked["profile"]["digest"], receipt["profile"]["digest"])
            self.assertEqual(
                locked["bindings"]["feature_policy_digest"],
                receipt["bindings"]["feature_policy_digest"],
            )
            self.assertEqual(stat.S_IMODE(marker.stat().st_mode), 0o600)
            with mock.patch.object(MODULE, "validation_gate", _force_pass):
                with self.assertRaisesRegex(
                    MODULE.Xrf55TrimodalFusionError, "locked_test_already_used"
                ):
                    MODULE.run_locked_test(paths, receipt_path, marker)

    def test_forged_passed_receipt_fails_replay_before_locked_open(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = _write_fixture(root)
            receipt_path = root / "receipt.json"
            marker = root / "receipt.used"
            with mock.patch.object(MODULE, "validation_gate", _force_pass):
                receipt, _ = MODULE.run_validation(
                    {role: paths[role] for role in MODULE.PRE_GATE_ROLES}
                )
                receipt["model"]["digest"] = "f" * 64
                MODULE._write_atomic(receipt_path, receipt)
                opened_roles = []
                original = MODULE._load_role_adapter

                def recording_load(role, selected_paths):
                    opened_roles.append(role)
                    return original(role, selected_paths)

                with mock.patch.object(MODULE, "_load_role_adapter", recording_load):
                    with self.assertRaisesRegex(
                        MODULE.Xrf55TrimodalFusionError,
                        "validation_receipt_replay_mismatch",
                    ):
                        MODULE.run_locked_test(paths, receipt_path, marker)

            self.assertFalse(marker.exists())
            self.assertNotIn("locked_test", opened_roles)


class Xrf55TrimodalFusionHardeningTests(unittest.TestCase):
    def test_reports_are_byte_deterministic_private_atomic_and_mmap_backed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = _write_fixture(root)
            selected = {role: paths[role] for role in MODULE.PRE_GATE_ROLES}
            roles = MODULE.load_pre_gate_roles(selected)
            first_report, _ = MODULE.evaluate_validation_roles(roles)
            second_report, _ = MODULE.run_validation(selected)
            first = root / "first.json"
            second = root / "second.json"
            MODULE._write_atomic(first, first_report)
            MODULE._write_atomic(second, second_report)
            first_bytes = first.read_bytes()

            self.assertEqual(first_bytes, second.read_bytes())
            self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o600)
            for role in roles.values():
                for matrix in role.matrices.values():
                    self.assertIsInstance(matrix, np.memmap)
                    self.assertEqual(matrix.mode, "r")
                    self.assertFalse(matrix.flags.writeable)
            encoded = first_bytes.decode("ascii")
            self.assertNotIn(str(root), encoded)
            for role in MODULE.PRE_GATE_ROLES:
                adapter = _read_adapter(paths[role].adapter)
                for event in adapter["events"]:
                    self.assertNotIn(event["event_id"], encoded)
                    self.assertNotIn(event["group_id"], encoded)

    def test_duplicate_json_tampered_matrix_and_private_field_fail_closed(self):
        with self.subTest(case="duplicate_json_key"):
            with tempfile.TemporaryDirectory() as directory:
                paths = _write_fixture(Path(directory))
                paths["train"].adapter.write_text('{"schema":1,"schema":2}\n')
                with self.assertRaisesRegex(
                    MODULE.Xrf55TrimodalFusionError, "invalid_adapter_json"
                ):
                    MODULE.run_validation(
                        {role: paths[role] for role in MODULE.PRE_GATE_ROLES}
                    )

        with self.subTest(case="tampered_matrix"):
            with tempfile.TemporaryDirectory() as directory:
                paths = _write_fixture(Path(directory))
                matrix_path = paths["calibration"].matrices["rfid"]
                with matrix_path.open("r+b") as output:
                    output.seek(-1, os.SEEK_END)
                    original = output.read(1)
                    output.seek(-1, os.SEEK_END)
                    output.write(bytes([original[0] ^ 1]))
                with self.assertRaisesRegex(
                    MODULE.Xrf55TrimodalFusionError, "matrix_digest_mismatch"
                ):
                    MODULE.run_validation(
                        {role: paths[role] for role in MODULE.PRE_GATE_ROLES}
                    )

        with self.subTest(case="private_field"):
            with tempfile.TemporaryDirectory() as directory:
                paths = _write_fixture(Path(directory))
                adapter = _read_adapter(paths["validation"].adapter)
                adapter["events"][0]["raw_label"] = "forbidden"
                _write_adapter(paths["validation"].adapter, adapter)
                with self.assertRaisesRegex(
                    MODULE.Xrf55TrimodalFusionError,
                    "invalid_role_event_schema",
                ):
                    MODULE.run_validation(
                        {role: paths[role] for role in MODULE.PRE_GATE_ROLES}
                    )

    def test_shape_nonfinite_row_drift_group_overlap_and_zero_normalizer_fail_closed(
        self,
    ):
        cases = (
            ("shape", "invalid_artifact_contract"),
            ("row", "invalid_role_event_record"),
            ("overlap", "role_group_overlap"),
        )
        for case, error in cases:
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as directory:
                    paths = _write_fixture(Path(directory))
                    adapter = _read_adapter(paths["validation"].adapter)
                    if case == "shape":
                        adapter["integrity"]["artifacts"]["wifi"]["shape"][0] -= 1
                    elif case == "row":
                        adapter["events"][0]["row"] = 1
                    else:
                        train = _read_adapter(paths["train"].adapter)
                        original_group = adapter["events"][0]["group_id"]
                        overlapping_group = train["events"][0]["group_id"]
                        for event in adapter["events"]:
                            if event["group_id"] == original_group:
                                event["group_id"] = overlapping_group
                    _write_adapter(paths["validation"].adapter, adapter)
                    with self.assertRaisesRegex(MODULE.Xrf55TrimodalFusionError, error):
                        MODULE.run_validation(
                            {role: paths[role] for role in MODULE.PRE_GATE_ROLES}
                        )

        with self.subTest(case="nonfinite"):

            def nonfinite(matrices):
                matrices["wifi"][0, 0] = np.nan

            with tempfile.TemporaryDirectory() as directory:
                paths = _write_fixture(Path(directory), {"calibration": nonfinite})
                with self.assertRaisesRegex(
                    MODULE.Xrf55TrimodalFusionError, "matrix_contract_mismatch"
                ):
                    MODULE.run_validation(
                        {role: paths[role] for role in MODULE.PRE_GATE_ROLES}
                    )

        with self.subTest(case="zero_normalizer"):
            with tempfile.TemporaryDirectory() as directory:
                paths = _write_fixture(Path(directory))
                roles = MODULE.load_pre_gate_roles(
                    {role: paths[role] for role in MODULE.PRE_GATE_ROLES}
                )
                with mock.patch.object(
                    MODULE,
                    "_mean_squared_residual",
                    return_value=np.zeros(MODULE.ROLE_EVENT_COUNTS["train"]),
                ):
                    with self.assertRaisesRegex(
                        MODULE.Xrf55TrimodalFusionError,
                        "zero_train_residual_normalizer",
                    ):
                        MODULE.fit_train_role(roles["train"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
