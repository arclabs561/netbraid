#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Hermetic checks for the XRF55 joint-representation evaluator."""

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
    "evaluate_xrf55_joint_representation_adequacy",
    HERE / "evaluate-xrf55-joint-representation-adequacy.py",
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
    event = repetition / MODULE.EVENTS_PER_GROUP
    return np.array(
        [
            1.0,
            group_index / 20.0,
            event,
            event**2,
            np.sin(np.pi * event),
            np.cos(np.pi * event),
            np.sin(2.0 * np.pi * event),
            np.cos(2.0 * np.pi * event),
            np.sin(3.0 * np.pi * event),
            np.cos(3.0 * np.pi * event),
        ],
        dtype=np.float64,
    )


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


def _role_matrices(role, events):
    first, last = MODULE.ROLE_GROUP_RANKS[role]
    group_by_id = {
        _opaque(f"group-{group_index}"): group_index
        for group_index in range(first, last + 1)
    }
    matrices = {}
    for modality_index, modality in enumerate(MODULE.MODALITIES):
        random = np.random.default_rng(3500 + modality_index)
        transform = random.normal(size=(10, 12))
        offset = random.normal(size=12)
        matrix = np.full(
            (len(events), MODULE.FEATURE_COUNT),
            fill_value=float(modality_index),
            dtype="<f8",
        )
        for event in events:
            group_index = group_by_id[event["group_id"]]
            repetition = event["row"] % MODULE.EVENTS_PER_GROUP + 1
            noise = 1e-4 * np.sin(
                np.arange(12, dtype=np.float64) + event["row"] * 0.37 + modality_index
            )
            matrix[event["row"], :12] = (
                _latent(group_index, repetition) @ transform + offset + noise
            )
        matrices[modality] = matrix
    return matrices


def _source_document():
    return {
        "archive_profile_set_sha256": _opaque("archive-profile-set"),
        "archive_receipt_set_sha256": _opaque("archive-receipt-set"),
    }


def _expected_cache_contract():
    source_binding = {
        "archive_profile_set_sha256": hashlib.sha256(
            b"archive-profile-set"
        ).hexdigest(),
        "archive_receipt_set_sha256": hashlib.sha256(
            b"archive-receipt-set"
        ).hexdigest(),
    }
    role_manifests = {}
    for role in MODULE.ROLE_ORDER:
        first, last = MODULE.ROLE_GROUP_RANKS[role]
        manifest = []
        for group_index in range(first, last + 1):
            group_id = hashlib.sha256(
                f"group-{group_index}".encode("ascii")
            ).hexdigest()
            for repetition in range(1, MODULE.EVENTS_PER_GROUP + 1):
                manifest.append(
                    MODULE.EventRecord(
                        event_id=hashlib.sha256(
                            f"event-{group_index}-{repetition}".encode("ascii")
                        ).hexdigest(),
                        group_id=group_id,
                        role=role,
                        row=len(manifest),
                    )
                )
        role_manifests[role] = tuple(manifest)
    return MODULE.ExpectedCacheContract(
        source_binding=source_binding,
        role_manifests=role_manifests,
    )


def _run_evaluation(paths):
    return MODULE.run_evaluation(paths, _expected_cache_contract())


def _load_roles(paths):
    return MODULE.load_roles(paths, _expected_cache_contract())


def _adapter(role, events, artifacts):
    source = _source_document()
    feature_policy = MODULE.JOINT.feature_policy_document()
    role_policy = MODULE._role_policy(role)
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
            "basis": ("exact_size_and_fetch_receipt_metadata_plus_selected_member_crc"),
            "artifacts": artifacts,
            "feature_policy_sha256": MODULE._json_digest(
                b"netbraid.xrf55-joint.feature-policy.v0\x00", feature_policy
            ),
            "role_policy_sha256": MODULE._json_digest(
                b"netbraid.xrf55-joint.role-policy.v0\x00",
                MODULE.JOINT.role_policy_document(),
            ),
            "source": source,
        },
        "feature_policy": feature_policy,
        "role_policy": role_policy,
        "events": events,
        "counts": {
            "archives": 2,
            "events": MODULE.ROLE_EVENT_COUNTS[role],
            "features_per_modality": MODULE.FEATURE_COUNT,
            "groups": MODULE.ROLE_GROUP_COUNTS[role],
            "modalities": len(MODULE.MODALITIES),
            "roles": 1,
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
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths = MODULE.role_paths(root, role)
    events = _events_for_role(role)
    matrices = _role_matrices(role, events)
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


class Xrf55JointRepresentationOutcomeTests(unittest.TestCase):
    def test_clean_cache_passes_all_pair_and_group_gates(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = _write_fixture(Path(directory))
            report = _run_evaluation(paths)

        self.assertEqual(report["status"], "validation_pass")
        self.assertTrue(report["calibration"]["gate"]["all_pairs_ordered"])
        self.assertEqual(
            tuple(report["calibration"]["thresholds"]), MODULE.PAIR_METHODS
        )
        self.assertEqual(
            report["calibration"]["support"]["overall"],
            {"different": 760, "same": 40, "total": 800},
        )
        self.assertIsNotNone(report["validation"])
        self.assertTrue(report["validation"]["gate"]["passed"])
        for method in MODULE.PAIR_METHODS:
            metrics = report["validation"]["metrics"][method]
            self.assertEqual(set(metrics), {"overall", "by_group"})
            self.assertEqual(len(metrics["by_group"]), 2)
            self.assertEqual(
                metrics["overall"]["support"],
                {"different": 760, "same": 40, "total": 800},
            )
            for scope in (metrics["overall"], *metrics["by_group"].values()):
                self.assertEqual(
                    set(scope),
                    {
                        "abstention",
                        "coverage",
                        "false_link",
                        "false_nonmatch",
                        "selective_risk",
                        "support",
                    },
                )
            for group in metrics["by_group"].values():
                self.assertEqual(
                    group["support"],
                    {"different": 380, "same": 20, "total": 400},
                )

    def test_calibration_failure_leaves_validation_unscored(self):
        def collapse(matrices):
            for matrix in matrices.values():
                matrix[:] = matrix[0]

        with tempfile.TemporaryDirectory() as directory:
            paths = _write_fixture(Path(directory), {"calibration": collapse})
            report = _run_evaluation(paths)

        self.assertEqual(report["status"], "calibration_failed")
        self.assertFalse(report["calibration"]["gate"]["all_pairs_ordered"])
        self.assertIsNone(report["validation"])

    def test_validation_gate_failure_is_reported_without_changing_calibration(self):
        def scramble(matrices):
            matrices["rfid"][:] = matrices["rfid"][::-1]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = _run_evaluation(_write_fixture(root / "baseline"))
            changed = _run_evaluation(
                _write_fixture(root / "changed", {"validation": scramble})
            )

        self.assertEqual(changed["status"], "validation_failed")
        self.assertFalse(changed["validation"]["gate"]["passed"])
        self.assertEqual(
            baseline["calibration"]["thresholds"],
            changed["calibration"]["thresholds"],
        )
        self.assertEqual(baseline["model"], changed["model"])

    def test_metrics_match_independent_hand_computed_oracle(self):
        observed = MODULE.metrics(
            np.array([0.1, 0.5, 0.9, 0.1, 0.9, 0.5], dtype=np.float64),
            np.array([True, True, True, False, False, False], dtype=bool),
            MODULE.Thresholds(same=0.2, different=0.8),
        )

        self.assertEqual(
            observed,
            {
                "support": {"different": 3, "same": 3, "total": 6},
                "coverage": {
                    "denominator": 6,
                    "numerator": 4,
                    "rate": 0.666666666667,
                },
                "abstention": {
                    "denominator": 6,
                    "numerator": 2,
                    "rate": 0.333333333333,
                },
                "selective_risk": {
                    "denominator": 4,
                    "numerator": 2,
                    "rate": 0.5,
                },
                "false_link": {
                    "denominator": 3,
                    "numerator": 1,
                    "rate": 0.333333333333,
                },
                "false_nonmatch": {
                    "denominator": 3,
                    "numerator": 1,
                    "rate": 0.333333333333,
                },
            },
        )


class Xrf55JointRepresentationContractTests(unittest.TestCase):
    def test_tamper_misalignment_and_overlap_fail_closed(self):
        with self.subTest(case="matrix_tamper"):
            with tempfile.TemporaryDirectory() as directory:
                paths = _write_fixture(Path(directory))
                matrix_path = paths["calibration"].matrices["wifi"]
                with matrix_path.open("r+b") as output:
                    output.seek(-1, os.SEEK_END)
                    value = output.read(1)
                    output.seek(-1, os.SEEK_END)
                    output.write(bytes([value[0] ^ 1]))
                with self.assertRaisesRegex(
                    MODULE.Xrf55JointEvaluationError, "matrix_digest_mismatch"
                ):
                    _run_evaluation(paths)

        with self.subTest(case="row_misalignment"):
            with tempfile.TemporaryDirectory() as directory:
                paths = _write_fixture(Path(directory))
                adapter = _read_adapter(paths["validation"].adapter)
                adapter["events"][0]["row"] = 1
                _write_adapter(paths["validation"].adapter, adapter)
                with self.assertRaisesRegex(
                    MODULE.Xrf55JointEvaluationError, "invalid_role_event_record"
                ):
                    _run_evaluation(paths)

        with self.subTest(case="group_overlap"):
            with tempfile.TemporaryDirectory() as directory:
                paths = _write_fixture(Path(directory))
                train = _read_adapter(paths["train"].adapter)
                validation = _read_adapter(paths["validation"].adapter)
                old_group = validation["events"][0]["group_id"]
                new_group = train["events"][0]["group_id"]
                for event in validation["events"]:
                    if event["group_id"] == old_group:
                        event["group_id"] = new_group
                _write_adapter(paths["validation"].adapter, validation)
                with self.assertRaisesRegex(
                    MODULE.Xrf55JointEvaluationError, "role_group_overlap"
                ):
                    _run_evaluation(paths)

    def test_source_and_policy_digests_are_content_bound(self):
        cases = (
            ("source", "source_digest_mismatch"),
            ("feature", "feature_policy_digest_mismatch"),
            ("role", "role_policy_digest_mismatch"),
        )
        for case, expected in cases:
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as directory:
                    paths = _write_fixture(Path(directory))
                    adapter = _read_adapter(paths["calibration"].adapter)
                    if case == "source":
                        adapter["integrity"]["source"]["archive_profile_set_sha256"] = (
                            "z" * 64
                        )
                    elif case == "feature":
                        adapter["integrity"]["feature_policy_sha256"] = "f" * 64
                    else:
                        adapter["integrity"]["role_policy_sha256"] = "f" * 64
                    _write_adapter(paths["calibration"].adapter, adapter)
                    with self.assertRaisesRegex(
                        MODULE.Xrf55JointEvaluationError, expected
                    ):
                        _run_evaluation(paths)

    def test_role_source_mismatch_is_rejected_after_each_digest_verifies(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = _write_fixture(Path(directory))
            adapter = _read_adapter(paths["validation"].adapter)
            source = {
                "archive_profile_set_sha256": _opaque("other-profile"),
                "archive_receipt_set_sha256": _opaque("other-receipt"),
            }
            adapter["integrity"]["source"] = source
            _write_adapter(paths["validation"].adapter, adapter)
            with self.assertRaisesRegex(
                MODULE.Xrf55JointEvaluationError, "role_source_mismatch"
            ):
                _run_evaluation(paths)

    def test_consistent_source_forgery_is_rejected_by_trusted_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = _write_fixture(Path(directory))
            forged_source = {
                "archive_profile_set_sha256": _opaque("forged-profile-set"),
                "archive_receipt_set_sha256": _opaque("forged-receipt-set"),
            }
            for role in MODULE.ROLE_ORDER:
                adapter = _read_adapter(paths[role].adapter)
                adapter["integrity"]["source"] = forged_source.copy()
                _write_adapter(paths[role].adapter, adapter)

            with mock.patch.object(
                MODULE,
                "_load_role_matrices",
                side_effect=AssertionError("matrix loading reached"),
            ):
                with self.assertRaisesRegex(
                    MODULE.Xrf55JointEvaluationError,
                    "expected_source_binding_mismatch",
                ):
                    _run_evaluation(paths)

    def test_valid_regrouping_is_rejected_by_trusted_role_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = _write_fixture(Path(directory))
            adapter = _read_adapter(paths["validation"].adapter)
            first_group = adapter["events"][0]["group_id"]
            second_group = adapter["events"][MODULE.EVENTS_PER_GROUP]["group_id"]
            for row in range(10, 20):
                adapter["events"][row]["group_id"] = second_group
            for row in range(20, 30):
                adapter["events"][row]["group_id"] = first_group
            _write_adapter(paths["validation"].adapter, adapter)

            with mock.patch.object(
                MODULE,
                "_load_role_matrices",
                side_effect=AssertionError("matrix loading reached"),
            ):
                with self.assertRaisesRegex(
                    MODULE.Xrf55JointEvaluationError,
                    "expected_role_manifest_mismatch",
                ):
                    _run_evaluation(paths)


class Xrf55JointRepresentationHardeningTests(unittest.TestCase):
    def test_expected_contract_is_reconstructed_from_compiler_sources(self):
        expected = _expected_cache_contract()
        sources = (object(), object())
        source_binding = mock.Mock(
            archive_profile_set_sha256=(
                expected.source_binding["archive_profile_set_sha256"]
            ),
            archive_receipt_set_sha256=(
                expected.source_binding["archive_receipt_set_sha256"]
            ),
        )
        compiler_events = {
            role: tuple(
                mock.Mock(
                    event_id=event.event_id,
                    group_id=event.group_id,
                    row=event.row,
                )
                for event in expected.role_manifests[role]
            )
            for role in MODULE.ROLE_ORDER
        }

        with (
            mock.patch.object(
                MODULE.COMPILER,
                "load_source_set",
                return_value=(sources, source_binding),
            ) as load_source_set,
            mock.patch.object(
                MODULE.COMPILER,
                "_collect_events",
                return_value=compiler_events,
            ) as collect_events,
        ):
            observed = MODULE.load_expected_cache_contract(
                Path("canonical-raw"), Path("canonical-receipts")
            )

        self.assertEqual(observed, expected)
        load_source_set.assert_called_once_with(
            Path("canonical-raw"), Path("canonical-receipts")
        )
        collect_events.assert_called_once_with(sources)

    def test_reports_are_deterministic_private_atomic_and_mmap_backed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = _write_fixture(root)
            roles = _load_roles(paths)
            first_report = MODULE.evaluate_roles(roles)
            second_report = _run_evaluation(paths)
            first_path = root / "first.json"
            second_path = root / "second.json"
            MODULE._write_atomic(first_path, first_report)
            MODULE._write_atomic(second_path, second_report)
            encoded = first_path.read_bytes()

            self.assertEqual(encoded, second_path.read_bytes())
            self.assertEqual(stat.S_IMODE(first_path.stat().st_mode), 0o600)
            for role in roles.values():
                for matrix in role.matrices.values():
                    self.assertIsInstance(matrix, np.memmap)
                    self.assertEqual(matrix.mode, "r")
                    self.assertFalse(matrix.flags.writeable)
            text = encoded.decode("ascii")
            self.assertNotIn(str(root), text)
            for role in MODULE.ROLE_ORDER:
                adapter = _read_adapter(paths[role].adapter)
                for event in adapter["events"]:
                    self.assertNotIn(event["event_id"], text)
                    self.assertNotIn(event["group_id"], text)

    def test_numpy_load_is_called_with_read_only_mmap_and_pickle_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = _write_fixture(Path(directory))
            original = np.load
            calls = []

            def recording_load(*args, **kwargs):
                calls.append(kwargs.copy())
                return original(*args, **kwargs)

            with mock.patch.object(MODULE.np, "load", side_effect=recording_load):
                _load_roles(paths)

        self.assertEqual(len(calls), len(MODULE.ROLE_ORDER) * len(MODULE.MODALITIES))
        self.assertTrue(
            all(call == {"allow_pickle": False, "mmap_mode": "r"} for call in calls)
        )

    def test_default_cache_and_filenames_are_exact(self):
        expected = (
            MODULE.ROOT / "data" / "derived" / "eval" / "xrf55-joint-representation-v0"
        )
        self.assertEqual(MODULE.DEFAULT_CACHE_DIR, expected)
        self.assertEqual(MODULE.DEFAULT_REPORT.parent, expected)
        arguments = MODULE._arguments([])
        self.assertEqual(arguments.raw_dir, MODULE.COMPILER.DEFAULT_RAW_DIR)
        self.assertEqual(arguments.receipt_dir, MODULE.COMPILER.DEFAULT_RECEIPT_DIR)
        for role in MODULE.ROLE_ORDER:
            paths = MODULE.role_paths(expected, role)
            self.assertEqual(paths.adapter.name, f"xrf55-joint-{role}-adapter.json")
            for modality in MODULE.MODALITIES:
                self.assertEqual(
                    paths.matrices[modality].name,
                    f"xrf55-joint-{role}-{modality}.npy",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
