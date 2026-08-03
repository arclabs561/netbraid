#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Hermetic tests for mmap-backed XRF55 exact-event retrieval evaluation."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import math
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "evaluate_xrf55_cross_modal_retrieval",
    HERE / "evaluate-xrf55-cross-modal-retrieval.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FEATURES = MODULE.FEATURES


def _events():
    observations = [
        (1, subject, 1, repetition)
        for subject in range(1, 9)
        for repetition in FEATURES.PUBLISHER_REPETITIONS
    ]
    return FEATURES.select_campaign(observations, group_count=8)


def _matrices(events):
    group_indices = {
        group_id: index
        for index, group_id in enumerate(sorted({event.group_id for event in events}))
    }
    latent = []
    for event in events:
        vector = np.zeros(16, dtype=np.float64)
        vector[group_indices[event.group_id]] = 1.0
        scaled = event.repetition / 20.0
        vector[8:] = (
            scaled,
            scaled**2,
            scaled**3,
            math.sin(math.pi * scaled),
            math.cos(math.pi * scaled),
            math.sin(2 * math.pi * scaled),
            math.cos(2 * math.pi * scaled),
            1.0,
        )
        latent.append(vector)
    latent_matrix = np.asarray(latent, dtype=np.float64)
    matrices = {}
    for index, modality in enumerate(FEATURES.MODALITIES):
        random = np.random.default_rng(100 + index)
        transform = random.normal(size=(16, FEATURES.FEATURE_COUNT))
        offset = random.normal(size=(FEATURES.FEATURE_COUNT,))
        matrices[modality] = np.asarray(latent_matrix @ transform + offset, dtype="<f8")
    return matrices


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_fixture(root, *, matrices=None):
    events = _events()
    matrices = _matrices(events) if matrices is None else matrices
    matrix_paths = {}
    artifacts = {}
    for modality in FEATURES.MODALITIES:
        path = root / f"{modality}.npy"
        with path.open("wb") as output:
            np.save(output, matrices[modality], allow_pickle=False)
        path.chmod(0o600)
        matrix_paths[modality] = path
        artifacts[modality] = {
            "bytes": path.stat().st_size,
            "dtype": "<f8",
            "sha256": _sha256(path),
            "shape": [160, FEATURES.FEATURE_COUNT],
        }
    adapter = {
        "schema": FEATURES.SCHEMA,
        "provenance": {
            "dataset": "synthetic-test",
            "publisher_implementation_revision": "0" * 40,
            "publisher_project": "https://example.invalid/",
        },
        "integrity": {
            "all_archive_bytes_freshly_rehashed": False,
            "basis": "exact_size_and_fetch_receipt_metadata_plus_selected_member_crc",
            "artifacts": artifacts,
        },
        "feature_policy": FEATURES.feature_policy_document(),
        "split_policy": {
            "candidate_set": "same_opaque_performer_action_group",
            "publisher_train_repetitions": sorted(FEATURES.TRAIN_REPETITIONS),
            "publisher_test_repetitions": sorted(FEATURES.TEST_REPETITIONS),
        },
        "events": FEATURES.campaign_document(events),
        "counts": {
            "archives": 2,
            "events": 160,
            "features_per_modality": FEATURES.FEATURE_COUNT,
            "groups": 8,
            "modalities": 3,
            "split_events": {"test": 48, "train": 112},
        },
        "privacy": {
            "archive_names_retained": 0,
            "local_paths_retained": 0,
            "member_names_retained": 0,
            "raw_action_identifiers_retained": 0,
            "raw_performer_identifiers_retained": 0,
            "raw_scene_identifiers_retained": 0,
        },
    }
    adapter_path = root / "adapter.json"
    adapter_path.write_text(json.dumps(adapter, indent=2, sort_keys=True) + "\n")
    adapter_path.chmod(0o600)
    return adapter_path, matrix_paths, adapter


class Xrf55CrossModalRetrievalTests(unittest.TestCase):
    def test_recovers_exact_events_for_all_linear_synthetic_directions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter_path, matrix_paths, _ = _write_fixture(root)
            cache = MODULE.load_cache(adapter_path, matrix_paths)
            report = MODULE.evaluate(cache)

        self.assertEqual(len(report["directions"]), 6)
        self.assertEqual(report["counts"]["test_queries_per_direction"], 48)
        for matrix in cache.matrices.values():
            self.assertIsInstance(matrix, np.memmap)
            self.assertEqual(matrix.mode, "r")
        for direction in report["directions"]:
            with self.subTest(source=direction["source"], target=direction["target"]):
                self.assertEqual(direction["learned"]["top1_correct"], 48)
                self.assertEqual(direction["learned"]["mrr"], 1.0)
                self.assertEqual(len(direction["per_group"]), 8)

    def test_report_is_byte_deterministic_and_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter_path, matrix_paths, _ = _write_fixture(root)
            report = MODULE.evaluate(MODULE.load_cache(adapter_path, matrix_paths))
            first = root / "first.json"
            second = root / "second.json"
            MODULE._write_report(first, report)
            MODULE._write_report(second, report)

            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o600)
            encoded = first.read_text()
            for forbidden in (str(root), "synthetic-test", "example.invalid"):
                self.assertNotIn(forbidden, encoded)

    def test_rejects_tampered_matrix_before_mmap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter_path, matrix_paths, _ = _write_fixture(root)
            with matrix_paths["wifi"].open("r+b") as output:
                output.seek(-1, os.SEEK_END)
                value = output.read(1)
                output.seek(-1, os.SEEK_END)
                output.write(bytes([value[0] ^ 0x01]))
            with self.assertRaisesRegex(
                MODULE.Xrf55RetrievalError, "matrix_digest_mismatch"
            ):
                MODULE.load_cache(adapter_path, matrix_paths)

    def test_rejects_split_and_candidate_group_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter_path, matrix_paths, adapter = _write_fixture(root)
            adapter["events"][0]["split"] = "test"
            adapter_path.write_text(json.dumps(adapter, sort_keys=True))
            with self.assertRaisesRegex(
                MODULE.Xrf55RetrievalError, "invalid_event_record"
            ):
                MODULE.load_cache(adapter_path, matrix_paths)

    def test_rejects_all_constant_training_features(self):
        events = _events()
        constant = {
            modality: np.ones((len(events), FEATURES.FEATURE_COUNT), dtype="<f8")
            for modality in FEATURES.MODALITIES
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter_path, matrix_paths, _ = _write_fixture(root, matrices=constant)
            cache = MODULE.load_cache(adapter_path, matrix_paths)
            with self.assertRaisesRegex(
                MODULE.Xrf55RetrievalError, "no_active_features"
            ):
                MODULE.evaluate(cache)

    def test_rank_ties_break_by_opaque_event_id(self):
        prediction = np.array([0.0])
        candidates = [("b", np.array([1.0])), ("a", np.array([-1.0]))]
        self.assertEqual(MODULE._rank(prediction, candidates, "a"), 1)
        self.assertEqual(MODULE._rank(prediction, candidates, "b"), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
