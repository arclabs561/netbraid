#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Hermetic tests for deterministic private XRF55 feature-cache compilation."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import numpy as np

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "compile_xrf55_feature_cache", HERE / "compile-xrf55-feature-cache.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FEATURES = MODULE.FEATURES
TEST_LAYOUTS = {
    "wifi": FEATURES.ArrayLayout("<f8", False, (8, 16)),
    "rfid": FEATURES.ArrayLayout("<f8", False, (8, 16)),
    "mmwave": FEATURES.ArrayLayout("<f4", True, (1, 8, 4, 4)),
}


def _contract(subjects, repetitions):
    return {
        "subject_groups": subjects,
        "scenes": frozenset({1}),
        "actions": frozenset({1}),
        "repetitions": frozenset(repetitions),
    }


def _array(modality, subject, repetition):
    layout = TEST_LAYOUTS[modality]
    values = np.arange(np.prod(layout.shape), dtype=np.float64).reshape(layout.shape)
    values = (
        values + subject * 100 + repetition * 10 + FEATURES.MODALITIES.index(modality)
    )
    array = values.astype(layout.dtype)
    if layout.fortran_order:
        array = np.asfortranarray(array)
    return array


def _write_archive(path, subjects=(1, 2), repetitions=(1, 2)):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for subject in subjects:
            for repetition in repetitions:
                name = f"{subject:02d}_01_{repetition:02d}.npy"
                for modality, directory in (
                    ("wifi", "WiFi"),
                    ("rfid", "RFID"),
                    ("mmwave", "mmWave"),
                ):
                    with tempfile.SpooledTemporaryFile() as output:
                        np.save(
                            output,
                            _array(modality, subject, repetition),
                            allow_pickle=False,
                        )
                        output.seek(0)
                        archive.writestr(f"Scene1/{directory}/{name}", output.read())


def _source(path, subjects=(1, 2), repetitions=(1, 2)):
    contract = _contract(len(subjects), repetitions)
    inspection = MODULE.PROFILE.profile_archive(path, path.stat().st_size, contract)
    return MODULE.ArchiveSource(path, path.stat().st_size, contract, inspection)


class Xrf55FeaturePolicyTests(unittest.TestCase):
    def test_official_layouts_produce_fixed_finite_vectors(self):
        for modality, layout in FEATURES.OFFICIAL_LAYOUTS.items():
            array = np.zeros(layout.shape, dtype=layout.dtype)
            if layout.fortran_order:
                array = np.asfortranarray(array)
            vector = FEATURES.feature_vector(modality, array)
            self.assertEqual(vector.shape, (FEATURES.FEATURE_COUNT,))
            self.assertTrue(np.isfinite(vector).all())

    def test_constant_arrays_have_hand_computed_region_moments(self):
        for modality, layout in TEST_LAYOUTS.items():
            array = np.full(layout.shape, 2, dtype=layout.dtype)
            if layout.fortran_order:
                array = np.asfortranarray(array)
            vector = FEATURES.feature_vector(modality, array, layouts=TEST_LAYOUTS)
            self.assertEqual(vector.shape, (96,))
            np.testing.assert_array_equal(
                vector.reshape(-1, 4),
                np.tile(np.array([2.0, 0.0, 2.0, 2.0]), (24, 1)),
            )

    def test_feature_contract_rejects_shape_order_and_nonfinite_values(self):
        wrong_shape = np.zeros((8, 15), dtype="<f8")
        with self.assertRaisesRegex(
            FEATURES.Xrf55FeatureError, "feature_shape_mismatch"
        ):
            FEATURES.feature_vector("wifi", wrong_shape, layouts=TEST_LAYOUTS)

        wrong_order = np.zeros(TEST_LAYOUTS["mmwave"].shape, dtype="<f4", order="C")
        with self.assertRaisesRegex(
            FEATURES.Xrf55FeatureError, "feature_order_mismatch"
        ):
            FEATURES.feature_vector("mmwave", wrong_order, layouts=TEST_LAYOUTS)

        nonfinite = np.zeros(TEST_LAYOUTS["wifi"].shape, dtype="<f8")
        nonfinite[0, 0] = np.nan
        with self.assertRaisesRegex(
            FEATURES.Xrf55FeatureError, "nonfinite_feature_input"
        ):
            FEATURES.feature_vector("wifi", nonfinite, layouts=TEST_LAYOUTS)

    def test_campaign_selection_is_input_order_invariant_and_opaque(self):
        observations = [
            (scene, subject, action, repetition)
            for scene, subject, action in ((1, 9, 2), (1, 4, 8), (2, 7, 3))
            for repetition in FEATURES.PUBLISHER_REPETITIONS
        ]
        first = FEATURES.select_campaign(observations, group_count=2)
        second = FEATURES.select_campaign(reversed(observations), group_count=2)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 40)
        document = FEATURES.campaign_document(first)
        self.assertEqual(
            set(document[0]), {"event_id", "group_id", "repetition", "row", "split"}
        )
        self.assertNotIn("subject", json.dumps(document, sort_keys=True))
        self.assertNotIn("action", json.dumps(document, sort_keys=True))
        self.assertNotIn("scene", json.dumps(document, sort_keys=True))


class Xrf55FeatureCacheIntegrationTests(unittest.TestCase):
    def test_compiles_selected_members_and_writes_byte_identical_private_caches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "processed.zip"
            _write_archive(archive)
            source = _source(archive)

            events, matrices = MODULE.compile_matrices(
                (source,),
                group_count=2,
                repetitions=(1, 2),
                layouts=TEST_LAYOUTS,
            )
            self.assertEqual(len(events), 4)
            for matrix in matrices.values():
                self.assertEqual(matrix.shape, (4, 96))
                self.assertTrue(np.isfinite(matrix).all())

            output_sets = []
            for suffix in ("first", "second"):
                output_sets.append(
                    MODULE.OutputSet(
                        root / f"adapter-{suffix}.json",
                        {
                            modality: root / f"{modality}-{suffix}.npy"
                            for modality in FEATURES.MODALITIES
                        },
                    )
                )
            first = MODULE.write_cache(output_sets[0], events, matrices, 1)
            second = MODULE.write_cache(output_sets[1], events, matrices, 1)

            self.assertEqual(first, second)
            self.assertEqual(
                output_sets[0].adapter.read_bytes(), output_sets[1].adapter.read_bytes()
            )
            for modality in FEATURES.MODALITIES:
                self.assertEqual(
                    output_sets[0].matrices[modality].read_bytes(),
                    output_sets[1].matrices[modality].read_bytes(),
                )
                mapped = np.load(
                    output_sets[0].matrices[modality],
                    mmap_mode="r",
                    allow_pickle=False,
                )
                self.assertIsInstance(mapped, np.memmap)
                np.testing.assert_array_equal(mapped, matrices[modality])
            encoded = json.dumps(first, sort_keys=True)
            for forbidden in (
                "processed.zip",
                "Scene1",
                "WiFi",
                "RFID",
                "mmWave",
                'raw_action_identifiers_retained": 1',
                'raw_performer_identifiers_retained": 1',
            ):
                self.assertNotIn(forbidden, encoded)
            for path in (
                output_sets[0].adapter,
                *output_sets[0].matrices.values(),
            ):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_rejects_nonregular_output_target(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "processed.zip"
            _write_archive(archive, subjects=(1,), repetitions=(1,))
            events, matrices = MODULE.compile_matrices(
                (_source(archive, subjects=(1,), repetitions=(1,)),),
                group_count=1,
                repetitions=(1,),
                layouts=TEST_LAYOUTS,
            )
            real = root / "real.json"
            real.write_text("{}\n")
            adapter = root / "adapter.json"
            adapter.symlink_to(real)
            outputs = MODULE.OutputSet(
                adapter,
                {
                    modality: root / f"{modality}.npy"
                    for modality in FEATURES.MODALITIES
                },
            )
            with self.assertRaisesRegex(
                MODULE.Xrf55CacheCompileError, "unsafe_output_path"
            ):
                MODULE.write_cache(outputs, events, matrices, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
