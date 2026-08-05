#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Hermetic tests for deterministic private XRF55 feature-cache compilation."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

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


def _role_observations():
    return [
        (1, subject, 1, repetition)
        for subject in range(1, 17)
        for repetition in FEATURES.PUBLISHER_REPETITIONS
    ]


def _role_outputs(root):
    return {role: MODULE.role_output_set(root, role) for role in MODULE.ROLE_ORDER}


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


class Xrf55TrimodalRoleCacheTests(unittest.TestCase):
    def test_role_cache_rejects_legacy_group_count_override_before_loading_sources(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            errors = io.StringIO()
            with (
                mock.patch.object(
                    MODULE,
                    "load_archive_sources",
                    side_effect=AssertionError("sources must not be loaded"),
                ),
                contextlib.redirect_stderr(errors),
            ):
                result = MODULE.main(
                    [
                        "--role-cache-dir",
                        directory,
                        "--group-count",
                        str(FEATURES.DEFAULT_GROUP_COUNT + 1),
                    ]
                )

        self.assertEqual(result, 2)
        self.assertEqual(errors.getvalue(), "role_cache_group_count_is_fixed\n")

    def test_role_partition_has_exact_counts_disjoint_groups_and_legacy_train_ranks(
        self,
    ):
        observations = _role_observations()
        roles = MODULE.select_role_events(observations)

        self.assertEqual(
            {role: len(events) for role, events in roles.items()},
            MODULE.ROLE_EVENT_COUNTS,
        )
        legacy = FEATURES.select_campaign(observations, group_count=8)
        legacy_groups = tuple(dict.fromkeys(event.group_id for event in legacy))
        train_groups = tuple(dict.fromkeys(event.group_id for event in roles["train"]))
        self.assertEqual(train_groups, legacy_groups)

        groups_by_role = {
            role: {event.group_id for event in events} for role, events in roles.items()
        }
        for index, role in enumerate(MODULE.ROLE_ORDER):
            first_rank, last_rank = MODULE.ROLE_GROUP_RANKS[role]
            self.assertEqual(len(groups_by_role[role]), last_rank - first_rank + 1)
            self.assertEqual(
                [event.row for event in roles[role]], list(range(len(roles[role])))
            )
            self.assertTrue(all(event.split == role for event in roles[role]))
            for other in MODULE.ROLE_ORDER[index + 1 :]:
                self.assertTrue(groups_by_role[role].isdisjoint(groups_by_role[other]))

    def test_role_partition_is_invariant_to_observation_and_request_order(self):
        observations = _role_observations()
        first = MODULE.select_role_events(observations, MODULE.ROLE_ORDER)
        second = MODULE.select_role_events(
            tuple(reversed(observations)), tuple(reversed(MODULE.ROLE_ORDER))
        )
        self.assertEqual(first, second)

    def test_earlier_role_request_colocates_modalities_without_reading_locked_payloads(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "processed.zip"
            subjects = tuple(range(1, 17))
            repetitions = FEATURES.PUBLISHER_REPETITIONS
            _write_archive(archive, subjects=subjects, repetitions=repetitions)
            source = _source(archive, subjects=subjects, repetitions=repetitions)
            all_roles = MODULE.select_role_events(_role_observations())
            locked_observations = {
                event.observation for event in all_roles["locked_test"]
            }
            read_observations = []
            original_member_open = zipfile.ZipFile.open

            def guarded_member_open(zip_archive, member, *args, **kwargs):
                subject, action, repetition = (
                    int(value) for value in Path(member.filename).stem.split("_")
                )
                observation = (1, subject, action, repetition)
                if observation in locked_observations:
                    self.fail("locked-test member payload was opened")
                read_observations.append(observation)
                return original_member_open(zip_archive, member, *args, **kwargs)

            with mock.patch.object(zipfile.ZipFile, "open", guarded_member_open):
                events_by_role, matrices = MODULE.compile_role_matrices(
                    (source,), layouts=TEST_LAYOUTS
                )

        self.assertEqual(
            len(read_observations),
            sum(MODULE.ROLE_EVENT_COUNTS[role] for role in MODULE.PRE_GATE_ROLES)
            * len(FEATURES.MODALITIES),
        )
        self.assertTrue(locked_observations.isdisjoint(read_observations))
        for role, events in events_by_role.items():
            self.assertEqual(set(matrices[role]), set(FEATURES.MODALITIES))
            for event in events:
                _, subject, _, repetition = event.observation
                for modality in FEATURES.MODALITIES:
                    expected = FEATURES.feature_vector(
                        modality,
                        _array(modality, subject, repetition),
                        layouts=TEST_LAYOUTS,
                    )
                    np.testing.assert_array_equal(
                        matrices[role][modality][event.row], expected
                    )

    def test_role_outputs_are_separate_mmap_ready_deterministic_and_private(self):
        events = MODULE.select_role_events(_role_observations())
        matrices = {
            role: {
                modality: (
                    np.arange(
                        len(role_events) * FEATURES.FEATURE_COUNT, dtype="<f8"
                    ).reshape(len(role_events), FEATURES.FEATURE_COUNT)
                    + role_index * 10
                    + modality_index
                )
                for modality_index, modality in enumerate(FEATURES.MODALITIES)
            }
            for role_index, (role, role_events) in enumerate(events.items())
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_outputs = _role_outputs(root / "first")
            second_outputs = _role_outputs(root / "second")
            first = MODULE.write_role_caches(first_outputs, events, matrices, 1)
            second = MODULE.write_role_caches(second_outputs, events, matrices, 1)

            self.assertEqual(first, second)
            all_paths = []
            for role in MODULE.ROLE_ORDER:
                first_set = first_outputs[role]
                second_set = second_outputs[role]
                self.assertEqual(
                    first_set.adapter.read_bytes(), second_set.adapter.read_bytes()
                )
                self.assertEqual(first[role]["schema"], MODULE.ROLE_CACHE_SCHEMA)
                self.assertEqual(first[role]["counts"]["events"], len(events[role]))
                self.assertEqual(
                    set(first[role]["events"][0]),
                    {"event_id", "group_id", "role", "row"},
                )
                self.assertTrue(
                    all(value == 0 for value in first[role]["privacy"].values())
                )
                all_paths.append(first_set.adapter)
                for modality in FEATURES.MODALITIES:
                    first_path = first_set.matrices[modality]
                    second_path = second_set.matrices[modality]
                    self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
                    mapped = np.load(first_path, mmap_mode="r", allow_pickle=False)
                    self.assertIsInstance(mapped, np.memmap)
                    self.assertFalse(mapped.flags.writeable)
                    np.testing.assert_array_equal(mapped, matrices[role][modality])
                    all_paths.append(first_path)

            self.assertEqual(len(all_paths), len(set(all_paths)))
            self.assertNotIn(str(root), json.dumps(first, sort_keys=True))
            for path in all_paths:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=2)
