#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Hermetic tests for the private XRF55 joint-grid feature policy."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

import numpy as np

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "xrf55_joint_features", HERE / "xrf55_joint_features.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FEATURES = MODULE.FEATURES
TEST_LAYOUTS = {
    "wifi": FEATURES.ArrayLayout("<f8", False, (16, 32)),
    "rfid": FEATURES.ArrayLayout("<f8", False, (16, 32)),
    "mmwave": FEATURES.ArrayLayout("<f4", True, (1, 16, 8, 8)),
}


def _constant_block_array(modality: str) -> np.ndarray:
    layout = TEST_LAYOUTS[modality]
    array = np.empty(layout.shape, dtype=layout.dtype)
    if modality in {"wifi", "rfid"}:
        for channel_bin in range(FEATURES.CHANNEL_BINS):
            for sequence_bin in range(FEATURES.SEQUENCE_BINS):
                value = channel_bin * FEATURES.SEQUENCE_BINS + sequence_bin + 1
                array[
                    channel_bin * 2 : (channel_bin + 1) * 2,
                    sequence_bin * 2 : (sequence_bin + 1) * 2,
                ] = value
        return array

    for channel_bin in range(FEATURES.CHANNEL_BINS):
        for row_bin in range(FEATURES.SPATIAL_BINS[0]):
            for column_bin in range(FEATURES.SPATIAL_BINS[1]):
                value = (
                    channel_bin * FEATURES.SPATIAL_BINS[0] * FEATURES.SPATIAL_BINS[1]
                    + row_bin * FEATURES.SPATIAL_BINS[1]
                    + column_bin
                    + 1
                )
                array[
                    0,
                    channel_bin * 2 : (channel_bin + 1) * 2,
                    row_bin * 2 : (row_bin + 1) * 2,
                    column_bin * 2 : (column_bin + 1) * 2,
                ] = value
    return np.asfortranarray(array)


def _observations() -> list[FEATURES.ObservationKey]:
    return [
        (1, group, 1, repetition)
        for group in range(1, MODULE.RANKED_GROUP_COUNT + 1)
        for repetition in FEATURES.PUBLISHER_REPETITIONS
    ]


class Xrf55JointFeatureTests(unittest.TestCase):
    def test_old_marginals_can_match_while_joint_vectors_differ(self):
        rows, columns = np.indices((8, 16))
        first = ((rows + columns) % 2).astype("<f8")
        second = ((rows + columns // 2) % 2).astype("<f8")
        layout = {"wifi": FEATURES.ArrayLayout("<f8", False, (8, 16))}

        first_marginal = FEATURES.feature_vector("wifi", first, layouts=layout)
        second_marginal = FEATURES.feature_vector("wifi", second, layouts=layout)
        np.testing.assert_array_equal(first_marginal, second_marginal)

        first_joint = MODULE.feature_vector("wifi", first, layouts=layout)
        second_joint = MODULE.feature_vector("wifi", second, layouts=layout)
        self.assertEqual(first_joint.shape, (MODULE.FEATURE_COUNT,))
        self.assertFalse(np.array_equal(first_joint, second_joint))

    def test_constant_blocks_have_exact_channel_major_moment_oracle(self):
        values = np.arange(1, 129, dtype=np.float64)
        expected = np.column_stack((values, np.zeros(values.shape), values, values))
        for modality in FEATURES.MODALITIES:
            vector = MODULE.feature_vector(
                modality,
                _constant_block_array(modality),
                layouts=TEST_LAYOUTS,
            )
            self.assertEqual(vector.shape, (MODULE.FEATURE_COUNT,))
            np.testing.assert_array_equal(vector.reshape(-1, 4), expected)

    def test_reuses_shape_order_and_nonfinite_validation(self):
        wrong_shape = np.zeros((16, 31), dtype="<f8")
        with self.assertRaisesRegex(
            FEATURES.Xrf55FeatureError, "feature_shape_mismatch"
        ):
            MODULE.feature_vector("wifi", wrong_shape, layouts=TEST_LAYOUTS)

        wrong_order = np.zeros(TEST_LAYOUTS["mmwave"].shape, dtype="<f4", order="C")
        with self.assertRaisesRegex(
            FEATURES.Xrf55FeatureError, "feature_order_mismatch"
        ):
            MODULE.feature_vector("mmwave", wrong_order, layouts=TEST_LAYOUTS)

        nonfinite = np.zeros(TEST_LAYOUTS["rfid"].shape, dtype="<f8")
        nonfinite[0, 0] = np.inf
        with self.assertRaisesRegex(
            FEATURES.Xrf55FeatureError, "nonfinite_feature_input"
        ):
            MODULE.feature_vector("rfid", nonfinite, layouts=TEST_LAYOUTS)

    def test_role_selection_is_deterministic_opaque_disjoint_and_exact(self):
        observations = _observations()
        first = MODULE.select_role_events(observations)
        second = MODULE.select_role_events(reversed(observations))

        self.assertEqual(first, second)
        self.assertEqual(tuple(first), MODULE.ROLE_ORDER)
        self.assertEqual(
            {role: len(events) for role, events in first.items()},
            {"train": 160, "calibration": 40, "validation": 40},
        )

        groups_by_role = {
            role: {event.group_id for event in events} for role, events in first.items()
        }
        self.assertEqual(
            {role: len(groups) for role, groups in groups_by_role.items()},
            {"train": 8, "calibration": 2, "validation": 2},
        )
        for index, role in enumerate(MODULE.ROLE_ORDER):
            self.assertEqual(
                [event.row for event in first[role]],
                list(range(MODULE.ROLE_EVENT_COUNTS[role])),
            )
            self.assertTrue(all(event.split == role for event in first[role]))
            for other in MODULE.ROLE_ORDER[index + 1 :]:
                self.assertTrue(groups_by_role[role].isdisjoint(groups_by_role[other]))

        campaign = FEATURES.select_campaign(
            observations,
            group_count=MODULE.RANKED_GROUP_COUNT,
            repetitions=FEATURES.PUBLISHER_REPETITIONS,
        )
        all_group_ids = {event.group_id for event in campaign}
        selected_group_ids = set().union(*groups_by_role.values())
        quarantined_group_ids = all_group_ids - selected_group_ids
        self.assertEqual(len(quarantined_group_ids), 8)
        self.assertEqual(
            sum(event.group_id in quarantined_group_ids for event in campaign), 160
        )

        encoded = json.dumps(
            {
                role: FEATURES.campaign_document(events)
                for role, events in first.items()
            },
            sort_keys=True,
        )
        for forbidden in ("observation", "scene", "subject", "action"):
            self.assertNotIn(forbidden, encoded)

        policy = MODULE.role_policy_document()
        self.assertEqual(policy["quarantined_group_ranks"], [9, 16])
        self.assertEqual(
            policy["roles"],
            {"train": [1, 8], "calibration": [17, 18], "validation": [19, 20]},
        )
        self.assertNotIn("locked_test", json.dumps(policy, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
