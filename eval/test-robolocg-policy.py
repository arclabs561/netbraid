#!/usr/bin/env python3
"""Hermetic tests for the preregistered RoboLoc-G structural policy."""

from __future__ import annotations

import importlib.util
import math
import random
import sys
import unittest
from dataclasses import replace
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "robolocg_policy", HERE / "robolocg_policy.py"
)
assert SPEC and SPEC.loader
POLICY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = POLICY
SPEC.loader.exec_module(POLICY)


class RoboLocGPolicyTests(unittest.TestCase):
    def assert_policy_error(self, code, function, *args):
        with self.assertRaises(POLICY.RoboLocGPolicyError) as raised:
            function(*args)
        self.assertEqual(raised.exception.code, code)

    def test_exact_take_roles_are_session_atomic_and_family_coherent(self):
        assignments = POLICY.TAKE_ASSIGNMENTS
        self.assertEqual(
            [
                (item.take.value, item.family.value, item.role.value)
                for item in assignments
            ],
            [
                ("zigzag1", "zigzag", "train"),
                ("zigzag2", "zigzag", "train"),
                ("zigzag3", "zigzag", "train"),
                ("zigzag4", "zigzag", "train"),
                ("still", "still", "calibration"),
                ("circle", "circle", "validation"),
                ("random1", "random", "locked_test"),
                ("random2", "random", "locked_test"),
            ],
        )
        self.assertEqual(len({item.session_id for item in assignments}), 8)
        domains = {}
        for item in assignments:
            domains.setdefault(item.family, set()).add(item.domain_id)
        self.assertTrue(all(len(values) == 1 for values in domains.values()))

    def test_session_and_family_role_leakage_fail_closed(self):
        assignments = list(POLICY.TAKE_ASSIGNMENTS)
        leaked_session = replace(assignments[0], role=POLICY.Role.CALIBRATION)
        self.assert_policy_error(
            "session_crosses_roles",
            POLICY.audit_take_assignments,
            assignments + [leaked_session],
        )

        random2_index = POLICY.TAKE_ORDER.index(POLICY.Take.RANDOM2)
        assignments[random2_index] = replace(
            assignments[random2_index], role=POLICY.Role.VALIDATION
        )
        self.assert_policy_error(
            "family_domain_crosses_roles",
            POLICY.audit_take_assignments,
            assignments,
        )

    def test_opaque_ids_and_assignment_order_are_permutation_deterministic(self):
        first = POLICY.opaque_id("session", "zigzag1")
        self.assertEqual(first, POLICY.opaque_id("session", "zigzag1"))
        self.assertEqual(len(first), 64)
        self.assertNotEqual(first, POLICY.opaque_id("domain", "zigzag1"))

        permuted = list(POLICY.TAKE_ORDER)
        random.Random(3601).shuffle(permuted)
        self.assertEqual(
            POLICY.build_take_assignments(permuted), POLICY.TAKE_ASSIGNMENTS
        )
        self.assertEqual(
            POLICY.build_take_assignments(reversed(permuted)),
            POLICY.TAKE_ASSIGNMENTS,
        )

    def test_still_is_observation_while_cnc_and_calibration_are_configuration(self):
        still = next(
            item for item in POLICY.TAKE_ASSIGNMENTS if item.take is POLICY.Take.STILL
        )
        self.assertEqual(still.role, POLICY.Role.CALIBRATION)
        self.assertEqual(
            {item.configuration_id for item in POLICY.TAKE_ASSIGNMENTS},
            {POLICY.FROZEN_CONFIGURATION_ID},
        )
        self.assertEqual(
            {item.role for item in POLICY.TAKE_ASSIGNMENTS}, set(POLICY.Role)
        )

        archives = {item.kind: item for item in POLICY.ARCHIVE_CONTRACTS}
        self.assertEqual(archives["gantry_cnc"].use, POLICY.ArchiveUse.CONFIGURATION)
        self.assertEqual(
            archives["optitrack_calibration"].use,
            POLICY.ArchiveUse.CONFIGURATION,
        )
        self.assertEqual(
            [(item.kind, item.count) for item in archives["gantry_cnc"].members],
            [("trajectory_gcode", 7), ("still_position_text", 1)],
        )

    def test_archive_counts_kinds_headers_and_evidence_roles_are_exact(self):
        archives = {item.kind: item for item in POLICY.ARCHIVE_CONTRACTS}
        self.assertEqual(
            [
                (item.kind, item.use.value, item.file_count, item.entry_count)
                for item in POLICY.ARCHIVE_CONTRACTS
            ],
            [
                ("sensor_measurements_csv", "observation", 64, 101),
                ("ground_truth", "oracle", 16, None),
                ("gantry_measurements", "dependent_consistency", 8, None),
                ("gantry_cnc", "configuration", 8, None),
                ("optitrack_calibration", "configuration", 12, None),
            ],
        )
        self.assertEqual(
            [
                (item.kind, item.count)
                for item in archives["sensor_measurements_csv"].members
            ],
            [
                ("radar_scan_csv", 24),
                ("radar_point_cloud_csv", 16),
                ("ftm_csv", 8),
                ("imu_csv", 8),
                ("uwb_ranging_csv", 8),
            ],
        )
        self.assertEqual(
            [(item.kind, item.count) for item in archives["ground_truth"].members],
            [
                ("gantry_frame_ground_truth_csv", 8),
                ("optitrack_frame_ground_truth_csv", 8),
            ],
        )
        self.assertEqual(
            [
                (item.kind, item.count)
                for item in archives["optitrack_calibration"].members
            ],
            [
                ("camera_node_json", 10),
                ("extracted_calibration_json", 1),
                ("native_calibration_binary", 1),
            ],
        )
        self.assertEqual(POLICY.RADAR_HEADER.columns[0], "timestamp")
        self.assertEqual(POLICY.POINT_CLOUD_HEADER.columns[0], "timestamp")
        self.assertEqual(POLICY.FTM_HEADER.columns[0], "timestamp")
        self.assertEqual(POLICY.IMU_HEADER.columns[0], "timestamp")
        self.assertEqual(POLICY.UWB_HEADER.columns[0], "timestamp")
        self.assertEqual(POLICY.GROUND_TRUTH_HEADER.columns[0], "time")
        self.assertEqual(
            POLICY.GANTRY_MEASUREMENT_HEADER.columns, ("time", "x", "y", "z")
        )
        self.assertEqual(len(POLICY.GROUND_TRUTH_HEADER.columns), 13)

        self.assertTrue(archives["sensor_measurements_csv"].model_input_allowed)
        self.assertTrue(archives["ground_truth"].scoring_oracle)
        self.assertFalse(archives["ground_truth"].model_input_allowed)
        self.assertFalse(archives["gantry_measurements"].scoring_oracle)
        self.assertFalse(archives["gantry_measurements"].model_input_allowed)

    def test_outer_timestamp_is_clock_and_embedded_stamps_are_diagnostic(self):
        self.assertEqual(
            POLICY.RADAR_HEADER.embedded_clock_columns,
            ("header.stamp.sec", "header.stamp.nanosec"),
        )
        self.assertEqual(POLICY.FTM_HEADER.embedded_clock_columns, ())
        for archive in POLICY.ARCHIVE_CONTRACTS[:3]:
            for member in archive.members:
                self.assertIsNotNone(member.header)
                self.assertEqual(
                    member.header.outer_clock_column, member.header.columns[0]
                )

    def test_integer_and_decimal_clocks_parse_exactly_without_float(self):
        self.assertEqual(
            POLICY.parse_integer_nanoseconds("1751473892576417887"),
            1_751_473_892_576_417_887,
        )
        self.assertEqual(
            POLICY.parse_decimal_seconds_nanoseconds("1751473889.7010956"),
            1_751_473_889_701_095_600,
        )
        self.assertEqual(POLICY.parse_decimal_seconds_nanoseconds("0.1"), 100_000_000)
        for invalid in ("1", "1e0", "-1.0", "01.0", "1.0000000000"):
            with self.subTest(value=invalid):
                self.assert_policy_error(
                    "invalid_decimal_seconds",
                    POLICY.parse_decimal_seconds_nanoseconds,
                    invalid,
                )

    def test_transform_freezes_translation_then_active_rz_ry_rx_and_y_sign(self):
        generated = POLICY.compose_rotation_matrix()
        for actual_row, frozen_row in zip(generated, POLICY.ROTATION_MATRIX):
            for actual, frozen in zip(actual_row, frozen_row):
                self.assertAlmostEqual(actual, frozen, places=15)

        negative_y = POLICY.active_axis_rotation("y", -90.0)
        rotated_x = tuple(row[0] for row in negative_y)
        self.assertAlmostEqual(rotated_x[0], 0.0, places=15)
        self.assertAlmostEqual(rotated_x[1], 0.0, places=15)
        self.assertAlmostEqual(rotated_x[2], 1.0, places=15)

        origin = POLICY.transform_optitrack_to_gantry_mm((0.0, 0.0, 0.0))
        published_origin = (2459.873, 2448.686, -2445.363)
        error_mm = math.sqrt(
            sum(
                (actual - expected) ** 2
                for actual, expected in zip(origin, published_origin)
            )
        )
        self.assertLessEqual(error_mm, 0.005)

    def test_blocker_closure_is_explicit_conjunctive_and_ordered(self):
        self.assertEqual(
            [blocker.value for blocker in POLICY.BLOCKER_ORDER],
            [
                "uwb_unit_conflict",
                "ftm_anchor_id_mismatch",
                "outer_vs_header_deltas_diagnostic",
                "radar_association_extrinsics_absent",
                "interpolation_no_extrapolation_tolerance_unfixed",
            ],
        )
        blocked = POLICY.evaluate_gate()
        self.assertFalse(blocked.fusion_capable)
        self.assertFalse(blocked.scoring_allowed)
        self.assertEqual(blocked.open_blockers, POLICY.BLOCKER_ORDER)

        partial = POLICY.evaluate_gate((POLICY.Blocker.UWB_UNIT_CONFLICT,))
        self.assertFalse(partial.fusion_capable)
        self.assertFalse(partial.scoring_allowed)
        self.assertNotIn(POLICY.Blocker.UWB_UNIT_CONFLICT, partial.open_blockers)

        closed = POLICY.evaluate_gate(reversed(POLICY.BLOCKER_ORDER))
        self.assertTrue(closed.fusion_capable)
        self.assertTrue(closed.scoring_allowed)
        self.assertEqual(closed.closed_blockers, POLICY.BLOCKER_ORDER)
        self.assertEqual(closed.open_blockers, ())

        self.assert_policy_error(
            "duplicate_blocker_closure",
            POLICY.evaluate_gate,
            (POLICY.Blocker.UWB_UNIT_CONFLICT,) * 2,
        )
        self.assert_policy_error(
            "invalid_blocker_closure", POLICY.evaluate_gate, ("uwb_unit_conflict",)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
