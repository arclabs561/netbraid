#!/usr/bin/env python3
"""Hermetic checks for the finite counter/capture evaluator."""

import importlib.util
import json
import sys
import unittest
from decimal import Decimal
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "counter_capture_eval", HERE / "counter_capture_eval.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def counters(interface="en0", received=100, transmitted=200, packets=10):
    return {
        "interface": interface,
        "received_bytes": received,
        "transmitted_bytes": transmitted,
        "received_packets": packets,
        "transmitted_packets": packets,
    }


def manifest(count, state="complete", quarantined=0, limit=False):
    return {
        "normalization": {
            "state": state,
            "packet_limit_reached": limit,
            "packet_rows_quarantined": quarantined,
            "packet_rows_emitted": count,
        }
    }


def packet(source, destination, size=100):
    return {
        "frame": {"original_len": size},
        "ipv4": {"source": source, "destination": destination},
    }


class CounterCaptureTests(unittest.TestCase):
    def test_exact_rational_scorer_matches_shared_rust_fixture(self):
        fixture_path = (
            HERE.parent
            / "rust"
            / "tests"
            / "fixtures"
            / "infer"
            / "v0"
            / "exact-rational-counter-capture.json"
        )
        fixture = json.loads(fixture_path.read_text())
        counter = MODULE.TrafficWindow(**fixture["counter"]["window"])
        capture = MODULE.TrafficWindow(**fixture["capture"]["window"])
        score = MODULE.exact_distance_ppb(
            counter, capture, fixture["profile"]["scales_ppb"]
        )
        self.assertEqual(score, fixture["expected"]["scaled_residual_sum_ppb"])
        self.assertEqual(score, 45_000_000_000)

        invalid_scales = dict(fixture["profile"]["scales_ppb"])
        invalid_scales["received_bytes"] = MODULE.SCALE_FLOOR_PPB - 1
        with self.assertRaisesRegex(MODULE.CandidateError, "invalid_exact_scales_ppb"):
            MODULE.exact_distance_ppb(counter, capture, invalid_scales)

    def test_counter_delta_rejects_generation_interface_and_reset(self):
        window = MODULE.counter_window(
            counters(),
            counters(received=400, transmitted=500, packets=30),
            first_generation=4,
            last_generation=4,
            duration_ms=20_000,
        )
        self.assertEqual(window.received_bytes, 300)
        self.assertEqual(window.transmitted_packets, 20)
        with self.assertRaisesRegex(MODULE.CandidateError, "path_generation_changed"):
            MODULE.counter_window(
                counters(),
                counters(),
                first_generation=1,
                last_generation=2,
                duration_ms=1,
            )
        with self.assertRaisesRegex(
            MODULE.CandidateError, "interface_changed_or_missing"
        ):
            MODULE.counter_window(
                counters(),
                counters(interface="en1"),
                first_generation=1,
                last_generation=1,
                duration_ms=1,
            )
        with self.assertRaisesRegex(MODULE.CandidateError, "counter_reset"):
            MODULE.counter_window(
                counters(received=200),
                counters(received=100),
                first_generation=1,
                last_generation=1,
                duration_ms=1,
            )

    def test_capture_orientation_discards_addresses_and_counts_exclusions(self):
        packets = [
            packet("192.0.2.5", "198.51.100.1", 80),
            packet("198.51.100.1", "192.0.2.5", 120),
            packet("198.51.100.2", "198.51.100.3", 60),
        ]
        candidate = MODULE.capture_window(
            manifest(3), packets, local_addresses={"192.0.2.5"}, duration_ms=1000
        )
        self.assertEqual(candidate.window.transmitted_bytes, 80)
        self.assertEqual(candidate.window.received_bytes, 120)
        self.assertEqual(candidate.packets_oriented, 2)
        self.assertEqual(candidate.packets_excluded, 1)
        self.assertNotIn("192.0.2.5", repr(candidate))

    def test_partial_limit_quarantine_and_count_mismatch_abstain(self):
        cases = [
            (manifest(1, state="partial"), "capture_partial"),
            (manifest(1, limit=True), "capture_packet_limit_reached"),
            (manifest(1, quarantined=1), "capture_quarantined"),
            (manifest(2), "capture_packet_count_mismatch"),
        ]
        for document, reason in cases:
            with (
                self.subTest(reason=reason),
                self.assertRaisesRegex(MODULE.CandidateError, reason),
            ):
                MODULE.capture_window(
                    document,
                    [packet("192.0.2.5", "198.51.100.1")],
                    local_addresses={"192.0.2.5"},
                    duration_ms=1000,
                )

    def test_calibration_ranking_tie_and_holdout_gate(self):
        true = MODULE.TrafficWindow(1000, 1000, 200, 10, 2)
        calibration = [MODULE.residuals(true, true) for _ in range(8)]
        scales = MODULE.calibration_scales(calibration)
        self.assertEqual(set(scales), set(MODULE.FEATURE_NAMES))
        self.assertTrue(all(value == Decimal("0.05") for value in scales.values()))

        decoys = [
            MODULE.TrafficWindow(1000, 100, 2000, 1, 20),
            MODULE.TrafficWindow(1000, 3000, 1000, 30, 10),
            MODULE.TrafficWindow(1000, 500, 500, 5, 5),
        ]
        ranked = MODULE.rank_candidates(true, [true, *decoys], scales)
        self.assertEqual((ranked.status, ranked.winner_index), ("ranked", 0))
        tied = MODULE.rank_candidates(true, [true, true, *decoys[:2]], scales)
        self.assertEqual(
            (tied.status, tied.reason), ("unknown", "minimum_distance_tie")
        )
        excluded = MODULE.rank_candidates(true, [true, *decoys[:2], None], scales)
        self.assertEqual(
            (excluded.status, excluded.reason), ("unknown", "candidate_excluded")
        )

        summary = MODULE.summarize_holdout([ranked] * 12 + [tied] * 4)
        self.assertEqual(summary["recall_at_1"], {"numerator": 12, "denominator": 16})
        self.assertEqual(summary["abstentions"], 4)
        self.assertEqual(summary["gate"], "pass")
        self.assertLess(summary["exact_95_percent_interval"]["lower"], 0.75)
        self.assertGreater(summary["exact_95_percent_interval"]["upper"], 0.75)

    def test_sparse_features_and_wrong_campaign_sizes_fail_closed(self):
        empty_receive = MODULE.TrafficWindow(1000, 0, 100, 0, 1)
        receive = MODULE.TrafficWindow(1000, 100, 100, 1, 1)
        with self.assertRaisesRegex(
            MODULE.CandidateError, "incomparable_sparse_feature"
        ):
            MODULE.residuals(empty_receive, receive)
        with self.assertRaisesRegex(
            MODULE.CandidateError, "calibration_requires_eight_runs"
        ):
            MODULE.calibration_scales([])
        with self.assertRaisesRegex(
            MODULE.CandidateError, "ranking_requires_four_candidates"
        ):
            MODULE.rank_candidates(
                receive, [receive], {name: Decimal(1) for name in MODULE.FEATURE_NAMES}
            )
        with self.assertRaisesRegex(
            MODULE.CandidateError, "holdout_requires_sixteen_runs"
        ):
            MODULE.summarize_holdout([])

    def test_declared_campaign_sizes_and_truth_positions_are_generic(self):
        true = MODULE.TrafficWindow(1000, 1000, 200, 10, 2)
        decoy = MODULE.TrafficWindow(1000, 100, 2000, 1, 20)
        scales = MODULE.calibration_scales(
            [MODULE.residuals(true, true)] * 3,
            expected_runs=3,
        )
        ranked = MODULE.rank_candidates(
            true,
            [decoy, true],
            scales,
            expected_candidates=2,
        )
        self.assertEqual(ranked.winner_index, 1)
        summary = MODULE.summarize_holdout(
            [ranked, ranked],
            expected_winner_indices=[1, 1],
            expected_runs=2,
            minimum_successes=2,
        )
        self.assertEqual(summary["recall_at_1"], {"numerator": 2, "denominator": 2})
        self.assertEqual(summary["gate"], "pass")

    def test_malformed_metadata_fails_closed(self):
        with self.assertRaisesRegex(MODULE.CandidateError, "invalid_path_generation"):
            MODULE.counter_window(
                counters(),
                counters(),
                first_generation=True,
                last_generation=True,
                duration_ms=1000,
            )
        malformed = manifest(1)
        malformed["normalization"]["packet_rows_quarantined"] = False
        with self.assertRaisesRegex(
            MODULE.CandidateError, "invalid_capture_quarantine_count"
        ):
            MODULE.capture_window(
                malformed,
                [packet("192.0.2.5", "198.51.100.1")],
                local_addresses={"192.0.2.5"},
                duration_ms=1000,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
