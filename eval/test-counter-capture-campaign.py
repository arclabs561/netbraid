#!/usr/bin/env python3
"""Hermetic end-to-end checks for the counter/capture campaign evaluator."""

import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "counter_capture_campaign", HERE / "counter_capture_campaign.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def window(seed):
    return {
        "duration_ms": 1000,
        "received_bytes": 1000 + seed * 311,
        "transmitted_bytes": 2300 + seed * 197,
        "received_packets": 10 + seed * 3,
        "transmitted_packets": 17 + seed * 2,
    }


def campaign_manifest():
    calibration = []
    heldout = []
    for regime_index, regime in enumerate(MODULE.REGIMES):
        for sample in range(2):
            run_window = window(1 + regime_index * 20 + sample)
            calibration.append(
                {
                    "run_id": f"{regime}-cal-{sample}",
                    "regime": regime,
                    "counter_window": run_window,
                    "capture_window": copy.deepcopy(run_window),
                }
            )
        regime_ids = [f"{regime}-hold-{sample}" for sample in range(4)]
        for sample, run_id in enumerate(regime_ids):
            run_window = window(5 + regime_index * 20 + sample * 3)
            heldout.append(
                {
                    "run_id": run_id,
                    "regime": regime,
                    "counter_window": run_window,
                    "capture_window": copy.deepcopy(run_window),
                    "true_candidate_index": 0,
                    "candidate_run_ids": [
                        run_id,
                        *sorted(
                            candidate for candidate in regime_ids if candidate != run_id
                        ),
                    ],
                }
            )
    return {
        "schema_version": 1,
        "calibration_runs": calibration,
        "heldout_runs": heldout,
    }


class CounterCaptureCampaignTests(unittest.TestCase):
    def test_synthetic_campaign_evaluates_end_to_end_deterministically(self):
        manifest = campaign_manifest()
        first = MODULE.evaluate_manifest(manifest)
        permuted = copy.deepcopy(manifest)
        permuted["calibration_runs"].reverse()
        permuted["heldout_runs"].reverse()
        second = MODULE.evaluate_manifest(permuted)

        self.assertEqual(first, second)
        self.assertEqual(first["schema"], MODULE.DEFAULT_RESULT_SCHEMA)
        self.assertEqual(
            first["run_counts"], {"total": 24, "calibration": 8, "heldout": 16}
        )
        self.assertEqual(
            [item["regime"] for item in first["regimes"]], list(MODULE.REGIMES)
        )
        self.assertTrue(
            all(
                item["recall_at_1"] == {"numerator": 4, "denominator": 4}
                and item["exclusion_counts"]["total"] == 0
                for item in first["regimes"]
            )
        )
        self.assertEqual(first["aggregate_holdout"]["gate"], "pass")
        self.assertEqual(
            first["aggregate_holdout"]["recall_at_1"],
            {"numerator": 16, "denominator": 16},
        )
        self.assertEqual(
            [item["run_id"] for item in first["heldout_outcomes"]],
            sorted(
                (run["run_id"] for run in manifest["heldout_runs"]),
                key=lambda run_id: (
                    MODULE.REGIMES.index(run_id.rsplit("-hold-", 1)[0]),
                    run_id,
                ),
            ),
        )

        process = subprocess.run(
            [sys.executable, str(HERE / "counter_capture_campaign.py")],
            input=json.dumps(manifest),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout), first)
        self.assertEqual(process.stdout.count("\n"), 1)

    def test_candidate_exclusions_are_counted_and_gate_uses_all_holdout_runs(self):
        manifest = campaign_manifest()
        for regime in MODULE.REGIMES[:2]:
            run = next(
                item for item in manifest["heldout_runs"] if item["regime"] == regime
            )
            run["capture_window"]["received_bytes"] = 0
            run["capture_window"]["received_packets"] = 0

        result = MODULE.evaluate_manifest(manifest)
        self.assertEqual(
            result["aggregate_holdout"]["recall_at_1"],
            {"numerator": 8, "denominator": 16},
        )
        self.assertEqual(result["aggregate_holdout"]["gate"], "fail")
        self.assertEqual(
            result["aggregate_holdout"]["exclusion_counts"],
            {
                "total": 8,
                "candidate_excluded": 8,
                "minimum_distance_tie": 0,
            },
        )
        self.assertEqual(
            [item["exclusion_counts"]["total"] for item in result["regimes"]],
            [4, 4, 0, 0],
        )

    def test_manifest_shape_and_campaign_invariants_fail_closed(self):
        cases = []

        wrong_size = campaign_manifest()
        wrong_size["heldout_runs"].pop()
        cases.append((wrong_size, "campaign_requires_twenty_four_runs"))

        wrong_split = campaign_manifest()
        wrong_split["calibration_runs"].pop()
        wrong_split["heldout_runs"].append(
            copy.deepcopy(wrong_split["heldout_runs"][0])
        )
        cases.append(
            (wrong_split, "campaign_requires_eight_calibration_and_sixteen_heldout")
        )

        duplicate = campaign_manifest()
        duplicate["calibration_runs"][1]["run_id"] = duplicate["calibration_runs"][0][
            "run_id"
        ]
        cases.append((duplicate, "duplicate_run_id"))

        overlap = campaign_manifest()
        overlap["heldout_runs"][0]["run_id"] = overlap["calibration_runs"][0]["run_id"]
        overlap["heldout_runs"][0]["candidate_run_ids"][0] = overlap["heldout_runs"][0][
            "run_id"
        ]
        cases.append((overlap, "calibration_heldout_overlap"))

        bad_regime_count = campaign_manifest()
        bad_regime_count["calibration_runs"][0]["regime"] = MODULE.REGIMES[1]
        cases.append((bad_regime_count, "each_regime_requires_six_runs"))

        wrong_true_index = campaign_manifest()
        wrong_true_index["heldout_runs"][0]["true_candidate_index"] = 0.0
        cases.append((wrong_true_index, "true_candidate_index_must_be_zero"))

        wrong_true_reference = campaign_manifest()
        candidates = wrong_true_reference["heldout_runs"][0]["candidate_run_ids"]
        candidates[0], candidates[1] = candidates[1], candidates[0]
        cases.append((wrong_true_reference, "true_candidate_must_reference_self"))

        wrong_candidate_count = campaign_manifest()
        wrong_candidate_count["heldout_runs"][0]["candidate_run_ids"].pop()
        cases.append((wrong_candidate_count, "heldout_requires_four_candidates"))

        duplicate_decoy = campaign_manifest()
        duplicate_decoy["heldout_runs"][0]["candidate_run_ids"][2] = duplicate_decoy[
            "heldout_runs"
        ][0]["candidate_run_ids"][1]
        cases.append((duplicate_decoy, "decoys_must_reference_distinct_runs"))

        unordered_decoys = campaign_manifest()
        candidates = unordered_decoys["heldout_runs"][0]["candidate_run_ids"]
        candidates[1], candidates[2] = candidates[2], candidates[1]
        cases.append((unordered_decoys, "decoys_must_be_canonically_ordered"))

        calibration_decoy = campaign_manifest()
        calibration_decoy["heldout_runs"][0]["candidate_run_ids"][1] = (
            calibration_decoy["calibration_runs"][0]["run_id"]
        )
        cases.append((calibration_decoy, "decoy_must_reference_heldout_run"))

        cross_regime = campaign_manifest()
        cross_regime["heldout_runs"][0]["candidate_run_ids"][1] = next(
            run["run_id"]
            for run in cross_regime["heldout_runs"]
            if run["regime"] != cross_regime["heldout_runs"][0]["regime"]
        )
        cases.append((cross_regime, "decoy_regime_mismatch"))

        for manifest, reason in cases:
            with (
                self.subTest(reason=reason),
                self.assertRaisesRegex(MODULE.CampaignError, reason),
            ):
                MODULE.evaluate_manifest(manifest)

    def test_raw_capture_address_path_and_unknown_metadata_are_rejected(self):
        unsupported_fields = (
            ("pcap", "capture.pcap"),
            ("local_addresses", ["192.0.2.1"]),
            ("path_generation", 3),
            ("collector", "tshark"),
        )
        for field, value in unsupported_fields:
            manifest = campaign_manifest()
            manifest["heldout_runs"][0][field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(MODULE.CampaignError, "invalid_run_schema"),
            ):
                MODULE.evaluate_manifest(manifest)

        manifest = campaign_manifest()
        manifest["heldout_runs"][0]["capture_window"]["source_address"] = "192.0.2.1"
        with self.assertRaisesRegex(
            MODULE.CampaignError, "invalid_traffic_window_schema"
        ):
            MODULE.evaluate_manifest(manifest)

    def test_malformed_json_and_duplicate_keys_fail_closed_at_cli_boundary(self):
        cases = (
            ("{", "invalid_json"),
            ('{"schema_version":1,"schema_version":1}', "duplicate_json_key"),
        )
        for payload, reason in cases:
            process = subprocess.run(
                [sys.executable, str(HERE / "counter_capture_campaign.py")],
                input=payload,
                text=True,
                capture_output=True,
                check=False,
            )
            with self.subTest(reason=reason):
                self.assertEqual(process.returncode, 2)
                self.assertEqual(process.stdout, "")
                self.assertEqual(process.stderr, f"{reason}\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
