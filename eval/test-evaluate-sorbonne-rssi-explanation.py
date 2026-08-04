#!/usr/bin/env python3
"""Hermetic tests for the Sorbonne RSSI explanation campaign."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("evaluate-sorbonne-rssi-explanation.py")
SPEC = importlib.util.spec_from_file_location("sorbonne_rssi_explanation", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def campaign() -> dict:
    return {
        "reference_frame_profile": {
            "schema": "netmon.rssi_reference_frame_profile.v0",
            "profile_id": "test-profile",
            "minimum_baseline_readings": 4,
            "minimum_absolute_shift_milli_db": 8000,
            "mad_multiplier_ppb": 4000000000,
            "minimum_steady_links": 3,
            "minimum_shifted_fraction_ppb": 600000000,
        },
        "explanation_profile": {
            "profile_id": "netbraid.rssi_shift_explanation.heuristic.v0",
            "inactive_endpoint_potential_ppb": 4000000000,
            "active_endpoint_potential_ppb": 1000000000,
            "shifted_without_endpoint_potential_ppb": 1000000000,
            "shifted_with_one_endpoint_potential_ppb": 64000000000,
            "shifted_with_both_endpoints_potential_ppb": 8000000000,
            "stable_without_endpoint_potential_ppb": 64000000000,
            "stable_with_one_endpoint_potential_ppb": 4000000000,
            "stable_with_both_endpoints_potential_ppb": 1000000000,
        },
    }


def observations() -> dict:
    return {
        condition: {
            observer: [(-20 - index) if condition == "control" else (-50 - index)] * 8
            for index, observer in enumerate(MODULE.EXPECTED_OBSERVERS)
        }
        for condition in ("control", "contrast")
    }


def belief(prefix: str, count: int, minimum: int, maximum: int, total: int) -> dict:
    if count == 0:
        minimum = None
        maximum = None
        total = 0
    return {
        "count": count,
        "{}_relative_belief_ppb_sum".format(prefix): total,
        "{}_relative_belief_ppb_min".format(prefix): minimum,
        "{}_relative_belief_ppb_max".format(prefix): maximum,
    }


def output(case_id: str, shifted: int, source: int, observer: int) -> dict:
    return {
        "schema": MODULE.BRIDGE_SCHEMA,
        "case_id": case_id,
        "heuristic_profile": "netbraid.rssi_shift_explanation.heuristic.v0",
        "links_seen": 10,
        "baseline_samples_seen": 40,
        "eligible_links": 10,
        "shifted_links": shifted,
        "heuristic_weights": {
            key: value
            for key, value in campaign()["explanation_profile"].items()
            if key != "profile_id"
        },
        "outcomes": {
            "exact_components": 1,
            "infeasible_components": 0,
            "abstained_components": 0,
            "assignments_evaluated": 2048,
        },
        "observer_beliefs": belief("shifted", 10, observer, observer, observer * 10),
        "source_beliefs": belief("shifted", 1, source, source, source),
        "residual_beliefs": belief("residual", shifted, 10, 20, shifted * 15),
    }


class SorbonneRssiExplanationTests(unittest.TestCase):
    def test_locked_campaign_loads(self) -> None:
        campaign_path = (
            Path(__file__).parent
            / "fixtures"
            / "sorbonne-rssi-explanation-campaign-v0.json"
        )

        value, digest = MODULE.load_campaign(campaign_path)

        self.assertEqual(digest, MODULE.CAMPAIGN_SHA256)
        self.assertEqual(value["protocol_lock"]["revision"], 1)

    def test_builds_closed_role_requests_without_forbidden_fields(self) -> None:
        requests, corpus = MODULE.build_requests(campaign(), observations())

        self.assertEqual(
            [request["case_id"] for request in requests], ["control", "contrast"]
        )
        self.assertEqual(corpus["baseline_samples"], 40)
        self.assertEqual(requests[0]["links"][0]["observer_id"], "observer-0")
        self.assertEqual(requests[0]["links"][-1]["observer_id"], "observer-9")
        self.assertTrue(
            all(
                link["source_id"] == "source-role-0"
                for request in requests
                for link in request["links"]
            )
        )
        encoded = json.dumps(requests)
        for forbidden in (
            "Source_MAC_address",
            "Frame_time_epoch",
            "Sequence_number",
            "member_path",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertEqual(
            [link["recent_rssi_milli_db"] for link in requests[0]["links"]],
            [(-20 - index) * 1000 for index in range(10)],
        )
        self.assertEqual(
            [link["recent_rssi_milli_db"] for link in requests[1]["links"]],
            [(-50 - index) * 1000 for index in range(10)],
        )

    def test_report_scores_registered_expectations_without_identifiers(self) -> None:
        report = MODULE.build_report(
            campaign(),
            MODULE.CAMPAIGN_SHA256,
            123,
            b"bridge",
            {
                "members": {"control": 10, "contrast": 10},
                "rows": {"control": 80, "contrast": 80},
                "baseline_samples": 40,
            },
            1,
            [output("control", 0, 100, 200), output("contrast", 10, 900, 300)],
        )

        self.assertTrue(report["gates"]["passed"])
        self.assertEqual(report["contrasts"]["source_belief_ppb_delta"], 800)
        encoded = json.dumps(report, sort_keys=True)
        for forbidden in ("observer_id", "source_id", "source_mac", "local_path"):
            self.assertNotIn(forbidden, encoded)

    def test_projection_rejects_identifier_bearing_extension(self) -> None:
        value = output("control", 0, 100, 200)
        value["observer_id"] = "observer-0"

        with self.assertRaisesRegex(MODULE.EvaluationError, "output fields differ"):
            MODULE.validate_projection(value, 40, campaign()["explanation_profile"])

    def test_projection_rejects_impossible_counts_and_empty_summary(self) -> None:
        value = output("control", 0, 100, 200)
        value["links_seen"] = 0
        value["residual_beliefs"] = belief("residual", 0, 10, 20, 0)

        with self.assertRaisesRegex(MODULE.EvaluationError, "submitted corpus"):
            MODULE.validate_projection(value, 40, campaign()["explanation_profile"])

    def test_projection_rejects_weight_drift_under_same_profile_id(self) -> None:
        value = output("control", 0, 100, 200)
        value["heuristic_weights"]["active_endpoint_potential_ppb"] += 1

        with self.assertRaisesRegex(
            MODULE.EvaluationError, "unexpected heuristic weights"
        ):
            MODULE.validate_projection(value, 40, campaign()["explanation_profile"])

    def test_lower_median_is_an_observed_value(self) -> None:
        self.assertEqual(MODULE.lower_median([9, 1, 7, 3]), 3)


if __name__ == "__main__":
    unittest.main()
