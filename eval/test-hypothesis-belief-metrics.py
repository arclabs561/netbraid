#!/usr/bin/env python3
"""Hermetic tests for source-agnostic finite-belief metrics."""

from __future__ import annotations

import copy
import io
import json
import unittest

import hypothesis_belief_metrics as metrics
from hypothesis_frame import SCHEMA as FRAME_SCHEMA


def frame(frame_id: str, *, event_relation: str = "unknown") -> dict[str, object]:
    return {
        "frame_id": frame_id,
        "artifact_object_relation": "unknown",
        "content_relation": "unknown",
        "event_relation": event_relation,
        "event_performer_relation": "unknown",
        "claimed_identifier_relation": "unknown",
        "cryptographic_principal_relation": "unknown",
        "physical_device_relation": "unknown",
        "physical_source_relation": "unknown",
        "software_relation": "unknown",
        "configuration_relation": "unknown",
        "variant_relation": "unknown",
        "lineage_relation": "unknown",
        "integrity": "unverifiable",
        "admissibility": "in_domain",
        "freshness": "unknown",
        "continuity": "unknown",
        "transmission": "unknown",
        "scenario": {
            "cause": "ambiguous",
            "mechanisms": ["unknown"],
            "modification_loci": ["unknown"],
            "authorization": "unknown",
            "intent": "unknown",
            "provenance": "insufficient_evidence",
            "tamper_hypothesis": {
                "disposition": "underdetermined",
                "basis": ["insufficient_policy_evidence"],
            },
        },
    }


def exact_row(
    frame_id: str,
    beliefs_ppb: dict[str, int],
    *,
    axis: str = "event_relation",
    strata: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "frame_id": frame_id,
        "axis": axis,
        "outcome": {"state": "exact", "beliefs_ppb": beliefs_ppb},
        "strata": {} if strata is None else strata,
    }


def manifest(
    frames: list[dict[str, object]], rows: list[dict[str, object]]
) -> dict[str, object]:
    return {
        "schema": metrics.SCHEMA,
        "profile": {
            "profile_id": "fixture.profile:v0",
            "profile_sha256": "a" * 64,
            "belief_semantics": "heuristic_relative",
        },
        "frame_manifest": {"schema": FRAME_SCHEMA, "frames": frames},
        "rows": rows,
    }


class HypothesisBeliefMetricsTests(unittest.TestCase):
    def test_binary_brier_and_confidence_bins_match_hand_oracle(self) -> None:
        document = manifest(
            [
                frame("same-frame", event_relation="same"),
                frame("different-frame", event_relation="different"),
            ],
            [
                exact_row(
                    "same-frame",
                    {"different": 200_000_000, "same": 800_000_000},
                ),
                exact_row(
                    "different-frame",
                    {"different": 600_000_000, "same": 400_000_000},
                ),
            ],
        )

        report = metrics.evaluate_manifest(document)
        axis = report["axes"]["event_relation"]

        self.assertEqual(
            axis["proper_score"]["mean"],
            {
                "numerator": 400_000_000_000_000_000,
                "denominator": 2_000_000_000_000_000_000,
            },
        )
        self.assertEqual(axis["maximum_state"]["unique_correct_count"], 2)
        self.assertEqual(axis["confidence_diagnostic"]["bins"][6]["count"], 1)
        self.assertEqual(axis["confidence_diagnostic"]["bins"][8]["count"], 1)
        self.assertNotIn("ece", axis["confidence_diagnostic"])

    def test_unknown_abstained_and_infeasible_are_distinct_and_unscored(self) -> None:
        document = manifest(
            [
                frame("unknown-frame"),
                frame("abstained-frame", event_relation="same"),
                frame("infeasible-frame", event_relation="different"),
            ],
            [
                exact_row(
                    "unknown-frame",
                    {"different": 500_000_000, "same": 500_000_000},
                ),
                {
                    "frame_id": "abstained-frame",
                    "axis": "event_relation",
                    "outcome": {
                        "state": "abstained",
                        "reason": "assignment_budget",
                    },
                    "strata": {},
                },
                {
                    "frame_id": "infeasible-frame",
                    "axis": "event_relation",
                    "outcome": {"state": "no_feasible_assignment"},
                    "strata": {},
                },
            ],
        )

        axis = metrics.evaluate_manifest(document)["axes"]["event_relation"]

        self.assertEqual(
            axis["outcomes"],
            {"exact": 1, "abstained": 1, "no_feasible_assignment": 1},
        )
        self.assertEqual(axis["proper_score"]["scored_count"], 0)
        self.assertEqual(axis["proper_score"]["unknown_reference_exact_count"], 1)
        self.assertEqual(
            axis["proper_score"]["mean"], {"numerator": 0, "denominator": 0}
        )
        self.assertEqual(axis["maximum_state"]["tied_count"], 0)

    def test_multiclass_states_are_axis_derived_and_ties_remain_visible(self) -> None:
        variant_frame = frame("variant-frame")
        variant_frame["variant_relation"] = "left_derived"
        document = manifest(
            [variant_frame],
            [
                exact_row(
                    "variant-frame",
                    {
                        "different": 100_000_000,
                        "left_derived": 400_000_000,
                        "right_derived": 400_000_000,
                        "same": 100_000_000,
                    },
                    axis="variant_relation",
                )
            ],
        )

        axis = metrics.evaluate_manifest(document)["axes"]["variant_relation"]

        self.assertEqual(axis["proper_score"]["scored_count"], 1)
        self.assertEqual(axis["maximum_state"]["unique_count"], 0)
        self.assertEqual(axis["maximum_state"]["tied_count"], 1)
        self.assertEqual(axis["maximum_state"]["tied_contains_reference_count"], 1)
        self.assertTrue(
            axis["confidence_diagnostic"]["excludes_tied_and_unknown_reference_rows"]
        )

    def test_exact_belief_shape_probability_and_sum_fail_closed(self) -> None:
        base = manifest(
            [frame("frame", event_relation="same")],
            [exact_row("frame", {"different": 200_000_000, "same": 800_000_000})],
        )
        mutations = []

        missing = copy.deepcopy(base)
        del missing["rows"][0]["outcome"]["beliefs_ppb"]["same"]
        mutations.append((missing, "invalid_belief_states"))

        unknown = copy.deepcopy(base)
        unknown["rows"][0]["outcome"]["beliefs_ppb"]["unknown"] = 0
        mutations.append((unknown, "invalid_belief_states"))

        boolean = copy.deepcopy(base)
        boolean["rows"][0]["outcome"]["beliefs_ppb"] = {
            "different": True,
            "same": metrics.PPB - 1,
        }
        mutations.append((boolean, "invalid_belief_probability"))

        wrong_sum = copy.deepcopy(base)
        wrong_sum["rows"][0]["outcome"]["beliefs_ppb"]["same"] -= 1
        mutations.append((wrong_sum, "belief_probability_sum_mismatch"))

        for value, code in mutations:
            with (
                self.subTest(code=code),
                self.assertRaisesRegex(metrics.HypothesisBeliefMetricsError, code),
            ):
                metrics.evaluate_manifest(value)

    def test_nonexact_outcomes_cannot_smuggle_beliefs_or_unknown_reasons(self) -> None:
        base = manifest(
            [frame("frame", event_relation="same")],
            [
                {
                    "frame_id": "frame",
                    "axis": "event_relation",
                    "outcome": {
                        "state": "abstained",
                        "reason": "assignment_budget",
                    },
                    "strata": {},
                }
            ],
        )
        with_beliefs = copy.deepcopy(base)
        with_beliefs["rows"][0]["outcome"]["beliefs_ppb"] = {
            "different": 0,
            "same": metrics.PPB,
        }
        with self.assertRaisesRegex(
            metrics.HypothesisBeliefMetricsError, "invalid_outcome_schema"
        ):
            metrics.evaluate_manifest(with_beliefs)

        unknown_reason = copy.deepcopy(base)
        unknown_reason["rows"][0]["outcome"]["reason"] = "network_error"
        with self.assertRaisesRegex(
            metrics.HypothesisBeliefMetricsError, "invalid_abstention_reason"
        ):
            metrics.evaluate_manifest(unknown_reason)

    def test_profile_slot_and_strata_contracts_are_bounded_and_path_free(self) -> None:
        stratum = "0123456789abcdef"
        base = manifest(
            [frame("frame", event_relation="same")],
            [
                exact_row(
                    "frame",
                    {"different": 0, "same": metrics.PPB},
                    strata={"domain": stratum},
                )
            ],
        )
        report = metrics.evaluate_manifest(base)
        self.assertEqual(report["profile"], base["profile"])
        self.assertEqual(report["strata"][0]["value"], stratum)
        self.assertNotIn("frame", json.dumps(report))

        duplicate = copy.deepcopy(base)
        duplicate["rows"].append(copy.deepcopy(duplicate["rows"][0]))
        with self.assertRaisesRegex(
            metrics.HypothesisBeliefMetricsError, "duplicate_frame_axis"
        ):
            metrics.evaluate_manifest(duplicate)

        leaking = copy.deepcopy(base)
        leaking["rows"][0]["source_path"] = "forbidden"
        with self.assertRaisesRegex(
            metrics.HypothesisBeliefMetricsError, "invalid_row_schema"
        ):
            metrics.evaluate_manifest(leaking)

        invalid_semantics = copy.deepcopy(base)
        invalid_semantics["profile"]["belief_semantics"] = ["heuristic_relative"]
        with self.assertRaisesRegex(
            metrics.HypothesisBeliefMetricsError, "invalid_belief_semantics"
        ):
            metrics.evaluate_manifest(invalid_semantics)

    def test_input_order_does_not_change_aggregate_report(self) -> None:
        frames = [
            frame("a", event_relation="same"),
            frame("b", event_relation="different"),
        ]
        rows = [
            exact_row("a", {"different": 100_000_000, "same": 900_000_000}),
            exact_row("b", {"different": 700_000_000, "same": 300_000_000}),
        ]
        forward = metrics.evaluate_manifest(manifest(frames, rows))
        reverse = metrics.evaluate_manifest(
            manifest(list(reversed(frames)), list(reversed(rows)))
        )
        self.assertEqual(forward, reverse)

    def test_json_boundary_and_cli_never_publish_partial_output(self) -> None:
        with self.assertRaisesRegex(
            metrics.HypothesisBeliefMetricsError, "duplicate_json_key"
        ):
            metrics.parse_json_bytes(b'{"schema":"x","schema":"y"}')
        with self.assertRaisesRegex(
            metrics.HypothesisBeliefMetricsError, "invalid_json"
        ):
            metrics.parse_json_bytes(b'{"value":NaN}')
        with self.assertRaisesRegex(
            metrics.HypothesisBeliefMetricsError, "manifest_too_large"
        ):
            metrics.parse_json_bytes(b" " * (metrics.MAX_INPUT_BYTES + 1))

        stdout = io.StringIO()
        stderr = io.StringIO()
        exit_code = metrics.main(io.StringIO("{}"), stdout, stderr)
        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "invalid_manifest_schema\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
