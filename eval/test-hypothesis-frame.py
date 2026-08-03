#!/usr/bin/env python3
"""Hermetic checks for the evaluation-only hypothesis-frame contract."""

import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "hypothesis_frame", HERE / "hypothesis_frame.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def frame():
    return {
        "frame_id": "same-model-sibling",
        "artifact_object_relation": "different_object",
        "content_relation": "different",
        "event_relation": "different",
        "event_performer_relation": "different",
        "claimed_identifier_relation": "different",
        "cryptographic_principal_relation": "not_observed",
        "physical_device_relation": "different",
        "physical_source_relation": "different",
        "software_relation": "same",
        "configuration_relation": "same",
        "variant_relation": "same",
        "lineage_relation": "common_ancestor",
        "integrity": "verified_unchanged",
        "admissibility": "in_domain",
        "freshness": "fresh",
        "continuity": "complete",
        "transmission": "direct",
        "scenario": {
            "cause": "benign_confounder",
            "mechanisms": ["none"],
            "modification_loci": ["none"],
            "authorization": "authorized",
            "intent": "benign",
            "provenance": "explicit_fixture",
            "tamper_hypothesis": {
                "disposition": "contradicted",
                "basis": [
                    "applicable_authorization_policy",
                    "no_change_or_interference",
                ],
            },
        },
    }


def assert_error(test, value, code):
    with test.assertRaises(MODULE.HypothesisFrameError) as raised:
        MODULE.parse_frame(value)
    test.assertEqual(raised.exception.code, code)


class HypothesisFrameTests(unittest.TestCase):
    def test_same_variant_does_not_collapse_different_sources(self):
        parsed = MODULE.parse_frame(frame())
        self.assertEqual(parsed.variant_relation, "same")
        self.assertEqual(parsed.physical_device_relation, "different")
        self.assertEqual(parsed.physical_source_relation, "different")

    def test_same_event_performer_is_independent_from_physical_source(self):
        value = frame()
        value.update(
            {
                "frame_id": "synchronized-multimodal-event",
                "event_relation": "same",
                "event_performer_relation": "same",
                "physical_device_relation": "different",
                "physical_source_relation": "different",
                "configuration_relation": "different",
            }
        )
        parsed = MODULE.parse_frame(value)
        self.assertEqual(parsed.event_relation, "same")
        self.assertEqual(parsed.event_performer_relation, "same")
        self.assertEqual(parsed.physical_source_relation, "different")

    def test_unobserved_event_performer_is_distinct_from_unknown(self):
        value = frame()
        value["event_performer_relation"] = "not_observed"
        self.assertEqual(
            MODULE.parse_frame(value).event_performer_relation, "not_observed"
        )
        value["event_performer_relation"] = "unknown"
        self.assertEqual(MODULE.parse_frame(value).event_performer_relation, "unknown")

    def test_compromised_enrolled_source_can_be_malicious_and_unchanged(self):
        value = frame()
        value.update(
            {
                "frame_id": "compromised-enrolled-source",
                "physical_device_relation": "same",
                "physical_source_relation": "same",
                "variant_relation": "same",
                "content_relation": "equal",
            }
        )
        value["scenario"] = {
            "cause": "compromise",
            "mechanisms": ["credential_theft"],
            "modification_loci": ["firmware"],
            "authorization": "unauthorized",
            "intent": "malicious",
            "provenance": "publisher_adjudicated_scenario",
            "tamper_hypothesis": {
                "disposition": "supported",
                "basis": [
                    "applicable_authorization_policy",
                    "unauthorized_change_or_interference",
                ],
            },
        }
        parsed = MODULE.parse_frame(value)
        self.assertEqual(parsed.integrity, "verified_unchanged")
        self.assertEqual(parsed.scenario.intent, "malicious")
        self.assertEqual(parsed.scenario.tamper_hypothesis.disposition, "supported")

    def test_hash_inequality_can_leave_tamper_underdetermined(self):
        value = frame()
        value["frame_id"] = "changed-bytes-unknown-policy"
        value["integrity"] = "verified_changed"
        value["scenario"] = {
            "cause": "ambiguous",
            "mechanisms": ["unknown"],
            "modification_loci": ["stored_artifact"],
            "authorization": "unknown",
            "intent": "unknown",
            "provenance": "insufficient_evidence",
            "tamper_hypothesis": {
                "disposition": "underdetermined",
                "basis": ["insufficient_policy_evidence"],
            },
        }
        parsed = MODULE.parse_frame(value)
        self.assertEqual(parsed.integrity, "verified_changed")
        self.assertEqual(
            parsed.scenario.tamper_hypothesis.disposition, "underdetermined"
        )

    def test_authorized_transformation_is_not_tampering(self):
        value = frame()
        value["frame_id"] = "authorized-conversion"
        value["content_relation"] = "different"
        value["variant_relation"] = "right_derived"
        value["lineage_relation"] = "right_derived"
        value["integrity"] = "authorized_transformation"
        value["scenario"] = {
            "cause": "benign_transformation",
            "mechanisms": ["none"],
            "modification_loci": ["stored_artifact"],
            "authorization": "authorized",
            "intent": "benign",
            "provenance": "operator_adjudication",
            "tamper_hypothesis": {
                "disposition": "contradicted",
                "basis": [
                    "applicable_authorization_policy",
                    "authorized_change_or_interference",
                ],
            },
        }
        parsed = MODULE.parse_frame(value)
        self.assertEqual(parsed.scenario.tamper_hypothesis.disposition, "contradicted")

    def test_cloned_claim_can_have_a_different_source(self):
        value = frame()
        value["frame_id"] = "cloned-claim"
        value["claimed_identifier_relation"] = "same"
        value["cryptographic_principal_relation"] = "same"
        value["scenario"].update(
            {
                "cause": "impersonation",
                "mechanisms": ["claimed_identifier_spoofing", "credential_cloning"],
                "authorization": "unauthorized",
                "intent": "unknown",
                "provenance": "publisher_adjudicated_scenario",
                "tamper_hypothesis": {
                    "disposition": "supported",
                    "basis": [
                        "applicable_authorization_policy",
                        "unauthorized_change_or_interference",
                    ],
                },
            }
        )
        parsed = MODULE.parse_frame(value)
        self.assertEqual(parsed.claimed_identifier_relation, "same")
        self.assertEqual(parsed.physical_source_relation, "different")

    def test_directional_relations_transpose_and_round_trip(self):
        value = frame()
        value["software_relation"] = "left_derived"
        value["variant_relation"] = "right_derived"
        value["lineage_relation"] = "left_derived"
        parsed = MODULE.parse_frame(value)
        transposed = parsed.transpose()
        self.assertEqual(transposed.software_relation, "right_derived")
        self.assertEqual(transposed.variant_relation, "left_derived")
        self.assertEqual(transposed.lineage_relation, "right_derived")
        self.assertEqual(transposed.transpose(), parsed)

    def test_bare_identity_tampered_and_malicious_fields_are_rejected(self):
        for field_name in ("identity", "actor", "performer", "tampered", "malicious"):
            with self.subTest(field_name=field_name):
                value = frame()
                value[field_name] = True
                assert_error(self, value, "invalid_frame_schema")

    def test_malicious_intent_requires_scenario_provenance(self):
        value = frame()
        value["scenario"]["intent"] = "malicious"
        value["scenario"]["provenance"] = "insufficient_evidence"
        assert_error(self, value, "intent_without_scenario_provenance")

    def test_tamper_support_requires_policy_and_unauthorized_interference(self):
        value = frame()
        value["scenario"]["tamper_hypothesis"] = {
            "disposition": "supported",
            "basis": ["unauthorized_change_or_interference"],
        }
        assert_error(self, value, "unsupported_tamper_support_basis")

        value = frame()
        value["scenario"].update(
            {
                "authorization": "authorized",
                "mechanisms": ["credential_theft"],
                "tamper_hypothesis": {
                    "disposition": "supported",
                    "basis": [
                        "applicable_authorization_policy",
                        "unauthorized_change_or_interference",
                    ],
                },
            }
        )
        assert_error(self, value, "tamper_support_conflicts_with_authorization")

        value = frame()
        value["scenario"].update(
            {
                "authorization": "unauthorized",
                "tamper_hypothesis": {
                    "disposition": "supported",
                    "basis": [
                        "applicable_authorization_policy",
                        "unauthorized_change_or_interference",
                    ],
                },
            }
        )
        assert_error(self, value, "tamper_support_without_change_or_interference")

    def test_replay_and_relay_contradictions_fail_closed(self):
        replay = frame()
        replay["scenario"]["mechanisms"] = ["replay"]
        replay["event_relation"] = "same"
        assert_error(self, replay, "replay_cannot_be_same_event")

        relayed = frame()
        relayed["scenario"]["mechanisms"] = ["relay"]
        relayed["transmission"] = "direct"
        assert_error(self, relayed, "relay_cannot_be_direct")

    def test_manifest_cli_canonicalizes_without_raw_observations(self):
        second = frame()
        second["frame_id"] = "a-first"
        manifest = {"schema": MODULE.SCHEMA, "frames": [frame(), second]}
        process = subprocess.run(
            [sys.executable, str(HERE / "hypothesis_frame.py")],
            input=json.dumps(manifest),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        output = json.loads(process.stdout)
        self.assertEqual(
            [item["frame_id"] for item in output["frames"]],
            ["a-first", "same-model-sibling"],
        )
        forbidden = ("path", "address", "device_id", "raw", "model_output")
        encoded = process.stdout.lower()
        self.assertTrue(all(token not in encoded for token in forbidden))

    def test_duplicate_frame_ids_fail_closed(self):
        manifest = {
            "schema": MODULE.SCHEMA,
            "frames": [frame(), copy.deepcopy(frame())],
        }
        with self.assertRaises(MODULE.HypothesisFrameError) as raised:
            MODULE.parse_manifest(manifest)
        self.assertEqual(raised.exception.code, "duplicate_frame_id")


if __name__ == "__main__":
    unittest.main()
