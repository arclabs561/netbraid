#!/usr/bin/env python3
"""Hermetic checks for Sorbonne relation-target accounting."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "evaluate_sorbonne_structural_reducer",
    HERE / "evaluate-sorbonne-structural-reducer.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def packet(record_id: str, digest: str):
    return (
        {
            "schema": MODULE.PACKET_SCHEMA,
            "capture_id": f"capture:{record_id}",
            "record_id": record_id,
        },
        digest,
    )


def claim(target):
    return {
        "schema": MODULE.CLAIM_SCHEMA,
        "projection": {
            "schema": MODULE.PROJECTION_SCHEMA,
            "family_schema": MODULE.PACKET_EVENT_FAMILY,
            "reducer": MODULE.PACKET_EVENT_REDUCER,
            "alternatives": [
                {"role": "same_event", "disposition": "underdetermined"},
                {"role": "different_event", "disposition": "underdetermined"},
                {"role": "unknown", "disposition": "supported"},
            ],
        },
        "inputs": [
            {
                "role": role,
                "source_schema": participant[0],
                "source_id": participant[1],
                "content_sha256": participant[2],
            }
            for role, participant in zip(("left_packet", "right_packet"), target)
        ],
    }


class SorbonneRelationTargetTests(unittest.TestCase):
    def test_target_is_content_bound_and_symmetric(self):
        left = packet("packet:a", "a" * 64)
        right = packet("packet:b", "b" * 64)

        forward = MODULE.relation_target(left, right)
        reverse = MODULE.relation_target(right, left)

        self.assertEqual(forward, reverse)
        self.assertNotEqual(
            forward,
            MODULE.relation_target(left, packet("packet:b", "c" * 64)),
        )
        MODULE.validate_packet_event_claim(claim(forward), forward)

    def test_claim_drift_and_unbound_inputs_fail_closed(self):
        target = MODULE.relation_target(
            packet("packet:a", "a" * 64), packet("packet:b", "b" * 64)
        )
        malformed = claim(target)
        malformed["projection"]["alternatives"][2]["disposition"] = "contradicted"
        with self.assertRaisesRegex(MODULE.EvaluationError, "does not abstain"):
            MODULE.validate_packet_event_claim(malformed, target)

        mismatched = claim(target)
        mismatched["inputs"][1]["content_sha256"] = "c" * 64
        with self.assertRaisesRegex(MODULE.EvaluationError, "target differs"):
            MODULE.validate_packet_event_claim(mismatched, target)

    def test_population_reports_duplicate_targets_without_retaining_ids(self):
        observation_a = MODULE.Observation("S01", 1, 1, -40, 1, 0, 8, 0, "a", 1)
        observation_b = MODULE.Observation("S02", 2, 2, -41, 1, 0, 8, 0, "b", 2)
        packets = {
            ("S01", 1): packet("packet:a", "a" * 64),
            ("S02", 2): packet("packet:b", "b" * 64),
        }
        audit, targets = MODULE.relation_target_population(
            [
                ("opaque-pair-a", observation_a, observation_b),
                ("opaque-pair-b", observation_b, observation_a),
            ],
            packets,
        )

        self.assertEqual(
            audit,
            {
                "claims": 2,
                "targets": 1,
                "duplicate_target_claims": 1,
                "population_sha256": MODULE.relation_target_digest(targets),
            },
        )
        rendered = str(audit).lower()
        self.assertNotIn("packet:a", rendered)
        self.assertNotIn("packet:b", rendered)


if __name__ == "__main__":
    unittest.main(verbosity=2)
