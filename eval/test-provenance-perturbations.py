#!/usr/bin/env python3
"""Hermetic adversarial checks for provenance perturbation evaluation."""

from __future__ import annotations

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
    "provenance_perturbations", HERE / "provenance_perturbations.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def scenarios(report):
    return {item["perturbation_kind"]: item for item in report["scenarios"]}


def lineage_by_id(scenario):
    return {item["annotation_id"]: item for item in scenario["lineage"]}


def assert_error(test, function, code):
    with test.assertRaises(MODULE.ProvenancePerturbationError) as raised:
        function()
    test.assertEqual(raised.exception.code, code)


class ProvenancePerturbationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = MODULE.generate_fixture()
        self.report = MODULE.evaluate_fixture(self.fixture)
        self.scenarios = scenarios(self.report)

    def test_fixed_seed_is_deterministic_bounded_and_path_free(self):
        first = MODULE.generate_fixture()
        second = MODULE.generate_fixture()
        self.assertEqual(first.canonical_json_bytes(), second.canonical_json_bytes())
        self.assertEqual(
            MODULE.report_json_bytes(first), MODULE.report_json_bytes(second)
        )
        self.assertLessEqual(len(first.canonical_json_bytes()), MODULE.MAX_INPUT_BYTES)
        self.assertLessEqual(
            len(MODULE.report_json_bytes(first)), MODULE.MAX_OUTPUT_BYTES
        )
        serialized = first.canonical_json_bytes().decode("ascii").lower()
        for forbidden in ("/users/", "documents/dev", "localhost", "@", "secret"):
            self.assertNotIn(forbidden, serialized)

    def test_exact_schema_and_duplicate_json_keys_fail_closed(self):
        document = self.fixture.document()
        document["raw_identifier"] = "forbidden"
        assert_error(
            self,
            lambda: MODULE.parse_fixture(document),
            "invalid_fixture_schema",
        )
        document = self.fixture.document()
        document["organic_annotations"][0]["provenance"]["path"] = "forbidden"
        assert_error(
            self,
            lambda: MODULE.parse_fixture(document),
            "invalid_provenance_schema",
        )
        assert_error(
            self,
            lambda: MODULE.load_fixture_bytes(b'{"schema":"a","schema":"b"}'),
            "duplicate_json_key",
        )
        assert_error(
            self,
            lambda: MODULE.load_fixture_bytes(b"{" * (MODULE.MAX_INPUT_BYTES + 1)),
            "fixture_bytes_outside_bound",
        )

        self.assertEqual(set(self.report), set(MODULE.REPORT_FIELDS))
        for scenario in self.report["scenarios"]:
            self.assertEqual(set(scenario), set(MODULE.SCENARIO_FIELDS))
            self.assertEqual(set(scenario["decision"]), set(MODULE.DECISION_FIELDS))
            self.assertTrue(
                all(
                    set(lineage) == set(MODULE.LINEAGE_FIELDS)
                    for lineage in scenario["lineage"]
                )
            )

    def test_organic_annotations_and_derived_perturbations_stay_separate(self):
        document = self.fixture.document()
        self.assertTrue(
            all(item["origin"] == "organic" for item in document["organic_annotations"])
        )
        self.assertEqual(
            [item["kind"] for item in document["perturbations"]],
            list(MODULE.PERTURBATION_KINDS),
        )
        generated = [
            item["generated_annotation"]
            for item in document["perturbations"]
            if item["generated_annotation"] is not None
        ]
        self.assertTrue(
            all(item["origin"] == "derived-perturbation" for item in generated)
        )

    def test_delay_changes_arrival_not_event_chronology_or_oracle(self):
        baseline = self.scenarios["none"]
        delayed = self.scenarios["delay"]
        self.assertEqual(
            baseline["event_chronology"],
            ["annotation-a-v1", "annotation-b-v1"],
        )
        self.assertEqual(delayed["event_chronology"], baseline["event_chronology"])
        self.assertEqual(
            baseline["arrival_chronology"],
            ["annotation-a-v1", "annotation-b-v1"],
        )
        self.assertEqual(
            delayed["arrival_chronology"],
            ["annotation-b-v1", "annotation-a-v1"],
        )
        self.assertEqual(
            delayed["active_annotation_ids"], baseline["active_annotation_ids"]
        )
        self.assertEqual(delayed["dependence_aware_evidence_count"], 2)
        self.assertEqual(
            delayed["decision"],
            {
                "state": "abstain",
                "label": None,
                "reason": "conflicting-active-labels",
            },
        )

    def test_reorder_does_not_conflate_input_event_or_arrival_order(self):
        baseline = self.scenarios["none"]
        reordered = self.scenarios["reorder"]
        self.assertNotEqual(
            reordered["input_annotation_ids"], baseline["input_annotation_ids"]
        )
        for field in (
            "event_chronology",
            "arrival_chronology",
            "active_annotation_ids",
            "dependence_aware_evidence_count",
            "decision",
        ):
            self.assertEqual(reordered[field], baseline[field], field)

    def test_exact_duplicate_cannot_inflate_a_vote(self):
        duplicate = self.scenarios["exact-duplicate"]
        self.assertEqual(duplicate["input_annotation_ids"].count("annotation-a-v1"), 2)
        self.assertEqual(
            duplicate["active_annotation_ids"],
            ["annotation-a-v1", "annotation-b-v1"],
        )
        self.assertEqual(duplicate["dependence_aware_evidence_count"], 2)
        self.assertEqual(duplicate["decision"]["state"], "abstain")

    def test_copied_source_shares_ancestry_and_dependence(self):
        copied = self.scenarios["copied-evidence"]
        self.assertEqual(len(copied["active_annotation_ids"]), 3)
        self.assertEqual(copied["dependence_aware_evidence_count"], 2)
        self.assertEqual(copied["decision"]["state"], "abstain")
        copied_lineage = lineage_by_id(copied)["annotation-a-copy"]
        self.assertEqual(copied_lineage["parent_annotation_id"], "annotation-a-v1")
        self.assertEqual(copied_lineage["root_annotation_id"], "annotation-a-v1")

    def test_supersession_changes_only_the_target_revision(self):
        correction = self.scenarios["superseding-correction"]
        self.assertEqual(
            correction["active_annotation_ids"],
            ["annotation-a-v2", "annotation-b-v1"],
        )
        self.assertEqual(correction["dependence_aware_evidence_count"], 2)
        self.assertEqual(
            correction["decision"],
            {"state": "decided", "label": "label-b", "reason": None},
        )
        self.assertEqual(
            lineage_by_id(correction)["annotation-a-v2"]["root_annotation_id"],
            "annotation-a-v1",
        )

    def test_withdrawal_removes_evidence_instead_of_becoming_a_vote(self):
        withdrawal = self.scenarios["withdrawal"]
        self.assertIn("annotation-b-withdrawal", withdrawal["event_chronology"])
        self.assertEqual(withdrawal["active_annotation_ids"], ["annotation-a-v1"])
        self.assertEqual(withdrawal["dependence_aware_evidence_count"], 1)
        self.assertEqual(
            withdrawal["decision"],
            {"state": "decided", "label": "label-a", "reason": None},
        )

    def test_independent_corroboration_counts_but_does_not_resolve_conflict(self):
        independent = self.scenarios["independent-corroboration"]
        self.assertEqual(len(independent["active_annotation_ids"]), 3)
        self.assertEqual(independent["dependence_aware_evidence_count"], 3)
        self.assertEqual(independent["decision"]["state"], "abstain")
        self.assertEqual(
            lineage_by_id(independent)["annotation-c-v1"],
            {
                "annotation_id": "annotation-c-v1",
                "parent_annotation_id": None,
                "root_annotation_id": "annotation-c-v1",
            },
        )

    def test_evaluation_does_not_mutate_organic_inputs(self):
        before = copy.deepcopy(self.fixture.document()["organic_annotations"])
        MODULE.evaluate_fixture(self.fixture)
        self.assertEqual(self.fixture.document()["organic_annotations"], before)

    def test_cli_roundtrip_is_stdin_stdout_only_and_deterministic(self):
        generated = subprocess.run(
            [sys.executable, str(HERE / "provenance_perturbations.py"), "generate"],
            cwd=HERE.parent,
            capture_output=True,
            check=False,
        )
        self.assertEqual(generated.returncode, 0, generated.stderr.decode())
        evaluated = subprocess.run(
            [sys.executable, str(HERE / "provenance_perturbations.py"), "evaluate"],
            cwd=HERE.parent,
            input=generated.stdout,
            capture_output=True,
            check=False,
        )
        self.assertEqual(evaluated.returncode, 0, evaluated.stderr.decode())
        self.assertEqual(json.loads(evaluated.stdout), self.report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
