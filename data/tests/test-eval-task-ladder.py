#!/usr/bin/env python3
"""Hermetic contract tests for the bounded evaluation-task ladder."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LADDER = ROOT / "data" / "catalog" / "eval-task-ladder-v1.json"
SURFACES = ROOT / "eval" / "fixtures" / "modality-coverage-v0.json"
SOURCE_LEADS = ROOT / "data" / "catalog" / "research-leads-v1.json"
HYPOTHESIS_FRAME = ROOT / "eval" / "hypothesis_frame.py"

TOP_FIELDS = {"schema", "bounds", "relation_axis_policy", "levels"}
BOUND_FIELDS = {
    "max_levels",
    "max_tasks_per_level",
    "max_surface_refs_per_level",
    "max_source_lead_refs_per_level",
    "max_relation_axes_per_level",
    "max_label_entries_per_class",
}
POLICY_FIELDS = {"axes", "separate_gates"}
LEVEL_FIELDS = {
    "id",
    "difficulty",
    "capabilities",
    "tasks",
    "surface_ids",
    "source_lead_ids",
    "relation_axes",
    "labels",
    "grouping",
    "pass_gates",
}
LABEL_FIELDS = {"organic", "derived_perturbations"}
LABEL_ENTRY_FIELDS = {"origin", "labels"}
GROUPING_FIELDS = {"unit_axes", "held_out_axes", "leakage_rules"}

CAPABILITIES = {
    "bounded_ingest",
    "typed_observation",
    "deterministic_replay",
    "cross_representation_alignment",
    "continuity_audit",
    "relation_oracle",
    "group_disjoint_evaluation",
    "domain_transfer",
    "calibrated_hypothesis_scoring",
    "open_set_abstention",
    "cross_modal_fusion",
    "missing_modality_eval",
    "provenance_graph",
    "annotation_revision",
    "dependence_audit",
    "conditional_source_reliability",
    "chronological_evaluation",
    "longitudinal_tracking",
    "temporal_drift_eval",
    "scenario_oracle",
    "perturbation_harness",
}
TASKS = {
    "packet_adapter_conformance",
    "saved_live_replay_parity",
    "signal_family_recognition",
    "signal_packet_alignment",
    "timestamp_alignment",
    "continuity_classification",
    "heldout_location_transfer",
    "physical_source_relation",
    "same_variant_different_source",
    "receiver_day_environment_shift",
    "cross_modal_event_relation",
    "event_performer_relation",
    "independent_evidence_fusion",
    "missing_modality_ablation",
    "delayed_annotation_revision",
    "conflicting_annotation_resolution",
    "copied_evidence_detection",
    "conditional_source_reliability",
    "track_continuity",
    "time_to_reacquire",
    "false_merge_fragmentation",
    "temporal_drift",
    "controlled_cause_discrimination",
    "replay_relay_discrimination",
    "variant_lineage_relation",
    "tamper_hypothesis",
    "open_set_abstention",
}
SEPARATE_GATES = {
    "integrity",
    "admissibility",
    "freshness",
    "continuity",
    "transmission",
    "scenario",
}
ORGANIC_ORIGINS = {
    "publisher_structure",
    "publisher_measurement_metadata",
    "publisher_adjudicated_scenario",
}
DERIVED_ORIGINS = {"reviewed_fixture", "deterministic_transform"}
ORGANIC_LABELS = {
    "artifact_membership",
    "protocol_family",
    "representation_group",
    "technology_family",
    "timestamp",
    "activity",
    "physical_device",
    "physical_source",
    "variant",
    "location",
    "day",
    "receiver_chain",
    "configuration",
    "capture_event",
    "event_performer",
    "controlled_cause",
    "acquisition_category",
    "annotation_producer",
    "annotation_revision",
}
DERIVED_LABELS = {
    "duplicate",
    "reorder",
    "delete",
    "replay",
    "relay",
    "content_mutation",
    "metadata_mutation",
    "delay",
    "withdrawal",
    "copied_annotation",
}
GROUP_AXES = {
    "artifact_object",
    "capture_event",
    "physical_device",
    "physical_source",
    "variant",
    "day",
    "receiver_chain",
    "location",
    "configuration",
    "event_performer",
    "representation",
    "scenario",
    "annotation_producer",
    "source_version",
    "track",
}
LEAKAGE_RULES = {
    "no_role_split_structural_only",
    "no_exact_artifact_cross_role",
    "derived_parent_stays_in_role",
    "zero_declared_group_overlap",
    "validation_only_selection",
    "test_role_unread_until_lock",
    "copied_sources_share_dependence_group",
    "chronological_roles_only",
}
PASS_GATES = {
    "artifact_admission_complete",
    "resource_bounds_enforced",
    "schema_conformance",
    "deterministic_repeat",
    "provenance_complete",
    "relation_oracle_complete",
    "perturbation_parent_binding",
    "zero_declared_group_overlap",
    "per_group_metrics",
    "calibration_report",
    "abstention_report",
    "fusion_ablation",
    "scenario_provenance_required",
    "no_intent_from_anomaly",
    "source_version_binding",
    "dependence_groups_complete",
    "chronological_split_audit",
    "track_metrics",
}
PRIVATE_TOKEN = re.compile(
    r"(?i)(/users/|documents/dev|localhost|api[_-]?key|password|secret|token)"
)


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def hypothesis_relation_axes() -> set[str]:
    spec = importlib.util.spec_from_file_location("hypothesis_frame", HYPOTHESIS_FRAME)
    if spec is None or spec.loader is None:
        raise RuntimeError("hypothesis_frame_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
        return set(module.RELATION_STATES)
    finally:
        del sys.modules[spec.name]


def assert_unique_nonempty(test: unittest.TestCase, values: list[str]) -> None:
    test.assertTrue(values)
    test.assertEqual(len(values), len(set(values)))
    test.assertTrue(all(isinstance(value, str) and value for value in values))


class EvalTaskLadderTests(unittest.TestCase):
    def test_strict_shape_vocabularies_and_bounds(self):
        ladder = load(LADDER)
        self.assertEqual(set(ladder), TOP_FIELDS)
        self.assertEqual(ladder["schema"], "netbraid.eval_task_ladder.v1")
        self.assertEqual(set(ladder["bounds"]), BOUND_FIELDS)
        self.assertEqual(set(ladder["relation_axis_policy"]), POLICY_FIELDS)

        bounds = ladder["bounds"]
        self.assertTrue(
            all(type(value) is int and value > 0 for value in bounds.values())
        )
        levels = ladder["levels"]
        self.assertTrue(1 <= len(levels) <= bounds["max_levels"])

        policy = ladder["relation_axis_policy"]
        self.assertEqual(set(policy["axes"]), hypothesis_relation_axes())
        self.assertEqual(len(policy["axes"]), len(set(policy["axes"])))
        self.assertEqual(set(policy["separate_gates"]), SEPARATE_GATES)

        for level in levels:
            self.assertEqual(set(level), LEVEL_FIELDS, level.get("id"))
            self.assertRegex(level["id"], r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
            assert_unique_nonempty(self, level["capabilities"])
            assert_unique_nonempty(self, level["tasks"])
            assert_unique_nonempty(self, level["surface_ids"])
            assert_unique_nonempty(self, level["relation_axes"])
            assert_unique_nonempty(self, level["pass_gates"])
            self.assertEqual(
                len(level["source_lead_ids"]), len(set(level["source_lead_ids"]))
            )
            self.assertLessEqual(len(level["tasks"]), bounds["max_tasks_per_level"])
            self.assertLessEqual(
                len(level["surface_ids"]), bounds["max_surface_refs_per_level"]
            )
            self.assertLessEqual(
                len(level["source_lead_ids"]),
                bounds["max_source_lead_refs_per_level"],
            )
            self.assertLessEqual(
                len(level["relation_axes"]), bounds["max_relation_axes_per_level"]
            )
            self.assertLessEqual(set(level["capabilities"]), CAPABILITIES)
            self.assertLessEqual(set(level["tasks"]), TASKS)
            self.assertLessEqual(set(level["relation_axes"]), set(policy["axes"]))
            self.assertLessEqual(set(level["pass_gates"]), PASS_GATES)

            labels = level["labels"]
            self.assertEqual(set(labels), LABEL_FIELDS)
            self.assertTrue(labels["organic"])
            for label_class, origins, vocabulary in (
                ("organic", ORGANIC_ORIGINS, ORGANIC_LABELS),
                ("derived_perturbations", DERIVED_ORIGINS, DERIVED_LABELS),
            ):
                entries = labels[label_class]
                self.assertLessEqual(
                    len(entries), bounds["max_label_entries_per_class"]
                )
                for entry in entries:
                    self.assertEqual(set(entry), LABEL_ENTRY_FIELDS)
                    self.assertIn(entry["origin"], origins)
                    assert_unique_nonempty(self, entry["labels"])
                    self.assertLessEqual(set(entry["labels"]), vocabulary)

            grouping = level["grouping"]
            self.assertEqual(set(grouping), GROUPING_FIELDS)
            assert_unique_nonempty(self, grouping["unit_axes"])
            self.assertEqual(
                len(grouping["held_out_axes"]), len(set(grouping["held_out_axes"]))
            )
            assert_unique_nonempty(self, grouping["leakage_rules"])
            self.assertLessEqual(set(grouping["unit_axes"]), GROUP_AXES)
            self.assertLessEqual(
                set(grouping["held_out_axes"]), set(grouping["unit_axes"])
            )
            self.assertLessEqual(set(grouping["leakage_rules"]), LEAKAGE_RULES)

    def test_ids_are_unique_and_difficulty_is_monotonic_contiguous(self):
        levels = load(LADDER)["levels"]
        ids = [level["id"] for level in levels]
        difficulties = [level["difficulty"] for level in levels]

        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(type(value) is int for value in difficulties))
        self.assertEqual(difficulties, list(range(1, len(levels) + 1)))

    def test_surface_and_source_references_match_current_catalogs(self):
        coverage = load(SURFACES)["surfaces"]
        surfaces = {surface["id"]: surface for surface in coverage}
        source_leads = {entry["id"] for entry in load(SOURCE_LEADS)["entries"]}
        referenced_surfaces: list[str] = []

        for level in load(LADDER)["levels"]:
            self.assertLessEqual(set(level["surface_ids"]), set(surfaces))
            self.assertLessEqual(set(level["source_lead_ids"]), source_leads)
            referenced_surfaces.extend(level["surface_ids"])
            for surface_id in level["surface_ids"]:
                source_lead = surfaces[surface_id]["source_lead"]
                if source_lead is not None:
                    self.assertIn(source_lead, level["source_lead_ids"], surface_id)

        self.assertEqual(len(referenced_surfaces), len(set(referenced_surfaces)))
        self.assertEqual(set(referenced_surfaces), set(surfaces))

    def test_relation_labels_remain_qualified_and_provenance_is_explicit(self):
        forbidden_generic = {"identity", "attack", "identity_relation", "attack_label"}
        for level in load(LADDER)["levels"]:
            self.assertTrue(
                all(axis.endswith("_relation") for axis in level["relation_axes"])
            )
            self.assertTrue(forbidden_generic.isdisjoint(level["relation_axes"]))

            organic_labels = {
                label
                for entry in level["labels"]["organic"]
                for label in entry["labels"]
            }
            derived_labels = {
                label
                for entry in level["labels"]["derived_perturbations"]
                for label in entry["labels"]
            }
            self.assertTrue(organic_labels)
            self.assertTrue(organic_labels.isdisjoint(derived_labels))
            self.assertTrue(
                forbidden_generic.isdisjoint(organic_labels | derived_labels)
            )

    def test_catalog_contains_no_local_or_secret_bearing_values(self):
        payload = LADDER.read_text(encoding="utf-8")
        self.assertIsNone(PRIVATE_TOKEN.search(payload))
        self.assertNotRegex(payload, r'"(?:raw_|local_)?(?:device|source|user)_id"')


if __name__ == "__main__":
    unittest.main(verbosity=2)
