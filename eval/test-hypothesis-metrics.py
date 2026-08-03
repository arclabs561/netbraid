#!/usr/bin/env python3
"""Hermetic checks for qualified hypothesis-relation metrics."""

import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    "hypothesis_metrics", HERE / "hypothesis_metrics.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
FRAME_MODULE = sys.modules["hypothesis_frame"]


REFERENCE = {
    "artifact_object_relation": "same_object",
    "claimed_identifier_relation": "same",
    "configuration_relation": "same",
    "content_relation": "equal",
    "cryptographic_principal_relation": "same",
    "event_relation": "same",
    "event_performer_relation": "same",
    "lineage_relation": "same",
    "physical_device_relation": "same",
    "physical_source_relation": "same",
    "software_relation": "same",
    "variant_relation": "same",
}


def opaque(seed):
    return f"{seed:016x}"


def row(frame_id, strata=None):
    return {
        "frame_id": frame_id,
        "references": dict(REFERENCE),
        "predictions": dict(REFERENCE),
        "strata": {} if strata is None else dict(strata),
    }


def manifest(rows):
    return {"schema": MODULE.SCHEMA, "rows": rows}


def qualified_frame(frame_id):
    return {
        "frame_id": frame_id,
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


def prediction_row(frame, strata=None):
    return {
        "frame_id": frame["frame_id"],
        "predictions": {axis: frame[axis] for axis in MODULE.RELATION_AXES},
        "strata": {} if strata is None else dict(strata),
    }


def qualified_manifest(frames, rows):
    return {
        "schema": MODULE.QUALIFIED_SCHEMA,
        "frames": {"schema": FRAME_MODULE.SCHEMA, "frames": frames},
        "rows": rows,
    }


def confusion(axis_report):
    return {
        (item["reference"], item["prediction"]): item["count"]
        for item in axis_report["confusion"]
    }


def support(axis_report):
    return {item["reference"]: item["count"] for item in axis_report["support"]}


def assert_manifest_error(test, value, code):
    with test.assertRaises(MODULE.HypothesisMetricsError) as raised:
        MODULE.parse_manifest(value)
    test.assertEqual(raised.exception.code, code)


def assert_qualified_error(test, value, code):
    with test.assertRaises(MODULE.HypothesisMetricsError) as raised:
        MODULE.parse_qualified_manifest(value)
    test.assertEqual(raised.exception.code, code)


class HypothesisMetricsTests(unittest.TestCase):
    def metric_rows(self):
        rows = [
            row("a", {"domain": opaque(1)}),
            row("b", {"domain": opaque(1)}),
            row("c", {"domain": opaque(2)}),
            row("d", {"domain": opaque(2)}),
            row("e", {"domain": opaque(2)}),
            row("f"),
        ]
        physical = [
            ("same", "same"),
            ("same", "different"),
            ("different", "same"),
            ("different", "different"),
            ("unknown", "same"),
            ("unknown", "abstain"),
        ]
        content = [
            ("equal", "equal"),
            ("different", "equal"),
            ("unknown", "equal"),
            ("equal", "abstain"),
            ("different", "different"),
            ("unknown", "abstain"),
        ]
        for item, (reference, prediction) in zip(rows, physical):
            item["references"]["physical_source_relation"] = reference
            item["predictions"]["physical_source_relation"] = prediction
        for item, (reference, prediction) in zip(rows, content):
            item["references"]["content_relation"] = reference
            item["predictions"]["content_relation"] = prediction
        return rows

    def test_raw_confusion_support_abstention_coverage_and_risk(self):
        report = MODULE.evaluate_manifest(manifest(self.metric_rows()))
        physical = report["axes"]["physical_source_relation"]
        self.assertEqual(
            confusion(physical),
            {
                ("different", "different"): 1,
                ("different", "same"): 1,
                ("same", "different"): 1,
                ("same", "same"): 1,
                ("unknown", "abstain"): 1,
                ("unknown", "same"): 1,
            },
        )
        self.assertEqual(support(physical), {"different": 2, "same": 2, "unknown": 2})
        self.assertEqual(physical["abstention"], {"numerator": 1, "denominator": 6})
        self.assertEqual(physical["coverage"], {"numerator": 5, "denominator": 6})
        self.assertEqual(
            physical["decided_known_references"],
            {
                "count": 4,
                "correct_count": 2,
                "error_count": 2,
                "risk": {"numerator": 2, "denominator": 4},
            },
        )
        self.assertEqual(
            physical["physical_source_counts"],
            {
                "false_match": 1,
                "false_nonmatch": 1,
                "unknown_forced_decision": 1,
                "same_source_true_accept": 1,
            },
        )

        content = report["axes"]["content_relation"]
        self.assertEqual(content["abstention"], {"numerator": 2, "denominator": 6})
        self.assertEqual(content["coverage"], {"numerator": 4, "denominator": 6})
        self.assertEqual(
            content["decided_known_references"],
            {
                "count": 3,
                "correct_count": 2,
                "error_count": 1,
                "risk": {"numerator": 1, "denominator": 3},
            },
        )

        for axis, axis_report in report["axes"].items():
            with self.subTest(axis=axis):
                self.assertEqual(sum(support(axis_report).values()), 6)
                self.assertEqual(
                    axis_report["abstention"]["numerator"]
                    + axis_report["coverage"]["numerator"],
                    6,
                )
                self.assertEqual(axis_report["abstention"]["denominator"], 6)
                self.assertEqual(axis_report["coverage"]["denominator"], 6)

    def test_reference_unknown_and_prediction_abstain_are_distinct(self):
        value = row("unknown-reference")
        value["references"]["event_relation"] = "unknown"
        value["predictions"]["event_relation"] = "abstain"
        report = MODULE.evaluate_manifest(manifest([value]))
        event = report["axes"]["event_relation"]
        self.assertEqual(confusion(event), {("unknown", "abstain"): 1})
        self.assertEqual(event["abstention"], {"numerator": 1, "denominator": 1})
        self.assertEqual(
            event["decided_known_references"]["risk"],
            {"numerator": 0, "denominator": 0},
        )

        invalid_prediction = copy.deepcopy(value)
        invalid_prediction["predictions"]["event_relation"] = "unknown"
        assert_manifest_error(
            self,
            manifest([invalid_prediction]),
            "invalid_event_relation_prediction",
        )
        invalid_reference = copy.deepcopy(value)
        invalid_reference["references"]["event_relation"] = "abstain"
        assert_manifest_error(
            self,
            manifest([invalid_reference]),
            "invalid_event_relation_reference",
        )

    def test_directional_relation_metrics_are_symmetric_under_transpose(self):
        original = row("directional")
        original["references"]["software_relation"] = "left_derived"
        original["predictions"]["software_relation"] = "right_derived"
        transposed = copy.deepcopy(original)
        transposed["frame_id"] = "directional-transposed"
        transposed["references"]["software_relation"] = "right_derived"
        transposed["predictions"]["software_relation"] = "left_derived"

        first = MODULE.evaluate_manifest(manifest([original]))["axes"]
        second = MODULE.evaluate_manifest(manifest([transposed]))["axes"]
        self.assertEqual(
            first["software_relation"]["decided_known_references"],
            second["software_relation"]["decided_known_references"],
        )
        self.assertEqual(
            confusion(first["software_relation"]),
            {("left_derived", "right_derived"): 1},
        )
        self.assertEqual(
            confusion(second["software_relation"]),
            {("right_derived", "left_derived"): 1},
        )
        for axis in set(MODULE.RELATION_AXES) - {"software_relation"}:
            self.assertEqual(first[axis], second[axis])

    def test_bounded_opaque_strata_report_raw_counts(self):
        report = MODULE.evaluate_manifest(manifest(self.metric_rows()))
        self.assertEqual(
            [
                (item["name"], item["value"], item["row_count"])
                for item in report["strata"]
            ],
            [("domain", opaque(1), 2), ("domain", opaque(2), 3)],
        )
        alpha = report["strata"][0]["axes"]["physical_source_relation"]
        self.assertEqual(alpha["row_count"], 2)
        self.assertEqual(alpha["physical_source_counts"]["false_nonmatch"], 1)

        invalid_name = row("invalid-name", {"Domain Name": opaque(1)})
        assert_manifest_error(self, manifest([invalid_name]), "invalid_stratum_name")
        invalid_value = row("invalid-value", {"domain": "alpha value"})
        assert_manifest_error(self, manifest([invalid_value]), "invalid_stratum_value")

        too_many_per_row = row(
            "too-many-per-row",
            {
                f"dimension_{index}": opaque(index)
                for index in range(MODULE.MAX_STRATA_PER_ROW + 1)
            },
        )
        assert_manifest_error(
            self,
            manifest([too_many_per_row]),
            "invalid_strata_schema",
        )

        too_many_dimensions = [
            row(f"dimension-{index}", {f"dimension_{index}": opaque(index)})
            for index in range(MODULE.MAX_STRATUM_DIMENSIONS + 1)
        ]
        assert_manifest_error(
            self,
            manifest(too_many_dimensions),
            "too_many_stratum_dimensions",
        )
        too_many_values = [
            row(f"value-{index}", {"domain": opaque(index)})
            for index in range(MODULE.MAX_STRATUM_VALUES_PER_DIMENSION + 1)
        ]
        assert_manifest_error(
            self,
            manifest(too_many_values),
            "too_many_stratum_values",
        )
        too_many_cells = [
            row(
                f"cell-{index}",
                {
                    f"dimension_{index % 5}": opaque(index),
                },
            )
            for index in range(MODULE.MAX_STRATUM_CELLS + 1)
        ]
        assert_manifest_error(
            self,
            manifest(too_many_cells),
            "too_many_stratum_cells",
        )

    def test_malformed_and_duplicate_rows_fail_closed(self):
        cases = []
        missing_row_field = row("missing-row-field")
        del missing_row_field["strata"]
        cases.append((manifest([missing_row_field]), "invalid_row_schema"))
        extra_row_field = row("extra-row-field")
        extra_row_field["raw"] = "forbidden"
        cases.append((manifest([extra_row_field]), "invalid_row_schema"))
        missing_axis = row("missing-axis")
        del missing_axis["references"]["content_relation"]
        cases.append((manifest([missing_axis]), "invalid_references_schema"))
        extra_axis = row("extra-axis")
        extra_axis["predictions"]["intent"] = "malicious"
        cases.append((manifest([extra_axis]), "invalid_predictions_schema"))
        cases.extend(
            [
                ({"schema": MODULE.SCHEMA, "rows": []}, "invalid_manifest_row_count"),
                (
                    {"schema": "other", "rows": [row("a")]},
                    "unsupported_manifest_schema",
                ),
                (
                    {"schema": MODULE.SCHEMA, "rows": ["not-a-row"]},
                    "invalid_row_schema",
                ),
                (manifest([row("UPPERCASE")]), "invalid_frame_id"),
            ]
        )
        for value, code in cases:
            with self.subTest(code=code):
                assert_manifest_error(self, value, code)

        duplicate = row("duplicate")
        assert_manifest_error(
            self,
            manifest([duplicate, copy.deepcopy(duplicate)]),
            "duplicate_frame_id",
        )
        with mock.patch.object(MODULE, "MAX_FRAMES", 1):
            assert_manifest_error(
                self,
                manifest([row("first"), row("second")]),
                "invalid_manifest_row_count",
            )

    def test_duplicate_json_keys_and_oversized_input_fail_closed(self):
        with self.assertRaises(MODULE.HypothesisMetricsError) as raised:
            MODULE.parse_json_bytes(b'{"schema":"first","schema":"second"}')
        self.assertEqual(raised.exception.code, "duplicate_json_key")
        with self.assertRaises(MODULE.HypothesisMetricsError) as raised:
            MODULE.parse_json_bytes(b"x" * (MODULE.MAX_INPUT_BYTES + 1))
        self.assertEqual(raised.exception.code, "manifest_too_large")

    def test_cli_is_canonical_bounded_and_order_independent(self):
        rows = self.metric_rows()
        first_input = manifest(rows)
        second_input = manifest(list(reversed(rows)))

        outputs = []
        for value in (first_input, second_input):
            process = subprocess.run(
                [sys.executable, str(HERE / "hypothesis_metrics.py")],
                input=json.dumps(value),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            outputs.append(process.stdout)
        self.assertEqual(outputs[0], outputs[1])
        parsed = json.loads(outputs[0])
        self.assertEqual(parsed["schema"], MODULE.REPORT_SCHEMA)
        self.assertEqual(list(parsed["axes"]), sorted(MODULE.RELATION_AXES))
        self.assertNotIn("frames", parsed)
        self.assertNotIn("frame_id", outputs[0])
        self.assertNotIn("intent", outputs[0])
        self.assertNotIn("tamper", outputs[0])
        self.assertNotIn("anomaly", outputs[0])
        self.assertNotIn("confidence", outputs[0])
        self.assertNotIn("interval", outputs[0])
        content = parsed["axes"]["content_relation"]
        confusion_order = [
            (item["reference"], item["prediction"]) for item in content["confusion"]
        ]
        self.assertEqual(confusion_order, sorted(confusion_order))
        support_order = [item["reference"] for item in content["support"]]
        self.assertEqual(support_order, sorted(support_order))
        self.assertTrue(all(item["count"] > 0 for item in content["confusion"]))

    def test_qualified_join_preserves_identity_variant_intent_and_tamper_axes(self):
        compromised = qualified_frame("compromised-enrolled-source")
        compromised.update(
            {
                "content_relation": "equal",
                "physical_device_relation": "same",
                "physical_source_relation": "same",
                "variant_relation": "same",
            }
        )
        compromised["scenario"] = {
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

        sibling = qualified_frame("same-variant-different-source")
        changed = qualified_frame("changed-bytes-unknown-policy")
        changed["integrity"] = "verified_changed"
        changed["scenario"] = {
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

        rows = [prediction_row(item) for item in (compromised, sibling, changed)]
        rows[1]["predictions"]["physical_source_relation"] = "same"
        rows[2]["predictions"]["physical_source_relation"] = "abstain"
        value = qualified_manifest([compromised, sibling, changed], rows)
        report = MODULE.evaluate_manifest(value)

        self.assertEqual(report["schema"], MODULE.QUALIFIED_REPORT_SCHEMA)
        self.assertEqual(report["input_schema"], MODULE.QUALIFIED_SCHEMA)
        self.assertEqual(report["row_count"], 3)
        self.assertEqual(len(report["qualified_reference_cells"]), 3)
        by_intent = {
            cell["qualifiers"]["scenario"]["intent"]: cell
            for cell in report["qualified_reference_cells"]
        }
        malicious = by_intent["malicious"]
        self.assertEqual(malicious["qualifiers"]["physical_device_relation"], "same")
        self.assertEqual(malicious["qualifiers"]["physical_source_relation"], "same")
        self.assertEqual(malicious["qualifiers"]["variant_relation"], "same")
        self.assertEqual(
            malicious["qualifiers"]["scenario"]["tamper_hypothesis"]["disposition"],
            "supported",
        )
        self.assertEqual(
            confusion(malicious["axes"]["physical_source_relation"]),
            {("same", "same"): 1},
        )
        benign = by_intent["benign"]
        self.assertEqual(
            benign["axes"]["physical_source_relation"]["physical_source_counts"][
                "false_match"
            ],
            1,
        )
        unknown = by_intent["unknown"]
        self.assertEqual(unknown["qualifiers"]["integrity"], "verified_changed")
        self.assertEqual(
            unknown["qualifiers"]["scenario"]["tamper_hypothesis"]["disposition"],
            "underdetermined",
        )
        encoded = json.dumps(report, sort_keys=True)
        self.assertNotIn("frame_id", encoded)
        self.assertNotIn("compromised-enrolled-source", encoded)

    def test_qualified_join_requires_bijection_and_relation_only_predictions(self):
        first = qualified_frame("first")
        second = qualified_frame("second")
        first_row = prediction_row(first)

        assert_qualified_error(
            self,
            qualified_manifest([first, second], [first_row]),
            "frame_prediction_id_mismatch",
        )
        extra = prediction_row(second)
        extra["frame_id"] = "unexpected"
        assert_qualified_error(
            self,
            qualified_manifest([first], [first_row, extra]),
            "frame_prediction_id_mismatch",
        )
        forbidden = prediction_row(first)
        forbidden["intent"] = "malicious"
        assert_qualified_error(
            self,
            qualified_manifest([first], [forbidden]),
            "invalid_prediction_row_schema",
        )

        malformed_frame = copy.deepcopy(first)
        malformed_frame["identity"] = "same"
        assert_qualified_error(
            self,
            qualified_manifest([malformed_frame], [first_row]),
            "frame_invalid_frame_schema",
        )

    def test_partial_relation_predictions_compose_without_collapsing_axes(self):
        parts = [
            {"event_relation": "same", "physical_source_relation": "abstain"},
            {"physical_source_relation": "different"},
            {"event_relation": "same", "variant_relation": "left_derived"},
        ]
        row = MODULE.compose_prediction_row(
            "composed-frame",
            parts,
            strata={"campaign": opaque(7)},
        )
        self.assertEqual(row["predictions"]["event_relation"], "same")
        self.assertEqual(row["predictions"]["physical_source_relation"], "different")
        self.assertEqual(row["predictions"]["variant_relation"], "left_derived")
        self.assertEqual(row["predictions"]["content_relation"], "abstain")
        self.assertEqual(row["strata"], {"campaign": opaque(7)})
        self.assertEqual(
            row,
            MODULE.compose_prediction_row(
                "composed-frame",
                list(reversed(parts)),
                strata={"campaign": opaque(7)},
            ),
        )
        self.assertEqual(MODULE.parse_prediction_row(row).frame_id, "composed-frame")

    def test_partial_relation_prediction_conflicts_fail_closed(self):
        cases = (
            (
                [{"event_relation": "same"}, {"event_relation": "different"}],
                "conflicting_event_relation_predictions",
            ),
            ([{"event_relation": "unknown"}], "invalid_event_relation_prediction"),
            ([{"identity": "same"}], "invalid_partial_prediction_axis"),
            ([{}], "invalid_partial_prediction"),
            ([], "invalid_partial_predictions"),
        )
        for parts, code in cases:
            with self.subTest(code=code):
                with self.assertRaises(MODULE.HypothesisMetricsError) as raised:
                    MODULE.compose_prediction_row("composed-frame", parts)
                self.assertEqual(raised.exception.code, code)

        with mock.patch.object(MODULE, "MAX_PARTIAL_PREDICTIONS", 1):
            with self.assertRaises(MODULE.HypothesisMetricsError) as raised:
                MODULE.compose_prediction_row(
                    "composed-frame",
                    [{"event_relation": "same"}, {"event_relation": "same"}],
                )
        self.assertEqual(raised.exception.code, "invalid_partial_predictions")

    def test_qualified_cli_is_order_independent_and_legacy_output_is_unchanged(self):
        first = qualified_frame("first")
        second = qualified_frame("second")
        second["physical_source_relation"] = "same"
        second["physical_device_relation"] = "same"
        rows = [prediction_row(first), prediction_row(second)]
        values = (
            qualified_manifest([first, second], rows),
            qualified_manifest([second, first], list(reversed(rows))),
        )
        outputs = []
        for value in values:
            process = subprocess.run(
                [sys.executable, str(HERE / "hypothesis_metrics.py")],
                input=json.dumps(value),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            outputs.append(process.stdout)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual(
            json.loads(outputs[0])["schema"], MODULE.QUALIFIED_REPORT_SCHEMA
        )

        legacy = manifest(self.metric_rows())
        self.assertEqual(
            MODULE.evaluate_manifest(legacy),
            MODULE.evaluate(MODULE.parse_manifest(legacy)),
        )

    def test_qualified_reference_cell_count_is_bounded(self):
        first = qualified_frame("first")
        second = qualified_frame("second")
        second["integrity"] = "verified_changed"
        rows = [prediction_row(first), prediction_row(second)]
        parsed_rows, frames = MODULE.parse_qualified_manifest(
            qualified_manifest([first, second], rows)
        )
        with mock.patch.object(MODULE, "MAX_QUALIFIED_REFERENCE_CELLS", 1):
            with self.assertRaises(MODULE.HypothesisMetricsError) as raised:
                MODULE.evaluate_qualified(parsed_rows, frames)
        self.assertEqual(raised.exception.code, "too_many_qualified_reference_cells")

        with self.assertRaises(MODULE.HypothesisMetricsError) as raised:
            MODULE.evaluate_qualified(parsed_rows, [frames[0], frames[0]])
        self.assertEqual(raised.exception.code, "duplicate_frame_id")


if __name__ == "__main__":
    unittest.main()
