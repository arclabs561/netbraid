#!/usr/bin/env python3
"""Hermetic checks for calibrated event-relation evaluation artifacts."""

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "calibrated_event_relation", HERE / "calibrated_event_relation.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def digest(seed):
    return f"{seed:064x}"


def profile_document():
    return {
        "schema": MODULE.PROFILE_SCHEMA,
        "profile_id": "event-relation-profile-v0",
        "reducer_revision": "reducer-v3",
        "model_revision": "model-4f8c2a1",
        "feature_policy_digest": digest(1),
        "input_matrix_digest": digest(2),
        "model_digest": digest(3),
        "fit_partition_digest": digest(4),
        "calibration_partition_digest": digest(5),
        "quantile_policy": dict(MODULE.FIXED_QUANTILE_POLICY),
        "forward_same_threshold": (0.25).hex(),
        "forward_different_threshold": (0.75).hex(),
        "reverse_same_threshold": (0.2).hex(),
        "reverse_different_threshold": (0.8).hex(),
    }


def prediction_document(profile, forward, reverse, decision, reason):
    return {
        "schema": MODULE.PREDICTION_SCHEMA,
        "frame_id": "frame-0001",
        "profile_digest": profile.content_digest(),
        "forward_score": forward.hex(),
        "reverse_score": reverse.hex(),
        "decision": decision,
        "abstain_reason": reason,
    }


def heldout_receipt_document(profile, status="passed"):
    return {
        "schema": MODULE.HELDOUT_RECEIPT_SCHEMA,
        "receipt_id": "heldout-event-relation-v0",
        "profile_digest": profile.content_digest(),
        "evaluation_protocol_digest": digest(6),
        "heldout_partition_digest": digest(7),
        "evaluation_report_digest": digest(8),
        "gate": {"policy_digest": digest(9), "status": status},
    }


def assert_error(test, function, code):
    with test.assertRaises(MODULE.EventRelationSchemaError) as raised:
        function()
    test.assertEqual(raised.exception.code, code)


class CalibratedEventRelationSchemaTests(unittest.TestCase):
    def setUp(self):
        self.profile = MODULE.parse_profile(profile_document())

    def test_profile_and_prediction_roundtrip_canonical_bytes(self):
        profile_bytes = self.profile.canonical_json_bytes()
        parsed_profile = MODULE.load_profile_bytes(profile_bytes)
        self.assertEqual(parsed_profile, self.profile)
        self.assertEqual(parsed_profile.canonical_json_bytes(), profile_bytes)

        value = prediction_document(self.profile, 0.25, 0.2, "same", None)
        prediction = MODULE.parse_prediction(value, self.profile)
        prediction_bytes = prediction.canonical_json_bytes()
        self.assertEqual(
            MODULE.load_prediction_bytes(prediction_bytes, self.profile), prediction
        )
        self.assertEqual(
            json.loads(prediction_bytes),
            value,
        )
        self.assertRegex(self.profile.content_digest(), r"\A[a-f0-9]{64}\Z")
        self.assertRegex(prediction.content_digest(), r"\A[a-f0-9]{64}\Z")

    def test_heldout_receipt_roundtrip_and_profile_binding(self):
        value = heldout_receipt_document(self.profile)
        receipt = MODULE.parse_heldout_receipt(value, self.profile)
        encoded = receipt.canonical_json_bytes()

        self.assertEqual(json.loads(encoded), value)
        self.assertEqual(
            MODULE.load_heldout_receipt_bytes(encoded, self.profile), receipt
        )
        self.assertRegex(receipt.content_digest(), r"\A[a-f0-9]{64}\Z")

        failed = MODULE.parse_heldout_receipt(
            heldout_receipt_document(self.profile, status="failed"), self.profile
        )
        self.assertEqual(failed.gate_status, "failed")

        wrong_profile = MODULE.parse_profile(
            dict(profile_document(), profile_id="different-profile-v0")
        )
        assert_error(
            self,
            lambda: MODULE.parse_heldout_receipt(value, wrong_profile),
            "profile_digest_mismatch",
        )

    def test_heldout_receipt_rejects_unknown_fields_and_invalid_gate(self):
        value = heldout_receipt_document(self.profile)
        value["identity"] = "forbidden"
        assert_error(
            self,
            lambda: MODULE.parse_heldout_receipt(value, self.profile),
            "invalid_heldout_receipt_schema",
        )

        value = heldout_receipt_document(self.profile)
        value["gate"]["metric"] = 1.0
        assert_error(
            self,
            lambda: MODULE.parse_heldout_receipt(value, self.profile),
            "invalid_heldout_gate_schema",
        )

        value = heldout_receipt_document(self.profile)
        value["gate"]["status"] = "unknown"
        assert_error(
            self,
            lambda: MODULE.parse_heldout_receipt(value, self.profile),
            "invalid_gate_status",
        )

    def test_shared_rust_fixture_has_cross_language_canonical_digests(self):
        fixture = json.loads(
            (
                HERE
                / "../rust/tests/fixtures/infer/v0/calibrated-event-relation-admission.json"
            ).read_text(encoding="utf-8")
        )
        profile = MODULE.parse_profile(fixture["profile"])
        prediction = MODULE.parse_prediction(fixture["prediction"], profile)
        receipt = MODULE.parse_heldout_receipt(
            fixture["heldout_evaluation_receipt"], profile
        )

        self.assertEqual(
            MODULE.observation_pair_id(
                fixture["observations"]["left"], fixture["observations"]["right"]
            ),
            fixture["prediction"]["frame_id"],
        )

        self.assertEqual(
            profile.content_digest(), fixture["expected"]["profile_digest"]
        )
        self.assertEqual(
            prediction.content_digest(), fixture["expected"]["prediction_digest"]
        )
        self.assertEqual(
            receipt.content_digest(),
            fixture["expected"]["heldout_evaluation_receipt_digest"],
        )

    def test_observation_pair_id_is_canonical_and_fail_closed(self):
        fixture = json.loads(
            (
                HERE
                / "../rust/tests/fixtures/infer/v0/calibrated-event-relation-admission.json"
            ).read_text(encoding="utf-8")
        )
        left = fixture["observations"]["left"]
        right = fixture["observations"]["right"]

        self.assertEqual(
            MODULE.observation_pair_id(left, right),
            MODULE.observation_pair_id(right, left),
        )
        changed = dict(right, source_id="another-observation")
        self.assertNotEqual(
            MODULE.observation_pair_id(left, right),
            MODULE.observation_pair_id(left, changed),
        )
        assert_error(
            self,
            lambda: MODULE.observation_pair_id(left, dict(right, identity="forbidden")),
            "invalid_observation_ref_schema",
        )

    def test_exact_shape_rejects_unknown_and_sensitive_fields(self):
        forbidden = (
            "identity",
            "device",
            "source",
            "performer",
            "principal",
            "owner",
        )
        for field in ("unknown", *forbidden):
            with self.subTest(kind="profile", field=field):
                value = profile_document()
                value[field] = "forbidden"
                assert_error(
                    self,
                    lambda value=value: MODULE.parse_profile(value),
                    "invalid_profile_schema",
                )
            with self.subTest(kind="prediction", field=field):
                value = prediction_document(self.profile, 0.25, 0.2, "same", None)
                value[field] = "forbidden"
                assert_error(
                    self,
                    lambda value=value: MODULE.parse_prediction(value, self.profile),
                    "invalid_prediction_schema",
                )

        nested = profile_document()
        nested["quantile_policy"]["unknown"] = "forbidden"
        assert_error(
            self,
            lambda: MODULE.parse_profile(nested),
            "invalid_quantile_policy_schema",
        )

    def test_digest_fields_require_canonical_sha256_and_profile_match(self):
        fields = (
            "feature_policy_digest",
            "input_matrix_digest",
            "model_digest",
            "fit_partition_digest",
            "calibration_partition_digest",
        )
        bad_digests = ("a" * 63, "A" * 64, "g" * 64, 7, None)
        for field in fields:
            for bad_digest in bad_digests:
                with self.subTest(field=field, bad_digest=bad_digest):
                    value = profile_document()
                    value[field] = bad_digest
                    assert_error(
                        self,
                        lambda value=value: MODULE.parse_profile(value),
                        f"invalid_{field}",
                    )

        value = prediction_document(self.profile, 0.25, 0.2, "same", None)
        value["profile_digest"] = digest(99)
        assert_error(
            self,
            lambda: MODULE.parse_prediction(value, self.profile),
            "profile_digest_mismatch",
        )

        value["profile_digest"] = "A" * 64
        assert_error(
            self,
            lambda: MODULE.parse_prediction(value, self.profile),
            "invalid_profile_digest",
        )

    def test_thresholds_and_scores_require_canonical_finite_float_hex(self):
        bad_floats = (
            0.25,
            "0.25",
            "nan",
            "inf",
            "-inf",
            "0x1.0p0",
            "0x1.00000000000000p+0",
            "0X1.0000000000000P+0",
            " 0x1.0000000000000p+0",
        )
        threshold_fields = (
            "forward_same_threshold",
            "forward_different_threshold",
            "reverse_same_threshold",
            "reverse_different_threshold",
        )
        for field in threshold_fields:
            for bad_float in bad_floats:
                with self.subTest(field=field, bad_float=bad_float):
                    value = profile_document()
                    value[field] = bad_float
                    assert_error(
                        self,
                        lambda value=value: MODULE.parse_profile(value),
                        f"invalid_{field}",
                    )

        for field in ("forward_score", "reverse_score"):
            for bad_float in bad_floats:
                with self.subTest(field=field, bad_float=bad_float):
                    value = prediction_document(self.profile, 0.25, 0.2, "same", None)
                    value[field] = bad_float
                    assert_error(
                        self,
                        lambda value=value: MODULE.parse_prediction(
                            value, self.profile
                        ),
                        f"invalid_{field}",
                    )

    def test_quantile_policy_is_exact_and_float_hex_canonical(self):
        cases = []
        changed = profile_document()
        changed["quantile_policy"]["same_quantile"] = (0.95).hex()
        cases.append((changed, "unsupported_quantile_policy"))

        noncanonical = profile_document()
        noncanonical["quantile_policy"]["different_quantile"] = "0x1.0p-4"
        cases.append((noncanonical, "invalid_quantile_policy_different_quantile"))

        wrong_method = profile_document()
        wrong_method["quantile_policy"]["interpolation"] = "nearest"
        cases.append((wrong_method, "unsupported_quantile_policy"))

        for value, code in cases:
            with self.subTest(code=code):
                assert_error(
                    self,
                    lambda value=value: MODULE.parse_profile(value),
                    code,
                )

    def test_lower_distance_thresholds_require_strict_gap_per_direction(self):
        for same_field, different_field, code in (
            (
                "forward_same_threshold",
                "forward_different_threshold",
                "invalid_forward_threshold_order",
            ),
            (
                "reverse_same_threshold",
                "reverse_different_threshold",
                "invalid_reverse_threshold_order",
            ),
        ):
            for same, different in ((0.5, 0.5), (0.75, 0.25)):
                with self.subTest(direction=code, same=same, different=different):
                    value = profile_document()
                    value[same_field] = same.hex()
                    value[different_field] = different.hex()
                    assert_error(
                        self,
                        lambda value=value: MODULE.parse_profile(value),
                        code,
                    )

        for field in (
            "forward_same_threshold",
            "forward_different_threshold",
            "reverse_same_threshold",
            "reverse_different_threshold",
        ):
            for invalid in (-0.0, -0.25):
                with self.subTest(field=field, invalid=invalid):
                    value = profile_document()
                    value[field] = invalid.hex()
                    assert_error(
                        self,
                        lambda value=value: MODULE.parse_profile(value),
                        f"invalid_{field}",
                    )

    def test_distance_scores_reject_negative_values_and_negative_zero(self):
        for field in ("forward_score", "reverse_score"):
            for invalid in (-0.0, -1.0):
                with self.subTest(field=field, invalid=invalid):
                    value = prediction_document(self.profile, 0.25, 0.2, "same", None)
                    value[field] = invalid.hex()
                    assert_error(
                        self,
                        lambda value=value: MODULE.parse_prediction(
                            value, self.profile
                        ),
                        f"invalid_{field}",
                    )

    def test_all_direction_state_pairs_have_exact_decisions(self):
        forward_scores = {
            "same": 0.25,
            "gap": 0.5,
            "different": 0.75,
        }
        reverse_scores = {
            "same": 0.2,
            "gap": 0.5,
            "different": 0.8,
        }
        expected = {
            ("same", "same"): ("same", None),
            ("same", "gap"): ("abstain", "score_gap"),
            ("same", "different"): (
                "abstain",
                "direction_disagreement",
            ),
            ("gap", "same"): ("abstain", "score_gap"),
            ("gap", "gap"): ("abstain", "score_gap"),
            ("gap", "different"): ("abstain", "score_gap"),
            ("different", "same"): (
                "abstain",
                "direction_disagreement",
            ),
            ("different", "gap"): ("abstain", "score_gap"),
            ("different", "different"): ("different", None),
        }
        for states, (decision, reason) in expected.items():
            forward_state, reverse_state = states
            with self.subTest(forward=forward_state, reverse=reverse_state):
                value = prediction_document(
                    self.profile,
                    forward_scores[forward_state],
                    reverse_scores[reverse_state],
                    decision,
                    reason,
                )
                prediction = MODULE.parse_prediction(value, self.profile)
                self.assertEqual(
                    (prediction.decision, prediction.abstain_reason),
                    (decision, reason),
                )

    def test_forged_decisions_and_reasons_are_rejected(self):
        valid = (
            prediction_document(self.profile, 0.25, 0.2, "same", None),
            prediction_document(self.profile, 0.75, 0.8, "different", None),
            prediction_document(
                self.profile, 0.25, 0.8, "abstain", "direction_disagreement"
            ),
            prediction_document(self.profile, 0.5, 0.8, "abstain", "score_gap"),
        )
        forged_pairs = (
            ("same", None),
            ("different", None),
            ("abstain", "score_gap"),
            ("abstain", "direction_disagreement"),
            ("abstain", None),
            ("same", "score_gap"),
            ("different", "direction_disagreement"),
        )
        for source in valid:
            correct = (source["decision"], source["abstain_reason"])
            for forged in forged_pairs:
                if forged == correct:
                    continue
                with self.subTest(correct=correct, forged=forged):
                    value = copy.deepcopy(source)
                    value["decision"], value["abstain_reason"] = forged
                    assert_error(
                        self,
                        lambda value=value: MODULE.parse_prediction(
                            value, self.profile
                        ),
                        "incoherent_decision",
                    )

        invalid_decision = prediction_document(self.profile, 0.25, 0.2, "unknown", None)
        assert_error(
            self,
            lambda: MODULE.parse_prediction(invalid_decision, self.profile),
            "invalid_decision",
        )
        invalid_reason = prediction_document(
            self.profile, 0.5, 0.8, "abstain", "uncertain"
        )
        assert_error(
            self,
            lambda: MODULE.parse_prediction(invalid_reason, self.profile),
            "invalid_abstain_reason",
        )

    def test_json_boundary_is_bounded_and_rejects_duplicates_and_constants(self):
        for payload, code in (
            (b"{", "invalid_json"),
            (b'{"schema":"x","schema":"x"}', "duplicate_json_key"),
            (b'{"schema":NaN}', "invalid_json_constant"),
            (b"\xff", "invalid_json"),
        ):
            with self.subTest(code=code):
                assert_error(
                    self,
                    lambda payload=payload: MODULE.load_profile_bytes(payload),
                    code,
                )

        oversized = b" " * (MODULE.MAX_DOCUMENT_BYTES + 1)
        assert_error(
            self,
            lambda: MODULE.load_profile_bytes(oversized),
            "document_too_large",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
