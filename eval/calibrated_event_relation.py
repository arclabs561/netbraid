#!/usr/bin/env python3
"""Strict evaluation-only calibrated event-relation artifacts.

These schemas retain only opaque evaluation identifiers, reproducibility
digests, calibrated lower-distance thresholds, and relation decisions. They
are not production identity classifiers and deliberately carry no actor,
device, source, performer, principal, or ownership fields.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import InitVar, dataclass
from typing import Any

PROFILE_SCHEMA = "netbraid.calibrated_event_relation_profile.v0"
PREDICTION_SCHEMA = "netbraid.event_relation_prediction.v0"
HELDOUT_RECEIPT_SCHEMA = "netbraid.heldout_event_relation_evaluation_receipt.v0"

MAX_DOCUMENT_BYTES = 16 * 1024
MAX_IDENTIFIER_BYTES = 96
MAX_REVISION_BYTES = 128
MAX_SOURCE_SCHEMA_BYTES = 128
MAX_SOURCE_ID_BYTES = 512

IDENTIFIER_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")
REVISION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}\Z")
DIGEST_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
SOURCE_SCHEMA_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")

PROFILE_FIELDS = (
    "schema",
    "profile_id",
    "reducer_revision",
    "model_revision",
    "feature_policy_digest",
    "input_matrix_digest",
    "model_digest",
    "fit_partition_digest",
    "calibration_partition_digest",
    "quantile_policy",
    "forward_same_threshold",
    "forward_different_threshold",
    "reverse_same_threshold",
    "reverse_different_threshold",
)
PREDICTION_FIELDS = (
    "schema",
    "frame_id",
    "profile_digest",
    "forward_score",
    "reverse_score",
    "decision",
    "abstain_reason",
)
HELDOUT_RECEIPT_FIELDS = (
    "schema",
    "receipt_id",
    "profile_digest",
    "evaluation_protocol_digest",
    "heldout_partition_digest",
    "evaluation_report_digest",
    "gate",
)
HELDOUT_GATE_FIELDS = ("policy_digest", "status")
OBSERVATION_REF_FIELDS = ("source_schema", "source_id", "content_sha256")
QUANTILE_POLICY_FIELDS = (
    "same_quantile",
    "different_quantile",
    "interpolation",
)

# Both directions use these calibration-partition quantiles. The same-pair
# upper quantile and different-pair lower quantile leave a deliberate gap.
FIXED_QUANTILE_POLICY = {
    "same_quantile": (0.9).hex(),
    "different_quantile": (0.1).hex(),
    "interpolation": "linear",
}

DECISIONS = frozenset(("same", "different", "abstain"))
ABSTAIN_REASONS = frozenset(("score_gap", "direction_disagreement"))
HELDOUT_GATE_STATUSES = frozenset(("passed", "failed"))

_PROFILE_DIGEST_DOMAIN = b"netbraid.calibrated-event-relation-profile.v0\x00"
_PREDICTION_DIGEST_DOMAIN = b"netbraid.event-relation-prediction.v0\x00"
_HELDOUT_RECEIPT_DIGEST_DOMAIN = (
    b"netbraid.heldout-event-relation-evaluation-receipt.v0\x00"
)
_OBSERVATION_PAIR_DIGEST_DOMAIN = (
    b"netbraid.calibrated-event-relation-observation-pair.v0\x00"
)


class EventRelationSchemaError(ValueError):
    """Stable fail-closed reason for an invalid evaluation artifact."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _expect_fields(value: Mapping[str, Any], fields: Sequence[str], code: str) -> None:
    if set(value) != set(fields):
        raise EventRelationSchemaError(code)


def _identifier(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or IDENTIFIER_PATTERN.fullmatch(value) is None
        or len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES
    ):
        raise EventRelationSchemaError(code)
    return value


def _revision(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or REVISION_PATTERN.fullmatch(value) is None
        or len(value.encode("utf-8")) > MAX_REVISION_BYTES
    ):
        raise EventRelationSchemaError(code)
    return value


def _digest(value: Any, code: str) -> str:
    if not isinstance(value, str) or DIGEST_PATTERN.fullmatch(value) is None:
        raise EventRelationSchemaError(code)
    return value


def _observation_ref(value: Any) -> tuple[str, str, str]:
    if not isinstance(value, Mapping):
        raise EventRelationSchemaError("invalid_observation_ref_schema")
    _expect_fields(value, OBSERVATION_REF_FIELDS, "invalid_observation_ref_schema")
    source_schema = value["source_schema"]
    if (
        not isinstance(source_schema, str)
        or SOURCE_SCHEMA_PATTERN.fullmatch(source_schema) is None
        or len(source_schema.encode("utf-8")) > MAX_SOURCE_SCHEMA_BYTES
    ):
        raise EventRelationSchemaError("invalid_observation_source_schema")
    source_id = value["source_id"]
    if (
        not isinstance(source_id, str)
        or not source_id
        or len(source_id.encode("utf-8")) > MAX_SOURCE_ID_BYTES
        or any(
            ord(character) < 32 or 127 <= ord(character) <= 159
            for character in source_id
        )
    ):
        raise EventRelationSchemaError("invalid_observation_source_id")
    return (
        source_schema,
        source_id,
        _digest(value["content_sha256"], "invalid_observation_content_digest"),
    )


def observation_pair_id(left: Any, right: Any) -> str:
    """Derive the prediction frame identifier for a canonical observation pair."""

    digest = hashlib.sha256(_OBSERVATION_PAIR_DIGEST_DOMAIN)
    for reference in sorted((_observation_ref(left), _observation_ref(right))):
        for value in reference:
            digest.update(value.encode("utf-8"))
            digest.update(b"\x00")
    return f"event-pair-{digest.hexdigest()}"


def _canonical_finite_float(value: Any, code: str) -> float:
    if not isinstance(value, str):
        raise EventRelationSchemaError(code)
    try:
        parsed = float.fromhex(value)
    except ValueError as error:
        raise EventRelationSchemaError(code) from error
    if not math.isfinite(parsed) or parsed.hex() != value:
        raise EventRelationSchemaError(code)
    return parsed


def _canonical_distance(value: Any, code: str) -> float:
    parsed = _canonical_finite_float(value, code)
    if parsed < 0.0 or math.copysign(1.0, parsed) < 0.0:
        raise EventRelationSchemaError(code)
    return parsed


def _validate_quantile_policy(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise EventRelationSchemaError("invalid_quantile_policy_schema")
    _expect_fields(value, QUANTILE_POLICY_FIELDS, "invalid_quantile_policy_schema")
    for field in ("same_quantile", "different_quantile"):
        _canonical_finite_float(value[field], f"invalid_quantile_policy_{field}")
    if dict(value) != FIXED_QUANTILE_POLICY:
        raise EventRelationSchemaError("unsupported_quantile_policy")


@dataclass(frozen=True)
class CalibratedEventRelationProfileV0:
    """Reproducibility-bound lower-distance calibration profile."""

    profile_id: str
    reducer_revision: str
    model_revision: str
    feature_policy_digest: str
    input_matrix_digest: str
    model_digest: str
    fit_partition_digest: str
    calibration_partition_digest: str
    forward_same_threshold: str
    forward_different_threshold: str
    reverse_same_threshold: str
    reverse_different_threshold: str

    def __post_init__(self) -> None:
        _identifier(self.profile_id, "invalid_profile_id")
        _revision(self.reducer_revision, "invalid_reducer_revision")
        _revision(self.model_revision, "invalid_model_revision")
        for field in (
            "feature_policy_digest",
            "input_matrix_digest",
            "model_digest",
            "fit_partition_digest",
            "calibration_partition_digest",
        ):
            _digest(getattr(self, field), f"invalid_{field}")

        forward_same = _canonical_distance(
            self.forward_same_threshold, "invalid_forward_same_threshold"
        )
        forward_different = _canonical_distance(
            self.forward_different_threshold,
            "invalid_forward_different_threshold",
        )
        reverse_same = _canonical_distance(
            self.reverse_same_threshold, "invalid_reverse_same_threshold"
        )
        reverse_different = _canonical_distance(
            self.reverse_different_threshold,
            "invalid_reverse_different_threshold",
        )
        if forward_same >= forward_different:
            raise EventRelationSchemaError("invalid_forward_threshold_order")
        if reverse_same >= reverse_different:
            raise EventRelationSchemaError("invalid_reverse_threshold_order")

    @classmethod
    def from_document(cls, value: Any) -> CalibratedEventRelationProfileV0:
        return parse_profile(value)

    @classmethod
    def from_json_bytes(cls, data: bytes) -> CalibratedEventRelationProfileV0:
        return load_profile_bytes(data)

    def document(self) -> dict[str, Any]:
        return {
            "schema": PROFILE_SCHEMA,
            "profile_id": self.profile_id,
            "reducer_revision": self.reducer_revision,
            "model_revision": self.model_revision,
            "feature_policy_digest": self.feature_policy_digest,
            "input_matrix_digest": self.input_matrix_digest,
            "model_digest": self.model_digest,
            "fit_partition_digest": self.fit_partition_digest,
            "calibration_partition_digest": self.calibration_partition_digest,
            "quantile_policy": dict(FIXED_QUANTILE_POLICY),
            "forward_same_threshold": self.forward_same_threshold,
            "forward_different_threshold": self.forward_different_threshold,
            "reverse_same_threshold": self.reverse_same_threshold,
            "reverse_different_threshold": self.reverse_different_threshold,
        }

    def canonical_json_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    def content_digest(self) -> str:
        return content_digest(self)


def parse_profile(value: Any) -> CalibratedEventRelationProfileV0:
    """Parse one exact-shape calibrated profile document."""

    if not isinstance(value, Mapping):
        raise EventRelationSchemaError("invalid_profile_schema")
    _expect_fields(value, PROFILE_FIELDS, "invalid_profile_schema")
    if value["schema"] != PROFILE_SCHEMA:
        raise EventRelationSchemaError("unsupported_profile_schema")
    _validate_quantile_policy(value["quantile_policy"])
    return CalibratedEventRelationProfileV0(
        profile_id=value["profile_id"],
        reducer_revision=value["reducer_revision"],
        model_revision=value["model_revision"],
        feature_policy_digest=value["feature_policy_digest"],
        input_matrix_digest=value["input_matrix_digest"],
        model_digest=value["model_digest"],
        fit_partition_digest=value["fit_partition_digest"],
        calibration_partition_digest=value["calibration_partition_digest"],
        forward_same_threshold=value["forward_same_threshold"],
        forward_different_threshold=value["forward_different_threshold"],
        reverse_same_threshold=value["reverse_same_threshold"],
        reverse_different_threshold=value["reverse_different_threshold"],
    )


def _direction_state(
    score: float, same_threshold: float, different_threshold: float
) -> str:
    if score <= same_threshold:
        return "same"
    if score >= different_threshold:
        return "different"
    return "gap"


def expected_decision(
    profile: CalibratedEventRelationProfileV0,
    forward_score: str,
    reverse_score: str,
) -> tuple[str, str | None]:
    """Return the only coherent decision and reason for two canonical scores."""

    forward = _canonical_distance(forward_score, "invalid_forward_score")
    reverse = _canonical_distance(reverse_score, "invalid_reverse_score")
    forward_state = _direction_state(
        forward,
        float.fromhex(profile.forward_same_threshold),
        float.fromhex(profile.forward_different_threshold),
    )
    reverse_state = _direction_state(
        reverse,
        float.fromhex(profile.reverse_same_threshold),
        float.fromhex(profile.reverse_different_threshold),
    )
    if forward_state == reverse_state == "same":
        return "same", None
    if forward_state == reverse_state == "different":
        return "different", None
    if {forward_state, reverse_state} == {"same", "different"}:
        return "abstain", "direction_disagreement"
    return "abstain", "score_gap"


@dataclass(frozen=True)
class EventRelationPredictionV0:
    """A profile-bound bidirectional event-relation decision."""

    frame_id: str
    profile_digest: str
    forward_score: str
    reverse_score: str
    decision: str
    abstain_reason: str | None
    profile: InitVar[CalibratedEventRelationProfileV0]

    def __post_init__(self, profile: CalibratedEventRelationProfileV0) -> None:
        _identifier(self.frame_id, "invalid_frame_id")
        _digest(self.profile_digest, "invalid_profile_digest")
        if not isinstance(profile, CalibratedEventRelationProfileV0):
            raise EventRelationSchemaError("profile_required")
        if self.profile_digest != profile.content_digest():
            raise EventRelationSchemaError("profile_digest_mismatch")
        if not isinstance(self.decision, str) or self.decision not in DECISIONS:
            raise EventRelationSchemaError("invalid_decision")
        if self.abstain_reason is not None and (
            not isinstance(self.abstain_reason, str)
            or self.abstain_reason not in ABSTAIN_REASONS
        ):
            raise EventRelationSchemaError("invalid_abstain_reason")
        expected = expected_decision(profile, self.forward_score, self.reverse_score)
        if (self.decision, self.abstain_reason) != expected:
            raise EventRelationSchemaError("incoherent_decision")

    @classmethod
    def from_document(
        cls, value: Any, profile: CalibratedEventRelationProfileV0
    ) -> EventRelationPredictionV0:
        return parse_prediction(value, profile)

    @classmethod
    def from_json_bytes(
        cls, data: bytes, profile: CalibratedEventRelationProfileV0
    ) -> EventRelationPredictionV0:
        return load_prediction_bytes(data, profile)

    def document(self) -> dict[str, Any]:
        return {
            "schema": PREDICTION_SCHEMA,
            "frame_id": self.frame_id,
            "profile_digest": self.profile_digest,
            "forward_score": self.forward_score,
            "reverse_score": self.reverse_score,
            "decision": self.decision,
            "abstain_reason": self.abstain_reason,
        }

    def canonical_json_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    def content_digest(self) -> str:
        return content_digest(self)


@dataclass(frozen=True)
class HeldoutEventRelationEvaluationReceiptV0:
    """A profile-bound receipt for one frozen held-out admission gate."""

    receipt_id: str
    profile_digest: str
    evaluation_protocol_digest: str
    heldout_partition_digest: str
    evaluation_report_digest: str
    gate_policy_digest: str
    gate_status: str
    profile: InitVar[CalibratedEventRelationProfileV0]

    def __post_init__(self, profile: CalibratedEventRelationProfileV0) -> None:
        _identifier(self.receipt_id, "invalid_receipt_id")
        for field in (
            "profile_digest",
            "evaluation_protocol_digest",
            "heldout_partition_digest",
            "evaluation_report_digest",
            "gate_policy_digest",
        ):
            _digest(getattr(self, field), f"invalid_{field}")
        if not isinstance(profile, CalibratedEventRelationProfileV0):
            raise EventRelationSchemaError("profile_required")
        if self.profile_digest != profile.content_digest():
            raise EventRelationSchemaError("profile_digest_mismatch")
        if self.gate_status not in HELDOUT_GATE_STATUSES:
            raise EventRelationSchemaError("invalid_gate_status")

    @classmethod
    def from_document(
        cls, value: Any, profile: CalibratedEventRelationProfileV0
    ) -> HeldoutEventRelationEvaluationReceiptV0:
        return parse_heldout_receipt(value, profile)

    @classmethod
    def from_json_bytes(
        cls, data: bytes, profile: CalibratedEventRelationProfileV0
    ) -> HeldoutEventRelationEvaluationReceiptV0:
        return load_heldout_receipt_bytes(data, profile)

    def document(self) -> dict[str, Any]:
        return {
            "schema": HELDOUT_RECEIPT_SCHEMA,
            "receipt_id": self.receipt_id,
            "profile_digest": self.profile_digest,
            "evaluation_protocol_digest": self.evaluation_protocol_digest,
            "heldout_partition_digest": self.heldout_partition_digest,
            "evaluation_report_digest": self.evaluation_report_digest,
            "gate": {
                "policy_digest": self.gate_policy_digest,
                "status": self.gate_status,
            },
        }

    def canonical_json_bytes(self) -> bytes:
        return canonical_json_bytes(self)

    def content_digest(self) -> str:
        return content_digest(self)


def parse_prediction(
    value: Any, profile: CalibratedEventRelationProfileV0
) -> EventRelationPredictionV0:
    """Parse one exact-shape prediction against its referenced profile."""

    if not isinstance(value, Mapping):
        raise EventRelationSchemaError("invalid_prediction_schema")
    _expect_fields(value, PREDICTION_FIELDS, "invalid_prediction_schema")
    if value["schema"] != PREDICTION_SCHEMA:
        raise EventRelationSchemaError("unsupported_prediction_schema")
    return EventRelationPredictionV0(
        frame_id=value["frame_id"],
        profile_digest=value["profile_digest"],
        forward_score=value["forward_score"],
        reverse_score=value["reverse_score"],
        decision=value["decision"],
        abstain_reason=value["abstain_reason"],
        profile=profile,
    )


def parse_heldout_receipt(
    value: Any, profile: CalibratedEventRelationProfileV0
) -> HeldoutEventRelationEvaluationReceiptV0:
    """Parse one exact-shape held-out evaluation receipt."""

    if not isinstance(value, Mapping):
        raise EventRelationSchemaError("invalid_heldout_receipt_schema")
    _expect_fields(value, HELDOUT_RECEIPT_FIELDS, "invalid_heldout_receipt_schema")
    if value["schema"] != HELDOUT_RECEIPT_SCHEMA:
        raise EventRelationSchemaError("unsupported_heldout_receipt_schema")
    gate = value["gate"]
    if not isinstance(gate, Mapping):
        raise EventRelationSchemaError("invalid_heldout_gate_schema")
    _expect_fields(gate, HELDOUT_GATE_FIELDS, "invalid_heldout_gate_schema")
    return HeldoutEventRelationEvaluationReceiptV0(
        receipt_id=value["receipt_id"],
        profile_digest=value["profile_digest"],
        evaluation_protocol_digest=value["evaluation_protocol_digest"],
        heldout_partition_digest=value["heldout_partition_digest"],
        evaluation_report_digest=value["evaluation_report_digest"],
        gate_policy_digest=gate["policy_digest"],
        gate_status=gate["status"],
        profile=profile,
    )


def canonical_json_bytes(
    value: (
        CalibratedEventRelationProfileV0
        | EventRelationPredictionV0
        | HeldoutEventRelationEvaluationReceiptV0
    ),
) -> bytes:
    """Encode one schema object with a single deterministic JSON representation."""

    if not isinstance(
        value,
        (
            CalibratedEventRelationProfileV0,
            EventRelationPredictionV0,
            HeldoutEventRelationEvaluationReceiptV0,
        ),
    ):
        raise TypeError("unsupported event-relation document")
    return json.dumps(
        value.document(),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def content_digest(
    value: (
        CalibratedEventRelationProfileV0
        | EventRelationPredictionV0
        | HeldoutEventRelationEvaluationReceiptV0
    ),
) -> str:
    """Return a domain-separated SHA-256 digest of canonical schema content."""

    if isinstance(value, CalibratedEventRelationProfileV0):
        domain = _PROFILE_DIGEST_DOMAIN
    elif isinstance(value, EventRelationPredictionV0):
        domain = _PREDICTION_DIGEST_DOMAIN
    elif isinstance(value, HeldoutEventRelationEvaluationReceiptV0):
        domain = _HELDOUT_RECEIPT_DIGEST_DOMAIN
    else:
        raise TypeError("unsupported event-relation document")
    return hashlib.sha256(domain + canonical_json_bytes(value)).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise EventRelationSchemaError("duplicate_json_key")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise EventRelationSchemaError("invalid_json_constant")


def _load_document_bytes(data: bytes) -> Any:
    if len(data) > MAX_DOCUMENT_BYTES:
        raise EventRelationSchemaError("document_too_large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EventRelationSchemaError("invalid_json") from error
    try:
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except json.JSONDecodeError as error:
        raise EventRelationSchemaError("invalid_json") from error


def load_profile_bytes(data: bytes) -> CalibratedEventRelationProfileV0:
    return parse_profile(_load_document_bytes(data))


def load_prediction_bytes(
    data: bytes, profile: CalibratedEventRelationProfileV0
) -> EventRelationPredictionV0:
    return parse_prediction(_load_document_bytes(data), profile)


def load_heldout_receipt_bytes(
    data: bytes, profile: CalibratedEventRelationProfileV0
) -> HeldoutEventRelationEvaluationReceiptV0:
    return parse_heldout_receipt(_load_document_bytes(data), profile)
