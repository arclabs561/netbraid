#!/usr/bin/env python3
"""Strict evaluation-only labels for independent evidence hypotheses.

The frame has no raw observations, paths, addresses, device identifiers, or
model outputs. It is an oracle contract for corpus adapters and evaluators,
not a production identity or attack classifier.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

SCHEMA = "netbraid.hypothesis_frame_manifest.v2"
MAX_FRAMES = 10_000
FRAME_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,95}\Z")

FRAME_FIELDS = (
    "frame_id",
    "artifact_object_relation",
    "content_relation",
    "event_relation",
    "event_performer_relation",
    "claimed_identifier_relation",
    "cryptographic_principal_relation",
    "physical_device_relation",
    "physical_source_relation",
    "software_relation",
    "configuration_relation",
    "variant_relation",
    "lineage_relation",
    "integrity",
    "admissibility",
    "freshness",
    "continuity",
    "transmission",
    "scenario",
)
SCENARIO_FIELDS = (
    "cause",
    "mechanisms",
    "modification_loci",
    "authorization",
    "intent",
    "provenance",
    "tamper_hypothesis",
)
TAMPER_FIELDS = ("disposition", "basis")

RELATION_STATES = {
    "artifact_object_relation": frozenset(
        ("same_object", "different_object", "unknown")
    ),
    "content_relation": frozenset(("equal", "different", "unknown")),
    "event_relation": frozenset(("same", "different", "unknown")),
    "event_performer_relation": frozenset(
        ("same", "different", "not_observed", "unknown")
    ),
    "claimed_identifier_relation": frozenset(
        ("same", "different", "not_observed", "unknown")
    ),
    "cryptographic_principal_relation": frozenset(
        ("same", "different", "not_observed", "unknown")
    ),
    "physical_device_relation": frozenset(("same", "different", "unknown")),
    "physical_source_relation": frozenset(("same", "different", "unknown")),
    "software_relation": frozenset(
        ("same", "left_derived", "right_derived", "different", "unknown")
    ),
    "configuration_relation": frozenset(("same", "different", "unknown")),
    "variant_relation": frozenset(
        ("same", "left_derived", "right_derived", "different", "unknown")
    ),
    "lineage_relation": frozenset(
        (
            "same",
            "left_derived",
            "right_derived",
            "common_ancestor",
            "unrelated",
            "unknown",
        )
    ),
}

INTEGRITY_STATES = frozenset(
    (
        "verified_unchanged",
        "verified_changed",
        "authorized_transformation",
        "unverifiable",
    )
)
ADMISSIBILITY_STATES = frozenset(("in_domain", "out_of_domain", "unknown"))
FRESHNESS_STATES = frozenset(("fresh", "replay_detected", "unknown"))
CONTINUITY_STATES = frozenset(
    ("complete", "gap", "reordered", "duplicate", "mixed", "unknown")
)
TRANSMISSION_STATES = frozenset(("direct", "relayed", "unknown"))

CAUSE_STATES = frozenset(
    (
        "benign_baseline",
        "benign_domain_drift",
        "benign_transformation",
        "benign_confounder",
        "replay",
        "relay",
        "impersonation",
        "evasion",
        "accidental_corruption",
        "compromise",
        "malicious_scenario",
        "ambiguous",
        "insufficient_evidence",
    )
)
MECHANISM_STATES = frozenset(
    (
        "none",
        "replay",
        "relay",
        "claimed_identifier_spoofing",
        "credential_cloning",
        "credential_theft",
        "rf_mimicry",
        "adversarial_perturbation",
        "poisoning",
        "deletion",
        "reordering",
        "duplication",
        "other_declared",
        "unknown",
    )
)
MODIFICATION_LOCUS_STATES = frozenset(
    (
        "none",
        "source_hardware",
        "firmware",
        "configuration",
        "payload",
        "transport",
        "capture_pipeline",
        "stored_artifact",
        "metadata_or_label",
        "model_or_index",
        "other_declared",
        "unknown",
    )
)
AUTHORIZATION_STATES = frozenset(("authorized", "unauthorized", "unknown"))
INTENT_STATES = frozenset(("benign", "accidental", "malicious", "mixed", "unknown"))
PROVENANCE_STATES = frozenset(
    (
        "explicit_fixture",
        "publisher_adjudicated_scenario",
        "operator_adjudication",
        "insufficient_evidence",
    )
)
TAMPER_DISPOSITIONS = frozenset(("supported", "contradicted", "underdetermined"))
TAMPER_BASIS_STATES = frozenset(
    (
        "applicable_authorization_policy",
        "unauthorized_change_or_interference",
        "authorized_change_or_interference",
        "no_change_or_interference",
        "insufficient_policy_evidence",
        "insufficient_change_or_interference_evidence",
    )
)

_DIRECTIONAL_FIELDS = ("software_relation", "variant_relation", "lineage_relation")
_DIRECTIONAL_SWAP = {
    "left_derived": "right_derived",
    "right_derived": "left_derived",
}


class HypothesisFrameError(ValueError):
    """Stable fail-closed reason for an invalid evaluation frame."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _expect_fields(value: Mapping[str, Any], fields: Sequence[str], code: str) -> None:
    if set(value) != set(fields):
        raise HypothesisFrameError(code)


def _state(value: Any, allowed: frozenset[str], code: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise HypothesisFrameError(code)
    return value


def _state_list(
    value: Any,
    allowed: frozenset[str],
    *,
    code: str,
    exclusive: str,
) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > len(allowed)
        or any(not isinstance(item, str) or item not in allowed for item in value)
        or len(set(value)) != len(value)
    ):
        raise HypothesisFrameError(code)
    if exclusive in value and len(value) != 1:
        raise HypothesisFrameError(code)
    return tuple(sorted(value))


@dataclass(frozen=True)
class TamperHypothesisV0:
    disposition: str
    basis: tuple[str, ...]

    def document(self) -> dict[str, Any]:
        return {"disposition": self.disposition, "basis": list(self.basis)}


@dataclass(frozen=True)
class ScenarioOracleV0:
    cause: str
    mechanisms: tuple[str, ...]
    modification_loci: tuple[str, ...]
    authorization: str
    intent: str
    provenance: str
    tamper_hypothesis: TamperHypothesisV0

    def document(self) -> dict[str, Any]:
        return {
            "cause": self.cause,
            "mechanisms": list(self.mechanisms),
            "modification_loci": list(self.modification_loci),
            "authorization": self.authorization,
            "intent": self.intent,
            "provenance": self.provenance,
            "tamper_hypothesis": self.tamper_hypothesis.document(),
        }


@dataclass(frozen=True)
class HypothesisFrameV0:
    frame_id: str
    artifact_object_relation: str
    content_relation: str
    event_relation: str
    event_performer_relation: str
    claimed_identifier_relation: str
    cryptographic_principal_relation: str
    physical_device_relation: str
    physical_source_relation: str
    software_relation: str
    configuration_relation: str
    variant_relation: str
    lineage_relation: str
    integrity: str
    admissibility: str
    freshness: str
    continuity: str
    transmission: str
    scenario: ScenarioOracleV0

    def transpose(self) -> HypothesisFrameV0:
        """Swap pair direction without changing symmetric evidence axes."""
        updates = {
            field: _DIRECTIONAL_SWAP.get(getattr(self, field), getattr(self, field))
            for field in _DIRECTIONAL_FIELDS
        }
        return replace(self, **updates)

    def document(self) -> dict[str, Any]:
        return {
            field: self.scenario.document()
            if field == "scenario"
            else getattr(self, field)
            for field in FRAME_FIELDS
        }


def _parse_tamper(value: Any) -> TamperHypothesisV0:
    if not isinstance(value, Mapping):
        raise HypothesisFrameError("invalid_tamper_hypothesis_schema")
    _expect_fields(value, TAMPER_FIELDS, "invalid_tamper_hypothesis_schema")
    disposition = _state(
        value["disposition"], TAMPER_DISPOSITIONS, "invalid_tamper_disposition"
    )
    basis = _state_list(
        value["basis"],
        TAMPER_BASIS_STATES,
        code="invalid_tamper_basis",
        exclusive="unused",
    )
    basis_set = set(basis)
    applicable = "applicable_authorization_policy"
    unauthorized = "unauthorized_change_or_interference"
    authorized = "authorized_change_or_interference"
    absent = "no_change_or_interference"
    insufficient = {
        "insufficient_policy_evidence",
        "insufficient_change_or_interference_evidence",
    }
    if disposition == "supported" and basis_set != {applicable, unauthorized}:
        raise HypothesisFrameError("unsupported_tamper_support_basis")
    if disposition == "contradicted" and basis_set not in (
        {applicable, authorized},
        {applicable, absent},
    ):
        raise HypothesisFrameError("unsupported_tamper_contradiction_basis")
    if disposition == "underdetermined" and not basis_set.intersection(insufficient):
        raise HypothesisFrameError("missing_tamper_uncertainty_basis")
    if disposition == "underdetermined" and basis_set.intersection(
        {unauthorized, authorized, absent}
    ):
        raise HypothesisFrameError("conflicting_tamper_uncertainty_basis")
    return TamperHypothesisV0(disposition=disposition, basis=basis)


def _parse_scenario(value: Any) -> ScenarioOracleV0:
    if not isinstance(value, Mapping):
        raise HypothesisFrameError("invalid_scenario_schema")
    _expect_fields(value, SCENARIO_FIELDS, "invalid_scenario_schema")
    cause = _state(value["cause"], CAUSE_STATES, "invalid_scenario_cause")
    mechanisms = _state_list(
        value["mechanisms"],
        MECHANISM_STATES,
        code="invalid_scenario_mechanisms",
        exclusive="none",
    )
    modification_loci = _state_list(
        value["modification_loci"],
        MODIFICATION_LOCUS_STATES,
        code="invalid_modification_loci",
        exclusive="none",
    )
    authorization = _state(
        value["authorization"], AUTHORIZATION_STATES, "invalid_authorization"
    )
    intent = _state(value["intent"], INTENT_STATES, "invalid_intent")
    provenance = _state(
        value["provenance"], PROVENANCE_STATES, "invalid_scenario_provenance"
    )
    if intent != "unknown" and provenance == "insufficient_evidence":
        raise HypothesisFrameError("intent_without_scenario_provenance")
    tamper_hypothesis = _parse_tamper(value["tamper_hypothesis"])
    tamper_basis = set(tamper_hypothesis.basis)
    if tamper_hypothesis.disposition == "supported":
        if authorization != "unauthorized":
            raise HypothesisFrameError("tamper_support_conflicts_with_authorization")
        if mechanisms == ("none",) and modification_loci == ("none",):
            raise HypothesisFrameError("tamper_support_without_change_or_interference")
    if (
        tamper_hypothesis.disposition == "contradicted"
        and "authorized_change_or_interference" in tamper_basis
        and authorization != "authorized"
    ):
        raise HypothesisFrameError("tamper_contradiction_conflicts_with_authorization")
    return ScenarioOracleV0(
        cause=cause,
        mechanisms=mechanisms,
        modification_loci=modification_loci,
        authorization=authorization,
        intent=intent,
        provenance=provenance,
        tamper_hypothesis=tamper_hypothesis,
    )


def parse_frame(value: Any) -> HypothesisFrameV0:
    if not isinstance(value, Mapping):
        raise HypothesisFrameError("invalid_frame_schema")
    _expect_fields(value, FRAME_FIELDS, "invalid_frame_schema")
    frame_id = value["frame_id"]
    if not isinstance(frame_id, str) or FRAME_ID_PATTERN.fullmatch(frame_id) is None:
        raise HypothesisFrameError("invalid_frame_id")

    relations = {
        field: _state(value[field], allowed, f"invalid_{field}")
        for field, allowed in RELATION_STATES.items()
    }
    integrity = _state(value["integrity"], INTEGRITY_STATES, "invalid_integrity")
    admissibility = _state(
        value["admissibility"], ADMISSIBILITY_STATES, "invalid_admissibility"
    )
    freshness = _state(value["freshness"], FRESHNESS_STATES, "invalid_freshness")
    continuity = _state(value["continuity"], CONTINUITY_STATES, "invalid_continuity")
    transmission = _state(
        value["transmission"], TRANSMISSION_STATES, "invalid_transmission"
    )
    scenario = _parse_scenario(value["scenario"])

    if "replay" in scenario.mechanisms:
        if relations["event_relation"] == "same":
            raise HypothesisFrameError("replay_cannot_be_same_event")
        if freshness == "fresh":
            raise HypothesisFrameError("replay_cannot_be_fresh")
    if "relay" in scenario.mechanisms and transmission == "direct":
        raise HypothesisFrameError("relay_cannot_be_direct")
    return HypothesisFrameV0(
        frame_id=frame_id,
        **relations,
        integrity=integrity,
        admissibility=admissibility,
        freshness=freshness,
        continuity=continuity,
        transmission=transmission,
        scenario=scenario,
    )


def parse_manifest(value: Any) -> tuple[HypothesisFrameV0, ...]:
    if not isinstance(value, Mapping):
        raise HypothesisFrameError("invalid_manifest_schema")
    _expect_fields(value, ("schema", "frames"), "invalid_manifest_schema")
    if value["schema"] != SCHEMA:
        raise HypothesisFrameError("unsupported_manifest_schema")
    frames = value["frames"]
    if not isinstance(frames, list) or not 1 <= len(frames) <= MAX_FRAMES:
        raise HypothesisFrameError("invalid_manifest_frame_count")
    parsed = tuple(parse_frame(frame) for frame in frames)
    if len({frame.frame_id for frame in parsed}) != len(parsed):
        raise HypothesisFrameError("duplicate_frame_id")
    return parsed


def canonical_manifest(frames: Sequence[HypothesisFrameV0]) -> dict[str, Any]:
    if not 1 <= len(frames) <= MAX_FRAMES:
        raise HypothesisFrameError("invalid_manifest_frame_count")
    ordered = sorted(frames, key=lambda frame: frame.frame_id)
    if len({frame.frame_id for frame in ordered}) != len(ordered):
        raise HypothesisFrameError("duplicate_frame_id")
    return {"schema": SCHEMA, "frames": [frame.document() for frame in ordered]}


def main() -> int:
    try:
        document = json.load(sys.stdin)
        frames = parse_manifest(document)
        json.dump(canonical_manifest(frames), sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except (HypothesisFrameError, json.JSONDecodeError) as error:
        code = error.code if isinstance(error, HypothesisFrameError) else "invalid_json"
        print(code, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
