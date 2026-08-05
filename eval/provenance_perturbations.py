#!/usr/bin/env python3
"""Bounded provenance perturbations for conflicting, delayed annotations.

The fixture uses only opaque evaluation identifiers and integer clock ticks.
It is an evaluation oracle, not an identity, intent, trust, or source-quality
classifier.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

FIXTURE_SCHEMA = "netbraid.provenance_perturbation_fixture.v0"
REPORT_SCHEMA = "netbraid.provenance_perturbation_report.v0"
FIXED_SEED = 3405

MAX_INPUT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 128 * 1024
MAX_OBSERVATIONS = 8
MAX_ORGANIC_ANNOTATIONS = 16
MAX_PERTURBATIONS = 16
MAX_SCENARIO_ANNOTATIONS = 32
MAX_TICK = 1_000_000
MAX_ID_BYTES = 48

ID_PATTERN = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
PERTURBATION_KINDS = (
    "delay",
    "reorder",
    "exact-duplicate",
    "copied-evidence",
    "superseding-correction",
    "withdrawal",
    "independent-corroboration",
)

FIXTURE_FIELDS = (
    "schema",
    "seed",
    "observations",
    "organic_annotations",
    "perturbations",
)
OBSERVATION_FIELDS = (
    "observation_id",
    "event_time",
    "arrival_time",
    "provenance",
    "dependence_group",
)
ANNOTATION_FIELDS = (
    "annotation_id",
    "observation_id",
    "event_time",
    "arrival_time",
    "label",
    "provenance",
    "dependence_group",
    "revision",
    "origin",
)
PROVENANCE_FIELDS = ("parent_id", "source_id", "source_version")
REVISION_FIELDS = (
    "state",
    "supersedes_annotation_id",
    "withdraws_annotation_id",
)
PERTURBATION_FIELDS = (
    "perturbation_id",
    "kind",
    "parent_annotation_id",
    "generated_annotation",
    "delay_ticks",
    "order",
)
REPORT_FIELDS = ("schema", "fixture_digest", "seed", "scenarios")
SCENARIO_FIELDS = (
    "scenario_id",
    "perturbation_kind",
    "input_annotation_ids",
    "event_chronology",
    "arrival_chronology",
    "active_annotation_ids",
    "dependence_aware_evidence_count",
    "lineage",
    "decision",
)
LINEAGE_FIELDS = (
    "annotation_id",
    "parent_annotation_id",
    "root_annotation_id",
)
DECISION_FIELDS = ("state", "label", "reason")


class ProvenancePerturbationError(ValueError):
    """Stable fail-closed reason for an invalid fixture or report."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _strict_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProvenancePerturbationError("duplicate_json_key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ProvenancePerturbationError("invalid_json_constant")


def _exact_mapping(value: Any, fields: Sequence[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != set(fields):
        raise ProvenancePerturbationError(code)
    return value


def _opaque_id(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or ID_PATTERN.fullmatch(value) is None
        or len(value.encode("utf-8")) > MAX_ID_BYTES
    ):
        raise ProvenancePerturbationError(code)
    return value


def _tick(value: Any, code: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TICK:
        raise ProvenancePerturbationError(code)
    return value


def _optional_id(value: Any, code: str) -> str | None:
    if value is None:
        return None
    return _opaque_id(value, code)


@dataclass(frozen=True)
class Provenance:
    parent_id: str | None
    source_id: str
    source_version: str

    def document(self) -> dict[str, Any]:
        return {
            "parent_id": self.parent_id,
            "source_id": self.source_id,
            "source_version": self.source_version,
        }


@dataclass(frozen=True)
class Revision:
    state: str
    supersedes_annotation_id: str | None
    withdraws_annotation_id: str | None

    def document(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "supersedes_annotation_id": self.supersedes_annotation_id,
            "withdraws_annotation_id": self.withdraws_annotation_id,
        }


@dataclass(frozen=True)
class Observation:
    observation_id: str
    event_time: int
    arrival_time: int
    provenance: Provenance
    dependence_group: str

    def document(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            "event_time": self.event_time,
            "arrival_time": self.arrival_time,
            "provenance": self.provenance.document(),
            "dependence_group": self.dependence_group,
        }


@dataclass(frozen=True)
class Annotation:
    annotation_id: str
    observation_id: str
    event_time: int
    arrival_time: int
    label: str | None
    provenance: Provenance
    dependence_group: str
    revision: Revision
    origin: str

    def document(self) -> dict[str, Any]:
        return {
            "annotation_id": self.annotation_id,
            "observation_id": self.observation_id,
            "event_time": self.event_time,
            "arrival_time": self.arrival_time,
            "label": self.label,
            "provenance": self.provenance.document(),
            "dependence_group": self.dependence_group,
            "revision": self.revision.document(),
            "origin": self.origin,
        }


@dataclass(frozen=True)
class Perturbation:
    perturbation_id: str
    kind: str
    parent_annotation_id: str | None
    generated_annotation: Annotation | None
    delay_ticks: int | None
    order: tuple[str, ...] | None

    def document(self) -> dict[str, Any]:
        return {
            "perturbation_id": self.perturbation_id,
            "kind": self.kind,
            "parent_annotation_id": self.parent_annotation_id,
            "generated_annotation": (
                None
                if self.generated_annotation is None
                else self.generated_annotation.document()
            ),
            "delay_ticks": self.delay_ticks,
            "order": None if self.order is None else list(self.order),
        }


@dataclass(frozen=True)
class Fixture:
    seed: int
    observations: tuple[Observation, ...]
    organic_annotations: tuple[Annotation, ...]
    perturbations: tuple[Perturbation, ...]

    def document(self) -> dict[str, Any]:
        return {
            "schema": FIXTURE_SCHEMA,
            "seed": self.seed,
            "observations": [item.document() for item in self.observations],
            "organic_annotations": [
                item.document() for item in self.organic_annotations
            ],
            "perturbations": [item.document() for item in self.perturbations],
        }

    def canonical_json_bytes(self) -> bytes:
        return _canonical_json_bytes(self.document(), MAX_INPUT_BYTES)

    def content_digest(self) -> str:
        return hashlib.sha256(self.canonical_json_bytes()).hexdigest()


def _parse_provenance(value: Any) -> Provenance:
    value = _exact_mapping(value, PROVENANCE_FIELDS, "invalid_provenance_schema")
    return Provenance(
        parent_id=_optional_id(value["parent_id"], "invalid_provenance_parent_id"),
        source_id=_opaque_id(value["source_id"], "invalid_source_id"),
        source_version=_opaque_id(value["source_version"], "invalid_source_version"),
    )


def _parse_revision(value: Any) -> Revision:
    value = _exact_mapping(value, REVISION_FIELDS, "invalid_revision_schema")
    state = value["state"]
    if state not in {"original", "superseding-correction", "withdrawal"}:
        raise ProvenancePerturbationError("invalid_revision_state")
    revision = Revision(
        state=state,
        supersedes_annotation_id=_optional_id(
            value["supersedes_annotation_id"], "invalid_supersedes_annotation_id"
        ),
        withdraws_annotation_id=_optional_id(
            value["withdraws_annotation_id"], "invalid_withdraws_annotation_id"
        ),
    )
    expected = {
        "original": (None, None),
        "superseding-correction": (revision.supersedes_annotation_id, None),
        "withdrawal": (None, revision.withdraws_annotation_id),
    }[state]
    if (
        revision.supersedes_annotation_id,
        revision.withdraws_annotation_id,
    ) != expected:
        raise ProvenancePerturbationError("invalid_revision_transition")
    if state != "original" and expected == (None, None):
        raise ProvenancePerturbationError("invalid_revision_transition")
    return revision


def _parse_observation(value: Any) -> Observation:
    value = _exact_mapping(value, OBSERVATION_FIELDS, "invalid_observation_schema")
    observation = Observation(
        observation_id=_opaque_id(value["observation_id"], "invalid_observation_id"),
        event_time=_tick(value["event_time"], "invalid_observation_event_time"),
        arrival_time=_tick(value["arrival_time"], "invalid_observation_arrival_time"),
        provenance=_parse_provenance(value["provenance"]),
        dependence_group=_opaque_id(
            value["dependence_group"], "invalid_observation_dependence_group"
        ),
    )
    if observation.provenance.parent_id is not None:
        raise ProvenancePerturbationError("invalid_observation_parent")
    return observation


def _parse_annotation(value: Any) -> Annotation:
    value = _exact_mapping(value, ANNOTATION_FIELDS, "invalid_annotation_schema")
    label = value["label"]
    if label is not None:
        label = _opaque_id(label, "invalid_annotation_label")
    origin = value["origin"]
    if origin not in {"organic", "derived-perturbation"}:
        raise ProvenancePerturbationError("invalid_annotation_origin")
    annotation = Annotation(
        annotation_id=_opaque_id(value["annotation_id"], "invalid_annotation_id"),
        observation_id=_opaque_id(value["observation_id"], "invalid_observation_id"),
        event_time=_tick(value["event_time"], "invalid_annotation_event_time"),
        arrival_time=_tick(value["arrival_time"], "invalid_annotation_arrival_time"),
        label=label,
        provenance=_parse_provenance(value["provenance"]),
        dependence_group=_opaque_id(
            value["dependence_group"], "invalid_annotation_dependence_group"
        ),
        revision=_parse_revision(value["revision"]),
        origin=origin,
    )
    if (annotation.revision.state == "withdrawal") != (annotation.label is None):
        raise ProvenancePerturbationError("invalid_annotation_label_state")
    return annotation


def _parse_perturbation(value: Any) -> Perturbation:
    value = _exact_mapping(value, PERTURBATION_FIELDS, "invalid_perturbation_schema")
    kind = value["kind"]
    if kind not in PERTURBATION_KINDS:
        raise ProvenancePerturbationError("invalid_perturbation_kind")
    generated = value["generated_annotation"]
    order = value["order"]
    delay_ticks = value["delay_ticks"]
    return Perturbation(
        perturbation_id=_opaque_id(value["perturbation_id"], "invalid_perturbation_id"),
        kind=kind,
        parent_annotation_id=_optional_id(
            value["parent_annotation_id"], "invalid_perturbation_parent_id"
        ),
        generated_annotation=(
            None if generated is None else _parse_annotation(generated)
        ),
        delay_ticks=(
            None if delay_ticks is None else _tick(delay_ticks, "invalid_delay_ticks")
        ),
        order=(
            None
            if order is None
            else tuple(_opaque_id(item, "invalid_reorder_id") for item in order)
            if isinstance(order, list)
            else _raise("invalid_reorder_order")
        ),
    )


def _raise(code: str) -> Any:
    raise ProvenancePerturbationError(code)


def parse_fixture(value: Any) -> Fixture:
    """Parse the exact fixture schema and carry its validated types forward."""

    value = _exact_mapping(value, FIXTURE_FIELDS, "invalid_fixture_schema")
    if value["schema"] != FIXTURE_SCHEMA:
        raise ProvenancePerturbationError("invalid_fixture_schema_version")
    seed = value["seed"]
    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ProvenancePerturbationError("invalid_seed")
    raw_observations = value["observations"]
    raw_annotations = value["organic_annotations"]
    raw_perturbations = value["perturbations"]
    if (
        not isinstance(raw_observations, list)
        or not 1 <= len(raw_observations) <= MAX_OBSERVATIONS
        or not isinstance(raw_annotations, list)
        or not 1 <= len(raw_annotations) <= MAX_ORGANIC_ANNOTATIONS
        or not isinstance(raw_perturbations, list)
        or not 1 <= len(raw_perturbations) <= MAX_PERTURBATIONS
    ):
        raise ProvenancePerturbationError("fixture_count_outside_bound")

    observations = tuple(_parse_observation(item) for item in raw_observations)
    annotations = tuple(_parse_annotation(item) for item in raw_annotations)
    perturbations = tuple(_parse_perturbation(item) for item in raw_perturbations)
    observation_ids = {item.observation_id for item in observations}
    annotation_by_id = {item.annotation_id: item for item in annotations}
    if len(observation_ids) != len(observations):
        raise ProvenancePerturbationError("duplicate_observation_id")
    if len(annotation_by_id) != len(annotations):
        raise ProvenancePerturbationError("duplicate_organic_annotation_id")
    if any(
        item.observation_id not in observation_ids
        or item.origin != "organic"
        or item.revision.state != "original"
        or item.provenance.parent_id is not None
        for item in annotations
    ):
        raise ProvenancePerturbationError("invalid_organic_annotation")
    if tuple(item.kind for item in perturbations) != PERTURBATION_KINDS:
        raise ProvenancePerturbationError("incomplete_perturbation_rung")
    if len({item.perturbation_id for item in perturbations}) != len(perturbations):
        raise ProvenancePerturbationError("duplicate_perturbation_id")

    _validate_perturbations(annotations, perturbations)
    return Fixture(seed, observations, annotations, perturbations)


def _validate_perturbations(
    organic: tuple[Annotation, ...], perturbations: tuple[Perturbation, ...]
) -> None:
    by_id = {item.annotation_id: item for item in organic}
    organic_ids = tuple(item.annotation_id for item in organic)
    organic_sources = {item.provenance.source_id for item in organic}
    organic_groups = {item.dependence_group for item in organic}
    generated_ids: set[str] = set()

    for perturbation in perturbations:
        parent = (
            None
            if perturbation.parent_annotation_id is None
            else by_id.get(perturbation.parent_annotation_id)
        )
        generated = perturbation.generated_annotation
        if perturbation.kind == "delay":
            if (
                parent is None
                or generated is not None
                or perturbation.delay_ticks is None
                or perturbation.delay_ticks <= 0
                or perturbation.order is not None
                or parent.arrival_time + perturbation.delay_ticks > MAX_TICK
            ):
                raise ProvenancePerturbationError("invalid_delay_perturbation")
            continue
        if perturbation.kind == "reorder":
            if (
                parent is not None
                or generated is not None
                or perturbation.delay_ticks is not None
                or perturbation.order is None
                or len(perturbation.order) != len(organic_ids)
                or set(perturbation.order) != set(organic_ids)
                or perturbation.order == organic_ids
            ):
                raise ProvenancePerturbationError("invalid_reorder_perturbation")
            continue
        if perturbation.kind == "exact-duplicate":
            if (
                parent is None
                or generated is not None
                or perturbation.delay_ticks is not None
                or perturbation.order is not None
            ):
                raise ProvenancePerturbationError("invalid_duplicate_perturbation")
            continue
        if (
            generated is None
            or perturbation.delay_ticks is not None
            or perturbation.order is not None
            or generated.origin != "derived-perturbation"
            or generated.observation_id not in {item.observation_id for item in organic}
            or generated.annotation_id in by_id
            or generated.annotation_id in generated_ids
        ):
            raise ProvenancePerturbationError("invalid_generated_perturbation")
        generated_ids.add(generated.annotation_id)

        if perturbation.kind == "copied-evidence":
            if (
                parent is None
                or generated.provenance.parent_id != parent.annotation_id
                or generated.provenance.source_id == parent.provenance.source_id
                or generated.dependence_group != parent.dependence_group
                or generated.label != parent.label
                or generated.revision.state != "original"
            ):
                raise ProvenancePerturbationError("invalid_copied_evidence")
        elif perturbation.kind == "superseding-correction":
            if (
                parent is None
                or generated.provenance.parent_id != parent.annotation_id
                or generated.provenance.source_id != parent.provenance.source_id
                or generated.provenance.source_version
                == parent.provenance.source_version
                or generated.dependence_group != parent.dependence_group
                or generated.label == parent.label
                or generated.revision.supersedes_annotation_id != parent.annotation_id
            ):
                raise ProvenancePerturbationError("invalid_superseding_correction")
        elif perturbation.kind == "withdrawal":
            if (
                parent is None
                or generated.provenance.parent_id != parent.annotation_id
                or generated.provenance.source_id != parent.provenance.source_id
                or generated.provenance.source_version
                == parent.provenance.source_version
                or generated.dependence_group != parent.dependence_group
                or generated.revision.withdraws_annotation_id != parent.annotation_id
            ):
                raise ProvenancePerturbationError("invalid_withdrawal")
        elif perturbation.kind == "independent-corroboration":
            if (
                parent is not None
                or generated.provenance.parent_id is not None
                or generated.provenance.source_id in organic_sources
                or generated.dependence_group in organic_groups
                or generated.revision.state != "original"
                or generated.label not in {item.label for item in organic}
            ):
                raise ProvenancePerturbationError("invalid_independent_corroboration")


def load_fixture_bytes(payload: bytes) -> Fixture:
    """Load bounded JSON while rejecting duplicate keys and non-finite constants."""

    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_INPUT_BYTES:
        raise ProvenancePerturbationError("fixture_bytes_outside_bound")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvenancePerturbationError("invalid_json") from error
    return parse_fixture(value)


def _original_revision() -> Revision:
    return Revision("original", None, None)


def _annotation(
    annotation_id: str,
    *,
    label: str | None,
    event_time: int,
    arrival_time: int,
    source_id: str,
    source_version: str,
    dependence_group: str,
    origin: str,
    parent_id: str | None = None,
    revision: Revision | None = None,
) -> Annotation:
    return Annotation(
        annotation_id=annotation_id,
        observation_id="observation-a",
        event_time=event_time,
        arrival_time=arrival_time,
        label=label,
        provenance=Provenance(parent_id, source_id, source_version),
        dependence_group=dependence_group,
        revision=_original_revision() if revision is None else revision,
        origin=origin,
    )


def generate_fixture(seed: int = FIXED_SEED) -> Fixture:
    """Generate the fixed difficulty-5 rung from a local deterministic RNG."""

    if type(seed) is not int or not 0 <= seed <= 2**32 - 1:
        raise ProvenancePerturbationError("invalid_seed")
    rng = random.Random(seed)
    observation = Observation(
        "observation-a",
        event_time=0,
        arrival_time=0,
        provenance=Provenance(None, "observation-source", "version-a"),
        dependence_group="observation-group",
    )
    annotation_a = _annotation(
        "annotation-a-v1",
        label="label-a",
        event_time=10,
        arrival_time=10,
        source_id="source-a",
        source_version="version-a",
        dependence_group="group-a",
        origin="organic",
    )
    annotation_b = _annotation(
        "annotation-b-v1",
        label="label-b",
        event_time=20,
        arrival_time=20,
        source_id="source-b",
        source_version="version-a",
        dependence_group="group-b",
        origin="organic",
    )
    organic = (annotation_a, annotation_b)
    reorder = [item.annotation_id for item in organic]
    rng.shuffle(reorder)
    if reorder == [item.annotation_id for item in organic]:
        reorder.reverse()

    copied = _annotation(
        "annotation-a-copy",
        label="label-a",
        event_time=15,
        arrival_time=24,
        source_id="source-copy",
        source_version="version-a",
        dependence_group="group-a",
        origin="derived-perturbation",
        parent_id=annotation_a.annotation_id,
    )
    correction = _annotation(
        "annotation-a-v2",
        label="label-b",
        event_time=30,
        arrival_time=31,
        source_id="source-a",
        source_version="version-b",
        dependence_group="group-a",
        origin="derived-perturbation",
        parent_id=annotation_a.annotation_id,
        revision=Revision("superseding-correction", annotation_a.annotation_id, None),
    )
    withdrawal = _annotation(
        "annotation-b-withdrawal",
        label=None,
        event_time=30,
        arrival_time=31,
        source_id="source-b",
        source_version="version-b",
        dependence_group="group-b",
        origin="derived-perturbation",
        parent_id=annotation_b.annotation_id,
        revision=Revision("withdrawal", None, annotation_b.annotation_id),
    )
    independent = _annotation(
        "annotation-c-v1",
        label="label-a",
        event_time=15,
        arrival_time=24,
        source_id="source-c",
        source_version="version-a",
        dependence_group="group-c",
        origin="derived-perturbation",
    )
    delay_ticks = rng.randint(17, 29)
    fixture = Fixture(
        seed=seed,
        observations=(observation,),
        organic_annotations=organic,
        perturbations=(
            Perturbation(
                "perturbation-delay",
                "delay",
                annotation_a.annotation_id,
                None,
                delay_ticks,
                None,
            ),
            Perturbation(
                "perturbation-reorder", "reorder", None, None, None, tuple(reorder)
            ),
            Perturbation(
                "perturbation-duplicate",
                "exact-duplicate",
                annotation_a.annotation_id,
                None,
                None,
                None,
            ),
            Perturbation(
                "perturbation-copy",
                "copied-evidence",
                annotation_a.annotation_id,
                copied,
                None,
                None,
            ),
            Perturbation(
                "perturbation-correction",
                "superseding-correction",
                annotation_a.annotation_id,
                correction,
                None,
                None,
            ),
            Perturbation(
                "perturbation-withdrawal",
                "withdrawal",
                annotation_b.annotation_id,
                withdrawal,
                None,
                None,
            ),
            Perturbation(
                "perturbation-independent",
                "independent-corroboration",
                None,
                independent,
                None,
                None,
            ),
        ),
    )
    return parse_fixture(fixture.document())


def _scenario_annotations(
    fixture: Fixture, perturbation: Perturbation | None
) -> list[Annotation]:
    annotations = list(fixture.organic_annotations)
    if perturbation is None:
        return annotations
    by_id = {item.annotation_id: item for item in annotations}
    if perturbation.kind == "delay":
        parent_id = perturbation.parent_annotation_id
        assert parent_id is not None and perturbation.delay_ticks is not None
        annotations = [
            replace(item, arrival_time=item.arrival_time + perturbation.delay_ticks)
            if item.annotation_id == parent_id
            else item
            for item in annotations
        ]
    elif perturbation.kind == "reorder":
        assert perturbation.order is not None
        annotations = [by_id[annotation_id] for annotation_id in perturbation.order]
    elif perturbation.kind == "exact-duplicate":
        assert perturbation.parent_annotation_id is not None
        annotations.append(by_id[perturbation.parent_annotation_id])
    else:
        assert perturbation.generated_annotation is not None
        annotations.append(perturbation.generated_annotation)
    if len(annotations) > MAX_SCENARIO_ANNOTATIONS:
        raise ProvenancePerturbationError("scenario_annotation_count_outside_bound")
    return annotations


def _deduplicate_exact(annotations: Sequence[Annotation]) -> tuple[Annotation, ...]:
    by_id: dict[str, Annotation] = {}
    for annotation in annotations:
        prior = by_id.get(annotation.annotation_id)
        if prior is not None and prior != annotation:
            raise ProvenancePerturbationError("conflicting_duplicate_annotation")
        by_id[annotation.annotation_id] = annotation
    return tuple(by_id.values())


def _lineage(annotations: Sequence[Annotation]) -> list[dict[str, Any]]:
    by_id = {item.annotation_id: item for item in annotations}
    result = []
    for annotation in sorted(annotations, key=lambda item: item.annotation_id):
        parent_id = annotation.provenance.parent_id
        root_id = annotation.annotation_id
        seen = {root_id}
        while parent_id is not None:
            if parent_id in seen or parent_id not in by_id:
                raise ProvenancePerturbationError("invalid_annotation_lineage")
            seen.add(parent_id)
            root_id = parent_id
            parent_id = by_id[parent_id].provenance.parent_id
        result.append(
            {
                "annotation_id": annotation.annotation_id,
                "parent_annotation_id": annotation.provenance.parent_id,
                "root_annotation_id": root_id,
            }
        )
    return result


def _scenario_report(
    fixture: Fixture, perturbation: Perturbation | None
) -> dict[str, Any]:
    input_annotations = _scenario_annotations(fixture, perturbation)
    unique = _deduplicate_exact(input_annotations)
    event_order = sorted(unique, key=lambda item: (item.event_time, item.annotation_id))
    arrival_order = sorted(
        unique, key=lambda item: (item.arrival_time, item.annotation_id)
    )
    active: dict[str, Annotation] = {}
    for annotation in event_order:
        if annotation.revision.state == "original":
            active[annotation.annotation_id] = annotation
        elif annotation.revision.state == "superseding-correction":
            target = annotation.revision.supersedes_annotation_id
            if target not in active:
                raise ProvenancePerturbationError("superseded_annotation_not_active")
            del active[target]
            active[annotation.annotation_id] = annotation
        else:
            target = annotation.revision.withdraws_annotation_id
            if target not in active:
                raise ProvenancePerturbationError("withdrawn_annotation_not_active")
            del active[target]

    active_annotations = sorted(active.values(), key=lambda item: item.annotation_id)
    labels = {item.label for item in active_annotations}
    if not active_annotations:
        decision = {
            "state": "abstain",
            "label": None,
            "reason": "no-active-annotations",
        }
    elif len(labels) != 1:
        decision = {
            "state": "abstain",
            "label": None,
            "reason": "conflicting-active-labels",
        }
    else:
        decision = {"state": "decided", "label": next(iter(labels)), "reason": None}

    report = {
        "scenario_id": "baseline"
        if perturbation is None
        else perturbation.perturbation_id,
        "perturbation_kind": "none" if perturbation is None else perturbation.kind,
        "input_annotation_ids": [item.annotation_id for item in input_annotations],
        "event_chronology": [item.annotation_id for item in event_order],
        "arrival_chronology": [item.annotation_id for item in arrival_order],
        "active_annotation_ids": [item.annotation_id for item in active_annotations],
        "dependence_aware_evidence_count": len(
            {item.dependence_group for item in active_annotations}
        ),
        "lineage": _lineage(unique),
        "decision": decision,
    }
    _validate_scenario_report(report)
    return report


def _validate_scenario_report(value: Any) -> None:
    value = _exact_mapping(value, SCENARIO_FIELDS, "invalid_scenario_report_schema")
    if not all(
        isinstance(value[field], list)
        for field in (
            "input_annotation_ids",
            "event_chronology",
            "arrival_chronology",
            "active_annotation_ids",
            "lineage",
        )
    ):
        raise ProvenancePerturbationError("invalid_scenario_report_schema")
    for item in value["lineage"]:
        _exact_mapping(item, LINEAGE_FIELDS, "invalid_lineage_report_schema")
    _exact_mapping(value["decision"], DECISION_FIELDS, "invalid_decision_report_schema")


def evaluate_fixture(fixture: Fixture | Mapping[str, Any]) -> dict[str, Any]:
    """Evaluate each perturbation independently against the organic baseline."""

    if not isinstance(fixture, Fixture):
        fixture = parse_fixture(fixture)
    report = {
        "schema": REPORT_SCHEMA,
        "fixture_digest": fixture.content_digest(),
        "seed": fixture.seed,
        "scenarios": [
            _scenario_report(fixture, None),
            *(
                _scenario_report(fixture, perturbation)
                for perturbation in fixture.perturbations
            ),
        ],
    }
    _exact_mapping(report, REPORT_FIELDS, "invalid_report_schema")
    _canonical_json_bytes(report, MAX_OUTPUT_BYTES)
    return report


def _canonical_json_bytes(value: Any, maximum: int) -> bytes:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    if len(encoded) > maximum:
        raise ProvenancePerturbationError("json_output_outside_bound")
    return encoded


def report_json_bytes(fixture: Fixture | Mapping[str, Any]) -> bytes:
    return _canonical_json_bytes(evaluate_fixture(fixture), MAX_OUTPUT_BYTES)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "evaluate"))
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "generate":
            output = generate_fixture().canonical_json_bytes()
        else:
            payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
            output = report_json_bytes(load_fixture_bytes(payload))
    except ProvenancePerturbationError as error:
        print(error.code, file=sys.stderr)
        return 2
    sys.stdout.buffer.write(output + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
