#!/usr/bin/env python3
"""Audit declared group separation in evaluation observation partitions.

The manifest carries manifest-local opaque identifiers only. It has no raw
observations, labels, paths, addresses, timestamps, or model outputs. The
report is a deterministic inventory of declared group overlap; it does not
estimate performance, uncertainty, significance, or population behavior.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any, Optional

MANIFEST_SCHEMA = "netbraid.relation_split_manifest.v2"
AUDIT_SCHEMA = "netbraid.relation_split_audit.v2"

AXES = (
    "event",
    "physical_device",
    "physical_source",
    "variant",
    "session",
    "domain",
    "day",
    "receiver",
    "location",
    "channel",
    "configuration",
)
ROLES = ("train", "calibration", "validation", "test")
ROLE_PAIRS = tuple(combinations(ROLES, 2))
ROLE_PAIR_SET = frozenset(ROLE_PAIRS)
MANDATORY_ALL_PAIR_AXES = frozenset(("event", "session"))
GROUP_STATES = ("known", "unknown", "not_observed")

MAX_PARTITIONS = 32
MAX_OBSERVATIONS_PER_PARTITION = 4_096
MAX_TOTAL_OBSERVATIONS = 10_000
MAX_ID_BYTES = 64
MAX_INPUT_BYTES = 16 * 1024 * 1024

# Hash-like identifiers prevent source values from being mistaken for local IDs.
OPAQUE_ID_PATTERN = re.compile(r"[a-f0-9]{16,64}\Z")

MANIFEST_FIELDS = ("schema", "policies", "partitions")
POLICY_FIELDS = ("forbidden_role_pairs",)
PARTITION_FIELDS = ("partition_id", "role", "observations")
GROUP_FIELDS = ("state", "group_id")
OBSERVATION_FIELDS = ("observation_id",) + tuple(f"{axis}_group" for axis in AXES)


class RelationSplitError(ValueError):
    """Stable fail-closed reason for an invalid relation-split manifest."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GroupValue:
    state: str
    group_id: Optional[str]

    def document(self) -> dict[str, Any]:
        return {"state": self.state, "group_id": self.group_id}


@dataclass(frozen=True)
class AxisPolicy:
    forbidden_role_pairs: tuple[tuple[str, str], ...]

    def document(self) -> dict[str, Any]:
        return {
            "forbidden_role_pairs": [
                list(role_pair) for role_pair in self.forbidden_role_pairs
            ]
        }


@dataclass(frozen=True)
class Observation:
    observation_id: str
    groups: tuple[GroupValue, ...]

    def group(self, axis: str) -> GroupValue:
        return self.groups[AXES.index(axis)]

    def document(self) -> dict[str, Any]:
        return {
            "observation_id": self.observation_id,
            **{
                f"{axis}_group": self.groups[index].document()
                for index, axis in enumerate(AXES)
            },
        }


@dataclass(frozen=True)
class Partition:
    partition_id: str
    role: str
    observations: tuple[Observation, ...]

    def document(self) -> dict[str, Any]:
        return {
            "partition_id": self.partition_id,
            "role": self.role,
            "observations": [
                observation.document()
                for observation in sorted(
                    self.observations, key=lambda item: item.observation_id
                )
            ],
        }


@dataclass(frozen=True)
class RelationSplitManifest:
    policies: tuple[AxisPolicy, ...]
    partitions: tuple[Partition, ...]

    def policy(self, axis: str) -> AxisPolicy:
        return self.policies[AXES.index(axis)]

    def document(self) -> dict[str, Any]:
        return {
            "schema": MANIFEST_SCHEMA,
            "policies": {
                axis: self.policies[index].document() for index, axis in enumerate(AXES)
            },
            "partitions": [
                partition.document()
                for partition in sorted(
                    self.partitions, key=lambda item: item.partition_id
                )
            ],
        }


def _expect_fields(value: Mapping[str, Any], fields: Sequence[str], code: str) -> None:
    if set(value) != set(fields):
        raise RelationSplitError(code)


def _parse_partition_id(value: Any) -> str:
    return _parse_opaque_id(value, "invalid_partition_id")


def _parse_opaque_id(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or OPAQUE_ID_PATTERN.fullmatch(value) is None
        or len(value.encode("utf-8")) > MAX_ID_BYTES
    ):
        raise RelationSplitError(code)
    return value


def _parse_group(value: Any, axis: str) -> GroupValue:
    if not isinstance(value, Mapping):
        raise RelationSplitError("invalid_group_schema")
    _expect_fields(value, GROUP_FIELDS, "invalid_group_schema")
    state = value["state"]
    if not isinstance(state, str) or state not in GROUP_STATES:
        raise RelationSplitError("invalid_group_state")
    group_id = value["group_id"]
    if state == "known":
        group_id = _parse_opaque_id(group_id, "invalid_group_id")
    elif group_id is not None:
        raise RelationSplitError(f"{axis}_group_id_requires_known_state")
    return GroupValue(state=state, group_id=group_id)


def _parse_role_pair(value: Any) -> tuple[str, str]:
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(not isinstance(role, str) or role not in ROLES for role in value)
        or value[0] == value[1]
    ):
        raise RelationSplitError("invalid_forbidden_role_pair")
    left, right = value
    if ROLES.index(left) > ROLES.index(right):
        left, right = right, left
    return left, right


def _parse_policy(value: Any, axis: str) -> AxisPolicy:
    if not isinstance(value, Mapping):
        raise RelationSplitError("invalid_axis_policy_schema")
    _expect_fields(value, POLICY_FIELDS, "invalid_axis_policy_schema")
    raw_pairs = value["forbidden_role_pairs"]
    if not isinstance(raw_pairs, list) or len(raw_pairs) > len(ROLE_PAIRS):
        raise RelationSplitError("invalid_forbidden_role_pairs")
    parsed_pairs = tuple(_parse_role_pair(item) for item in raw_pairs)
    pair_set = frozenset(parsed_pairs)
    if len(pair_set) != len(parsed_pairs):
        raise RelationSplitError("duplicate_forbidden_role_pair")
    if axis in MANDATORY_ALL_PAIR_AXES and pair_set != ROLE_PAIR_SET:
        raise RelationSplitError("mandatory_axis_requires_all_role_pairs")
    return AxisPolicy(
        forbidden_role_pairs=tuple(
            role_pair for role_pair in ROLE_PAIRS if role_pair in pair_set
        )
    )


def _parse_observation(value: Any) -> Observation:
    if not isinstance(value, Mapping):
        raise RelationSplitError("invalid_observation_schema")
    _expect_fields(value, OBSERVATION_FIELDS, "invalid_observation_schema")
    observation_id = _parse_opaque_id(value["observation_id"], "invalid_observation_id")
    groups = tuple(_parse_group(value[f"{axis}_group"], axis) for axis in AXES)
    return Observation(observation_id=observation_id, groups=groups)


def _parse_partition(value: Any) -> Partition:
    if not isinstance(value, Mapping):
        raise RelationSplitError("invalid_partition_schema")
    _expect_fields(value, PARTITION_FIELDS, "invalid_partition_schema")
    partition_id = _parse_partition_id(value["partition_id"])
    role = value["role"]
    if not isinstance(role, str) or role not in ROLES:
        raise RelationSplitError("invalid_partition_role")
    observations = value["observations"]
    if (
        not isinstance(observations, list)
        or not 1 <= len(observations) <= MAX_OBSERVATIONS_PER_PARTITION
    ):
        raise RelationSplitError("invalid_partition_observation_count")
    return Partition(
        partition_id=partition_id,
        role=role,
        observations=tuple(_parse_observation(item) for item in observations),
    )


def parse_manifest(value: Any) -> RelationSplitManifest:
    """Parse one exact-shape, bounded observation-partition manifest."""

    if not isinstance(value, Mapping):
        raise RelationSplitError("invalid_manifest_schema")
    _expect_fields(value, MANIFEST_FIELDS, "invalid_manifest_schema")
    if value["schema"] != MANIFEST_SCHEMA:
        raise RelationSplitError("unsupported_manifest_schema")

    policies = value["policies"]
    if not isinstance(policies, Mapping):
        raise RelationSplitError("invalid_policy_schema")
    _expect_fields(policies, AXES, "invalid_policy_schema")
    parsed_policies = tuple(_parse_policy(policies[axis], axis) for axis in AXES)

    raw_partitions = value["partitions"]
    if (
        not isinstance(raw_partitions, list)
        or not len(ROLES) <= len(raw_partitions) <= MAX_PARTITIONS
    ):
        raise RelationSplitError("invalid_partition_count")
    partitions = tuple(_parse_partition(item) for item in raw_partitions)
    partition_ids = [partition.partition_id for partition in partitions]
    if len(set(partition_ids)) != len(partition_ids):
        raise RelationSplitError("duplicate_partition_id")
    if {partition.role for partition in partitions} != set(ROLES):
        raise RelationSplitError("missing_required_role")

    observation_ids = [
        observation.observation_id
        for partition in partitions
        for observation in partition.observations
    ]
    if len(observation_ids) > MAX_TOTAL_OBSERVATIONS:
        raise RelationSplitError("total_observation_limit_exceeded")
    if len(set(observation_ids)) != len(observation_ids):
        raise RelationSplitError("duplicate_observation_id")

    return RelationSplitManifest(
        policies=parsed_policies,
        partitions=partitions,
    )


def canonical_manifest(manifest: RelationSplitManifest) -> dict[str, Any]:
    """Return the parsed manifest with partitions and observations ordered."""

    return manifest.document()


def _axis_audit(manifest: RelationSplitManifest, axis: str) -> dict[str, Any]:
    policy = manifest.policy(axis)
    state_counts: Counter[str] = Counter()
    role_state_counts = {role: Counter() for role in ROLES}
    known_by_role = {role: Counter() for role in ROLES}

    for partition in manifest.partitions:
        for observation in partition.observations:
            group = observation.group(axis)
            state_counts[group.state] += 1
            role_state_counts[partition.role][group.state] += 1
            if group.state == "known":
                assert group.group_id is not None
                known_by_role[partition.role][group.group_id] += 1

    forbidden_pairs = frozenset(policy.forbidden_role_pairs)
    pair_intersections = []
    for left, right in ROLE_PAIRS:
        intersection = known_by_role[left].keys() & known_by_role[right].keys()
        forbidden = (left, right) in forbidden_pairs
        incomplete_coverage = any(
            role_state_counts[role]["unknown"]
            or role_state_counts[role]["not_observed"]
            for role in (left, right)
        )
        if not forbidden:
            pair_status = "allowed"
        elif intersection:
            pair_status = "fail"
        elif incomplete_coverage:
            pair_status = "unknown"
        else:
            pair_status = "pass"
        pair_intersections.append(
            {
                "roles": [left, right],
                "forbidden": forbidden,
                "status": pair_status,
                "known_group_intersection_count": len(intersection),
                "known_observations_in_intersection": {
                    left: sum(known_by_role[left][item] for item in intersection),
                    right: sum(known_by_role[right][item] for item in intersection),
                },
            }
        )

    forbidden_statuses = [
        item["status"] for item in pair_intersections if item["forbidden"]
    ]
    if "fail" in forbidden_statuses:
        status = "fail"
    elif "unknown" in forbidden_statuses:
        status = "unknown"
    else:
        status = "pass"

    return {
        "axis": axis,
        "policy": policy.document(),
        "status": status,
        "observation_state_counts": {
            state: state_counts[state] for state in GROUP_STATES
        },
        "role_observation_state_counts": {
            role: {state: role_state_counts[role][state] for state in GROUP_STATES}
            for role in ROLES
        },
        "distinct_known_group_count": len(
            set().union(*(known_by_role[role] for role in ROLES))
        ),
        "pair_intersections": pair_intersections,
    }


def audit_parsed_manifest(manifest: RelationSplitManifest) -> dict[str, Any]:
    """Report raw declared-group counts and policy violations."""

    axes = [_axis_audit(manifest, axis) for axis in AXES]
    if any(axis["status"] == "fail" for axis in axes):
        status = "fail"
    elif any(axis["status"] == "unknown" for axis in axes):
        status = "unknown"
    else:
        status = "pass"

    ordered_partitions = sorted(
        manifest.partitions, key=lambda partition: partition.partition_id
    )
    return {
        "schema": AUDIT_SCHEMA,
        "manifest_schema": MANIFEST_SCHEMA,
        "status": status,
        "counts": {
            "partitions": len(ordered_partitions),
            "observations": sum(
                len(partition.observations) for partition in ordered_partitions
            ),
            "roles": len(ROLES),
        },
        "roles": [
            {
                "role": role,
                "partition_count": sum(
                    partition.role == role for partition in ordered_partitions
                ),
                "observation_count": sum(
                    len(partition.observations)
                    for partition in ordered_partitions
                    if partition.role == role
                ),
            }
            for role in ROLES
        ],
        "partitions": [
            {
                "partition_id": partition.partition_id,
                "role": partition.role,
                "observation_count": len(partition.observations),
            }
            for partition in ordered_partitions
        ],
        "axes": axes,
        "interpretation": {
            "basis": "manifest_declared_groups_only",
            "reported_values": "raw_counts",
            "statistical_inference": "not_performed",
            "population_claims": "not_made",
        },
        "limits": {
            "partitions": MAX_PARTITIONS,
            "observations_per_partition": MAX_OBSERVATIONS_PER_PARTITION,
            "total_observations": MAX_TOTAL_OBSERVATIONS,
            "identifier_bytes": MAX_ID_BYTES,
        },
    }


def audit_manifest(value: Any) -> dict[str, Any]:
    """Validate and audit a relation-split manifest."""

    return audit_parsed_manifest(parse_manifest(value))


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RelationSplitError("duplicate_json_key")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise RelationSplitError("invalid_json_constant")


def load_manifest_bytes(data: bytes) -> Mapping[str, Any]:
    if len(data) > MAX_INPUT_BYTES:
        raise RelationSplitError("manifest_too_large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RelationSplitError("invalid_json") from error
    value = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(value, Mapping):
        raise RelationSplitError("invalid_manifest_schema")
    return value


def _arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "manifest",
        nargs="?",
        default="-",
        help="JSON manifest path, or -/omitted for stdin",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = _arguments(argv)
    try:
        if arguments.manifest == "-":
            manifest = load_manifest_bytes(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
        else:
            with Path(arguments.manifest).open("rb") as source:
                manifest = load_manifest_bytes(source.read(MAX_INPUT_BYTES + 1))
        report = audit_manifest(manifest)
    except RelationSplitError as error:
        print(error.code, file=sys.stderr)
        return 2
    except json.JSONDecodeError:
        print("invalid_json", file=sys.stderr)
        return 2
    except OSError:
        print("manifest_io_error", file=sys.stderr)
        return 2

    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
