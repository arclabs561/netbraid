#!/usr/bin/env python3
"""Audit the aggregate split capabilities of the pinned UJIIndoorLoc archive."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import stat
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

import ujiindoorloc as shared_uji

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARCHIVE = ROOT / "data" / "raw" / "UJIIndoorLoc.zip"
DEFAULT_RECEIPT = (
    ROOT / "data" / "receipts" / "public-eval-corpus" / "UJIIndoorLoc.zip.json"
)
DEFAULT_REPORT = (
    ROOT / "data" / "derived" / "eval" / "ujiindoorloc-split-capability.json"
)
DEFAULT_PHONE_HOLDOUT_REPORT = (
    ROOT / "data" / "derived" / "eval" / "ujiindoorloc-phone-holdout-feasibility.json"
)

SCHEMA = "netbraid.ujiindoorloc_split_capability.v0"
PHONE_HOLDOUT_SCHEMA = "netbraid.ujiindoorloc_phone_holdout_feasibility.v0"
RECEIPT_SCHEMA = "local.public_wireless_archive.v1"
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_ROWS = 22_000
MAX_FIELD_BYTES = 256
CHUNK_BYTES = 1024 * 1024

TRAIN_MEMBER = "UJIndoorLoc/trainingData.csv"
VALIDATION_MEMBER = "UJIndoorLoc/validationData.csv"
DIRECTORY_MEMBER = "UJIndoorLoc/"
WAP_FIELDS = tuple(f"WAP{index:03d}" for index in range(1, 521))
METADATA_FIELDS = (
    "LONGITUDE",
    "LATITUDE",
    "FLOOR",
    "BUILDINGID",
    "SPACEID",
    "RELATIVEPOSITION",
    "USERID",
    "PHONEID",
    "TIMESTAMP",
)
EXPECTED_HEADER = WAP_FIELDS + METADATA_FIELDS

DEFAULT_SOURCE = {
    "bytes": 1_463_759,
    "doi": "10.24432/C5MS59",
    "filename": "UJIIndoorLoc.zip",
    "group": "indoor-positioning",
    "license": "CC BY 4.0",
    "md5": "1699ee0071fa0ac43f5e59dde511f48a",
    "record": "ipin-2015-track3-ujiindoorloc",
    "record_bytes": 1_463_759,
    "sha256": "893512b82dfd7a7c345d84195b1c8019fbca0fa0d7820ce491ce5aa45ec3782f",
    "sha256_provenance": "computed_from_uci_static_artifact",
    "url": "https://archive.ics.uci.edu/static/public/310/ujiindoorloc.zip",
}


class SplitCapabilityError(RuntimeError):
    """Stable fail-closed reason for an invalid corpus or report boundary."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ArtifactContract:
    source: Mapping[str, Any]
    member_sizes: Mapping[str, int]
    row_counts: Mapping[str, int]


DEFAULT_CONTRACT = ArtifactContract(
    source=DEFAULT_SOURCE,
    member_sizes={
        TRAIN_MEMBER: 42_725_381,
        VALIDATION_MEMBER: 2_381_949,
    },
    row_counts={"train": 19_937, "validation": 1_111},
)


@dataclass
class PartitionSummary:
    rows: int
    observed_rssi_cells: int
    groups: Dict[str, set[Tuple[int, ...]]]
    axis_observed_rows: Dict[str, int]
    user_phone_units: Dict[Tuple[int, int], "UnitAggregate"]


@dataclass
class UnitAggregate:
    rows: int = 0
    target_groups: set[Tuple[int, int]] = field(default_factory=set)


@dataclass(frozen=True)
class HoldoutUnit:
    key: Tuple[int, ...]
    rows: int
    target_mask: int


AXIS_POLICIES = {
    "user": "identity_holdout",
    "phone": "acquisition_domain_holdout",
    "user_phone": "joint_identity_domain_holdout",
    "building": "target_coverage",
    "floor": "target_coverage",
    "building_floor": "target_coverage",
    "location_cell": "target_coverage",
}


def _digest_regular_file(path: Path) -> Tuple[int, str, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SplitCapabilityError("unsafe_archive_path") from error
    size = 0
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARCHIVE_BYTES:
            raise SplitCapabilityError("invalid_archive_extent")
        while chunk := source.read(CHUNK_BYTES):
            size += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
        after = os.fstat(source.fileno())
    if size != before.st_size or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise SplitCapabilityError("archive_changed_during_read")
    return size, md5.hexdigest(), sha256.hexdigest()


def _load_json_regular(path: Path, byte_limit: int) -> Mapping[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SplitCapabilityError("unsafe_receipt_path") from error
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > byte_limit:
            raise SplitCapabilityError("invalid_receipt_extent")
        payload = source.read(byte_limit + 1)
        after = os.fstat(source.fileno())
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise SplitCapabilityError("receipt_changed_during_read")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SplitCapabilityError("invalid_receipt_json") from error
    if not isinstance(value, Mapping):
        raise SplitCapabilityError("invalid_receipt_schema")
    return value


def _expected_receipt(contract: ArtifactContract) -> Dict[str, Any]:
    source = dict(contract.source)
    return {
        "schema": RECEIPT_SCHEMA,
        "archive": source["filename"],
        "bytes": source["bytes"],
        "md5": source["md5"],
        "sha256": source["sha256"],
        "source": source,
    }


def _verify_integrity(
    archive_path: Path, receipt_path: Path, contract: ArtifactContract
) -> Tuple[int, str, str]:
    receipt = _load_json_regular(receipt_path, MAX_RECEIPT_BYTES)
    if receipt != _expected_receipt(contract):
        raise SplitCapabilityError("receipt_contract_mismatch")
    size, md5, sha256 = _digest_regular_file(archive_path)
    source = contract.source
    if (size, md5, sha256) != (
        source["bytes"],
        source["md5"],
        source["sha256"],
    ):
        raise SplitCapabilityError("archive_integrity_mismatch")
    return size, md5, sha256


def _parse_int(value: str, minimum: int, maximum: int, code: str) -> int:
    if len(value.encode("utf-8")) > MAX_FIELD_BYTES:
        raise SplitCapabilityError(code)
    try:
        parsed = int(value)
    except ValueError as error:
        raise SplitCapabilityError(code) from error
    if not minimum <= parsed <= maximum:
        raise SplitCapabilityError(code)
    return parsed


def _parse_finite(value: str, code: str) -> None:
    if len(value.encode("utf-8")) > MAX_FIELD_BYTES:
        raise SplitCapabilityError(code)
    try:
        parsed = float(value)
    except ValueError as error:
        raise SplitCapabilityError(code) from error
    if not math.isfinite(parsed):
        raise SplitCapabilityError(code)


def _empty_groups() -> Dict[str, set[Tuple[int, ...]]]:
    return {axis: set() for axis in AXIS_POLICIES}


def _read_partition(
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    expected_rows: int,
) -> PartitionSummary:
    groups = _empty_groups()
    axis_observed_rows = {axis: 0 for axis in AXIS_POLICIES}
    rows = 0
    observed_rssi_cells = 0
    user_phone_units: Dict[Tuple[int, int], UnitAggregate] = {}
    try:
        raw = archive.open(member, "r")
        text = io.TextIOWrapper(raw, encoding="utf-8", newline="")
        with raw, text:
            reader = csv.reader(text)
            try:
                header = tuple(next(reader))
            except StopIteration as error:
                raise SplitCapabilityError("empty_csv_member") from error
            if header != EXPECTED_HEADER:
                raise SplitCapabilityError("unexpected_csv_header")
            for row in reader:
                rows += 1
                if rows > MAX_ROWS or len(row) != len(EXPECTED_HEADER):
                    raise SplitCapabilityError("invalid_csv_row_shape")
                for value in row[: len(WAP_FIELDS)]:
                    rssi = _parse_int(value, -104, 100, "invalid_rssi_value")
                    if 0 < rssi < 100:
                        raise SplitCapabilityError("invalid_rssi_value")
                    observed_rssi_cells += int(rssi != 100)
                _parse_finite(row[520], "invalid_longitude")
                _parse_finite(row[521], "invalid_latitude")
                floor = _parse_int(row[522], 0, 4, "invalid_floor")
                building = _parse_int(row[523], 0, 2, "invalid_building")
                space = _parse_int(row[524], 0, 10_000, "invalid_space")
                relative = _parse_int(row[525], 0, 2, "invalid_relative_position")
                user = _parse_int(row[526], 0, 18, "invalid_user")
                phone = _parse_int(row[527], 0, 24, "invalid_phone")
                _parse_int(row[528], 1, 4_294_967_295, "invalid_timestamp")

                groups["user"].add((user,))
                groups["phone"].add((phone,))
                groups["user_phone"].add((user, phone))
                groups["building"].add((building,))
                groups["floor"].add((floor,))
                groups["building_floor"].add((building, floor))
                unit = user_phone_units.setdefault((user, phone), UnitAggregate())
                unit.rows += 1
                unit.target_groups.add((building, floor))
                for axis in AXIS_POLICIES:
                    if axis != "location_cell":
                        axis_observed_rows[axis] += 1
                if (space == 0) != (relative == 0):
                    raise SplitCapabilityError("inconsistent_location_cell_state")
                if space != 0:
                    groups["location_cell"].add((building, floor, space, relative))
                    axis_observed_rows["location_cell"] += 1
    except SplitCapabilityError:
        raise
    except (
        OSError,
        RuntimeError,
        UnicodeDecodeError,
        csv.Error,
        zipfile.BadZipFile,
    ) as error:
        raise SplitCapabilityError("csv_stream_error") from error
    if rows != expected_rows:
        raise SplitCapabilityError("unexpected_partition_row_count")
    return PartitionSummary(
        rows=rows,
        observed_rssi_cells=observed_rssi_cells,
        groups=groups,
        axis_observed_rows=axis_observed_rows,
        user_phone_units=user_phone_units,
    )


def _validated_members(
    archive: zipfile.ZipFile, contract: ArtifactContract
) -> Dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    by_name: Dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        if info.filename in by_name:
            raise SplitCapabilityError("duplicate_archive_member")
        by_name[info.filename] = info
    expected = {DIRECTORY_MEMBER, *contract.member_sizes}
    if set(by_name) != expected:
        raise SplitCapabilityError("unexpected_archive_inventory")
    directory = by_name[DIRECTORY_MEMBER]
    if not directory.is_dir() or directory.file_size != 0:
        raise SplitCapabilityError("invalid_archive_directory")
    for name, expected_size in contract.member_sizes.items():
        info = by_name[name]
        mode = info.external_attr >> 16
        if (
            info.is_dir()
            or info.file_size != expected_size
            or info.file_size > 45 * 1024 * 1024
            or info.flag_bits & 0x1
            or stat.S_ISLNK(mode)
        ):
            raise SplitCapabilityError("invalid_archive_member")
    return by_name


def _read_verified_partitions(
    archive_path: Path,
    receipt_path: Path,
    contract: ArtifactContract = DEFAULT_CONTRACT,
) -> Tuple[Tuple[int, str, str], PartitionSummary, PartitionSummary]:
    """Verify one archive and return bounded in-memory aggregate summaries."""

    try:
        with shared_uji.verified_archive(
            archive_path,
            receipt_path,
            contract,
            verify=_verify_integrity,
            validate=_validated_members,
            digest=_digest_regular_file,
        ) as opened:
            integrity, archive, members = opened
            train = _read_partition(
                archive, members[TRAIN_MEMBER], contract.row_counts["train"]
            )
            validation = _read_partition(
                archive,
                members[VALIDATION_MEMBER],
                contract.row_counts["validation"],
            )
    except shared_uji.UjiIndoorLocError as error:
        raise SplitCapabilityError(error.code) from error
    return integrity, train, validation


def evaluate_archive(
    archive_path: Path,
    receipt_path: Path,
    contract: ArtifactContract = DEFAULT_CONTRACT,
) -> Dict[str, Any]:
    """Verify and aggregate the publisher split without retaining row values."""

    (size, md5, sha256), train, validation = _read_verified_partitions(
        archive_path, receipt_path, contract
    )

    axes = []
    intersections: Dict[str, int] = {}
    for axis, policy in AXIS_POLICIES.items():
        train_groups = train.groups[axis]
        validation_groups = validation.groups[axis]
        intersection = len(train_groups & validation_groups)
        intersections[axis] = intersection
        axes.append(
            {
                "axis": axis,
                "policy": policy,
                "train_group_count": len(train_groups),
                "validation_group_count": len(validation_groups),
                "intersection_group_count": intersection,
                "train_only_group_count": len(train_groups - validation_groups),
                "validation_only_group_count": len(validation_groups - train_groups),
                "train_observed_row_count": train.axis_observed_rows[axis],
                "validation_observed_row_count": validation.axis_observed_rows[axis],
            }
        )

    return {
        "schema": SCHEMA,
        "status": "pass",
        "integrity": {"bytes": size, "md5": md5, "sha256": sha256},
        "schema_summary": {
            "columns": len(EXPECTED_HEADER),
            "rssi_columns": len(WAP_FIELDS),
            "metadata_columns": len(METADATA_FIELDS),
            "csv_members": 2,
        },
        "rows": {
            "train": train.rows,
            "validation": validation.rows,
            "total": train.rows + validation.rows,
            "observed_rssi_cells": (
                train.observed_rssi_cells + validation.observed_rssi_cells
            ),
        },
        "axes": axes,
        "capabilities": {
            "user_disjoint": intersections["user"] == 0,
            "phone_disjoint": intersections["phone"] == 0,
            "joint_user_phone_disjoint": intersections["user_phone"] == 0,
            "shared_building_floor_coverage": intersections["building_floor"] > 0,
            "shared_location_cell_coverage": (
                None
                if train.axis_observed_rows["location_cell"] == 0
                or validation.axis_observed_rows["location_cell"] == 0
                else intersections["location_cell"] > 0
            ),
        },
        "privacy": {
            "rows_retained": 0,
            "rssi_vectors_retained": 0,
            "coordinate_values_retained": 0,
            "timestamp_values_retained": 0,
            "identifier_values_retained": 0,
            "member_paths_retained": 0,
            "source_urls_retained": 0,
            "local_paths_retained": 0,
        },
    }


def _combined_user_phone_units(
    partitions: Sequence[PartitionSummary],
) -> Dict[Tuple[int, int], UnitAggregate]:
    combined: Dict[Tuple[int, int], UnitAggregate] = {}
    for partition in partitions:
        for key, source in partition.user_phone_units.items():
            target = combined.setdefault(key, UnitAggregate())
            target.rows += source.rows
            target.target_groups.update(source.target_groups)
    return combined


def _target_masks(
    aggregates: Mapping[Tuple[int, ...], UnitAggregate],
) -> Tuple[list[HoldoutUnit], int, int]:
    target_groups = sorted(
        {
            target
            for aggregate in aggregates.values()
            for target in aggregate.target_groups
        }
    )
    target_bits = {target: 1 << index for index, target in enumerate(target_groups)}
    units = [
        HoldoutUnit(
            key=key,
            rows=aggregate.rows,
            target_mask=sum(target_bits[target] for target in aggregate.target_groups),
        )
        for key, aggregate in sorted(aggregates.items())
    ]
    return units, (1 << len(target_groups)) - 1, len(target_groups)


def _phone_units(
    edges: Mapping[Tuple[int, int], UnitAggregate],
) -> Dict[Tuple[int, ...], UnitAggregate]:
    phones: Dict[Tuple[int, ...], UnitAggregate] = {}
    for (_, phone), edge in edges.items():
        unit = phones.setdefault((phone,), UnitAggregate())
        unit.rows += edge.rows
        unit.target_groups.update(edge.target_groups)
    return phones


def _joint_user_phone_units(
    edges: Mapping[Tuple[int, int], UnitAggregate],
) -> Dict[Tuple[int, ...], UnitAggregate]:
    parents: Dict[Tuple[str, int], Tuple[str, int]] = {}

    def root(node: Tuple[str, int]) -> Tuple[str, int]:
        parents.setdefault(node, node)
        while parents[node] != node:
            parents[node] = parents[parents[node]]
            node = parents[node]
        return node

    def union(left: Tuple[str, int], right: Tuple[str, int]) -> None:
        left_root = root(left)
        right_root = root(right)
        if left_root == right_root:
            return
        if left_root > right_root:
            left_root, right_root = right_root, left_root
        parents[right_root] = left_root

    for user, phone in edges:
        union(("user", user), ("phone", phone))

    components: Dict[Tuple[str, int], UnitAggregate] = {}
    identities: Dict[Tuple[str, int], set[int]] = {}
    for (user, phone), edge in edges.items():
        component = root(("user", user))
        aggregate = components.setdefault(component, UnitAggregate())
        aggregate.rows += edge.rows
        aggregate.target_groups.update(edge.target_groups)
        values = identities.setdefault(component, set())
        values.add(-(user + 1))
        values.add(phone + 1)
    return {tuple(sorted(identities[key])): value for key, value in components.items()}


def _minimum_target_support(units: Sequence[HoldoutUnit], full_mask: int) -> int:
    if full_mask == 0:
        return 0
    return min(
        sum(bool(unit.target_mask & (1 << bit)) for unit in units)
        for bit in range(full_mask.bit_length())
    )


def _count_bits(value: int) -> int:
    return bin(value).count("1")


def _covering_subsets(available: Tuple[HoldoutUnit, ...], full_mask: int):
    """Yield deterministic covers containing the first unit.

    Roles are interchangeable during the feasibility search, so every complete
    assignment has an equivalent ordering where the first available unit is in
    the role currently being constructed.
    """

    first = available[0]
    yielded: set[Tuple[Tuple[int, ...], ...]] = set()

    def visit(
        selected: Tuple[HoldoutUnit, ...],
        remaining: Tuple[HoldoutUnit, ...],
        covered: int,
    ):
        if covered == full_mask:
            identity = tuple(unit.key for unit in selected)
            if identity not in yielded:
                yielded.add(identity)
                yield selected
            return
        if covered | _union_mask(remaining) != full_mask:
            return
        missing_bits = [
            bit for bit in range(full_mask.bit_length()) if not covered & (1 << bit)
        ]
        bit = min(
            missing_bits,
            key=lambda item: (
                sum(bool(unit.target_mask & (1 << item)) for unit in remaining),
                item,
            ),
        )
        candidates = [unit for unit in remaining if unit.target_mask & (1 << bit)]
        candidates.sort(
            key=lambda unit: (
                -_count_bits(unit.target_mask & ~covered),
                unit.rows,
                unit.key,
            )
        )
        for candidate in candidates:
            next_remaining = tuple(unit for unit in remaining if unit != candidate)
            yield from visit(
                selected + (candidate,),
                next_remaining,
                covered | candidate.target_mask,
            )

    remaining = tuple(unit for unit in available if unit != first)
    yield from visit((first,), remaining, first.target_mask)


def _union_mask(units: Sequence[HoldoutUnit]) -> int:
    result = 0
    for unit in units:
        result |= unit.target_mask
    return result


def _find_role_assignment(
    units: Sequence[HoldoutUnit], full_mask: int, role_count: int
) -> Optional[Tuple[Tuple[HoldoutUnit, ...], ...]]:
    return shared_uji.find_role_assignment(units, full_mask, role_count)


def _assignment_balance(
    assignment: Sequence[Sequence[HoldoutUnit]],
) -> Tuple[int, int, int]:
    row_counts = [sum(unit.rows for unit in role_units) for role_units in assignment]
    return (
        max(row_counts),
        max(row_counts) - min(row_counts),
        sum(count * count for count in row_counts),
    )


def _balance_assignment(
    assignment: Tuple[Tuple[HoldoutUnit, ...], ...], full_mask: int
) -> Tuple[Tuple[HoldoutUnit, ...], ...]:
    """Improve row balance with deterministic coverage-preserving moves."""

    current = tuple(tuple(role_units) for role_units in assignment)
    while True:
        current_score = _assignment_balance(current)
        best = None
        for donor_index, donor in enumerate(current):
            if len(donor) <= 1:
                continue
            for unit in donor:
                reduced = tuple(item for item in donor if item != unit)
                if _union_mask(reduced) != full_mask:
                    continue
                for receiver_index in range(len(current)):
                    if receiver_index == donor_index:
                        continue
                    candidate = list(current)
                    candidate[donor_index] = reduced
                    candidate[receiver_index] = tuple(
                        sorted(
                            (*candidate[receiver_index], unit),
                            key=lambda item: item.key,
                        )
                    )
                    candidate_tuple = tuple(candidate)
                    score = _assignment_balance(candidate_tuple)
                    tie_break = (donor_index, receiver_index, unit.key)
                    if score >= current_score:
                        continue
                    if best is None or (score, tie_break) < (best[0], best[1]):
                        best = (score, tie_break, candidate_tuple)
        if best is None:
            return current
        current = best[2]


def _feasibility_report(
    units: Sequence[HoldoutUnit], full_mask: int, target_count: int
) -> Dict[str, Any]:
    roles = ("train", "calibration", "validation", "test")
    minimum_support = _minimum_target_support(units, full_mask)
    if len(units) < len(roles):
        blocker = "insufficient_disjoint_units"
        assignment = None
    elif minimum_support < len(roles):
        blocker = "target_group_support_below_role_count"
        assignment = None
    else:
        assignment = _find_role_assignment(units, full_mask, len(roles))
        blocker = None if assignment is not None else "no_complete_role_assignment"

    candidate = None
    if assignment is not None:
        assigned_units = [unit for role_units in assignment for unit in role_units]
        assigned_keys = [unit.key for unit in assigned_units]
        unique_assigned_keys = set(assigned_keys)
        expected_keys = {unit.key for unit in units}
        candidate = {
            "all_rows_assigned_once": (
                len(assigned_keys) == len(unique_assigned_keys)
                and unique_assigned_keys == expected_keys
                and sum(unit.rows for unit in assigned_units)
                == sum(unit.rows for unit in units)
            ),
            "all_units_assigned_once": (
                len(assigned_keys) == len(unique_assigned_keys)
                and unique_assigned_keys == expected_keys
            ),
            "disjoint_unit_overlap_count": len(assigned_keys)
            - len(unique_assigned_keys),
            "is_benchmark_recommendation": False,
            "row_balance_method": "coverage_preserving_single_unit_local_search",
            "roles": [
                {
                    "role": role,
                    "unit_count": len(role_units),
                    "row_count": sum(unit.rows for unit in role_units),
                    "target_group_count": _count_bits(_union_mask(role_units)),
                    "missing_target_group_count": _count_bits(
                        full_mask & ~_union_mask(role_units)
                    ),
                }
                for role, role_units in zip(roles, assignment)
            ],
        }
    return {
        "status": "candidate_found" if assignment is not None else "blocked",
        "blocker": blocker,
        "unit_count": len(units),
        "target_group_count": target_count,
        "minimum_target_group_unit_support": minimum_support,
        "candidate": candidate,
    }


def evaluate_phone_holdout_feasibility(
    archive_path: Path,
    receipt_path: Path,
    contract: ArtifactContract = DEFAULT_CONTRACT,
) -> Dict[str, Any]:
    """Test aggregate four-role holdout feasibility on the verified corpus."""

    (size, md5, sha256), train, validation = _read_verified_partitions(
        archive_path, receipt_path, contract
    )
    edges = _combined_user_phone_units((train, validation))
    phone_units, full_mask, target_count = _target_masks(_phone_units(edges))
    joint_units, joint_mask, joint_target_count = _target_masks(
        _joint_user_phone_units(edges)
    )
    if (joint_mask, joint_target_count) != (full_mask, target_count):
        raise SplitCapabilityError("inconsistent_holdout_target_frame")
    return {
        "schema": PHONE_HOLDOUT_SCHEMA,
        "status": "pass",
        "integrity": {"bytes": size, "md5": md5, "sha256": sha256},
        "rows": {
            "publisher_train": train.rows,
            "publisher_validation": validation.rows,
            "total": train.rows + validation.rows,
        },
        "roles": ["train", "calibration", "validation", "test"],
        "coverage_axis": "building_floor",
        "phone_holdout": _feasibility_report(phone_units, full_mask, target_count),
        "joint_user_phone_holdout": _feasibility_report(
            joint_units, joint_mask, joint_target_count
        ),
        "privacy": {
            "rows_retained": 0,
            "rssi_vectors_retained": 0,
            "coordinate_values_retained": 0,
            "timestamp_values_retained": 0,
            "identifier_values_retained": 0,
            "group_assignments_retained": 0,
            "member_paths_retained": 0,
            "source_urls_retained": 0,
            "local_paths_retained": 0,
        },
    }


def render_report(report: Mapping[str, Any]) -> bytes:
    try:
        return (
            json.dumps(
                report,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise SplitCapabilityError("report_not_json_serializable") from error


def write_report(path: Path, payload: bytes) -> None:
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = path.parent.lstat()
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
            raise SplitCapabilityError("unsafe_report_directory")
        if path.is_symlink() or (
            path.exists() and not stat.S_ISREG(path.lstat().st_mode)
        ):
            raise SplitCapabilityError("unsafe_report_path")
        descriptor, temporary = tempfile.mkstemp(
            prefix="." + path.name + ".", dir=path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    except SplitCapabilityError:
        raise
    except OSError as error:
        raise SplitCapabilityError("report_io_error") from error


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--phone-holdout-report", type=Path)
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = parse_args(argv)
    try:
        archive = arguments.archive.expanduser().absolute()
        receipt = arguments.receipt.expanduser().absolute()
        if arguments.phone_holdout_report is None:
            report = evaluate_archive(archive, receipt)
            report_path = arguments.report
        else:
            report = evaluate_phone_holdout_feasibility(archive, receipt)
            report_path = arguments.phone_holdout_report
        payload = render_report(report)
        write_report(report_path.expanduser().absolute(), payload)
    except SplitCapabilityError as error:
        print(error.code, file=sys.stderr)
        return 2
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
