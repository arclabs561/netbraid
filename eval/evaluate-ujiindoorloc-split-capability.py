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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARCHIVE = ROOT / "data" / "raw" / "UJIIndoorLoc.zip"
DEFAULT_RECEIPT = (
    ROOT / "data" / "receipts" / "public-eval-corpus" / "UJIIndoorLoc.zip.json"
)
DEFAULT_REPORT = (
    ROOT / "data" / "derived" / "eval" / "ujiindoorloc-split-capability.json"
)

SCHEMA = "netbraid.ujiindoorloc_split_capability.v0"
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


def evaluate_archive(
    archive_path: Path,
    receipt_path: Path,
    contract: ArtifactContract = DEFAULT_CONTRACT,
) -> Dict[str, Any]:
    """Verify and aggregate one archive without retaining row-level values."""

    size, md5, sha256 = _verify_integrity(archive_path, receipt_path, contract)
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            members = _validated_members(archive, contract)
            train = _read_partition(
                archive, members[TRAIN_MEMBER], contract.row_counts["train"]
            )
            validation = _read_partition(
                archive,
                members[VALIDATION_MEMBER],
                contract.row_counts["validation"],
            )
    except (OSError, zipfile.BadZipFile) as error:
        raise SplitCapabilityError("invalid_zip_archive") from error
    if _digest_regular_file(archive_path) != (size, md5, sha256):
        raise SplitCapabilityError("archive_changed_during_evaluation")

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
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = parse_args(argv)
    try:
        report = evaluate_archive(
            arguments.archive.expanduser().absolute(),
            arguments.receipt.expanduser().absolute(),
        )
        payload = render_report(report)
        write_report(arguments.report.expanduser().absolute(), payload)
    except SplitCapabilityError as error:
        print(error.code, file=sys.stderr)
        return 2
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
