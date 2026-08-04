"""Verified UJIIndoorLoc reading and deterministic phone-role splitting."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import os
import stat
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARCHIVE = ROOT / "data" / "raw" / "UJIIndoorLoc.zip"
DEFAULT_RECEIPT = (
    ROOT / "data" / "receipts" / "public-eval-corpus" / "UJIIndoorLoc.zip.json"
)
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
ROLES = ("train", "calibration", "validation", "test")

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


class UjiIndoorLocError(RuntimeError):
    """Stable fail-closed reason for an invalid corpus or split boundary."""

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
    member_sizes={TRAIN_MEMBER: 42_725_381, VALIDATION_MEMBER: 2_381_949},
    row_counts={"train": 19_937, "validation": 1_111},
)


@dataclass(frozen=True)
class ModelRow:
    rssi: tuple[int | None, ...]
    building: int
    floor: int
    phone: int

    @property
    def target(self) -> tuple[int, int]:
        return (self.building, self.floor)


@dataclass
class PhoneAggregate:
    rows: int = 0
    targets: set[tuple[int, int]] = field(default_factory=set)


@dataclass(frozen=True)
class SplitUnit:
    key: tuple[int, ...]
    rows: int
    target_mask: int


@dataclass(frozen=True)
class CorpusScan:
    integrity: tuple[int, str, str]
    publisher_rows: Mapping[str, int]
    phones: Mapping[int, PhoneAggregate]


@dataclass(frozen=True)
class PhoneRolePlan:
    phone_roles: Mapping[int, str]
    row_counts: Mapping[str, int]
    phone_counts: Mapping[str, int]
    target_counts: Mapping[str, int]
    target_count: int


def digest_regular_file(path: Path) -> tuple[int, str, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise UjiIndoorLocError("unsafe_archive_path") from error
    size = 0
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARCHIVE_BYTES:
            raise UjiIndoorLocError("invalid_archive_extent")
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
        raise UjiIndoorLocError("archive_changed_during_read")
    return size, md5.hexdigest(), sha256.hexdigest()


def load_json_regular(path: Path, byte_limit: int) -> Mapping[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise UjiIndoorLocError("unsafe_receipt_path") from error
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > byte_limit:
            raise UjiIndoorLocError("invalid_receipt_extent")
        payload = source.read(byte_limit + 1)
        after = os.fstat(source.fileno())
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise UjiIndoorLocError("receipt_changed_during_read")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UjiIndoorLocError("invalid_receipt_json") from error
    if not isinstance(value, Mapping):
        raise UjiIndoorLocError("invalid_receipt_schema")
    return value


def expected_receipt(contract: ArtifactContract) -> dict[str, Any]:
    source = dict(contract.source)
    return {
        "schema": RECEIPT_SCHEMA,
        "archive": source["filename"],
        "bytes": source["bytes"],
        "md5": source["md5"],
        "sha256": source["sha256"],
        "source": source,
    }


def verify_integrity(
    archive_path: Path, receipt_path: Path, contract: ArtifactContract
) -> tuple[int, str, str]:
    if load_json_regular(receipt_path, MAX_RECEIPT_BYTES) != expected_receipt(contract):
        raise UjiIndoorLocError("receipt_contract_mismatch")
    integrity = digest_regular_file(archive_path)
    if integrity != (
        contract.source["bytes"],
        contract.source["md5"],
        contract.source["sha256"],
    ):
        raise UjiIndoorLocError("archive_integrity_mismatch")
    return integrity


def validated_members(
    archive: zipfile.ZipFile, contract: ArtifactContract
) -> dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    by_name: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        if info.filename in by_name:
            raise UjiIndoorLocError("duplicate_archive_member")
        by_name[info.filename] = info
    if set(by_name) != {DIRECTORY_MEMBER, *contract.member_sizes}:
        raise UjiIndoorLocError("unexpected_archive_inventory")
    directory = by_name[DIRECTORY_MEMBER]
    if not directory.is_dir() or directory.file_size != 0:
        raise UjiIndoorLocError("invalid_archive_directory")
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
            raise UjiIndoorLocError("invalid_archive_member")
    return by_name


@contextmanager
def verified_archive(
    archive_path: Path,
    receipt_path: Path,
    contract: ArtifactContract,
    *,
    verify: Callable[
        [Path, Path, ArtifactContract], tuple[int, str, str]
    ] = verify_integrity,
    validate: Callable[
        [zipfile.ZipFile, ArtifactContract], Mapping[str, zipfile.ZipInfo]
    ] = validated_members,
    digest: Callable[[Path], tuple[int, str, str]] = digest_regular_file,
) -> Iterator[
    tuple[tuple[int, str, str], zipfile.ZipFile, Mapping[str, zipfile.ZipInfo]]
]:
    """Open an exact archive and prove it remained unchanged after consumption."""

    integrity = verify(archive_path, receipt_path, contract)
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            yield integrity, archive, validate(archive, contract)
    except UjiIndoorLocError:
        raise
    except (OSError, zipfile.BadZipFile) as error:
        raise UjiIndoorLocError("invalid_zip_archive") from error
    if digest(archive_path) != integrity:
        raise UjiIndoorLocError("archive_changed_during_evaluation")


def _parse_int(value: str, minimum: int, maximum: int, code: str) -> int:
    if len(value.encode("utf-8")) > MAX_FIELD_BYTES:
        raise UjiIndoorLocError(code)
    try:
        parsed = int(value)
    except ValueError as error:
        raise UjiIndoorLocError(code) from error
    if not minimum <= parsed <= maximum:
        raise UjiIndoorLocError(code)
    return parsed


def _parse_finite(value: str, code: str) -> None:
    if len(value.encode("utf-8")) > MAX_FIELD_BYTES:
        raise UjiIndoorLocError(code)
    try:
        parsed = float(value)
    except ValueError as error:
        raise UjiIndoorLocError(code) from error
    if not math.isfinite(parsed):
        raise UjiIndoorLocError(code)


def parse_model_row(row: Sequence[str], *, include_rssi: bool) -> ModelRow:
    if len(row) != len(EXPECTED_HEADER):
        raise UjiIndoorLocError("invalid_csv_row_shape")
    parsed_rssi: list[int | None] = []
    if include_rssi:
        for value in row[: len(WAP_FIELDS)]:
            rssi = _parse_int(value, -104, 100, "invalid_rssi_value")
            if 0 < rssi < 100:
                raise UjiIndoorLocError("invalid_rssi_value")
            parsed_rssi.append(None if rssi == 100 else rssi)
    _parse_finite(row[520], "invalid_longitude")
    _parse_finite(row[521], "invalid_latitude")
    floor = _parse_int(row[522], 0, 4, "invalid_floor")
    building = _parse_int(row[523], 0, 2, "invalid_building")
    space = _parse_int(row[524], 0, 10_000, "invalid_space")
    relative = _parse_int(row[525], 0, 2, "invalid_relative_position")
    _parse_int(row[526], 0, 18, "invalid_user")
    phone = _parse_int(row[527], 0, 24, "invalid_phone")
    _parse_int(row[528], 1, 4_294_967_295, "invalid_timestamp")
    if (space == 0) != (relative == 0):
        raise UjiIndoorLocError("inconsistent_location_cell_state")
    return ModelRow(tuple(parsed_rssi), building, floor, phone)


def _visit_rows(
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    expected_rows: int,
    visitor: Callable[[ModelRow], None],
    *,
    include_rssi: bool | Callable[[ModelRow], bool],
) -> int:
    rows = 0
    try:
        raw = archive.open(member, "r")
        text = io.TextIOWrapper(raw, encoding="utf-8", newline="")
        with raw, text:
            reader = csv.reader(text)
            try:
                header = tuple(next(reader))
            except StopIteration as error:
                raise UjiIndoorLocError("empty_csv_member") from error
            if header != EXPECTED_HEADER:
                raise UjiIndoorLocError("unexpected_csv_header")
            for values in reader:
                rows += 1
                if rows > MAX_ROWS:
                    raise UjiIndoorLocError("invalid_csv_row_shape")
                if callable(include_rssi):
                    metadata = parse_model_row(values, include_rssi=False)
                    parsed = (
                        parse_model_row(values, include_rssi=True)
                        if include_rssi(metadata)
                        else metadata
                    )
                else:
                    parsed = parse_model_row(values, include_rssi=include_rssi)
                visitor(parsed)
    except UjiIndoorLocError:
        raise
    except (OSError, RuntimeError, UnicodeDecodeError, csv.Error) as error:
        raise UjiIndoorLocError("csv_stream_error") from error
    if rows != expected_rows:
        raise UjiIndoorLocError("unexpected_partition_row_count")
    return rows


def scan_archive(
    archive_path: Path,
    receipt_path: Path,
    contract: ArtifactContract = DEFAULT_CONTRACT,
) -> CorpusScan:
    phones: dict[int, PhoneAggregate] = {}

    def aggregate(row: ModelRow) -> None:
        phone = phones.setdefault(row.phone, PhoneAggregate())
        phone.rows += 1
        phone.targets.add(row.target)

    publisher_rows: dict[str, int] = {}
    with verified_archive(archive_path, receipt_path, contract) as opened:
        integrity, archive, members = opened
        for role, name in (("train", TRAIN_MEMBER), ("validation", VALIDATION_MEMBER)):
            publisher_rows[role] = _visit_rows(
                archive,
                members[name],
                contract.row_counts[role],
                aggregate,
                include_rssi=False,
            )
    return CorpusScan(integrity, publisher_rows, phones)


def _union_mask(units: Sequence[SplitUnit]) -> int:
    value = 0
    for unit in units:
        value |= unit.target_mask
    return value


def _minimum_target_support(units: Sequence[SplitUnit], full_mask: int) -> int:
    if full_mask == 0:
        return 0
    return min(
        sum(bool(unit.target_mask & (1 << bit)) for unit in units)
        for bit in range(full_mask.bit_length())
    )


def _covering_subsets(
    available: tuple[SplitUnit, ...], full_mask: int
) -> Iterator[tuple[SplitUnit, ...]]:
    first = available[0]
    yielded: set[tuple[tuple[int, ...], ...]] = set()

    def visit(
        selected: tuple[SplitUnit, ...],
        remaining: tuple[SplitUnit, ...],
        covered: int,
    ) -> Iterator[tuple[SplitUnit, ...]]:
        if covered == full_mask:
            identity = tuple(unit.key for unit in selected)
            if identity not in yielded:
                yielded.add(identity)
                yield selected
            return
        if covered | _union_mask(remaining) != full_mask:
            return
        missing = [
            bit for bit in range(full_mask.bit_length()) if not covered & (1 << bit)
        ]
        bit = min(
            missing,
            key=lambda item: (
                sum(bool(unit.target_mask & (1 << item)) for unit in remaining),
                item,
            ),
        )
        candidates = [unit for unit in remaining if unit.target_mask & (1 << bit)]
        candidates.sort(
            key=lambda unit: (
                -bin(unit.target_mask & ~covered).count("1"),
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


def _balance_score(assignment: Sequence[Sequence[SplitUnit]]) -> tuple[int, int, int]:
    counts = [sum(unit.rows for unit in role) for role in assignment]
    return (
        max(counts),
        max(counts) - min(counts),
        sum(count * count for count in counts),
    )


def _balance_assignment(
    assignment: tuple[tuple[SplitUnit, ...], ...], full_mask: int
) -> tuple[tuple[SplitUnit, ...], ...]:
    current = assignment
    while True:
        current_score = _balance_score(current)
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
                    score = _balance_score(candidate_tuple)
                    tie_break = donor_index, receiver_index, unit.key
                    if score >= current_score:
                        continue
                    if best is None or (score, tie_break) < (best[0], best[1]):
                        best = score, tie_break, candidate_tuple
        if best is None:
            return current
        current = best[2]


def find_role_assignment(
    units: Sequence[SplitUnit], full_mask: int, role_count: int
) -> tuple[tuple[SplitUnit, ...], ...] | None:
    ordered = tuple(sorted(units, key=lambda unit: unit.key))

    def visit(
        available: tuple[SplitUnit, ...], roles_remaining: int
    ) -> tuple[tuple[SplitUnit, ...], ...] | None:
        if len(available) < roles_remaining:
            return None
        if _minimum_target_support(available, full_mask) < roles_remaining:
            return None
        if roles_remaining == 1:
            return (
                (available,)
                if available and _union_mask(available) == full_mask
                else None
            )
        for selected in _covering_subsets(available, full_mask):
            selected_keys = {unit.key for unit in selected}
            remaining = tuple(
                unit for unit in available if unit.key not in selected_keys
            )
            tail = visit(remaining, roles_remaining - 1)
            if tail is not None:
                return (selected, *tail)
        return None

    assignment = visit(ordered, role_count)
    return None if assignment is None else _balance_assignment(assignment, full_mask)


def build_phone_role_plan(scan: CorpusScan) -> PhoneRolePlan:
    targets = sorted(
        {target for phone in scan.phones.values() for target in phone.targets}
    )
    target_bits = {target: 1 << index for index, target in enumerate(targets)}
    full_mask = (1 << len(targets)) - 1
    units = [
        SplitUnit(
            key=(phone,),
            rows=aggregate.rows,
            target_mask=sum(target_bits[target] for target in aggregate.targets),
        )
        for phone, aggregate in sorted(scan.phones.items())
    ]
    assignment = find_role_assignment(units, full_mask, len(ROLES))
    if assignment is None:
        raise UjiIndoorLocError("no_complete_phone_role_assignment")
    phone_roles: dict[int, str] = {}
    row_counts: dict[str, int] = {}
    phone_counts: dict[str, int] = {}
    target_counts: dict[str, int] = {}
    for role, role_units in zip(ROLES, assignment):
        row_counts[role] = sum(unit.rows for unit in role_units)
        phone_counts[role] = len(role_units)
        target_counts[role] = bin(_union_mask(role_units)).count("1")
        for unit in role_units:
            phone_roles[unit.key[0]] = role
    if len(phone_roles) != len(scan.phones) or sum(row_counts.values()) != sum(
        scan.publisher_rows.values()
    ):
        raise UjiIndoorLocError("phone_role_reconciliation_failed")
    return PhoneRolePlan(
        phone_roles, row_counts, phone_counts, target_counts, len(targets)
    )


def read_roles(
    archive_path: Path,
    receipt_path: Path,
    plan: PhoneRolePlan,
    selected_roles: Sequence[str],
    contract: ArtifactContract = DEFAULT_CONTRACT,
) -> dict[str, tuple[ModelRow, ...]]:
    selected = tuple(selected_roles)
    if len(set(selected)) != len(selected) or any(
        role not in ROLES for role in selected
    ):
        raise UjiIndoorLocError("invalid_selected_roles")
    rows: dict[str, list[ModelRow]] = {role: [] for role in selected}

    def collect(row: ModelRow) -> None:
        role = plan.phone_roles.get(row.phone)
        if role is None:
            raise UjiIndoorLocError("unassigned_phone")
        if role in rows:
            if not row.rssi:
                raise UjiIndoorLocError("selected_role_rssi_not_read")
            rows[role].append(row)

    def include_selected_rssi(row: ModelRow) -> bool:
        role = plan.phone_roles.get(row.phone)
        if role is None:
            raise UjiIndoorLocError("unassigned_phone")
        return role in rows

    with verified_archive(archive_path, receipt_path, contract) as opened:
        _, archive, members = opened
        for publisher_role, name in (
            ("train", TRAIN_MEMBER),
            ("validation", VALIDATION_MEMBER),
        ):
            _visit_rows(
                archive,
                members[name],
                contract.row_counts[publisher_role],
                collect,
                include_rssi=include_selected_rssi,
            )
    for role in selected:
        if len(rows[role]) != plan.row_counts[role]:
            raise UjiIndoorLocError("role_read_reconciliation_failed")
    return {role: tuple(rows[role]) for role in selected}
