#!/usr/bin/env python3
"""Compile a bounded opaque oracle inventory from pinned RUFF-UWB labels.

The compiler opens ZIP central directories and the two ``*.labels.npy``
members only. Waveform members are validated from central-directory metadata
but are never opened, extracted, or deserialized.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
import struct
import sys
import tempfile
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, Mapping, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.ruff_uwb_observation_oracles.v0"
CATALOG_SCHEMA = "netbraid.public_source_leads.v1"
CATALOG_ENTRY_ID = "zenodo-11083153-ruff-uwb"
RECEIPT_SCHEMA = "local.public_wireless_archive.v1"

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB
READ_CHUNK_BYTES = MIB
MAX_CATALOG_BYTES = MIB
MAX_RECEIPT_BYTES = 64 * KIB
MAX_ARCHIVE_BYTES = 2 * GIB
MAX_ARCHIVE_MEMBERS = 2
MAX_MEMBER_NAME_BYTES = 255
MAX_LABEL_MEMBER_BYTES = 32 * MIB
MAX_NPY_HEADER_BYTES = 4 * KIB
MAX_ROWS_PER_ARCHIVE = 1_500_000
MAX_TOTAL_ROWS = 2_000_000
MAX_LABEL_FIELDS = 2
MAX_LABEL_VALUE = (1 << 31) - 1
MAX_DISTINCT_SOURCES = 32
MAX_DISTINCT_LOCATIONS = 256
MAX_RECORDS = 4_096
MAX_OBSERVATIONS_PER_RECORD = 100_000
MAX_OUTPUT_BYTES = 8 * MIB

AXES = (
    "event",
    "physical_source",
    "physical_device",
    "variant",
    "session",
    "domain",
    "day",
    "receiver",
    "location",
    "channel",
    "configuration",
)
UNOBSERVED_AXES = frozenset(("event", "session"))
OPAQUE_ID_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
MD5_PATTERN = re.compile(r"[a-f0-9]{32}\Z")
SHA256_PATTERN = re.compile(r"[a-f0-9]{64}\Z")


class OracleCompileError(RuntimeError):
    """Stable fail-closed reason for rejected input or output."""


class DuplicateJsonKeyError(ValueError):
    """Raised when a supposedly strict JSON object repeats a key."""


@dataclass(frozen=True)
class PublisherClaim:
    source_count: int
    location_count: int
    variant_token: str
    receiver_token: str = "fixed-dwm3001cdk-anchor"
    channel_token: str = "uwb-channel-5"


@dataclass(frozen=True)
class ArchiveContract:
    key: str
    filename: str
    archive_bytes: int
    archive_md5: str
    archive_sha256: str
    label_member: str
    label_member_bytes: int
    waveform_member: str
    waveform_member_bytes: int
    configuration_token: str
    receipt_source: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class ArchiveLabels:
    contract: ArchiveContract
    identity: FileIdentity
    md5: str
    sha256: str
    rows: int
    combinations: Tuple[Tuple[Tuple[int, int], int], ...]
    sources: frozenset[int]
    locations: frozenset[int]


PRODUCTION_RECEIPT_SOURCES: Dict[str, Mapping[str, Any]] = {
    "distance-1": {
        "bytes": 793_083_301,
        "doi": "10.5281/zenodo.11083153",
        "filename": "RUFF-UWB_mesures1meter.npy_format.zip",
        "group": "rf-fingerprinting",
        "license": "CC BY 4.0",
        "md5": "035d22d657c84b77df980a482cff47b1",
        "record": "ruff-uwb-rff",
        "record_bytes": 3_835_056_792,
        "representation": "npy",
        "url": (
            "https://zenodo.org/api/records/11083153/files/"
            "UWB_mesures1meter.npy_format.zip/content"
        ),
    },
    "distance-2": {
        "bytes": 1_724_857_002,
        "doi": "10.5281/zenodo.11083153",
        "filename": "RUFF-UWB_mesures2meters.npy_format.zip",
        "group": "rf-fingerprinting",
        "license": "CC BY 4.0",
        "md5": "cf0a3274285bb6fc58fecfb4cb252d7d",
        "record": "ruff-uwb-rff",
        "record_bytes": 3_835_056_792,
        "representation": "npy",
        "url": (
            "https://zenodo.org/api/records/11083153/files/"
            "UWB_mesures2meters.npy_format.zip/content"
        ),
    },
}

PRODUCTION_ARCHIVES = (
    ArchiveContract(
        key="distance-1",
        filename="RUFF-UWB_mesures1meter.npy_format.zip",
        archive_bytes=793_083_301,
        archive_md5="035d22d657c84b77df980a482cff47b1",
        archive_sha256=(
            "43f344b23ba4981dd8005c02091152fa1f15205703757027630f4708aaf5ba9b"
        ),
        label_member="UWB_mesures1meter.labels.npy",
        label_member_bytes=12_339_840,
        waveform_member="UWB_mesures1meter.data.npy",
        waveform_member_bytes=3_084_928_128,
        configuration_token="distance-1",
        receipt_source=PRODUCTION_RECEIPT_SOURCES["distance-1"],
    ),
    ArchiveContract(
        key="distance-2",
        filename="RUFF-UWB_mesures2meters.npy_format.zip",
        archive_bytes=1_724_857_002,
        archive_md5="cf0a3274285bb6fc58fecfb4cb252d7d",
        archive_sha256=(
            "73582fd27abfe8ff746c3a2148ce6b43a2f5f350c175c0aa58654ba23c1a6cc0"
        ),
        label_member="UWB_mesures2meter.labels.npy",
        label_member_bytes=18_439_984,
        waveform_member="UWB_mesures2meter.data.npy",
        waveform_member_bytes=1_843_985_728,
        configuration_token="distance-2",
        receipt_source=PRODUCTION_RECEIPT_SOURCES["distance-2"],
    ),
)


def _strict_object(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJsonKeyError(key)
        value[key] = item
    return value


def _identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _read_regular_file(path: Path, maximum_bytes: int, error_prefix: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise OracleCompileError(f"{error_prefix}_unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise OracleCompileError(f"{error_prefix}_not_regular")
    if not 0 < before.st_size <= maximum_bytes:
        raise OracleCompileError(f"{error_prefix}_size_limit")
    try:
        with path.open("rb") as source:
            opened = _identity(os.fstat(source.fileno()))
            if _identity(before) != opened:
                raise OracleCompileError(f"{error_prefix}_identity_changed")
            data = source.read(maximum_bytes + 1)
            if len(data) != opened.size or source.read(1):
                raise OracleCompileError(f"{error_prefix}_changed_during_read")
            if _identity(os.fstat(source.fileno())) != opened:
                raise OracleCompileError(f"{error_prefix}_changed_during_read")
    except OracleCompileError:
        raise
    except OSError as error:
        raise OracleCompileError(f"{error_prefix}_read_failed") from error
    return data


def _parse_json_file(path: Path, maximum_bytes: int, error_prefix: str) -> Any:
    data = _read_regular_file(path, maximum_bytes, error_prefix)
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_strict_object)
    except DuplicateJsonKeyError as error:
        raise OracleCompileError(f"{error_prefix}_duplicate_json_key") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OracleCompileError(f"{error_prefix}_invalid_json") from error


def load_publisher_claim(path: Path) -> PublisherClaim:
    """Load only the bounded publisher assertions needed by this compiler."""

    document = _parse_json_file(path, MAX_CATALOG_BYTES, "catalog")
    if not isinstance(document, Mapping) or document.get("schema") != CATALOG_SCHEMA:
        raise OracleCompileError("unsupported_catalog_schema")
    entries = document.get("entries")
    if not isinstance(entries, list) or not 1 <= len(entries) <= 1_000:
        raise OracleCompileError("invalid_catalog_entries")
    matches = [
        entry
        for entry in entries
        if isinstance(entry, Mapping) and entry.get("id") == CATALOG_ENTRY_ID
    ]
    if len(matches) != 1:
        raise OracleCompileError("catalog_entry_count")
    entry = matches[0]
    modalities = entry.get("modalities")
    roles = entry.get("roles")
    note = entry.get("note")
    if (
        not isinstance(modalities, list)
        or not {"physical_source_observation", "location_observation"}.issubset(
            modalities
        )
        or not isinstance(roles, list)
        or "source_location_split_eval" not in roles
        or not isinstance(note, str)
        or re.search(r"\b13 boards across 100 positions\b", note) is None
        or "DWM3001CDK" not in note
        or "fixed receiver and channel 5" not in note
        or "two distinct collection days" not in note
    ):
        raise OracleCompileError("catalog_claim_not_supported")
    return PublisherClaim(
        source_count=13,
        location_count=100,
        variant_token="DWM3001CDK",
    )


def _validate_contract(contract: ArchiveContract) -> None:
    names = (contract.filename, contract.label_member, contract.waveform_member)
    if (
        not contract.key
        or not contract.configuration_token
        or any(not isinstance(value, str) or not value for value in names)
        or contract.label_member == contract.waveform_member
        or not 0 < contract.archive_bytes <= MAX_ARCHIVE_BYTES
        or not 0 < contract.label_member_bytes <= MAX_LABEL_MEMBER_BYTES
        or contract.waveform_member_bytes <= 0
        or MD5_PATTERN.fullmatch(contract.archive_md5) is None
        or SHA256_PATTERN.fullmatch(contract.archive_sha256) is None
    ):
        raise OracleCompileError("invalid_archive_contract")


def _safe_member_name(name: str) -> None:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise OracleCompileError("unsafe_archive_member_name") from error
    if (
        not encoded
        or len(encoded) > MAX_MEMBER_NAME_BYTES
        or name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in name.split("/"))
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise OracleCompileError("unsafe_archive_member_name")


def _open_archive(
    path: Path, contract: ArchiveContract
) -> Tuple[BinaryIO, FileIdentity]:
    try:
        before = path.lstat()
    except OSError as error:
        raise OracleCompileError("archive_unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise OracleCompileError("archive_not_regular")
    if before.st_size != contract.archive_bytes or before.st_size > MAX_ARCHIVE_BYTES:
        raise OracleCompileError("archive_size_mismatch")
    try:
        source = path.open("rb")
    except OSError as error:
        raise OracleCompileError("archive_open_failed") from error
    opened = _identity(os.fstat(source.fileno()))
    if opened != _identity(before):
        source.close()
        raise OracleCompileError("archive_identity_changed")
    return source, opened


def _require_unchanged(source: BinaryIO, expected: FileIdentity) -> None:
    if _identity(os.fstat(source.fileno())) != expected:
        raise OracleCompileError("archive_changed_during_compile")


def _digest_archive(source: BinaryIO, expected: FileIdentity) -> Tuple[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    source.seek(0)
    remaining = expected.size
    while remaining:
        chunk = source.read(min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise OracleCompileError("archive_changed_during_digest")
        remaining -= len(chunk)
        md5.update(chunk)
        sha256.update(chunk)
    if source.read(1):
        raise OracleCompileError("archive_exceeds_contract")
    _require_unchanged(source, expected)
    source.seek(0)
    return md5.hexdigest(), sha256.hexdigest()


def _validate_receipt(
    path: Path, contract: ArchiveContract, md5: str, sha256: str
) -> None:
    receipt = _parse_json_file(
        path.with_suffix(path.suffix + ".json"), MAX_RECEIPT_BYTES, "receipt"
    )
    expected = {
        "schema": RECEIPT_SCHEMA,
        "source": contract.receipt_source,
        "bytes": contract.archive_bytes,
        "md5": md5,
        "sha256": sha256,
        "archive": contract.filename,
    }
    if contract.receipt_source is None or receipt != expected:
        raise OracleCompileError("archive_receipt_mismatch")


def _inspect_members(
    archive: zipfile.ZipFile, contract: ArchiveContract
) -> zipfile.ZipInfo:
    members = archive.infolist()
    if len(members) != MAX_ARCHIVE_MEMBERS:
        raise OracleCompileError("archive_member_count")
    names = [member.filename for member in members]
    if len(set(names)) != len(names):
        raise OracleCompileError("duplicate_archive_member")
    expected_names = {contract.label_member, contract.waveform_member}
    if set(names) != expected_names:
        raise OracleCompileError("archive_member_schema")
    by_name = {member.filename: member for member in members}
    expected_sizes = {
        contract.label_member: contract.label_member_bytes,
        contract.waveform_member: contract.waveform_member_bytes,
    }
    for member in members:
        _safe_member_name(member.filename)
        mode = member.external_attr >> 16
        if (
            member.is_dir()
            or member.flag_bits & 0x1
            or stat.S_ISLNK(mode)
            or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
            or member.file_size != expected_sizes[member.filename]
            or member.compress_size <= 0
        ):
            raise OracleCompileError("unsupported_archive_member")
    return by_name[contract.label_member]


def _read_npy_header(source: BinaryIO, member_bytes: int) -> Tuple[int, int]:
    prefix = source.read(8)
    if prefix != b"\x93NUMPY\x01\x00":
        raise OracleCompileError("unsupported_label_npy_version")
    encoded_header_size = source.read(2)
    if len(encoded_header_size) != 2:
        raise OracleCompileError("truncated_label_npy_header")
    header_size = struct.unpack("<H", encoded_header_size)[0]
    if not 1 <= header_size <= MAX_NPY_HEADER_BYTES:
        raise OracleCompileError("label_npy_header_size")
    encoded_header = source.read(header_size)
    if len(encoded_header) != header_size:
        raise OracleCompileError("truncated_label_npy_header")
    try:
        header = ast.literal_eval(encoded_header.decode("latin1").strip())
    except (SyntaxError, ValueError) as error:
        raise OracleCompileError("invalid_label_npy_header") from error
    if not isinstance(header, dict) or set(header) != {
        "descr",
        "fortran_order",
        "shape",
    }:
        raise OracleCompileError("invalid_label_npy_header")
    shape = header["shape"]
    if (
        header["descr"] != "<i8"
        or header["fortran_order"] is not False
        or not isinstance(shape, tuple)
        or len(shape) != 2
        or any(type(value) is not int for value in shape)
    ):
        raise OracleCompileError("unsupported_label_array")
    rows, fields = shape
    if not 1 <= rows <= MAX_ROWS_PER_ARCHIVE or fields != MAX_LABEL_FIELDS:
        raise OracleCompileError("invalid_label_shape")
    expected_bytes = 10 + header_size + rows * fields * 8
    if expected_bytes != member_bytes:
        raise OracleCompileError("label_extent_mismatch")
    return rows, fields


def _read_labels(
    archive: zipfile.ZipFile, member: zipfile.ZipInfo
) -> Tuple[int, Counter[Tuple[int, int]], frozenset[int], frozenset[int]]:
    combinations: Counter[Tuple[int, int]] = Counter()
    sources: set[int] = set()
    locations: set[int] = set()
    try:
        with archive.open(member, "r") as label_source:
            rows, fields = _read_npy_header(label_source, member.file_size)
            remaining = rows * fields * 8
            carry = b""
            parsed_rows = 0
            while remaining:
                chunk = label_source.read(min(READ_CHUNK_BYTES, remaining))
                if not chunk:
                    raise OracleCompileError("truncated_label_payload")
                remaining -= len(chunk)
                chunk = carry + chunk
                row_bytes = fields * 8
                usable = len(chunk) - len(chunk) % row_bytes
                for source_value, location_value in struct.iter_unpack(
                    "<qq", chunk[:usable]
                ):
                    if (
                        not 0 <= source_value <= MAX_LABEL_VALUE
                        or not 0 <= location_value <= MAX_LABEL_VALUE
                    ):
                        raise OracleCompileError("label_value_out_of_range")
                    key = (source_value, location_value)
                    combinations[key] += 1
                    if combinations[key] > MAX_OBSERVATIONS_PER_RECORD:
                        raise OracleCompileError("record_observation_count_limit")
                    sources.add(source_value)
                    locations.add(location_value)
                    if len(sources) > MAX_DISTINCT_SOURCES:
                        raise OracleCompileError("source_count_limit")
                    if len(locations) > MAX_DISTINCT_LOCATIONS:
                        raise OracleCompileError("location_count_limit")
                    parsed_rows += 1
                carry = chunk[usable:]
            if carry or parsed_rows != rows or label_source.read(1):
                raise OracleCompileError("label_extent_mismatch")
    except OracleCompileError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise OracleCompileError("label_member_read_failed") from error
    return rows, combinations, frozenset(sources), frozenset(locations)


def inspect_archive(
    path: Path, contract: ArchiveContract, *, require_receipt: bool
) -> ArchiveLabels:
    """Verify one archive and read only its bounded label member."""

    _validate_contract(contract)
    source, identity = _open_archive(path, contract)
    try:
        md5, sha256 = _digest_archive(source, identity)
        if md5 != contract.archive_md5 or sha256 != contract.archive_sha256:
            raise OracleCompileError("archive_digest_mismatch")
        if require_receipt:
            _validate_receipt(path, contract, md5, sha256)
        try:
            archive = zipfile.ZipFile(source, "r")
        except (OSError, zipfile.BadZipFile) as error:
            raise OracleCompileError("invalid_zip_archive") from error
        with archive:
            member = _inspect_members(archive, contract)
            rows, combinations, sources, locations = _read_labels(archive, member)
        _require_unchanged(source, identity)
    finally:
        source.close()
    return ArchiveLabels(
        contract=contract,
        identity=identity,
        md5=md5,
        sha256=sha256,
        rows=rows,
        combinations=tuple(sorted(combinations.items())),
        sources=sources,
        locations=locations,
    )


def _opaque_id(domain: str, *components: object) -> str:
    digest = hashlib.sha256()
    namespace = b"netbraid.ruff-uwb-oracle-id.v1"
    digest.update(len(namespace).to_bytes(4, "big"))
    digest.update(namespace)
    domain_bytes = domain.encode("utf-8")
    digest.update(len(domain_bytes).to_bytes(4, "big"))
    digest.update(domain_bytes)
    for component in components:
        if isinstance(component, int):
            if component < 0:
                raise OracleCompileError("negative_id_component")
            payload = b"i" + component.to_bytes(8, "big")
        elif isinstance(component, str):
            payload = b"s" + component.encode("utf-8")
        else:
            raise OracleCompileError("unsupported_id_component")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _known(group_id: str) -> Dict[str, Optional[str]]:
    if OPAQUE_ID_PATTERN.fullmatch(group_id) is None:
        raise OracleCompileError("invalid_generated_group_id")
    return {"state": "known", "group_id": group_id}


def _not_observed() -> Dict[str, Optional[str]]:
    return {"state": "not_observed", "group_id": None}


def _record(
    facts: ArchiveLabels,
    source_value: int,
    location_value: int,
    observation_count: int,
    claim: PublisherClaim,
) -> Dict[str, Any]:
    archive_key = facts.contract.key
    observation_id = _opaque_id(
        "observation", archive_key, source_value, location_value
    )
    groups = {
        "event": _not_observed(),
        "physical_source": _known(_opaque_id("physical_source", source_value)),
        "physical_device": _known(_opaque_id("physical_device", source_value)),
        "variant": _known(_opaque_id("variant", claim.variant_token)),
        "session": _not_observed(),
        "domain": _known(_opaque_id("domain", "uwb-cir")),
        "day": _known(_opaque_id("day", archive_key)),
        "receiver": _known(_opaque_id("receiver", claim.receiver_token)),
        "location": _known(_opaque_id("location", archive_key, location_value)),
        "channel": _known(_opaque_id("channel", claim.channel_token)),
        "configuration": _known(
            _opaque_id("configuration", facts.contract.configuration_token)
        ),
    }
    return {
        "observation_id": observation_id,
        "observation_count": observation_count,
        **{f"{axis}_group": groups[axis] for axis in AXES},
        "source_location_group": _known(
            _opaque_id("source_location", archive_key, source_value, location_value)
        ),
        "campaign_group": _known(_opaque_id("campaign", archive_key)),
    }


def compile_inventory(
    archives: Sequence[Tuple[ArchiveContract, Path]],
    claim: PublisherClaim,
    *,
    require_receipts: bool = False,
) -> Dict[str, Any]:
    """Compile deterministic records for observed source/location cells only."""

    if (
        not 1 <= claim.source_count <= MAX_DISTINCT_SOURCES
        or not 1 <= claim.location_count <= MAX_DISTINCT_LOCATIONS
        or not claim.variant_token
        or not claim.receiver_token
        or not claim.channel_token
    ):
        raise OracleCompileError("invalid_publisher_claim")
    if len(archives) != 2:
        raise OracleCompileError("archive_count")
    ordered = sorted(archives, key=lambda item: item[0].key)
    keys = [contract.key for contract, _ in ordered]
    if len(set(keys)) != len(keys):
        raise OracleCompileError("duplicate_archive_key")
    resolved_paths = [os.path.abspath(os.fspath(path)) for _, path in ordered]
    if len(set(resolved_paths)) != len(resolved_paths):
        raise OracleCompileError("duplicate_archive_path")

    facts = tuple(
        inspect_archive(path, contract, require_receipt=require_receipts)
        for contract, path in ordered
    )
    identities = {(item.identity.device, item.identity.inode) for item in facts}
    if len(identities) != len(facts):
        raise OracleCompileError("duplicate_archive_file")
    total_rows = sum(item.rows for item in facts)
    if total_rows > MAX_TOTAL_ROWS:
        raise OracleCompileError("total_row_count_limit")
    source_union = frozenset().union(*(item.sources for item in facts))
    location_union = frozenset().union(*(item.locations for item in facts))
    if len(source_union) != claim.source_count or any(
        item.sources != source_union for item in facts
    ):
        raise OracleCompileError("publisher_source_count_mismatch")
    if len(location_union) != claim.location_count:
        raise OracleCompileError("publisher_location_count_mismatch")

    records = []
    archive_summaries = []
    observation_ids: set[str] = set()
    source_location_ids: set[str] = set()
    for item in facts:
        archive_records = []
        for (source_value, location_value), count in item.combinations:
            record = _record(item, source_value, location_value, count, claim)
            observation_id = record["observation_id"]
            if observation_id in observation_ids:
                raise OracleCompileError("duplicate_observation_record")
            observation_ids.add(observation_id)
            source_location_ids.add(record["source_location_group"]["group_id"])
            archive_records.append(record)
        records.extend(archive_records)
        archive_summaries.append(
            {
                "archive_id": _opaque_id("archive", item.contract.key),
                "campaign_group_id": _opaque_id("campaign", item.contract.key),
                "configuration_group_id": _opaque_id(
                    "configuration", item.contract.configuration_token
                ),
                "archive_bytes": item.identity.size,
                "archive_md5": item.md5,
                "archive_sha256": item.sha256,
                "label_rows": item.rows,
                "oracle_records": len(archive_records),
                "distinct_sources": len(item.sources),
                "distinct_locations": len(item.locations),
            }
        )
    if not 1 <= len(records) <= MAX_RECORDS:
        raise OracleCompileError("record_count_limit")
    if len(observation_ids) != len(records):
        raise OracleCompileError("duplicate_observation_record")

    axis_states = {}
    distinct_known_groups = {}
    for axis in AXES:
        groups = [record[f"{axis}_group"] for record in records]
        state_counts = Counter(group["state"] for group in groups)
        axis_states[axis] = {
            state: state_counts[state] for state in ("known", "unknown", "not_observed")
        }
        distinct_known_groups[axis] = len(
            {group["group_id"] for group in groups if group["state"] == "known"}
        )

    inventory = {
        "schema": SCHEMA,
        "inventory_id": _opaque_id(
            "inventory", *(record["observation_id"] for record in records)
        ),
        "status": "pass",
        "provenance": {
            "catalog_schema": CATALOG_SCHEMA,
            "archive_integrity": "exact_size_md5_sha256_and_fetcher_receipt",
        },
        "manifest": {
            "local_ignored_manifest": True,
            "partitions_assigned": 0,
            "train_test_splits_assigned": False,
        },
        "publisher_claims": {
            "physical_sources": len(source_union),
            "physical_devices": len(source_union),
            "locations": len(location_union),
            "variants": 1,
            "receivers": 1,
            "channels": 1,
        },
        "required_split_groups": [
            "physical_source_group",
            "location_group",
            "source_location_group",
            "campaign_group",
            "day_group",
        ],
        "archives": archive_summaries,
        "counts": {
            "label_rows": total_rows,
            "observations": len(records),
            "distinct_source_location_groups": len(source_location_ids),
            "axis_states": axis_states,
            "distinct_known_groups": distinct_known_groups,
        },
        "privacy": {
            "absolute_paths_retained": 0,
            "relative_paths_retained": 0,
            "filenames_retained": 0,
            "source_urls_retained": 0,
            "date_values_retained": 0,
            "private_values_retained": 0,
            "waveform_members_opened": 0,
            "waveform_payload_bytes_read": 0,
            "raw_label_values_emitted": 0,
        },
        "observations": records,
    }
    render_inventory(inventory)
    return inventory


def render_inventory(inventory: Mapping[str, Any]) -> bytes:
    try:
        encoded = (
            json.dumps(
                inventory,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise OracleCompileError("inventory_not_json_serializable") from error
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise OracleCompileError("inventory_output_size_limit")
    return encoded


def write_inventory(path: Path, inventory: Mapping[str, Any]) -> None:
    encoded = render_inventory(inventory)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.exists() and not path.is_file():
        raise OracleCompileError("unsafe_output_path")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=ROOT / "data" / "raw",
        help="ignored directory containing the two pinned RUFF-UWB archives",
    )
    parser.add_argument(
        "--catalog",
        type=Path,
        default=ROOT / "data" / "catalog" / "research-leads-v1.json",
        help="publisher-claim catalog",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            ROOT / "data" / "derived" / "eval" / "ruff-uwb-observation-oracles.json"
        ),
        help="ignored deterministic oracle inventory output",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        claim = load_publisher_claim(args.catalog)
        archives = tuple(
            (contract, args.raw_dir / contract.filename)
            for contract in PRODUCTION_ARCHIVES
        )
        inventory = compile_inventory(archives, claim, require_receipts=True)
        write_inventory(args.output, inventory)
    except OracleCompileError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "pass",
                "inventory_id": inventory["inventory_id"],
                "observations": inventory["counts"]["observations"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
