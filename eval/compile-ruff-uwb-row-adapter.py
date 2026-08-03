#!/usr/bin/env python3
"""Compile the pinned RUFF-UWB one-meter row adapter and standalone NPY.

The compiler verifies the fetch receipt and complete archive identity, parses the
label member in publisher order, emits contiguous half-open metadata spans, and
streams the waveform member to a private standalone file. No raw label value,
member name, archive name, or input path is retained in the adapter.
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
import zlib
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import (
    Any,
    BinaryIO,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.ruff_uwb_row_adapter.v0"
RECEIPT_SCHEMA = "local.public_wireless_archive.v1"

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB
READ_CHUNK_BYTES = MIB
MAX_RECEIPT_BYTES = 64 * KIB
MAX_ADAPTER_BYTES = 4 * MIB
MAX_ARCHIVE_BYTES = 2 * GIB
MAX_WAVEFORM_BYTES = 4 * GIB
MAX_MEMBER_NAME_BYTES = 255
MAX_NPY_HEADER_BYTES = 4 * KIB
MAX_ROWS = 1_500_000
MAX_SAMPLES_PER_ROW = 65_536
MAX_SPANS = 100_000
MAX_DISTINCT_SOURCES = 32
MAX_DISTINCT_LOCATIONS = 256

MD5_PATTERN = re.compile(r"[a-f0-9]{32}\Z")
SHA256_PATTERN = re.compile(r"[a-f0-9]{64}\Z")


class AdapterCompileError(RuntimeError):
    """Stable fail-closed reason for rejected input or output."""


class DuplicateJsonKeyError(ValueError):
    """Raised when strict JSON contains a duplicate object key."""


@dataclass(frozen=True)
class ZipMemberContract:
    name: str
    file_bytes: int
    compressed_bytes: int
    crc32: int
    compression: int
    flags: int
    header_offset: int
    dtype: str
    shape: Tuple[int, int]
    sha256: Optional[str] = None


@dataclass(frozen=True)
class ArchiveContract:
    filename: str
    archive_bytes: int
    archive_md5: str
    archive_sha256: str
    receipt_source: Mapping[str, Any]
    collection_token: str
    source_count: int
    location_count: int
    label: ZipMemberContract
    waveform: ZipMemberContract


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class NpyHeader:
    version: Tuple[int, int]
    dtype: str
    fortran_order: bool
    shape: Tuple[int, int]
    encoded: bytes


@dataclass(frozen=True)
class LabelFacts:
    sha256: str
    spans: Tuple[Mapping[str, Any], ...]
    rows: int
    sources: int
    locations: int


PRODUCTION_RECEIPT_SOURCE: Mapping[str, Any] = {
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
}

PRODUCTION_CONTRACT = ArchiveContract(
    filename="RUFF-UWB_mesures1meter.npy_format.zip",
    archive_bytes=793_083_301,
    archive_md5="035d22d657c84b77df980a482cff47b1",
    archive_sha256=("43f344b23ba4981dd8005c02091152fa1f15205703757027630f4708aaf5ba9b"),
    receipt_source=PRODUCTION_RECEIPT_SOURCE,
    collection_token="distance-1",
    source_count=13,
    location_count=50,
    label=ZipMemberContract(
        name="UWB_mesures1meter.labels.npy",
        file_bytes=12_339_840,
        compressed_bytes=25_488,
        crc32=0x6B9AD755,
        compression=zipfile.ZIP_DEFLATED,
        flags=0x8,
        header_offset=793_057_475,
        dtype="<i8",
        shape=(771_232, 2),
        sha256="6f8cf19dc00666bcc61aae08b60426107b7d1073cdefbf86af9d40dbd5e306a6",
    ),
    waveform=ZipMemberContract(
        name="UWB_mesures1meter.data.npy",
        file_bytes=3_084_928_128,
        compressed_bytes=793_057_371,
        crc32=0x14AE6A49,
        compression=zipfile.ZIP_DEFLATED,
        flags=0x8,
        header_offset=0,
        dtype="<c16",
        shape=(771_232, 250),
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


def _read_regular_file(path: Path, maximum_bytes: int, prefix: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise AdapterCompileError(f"{prefix}_unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise AdapterCompileError(f"{prefix}_not_regular")
    if not 0 < before.st_size <= maximum_bytes:
        raise AdapterCompileError(f"{prefix}_size_limit")
    try:
        with path.open("rb") as source:
            opened = _identity(os.fstat(source.fileno()))
            if opened != _identity(before):
                raise AdapterCompileError(f"{prefix}_identity_changed")
            data = source.read(maximum_bytes + 1)
            if len(data) != opened.size or source.read(1):
                raise AdapterCompileError(f"{prefix}_changed_during_read")
            if _identity(os.fstat(source.fileno())) != opened:
                raise AdapterCompileError(f"{prefix}_changed_during_read")
    except AdapterCompileError:
        raise
    except OSError as error:
        raise AdapterCompileError(f"{prefix}_read_failed") from error
    return data


def _parse_json_file(path: Path, maximum_bytes: int, prefix: str) -> Any:
    data = _read_regular_file(path, maximum_bytes, prefix)
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_strict_object)
    except DuplicateJsonKeyError as error:
        raise AdapterCompileError(f"{prefix}_duplicate_json_key") from error
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdapterCompileError(f"{prefix}_invalid_json") from error


def _safe_member_name(name: str) -> None:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise AdapterCompileError("unsafe_archive_member_name") from error
    if (
        not encoded
        or len(encoded) > MAX_MEMBER_NAME_BYTES
        or name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in name.split("/"))
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise AdapterCompileError("unsafe_archive_member_name")


def _validate_member_contract(member: ZipMemberContract, role: str) -> None:
    _safe_member_name(member.name)
    if (
        not 0 < member.file_bytes <= MAX_WAVEFORM_BYTES
        or not 0 < member.compressed_bytes <= MAX_ARCHIVE_BYTES
        or not 0 <= member.crc32 <= 0xFFFFFFFF
        or member.compression not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
        or not 0 <= member.flags <= 0xFFFF
        or member.header_offset < 0
        or not isinstance(member.dtype, str)
        or not 1 <= len(member.dtype) <= 32
        or not isinstance(member.shape, tuple)
        or len(member.shape) != 2
        or any(type(value) is not int for value in member.shape)
        or not 1 <= member.shape[0] <= MAX_ROWS
        or not 1 <= member.shape[1] <= MAX_SAMPLES_PER_ROW
        or member.sha256 is not None
        and SHA256_PATTERN.fullmatch(member.sha256) is None
    ):
        raise AdapterCompileError(f"invalid_{role}_member_contract")


def _validate_contract(contract: ArchiveContract) -> None:
    if (
        not isinstance(contract.filename, str)
        or not contract.filename
        or not 0 < contract.archive_bytes <= MAX_ARCHIVE_BYTES
        or MD5_PATTERN.fullmatch(contract.archive_md5) is None
        or SHA256_PATTERN.fullmatch(contract.archive_sha256) is None
        or not isinstance(contract.receipt_source, Mapping)
        or not contract.receipt_source
        or not isinstance(contract.collection_token, str)
        or not contract.collection_token
        or not 1 <= contract.source_count <= MAX_DISTINCT_SOURCES
        or not 1 <= contract.location_count <= MAX_DISTINCT_LOCATIONS
        or contract.label.name == contract.waveform.name
        or contract.label.shape[0] != contract.waveform.shape[0]
        or contract.label.shape[1] != 2
        or contract.label.sha256 is None
    ):
        raise AdapterCompileError("invalid_archive_contract")
    _safe_member_name(contract.filename)
    _validate_member_contract(contract.label, "label")
    _validate_member_contract(contract.waveform, "waveform")


def _open_archive(
    path: Path, contract: ArchiveContract
) -> Tuple[BinaryIO, FileIdentity]:
    try:
        before = path.lstat()
    except OSError as error:
        raise AdapterCompileError("archive_unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise AdapterCompileError("archive_not_regular")
    if before.st_size != contract.archive_bytes:
        raise AdapterCompileError("archive_size_mismatch")
    try:
        source = path.open("rb")
    except OSError as error:
        raise AdapterCompileError("archive_open_failed") from error
    opened = _identity(os.fstat(source.fileno()))
    if opened != _identity(before):
        source.close()
        raise AdapterCompileError("archive_identity_changed")
    return source, opened


def _require_unchanged(source: BinaryIO, expected: FileIdentity) -> None:
    try:
        actual = _identity(os.fstat(source.fileno()))
    except OSError as error:
        raise AdapterCompileError("archive_changed_during_compile") from error
    if actual != expected:
        raise AdapterCompileError("archive_changed_during_compile")


def _digest_archive(source: BinaryIO, expected: FileIdentity) -> Tuple[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    source.seek(0)
    remaining = expected.size
    while remaining:
        chunk = source.read(min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise AdapterCompileError("archive_changed_during_digest")
        md5.update(chunk)
        sha256.update(chunk)
        remaining -= len(chunk)
    if source.read(1):
        raise AdapterCompileError("archive_exceeds_contract")
    _require_unchanged(source, expected)
    source.seek(0)
    return md5.hexdigest(), sha256.hexdigest()


def _validate_receipt(
    receipt_path: Path, contract: ArchiveContract, md5: str, sha256: str
) -> None:
    receipt = _parse_json_file(receipt_path, MAX_RECEIPT_BYTES, "receipt")
    expected = {
        "schema": RECEIPT_SCHEMA,
        "source": contract.receipt_source,
        "bytes": contract.archive_bytes,
        "md5": md5,
        "sha256": sha256,
        "archive": contract.filename,
    }
    if receipt != expected:
        raise AdapterCompileError("archive_receipt_mismatch")


def _member_metadata(member: zipfile.ZipInfo) -> Tuple[int, int, int, int, int, int]:
    return (
        member.file_size,
        member.compress_size,
        member.CRC,
        member.compress_type,
        member.flag_bits,
        member.header_offset,
    )


def _contract_metadata(
    member: ZipMemberContract,
) -> Tuple[int, int, int, int, int, int]:
    return (
        member.file_bytes,
        member.compressed_bytes,
        member.crc32,
        member.compression,
        member.flags,
        member.header_offset,
    )


def _local_data_offset(source: BinaryIO, member: zipfile.ZipInfo) -> int:
    source.seek(member.header_offset)
    header = source.read(30)
    if len(header) != 30:
        raise AdapterCompileError("archive_member_extent")
    fields = struct.unpack("<4s5H3L2H", header)
    (
        signature,
        _,
        flags,
        compression,
        _,
        _,
        crc32,
        compressed,
        size,
        name_len,
        extra_len,
    ) = fields
    if (
        signature != b"PK\x03\x04"
        or flags != member.flag_bits
        or compression != member.compress_type
    ):
        raise AdapterCompileError("archive_local_header_mismatch")
    encoded_name = source.read(name_len)
    if encoded_name != member.filename.encode("utf-8"):
        raise AdapterCompileError("archive_local_header_mismatch")
    if member.flag_bits & 0x8:
        if (
            crc32 not in {0, member.CRC}
            or compressed not in {0, member.compress_size}
            or size not in {0, member.file_size}
        ):
            raise AdapterCompileError("archive_local_header_mismatch")
    elif (crc32, compressed, size) != (
        member.CRC,
        member.compress_size,
        member.file_size,
    ):
        raise AdapterCompileError("archive_local_header_mismatch")
    return member.header_offset + 30 + name_len + extra_len


def _inspect_members(
    archive: zipfile.ZipFile, source: BinaryIO, contract: ArchiveContract
) -> Mapping[str, zipfile.ZipInfo]:
    members = archive.infolist()
    if len(members) != 2:
        raise AdapterCompileError("archive_member_count")
    if len({member.filename for member in members}) != len(members):
        raise AdapterCompileError("duplicate_archive_member")
    expected = {
        contract.label.name: contract.label,
        contract.waveform.name: contract.waveform,
    }
    if set(member.filename for member in members) != set(expected):
        raise AdapterCompileError("archive_member_schema")
    ordered = sorted(members, key=lambda member: member.header_offset)
    for index, member in enumerate(ordered):
        _safe_member_name(member.filename)
        mode = member.external_attr >> 16
        if (
            member.is_dir()
            or member.flag_bits & 0x1
            or stat.S_ISLNK(mode)
            or _member_metadata(member) != _contract_metadata(expected[member.filename])
        ):
            raise AdapterCompileError("archive_member_metadata_mismatch")
        data_offset = _local_data_offset(source, member)
        extent_limit = (
            ordered[index + 1].header_offset
            if index + 1 < len(ordered)
            else archive.start_dir
        )
        if (
            not member.header_offset
            < data_offset
            <= data_offset + member.compress_size
            <= extent_limit
        ):
            raise AdapterCompileError("archive_member_extent")
    if not 0 < archive.start_dir < contract.archive_bytes:
        raise AdapterCompileError("archive_member_extent")
    source.seek(0)
    return {member.filename: member for member in members}


def _read_npy_header(source: BinaryIO, member_bytes: int, prefix: str) -> NpyHeader:
    magic = source.read(8)
    if magic != b"\x93NUMPY\x01\x00":
        raise AdapterCompileError(f"unsupported_{prefix}_npy_version")
    encoded_size = source.read(2)
    if len(encoded_size) != 2:
        raise AdapterCompileError(f"truncated_{prefix}_npy_header")
    header_size = struct.unpack("<H", encoded_size)[0]
    if not 1 <= header_size <= MAX_NPY_HEADER_BYTES:
        raise AdapterCompileError(f"{prefix}_npy_header_size")
    encoded_header = source.read(header_size)
    if len(encoded_header) != header_size:
        raise AdapterCompileError(f"truncated_{prefix}_npy_header")
    try:
        value = ast.literal_eval(encoded_header.decode("latin1").strip())
    except (SyntaxError, ValueError) as error:
        raise AdapterCompileError(f"invalid_{prefix}_npy_header") from error
    if not isinstance(value, dict) or set(value) != {"descr", "fortran_order", "shape"}:
        raise AdapterCompileError(f"invalid_{prefix}_npy_header")
    shape = value["shape"]
    if (
        not isinstance(value["descr"], str)
        or value["fortran_order"] is not False
        or not isinstance(shape, tuple)
        or len(shape) != 2
        or any(type(item) is not int for item in shape)
    ):
        raise AdapterCompileError(f"unsupported_{prefix}_array")
    encoded = magic + encoded_size + encoded_header
    if len(encoded) >= member_bytes:
        raise AdapterCompileError(f"{prefix}_extent_mismatch")
    return NpyHeader(
        version=(1, 0),
        dtype=value["descr"],
        fortran_order=False,
        shape=shape,
        encoded=encoded,
    )


def _dtype_itemsize(dtype: str) -> int:
    match = re.fullmatch(r"[<>=|]?[A-Za-z?](\d+)", dtype)
    if match is None:
        raise AdapterCompileError("unsupported_npy_dtype")
    return int(match.group(1))


def _validate_npy_extent(header: NpyHeader, member_bytes: int, prefix: str) -> None:
    rows, fields = header.shape
    if (
        not 1 <= rows <= MAX_ROWS
        or not 1 <= fields <= MAX_SAMPLES_PER_ROW
        or len(header.encoded) + rows * fields * _dtype_itemsize(header.dtype)
        != member_bytes
    ):
        raise AdapterCompileError(f"{prefix}_extent_mismatch")


def _opaque_id(domain: str, *components: object) -> str:
    digest = hashlib.sha256()
    namespace = b"netbraid.ruff-uwb-row-adapter-id.v0"
    for value in (namespace, domain.encode("utf-8")):
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    for component in components:
        if isinstance(component, int):
            if component < 0:
                raise AdapterCompileError("negative_id_component")
            encoded = b"i" + component.to_bytes(8, "big")
        elif isinstance(component, str):
            encoded = b"s" + component.encode("utf-8")
        else:
            raise AdapterCompileError("unsupported_id_component")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _read_labels(
    archive: zipfile.ZipFile, member: zipfile.ZipInfo, contract: ArchiveContract
) -> LabelFacts:
    spans: List[Mapping[str, Any]] = []
    sources: set[int] = set()
    locations: set[int] = set()
    digest = hashlib.sha256()
    row_index = 0
    prior: Optional[Tuple[int, int]] = None
    try:
        with archive.open(member, "r") as label_source:
            header = _read_npy_header(label_source, member.file_size, "label")
            _validate_npy_extent(header, member.file_size, "label")
            if (
                header.dtype != contract.label.dtype
                or header.shape != contract.label.shape
            ):
                raise AdapterCompileError("label_shape_or_dtype_mismatch")
            digest.update(header.encoded)
            remaining = member.file_size - len(header.encoded)
            carry = b""
            while remaining:
                chunk = label_source.read(min(READ_CHUNK_BYTES, remaining))
                if not chunk:
                    raise AdapterCompileError("truncated_label_payload")
                remaining -= len(chunk)
                digest.update(chunk)
                chunk = carry + chunk
                usable = len(chunk) - len(chunk) % 16
                for source_value, location_value in struct.iter_unpack(
                    "<qq", chunk[:usable]
                ):
                    if (
                        not 0 <= source_value < 1 << 63
                        or not 0 <= location_value < 1 << 63
                    ):
                        raise AdapterCompileError("label_value_out_of_range")
                    pair = (source_value, location_value)
                    if pair != prior:
                        if spans:
                            spans[-1]["row_stop"] = row_index
                        spans.append(
                            {
                                "row_start": row_index,
                                "row_stop": None,
                                "distance_collection": _opaque_id(
                                    "distance_collection", contract.collection_token
                                ),
                                "physical_source": _opaque_id(
                                    "physical_source", source_value
                                ),
                                "physical_device": _opaque_id(
                                    "physical_device", source_value
                                ),
                                "location": _opaque_id(
                                    "location",
                                    contract.collection_token,
                                    location_value,
                                ),
                            }
                        )
                        if len(spans) > MAX_SPANS:
                            raise AdapterCompileError("row_span_count_limit")
                        prior = pair
                    sources.add(source_value)
                    locations.add(location_value)
                    if len(sources) > MAX_DISTINCT_SOURCES:
                        raise AdapterCompileError("source_count_limit")
                    if len(locations) > MAX_DISTINCT_LOCATIONS:
                        raise AdapterCompileError("location_count_limit")
                    row_index += 1
                carry = chunk[usable:]
            if carry or row_index != header.shape[0] or label_source.read(1):
                raise AdapterCompileError("label_extent_mismatch")
    except AdapterCompileError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as error:
        raise AdapterCompileError("label_member_read_failed") from error
    if spans:
        spans[-1]["row_stop"] = row_index
    if digest.hexdigest() != contract.label.sha256:
        raise AdapterCompileError("label_member_digest_mismatch")
    if (
        len(sources) != contract.source_count
        or len(locations) != contract.location_count
    ):
        raise AdapterCompileError("label_distinct_count_mismatch")
    return LabelFacts(
        sha256=digest.hexdigest(),
        spans=tuple(spans),
        rows=row_index,
        sources=len(sources),
        locations=len(locations),
    )


def _member_binding(member: ZipMemberContract, sha256: str) -> Mapping[str, Any]:
    return {
        "member_bytes": member.file_bytes,
        "compressed_bytes": member.compressed_bytes,
        "crc32": f"{member.crc32:08x}",
        "compression": member.compression,
        "flags": member.flags,
        "header_offset": member.header_offset,
        "sha256": sha256,
        "npy_version": [1, 0],
        "dtype": member.dtype,
        "fortran_order": False,
        "shape": list(member.shape),
    }


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _adapter_document(
    contract: ArchiveContract, labels: LabelFacts, waveform_sha256: str
) -> Dict[str, Any]:
    collection_ids = {span["distance_collection"] for span in labels.spans}
    source_ids = {span["physical_source"] for span in labels.spans}
    device_ids = {span["physical_device"] for span in labels.spans}
    location_ids = {span["location"] for span in labels.spans}
    value: Dict[str, Any] = {
        "schema": SCHEMA,
        "status": "pass",
        "archive": {
            "archive_bytes": contract.archive_bytes,
            "archive_md5": contract.archive_md5,
            "archive_sha256": contract.archive_sha256,
            "receipt_schema": RECEIPT_SCHEMA,
        },
        "label_member": _member_binding(contract.label, labels.sha256),
        "waveform_member": _member_binding(contract.waveform, waveform_sha256),
        "waveform_source": {
            "file_bytes": contract.waveform.file_bytes,
            "sha256": waveform_sha256,
            "rows": contract.waveform.shape[0],
            "samples_per_row": contract.waveform.shape[1],
            "dtype": contract.waveform.dtype,
        },
        "counts": {
            "rows": labels.rows,
            "spans": len(labels.spans),
            "distance_collections": len(collection_ids),
            "physical_sources": len(source_ids),
            "physical_devices": len(device_ids),
            "locations": len(location_ids),
        },
        "spans": list(labels.spans),
        "privacy": {
            "input_paths_retained": 0,
            "filenames_retained": 0,
            "raw_label_values_retained": 0,
            "source_urls_retained": 0,
        },
    }
    value["adapter_id"] = hashlib.sha256(
        b"netbraid.ruff-uwb-row-adapter.v0\x00" + _canonical_json(value)
    ).hexdigest()
    return value


def render_adapter(adapter: Mapping[str, Any]) -> bytes:
    try:
        encoded = _canonical_json(adapter) + b"\n"
    except (TypeError, ValueError) as error:
        raise AdapterCompileError("adapter_not_json_serializable") from error
    if len(encoded) > MAX_ADAPTER_BYTES:
        raise AdapterCompileError("adapter_output_size_limit")
    return encoded


def _sha256_file(path: Path, expected_bytes: int, prefix: str) -> str:
    try:
        before = path.lstat()
    except OSError as error:
        raise AdapterCompileError(f"{prefix}_unavailable") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size != expected_bytes
        or stat.S_IMODE(before.st_mode) != 0o600
    ):
        raise AdapterCompileError(f"{prefix}_contract_mismatch")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            opened = _identity(os.fstat(source.fileno()))
            if opened != _identity(before):
                raise AdapterCompileError(f"{prefix}_changed")
            remaining = expected_bytes
            while remaining:
                chunk = source.read(min(READ_CHUNK_BYTES, remaining))
                if not chunk:
                    raise AdapterCompileError(f"{prefix}_changed")
                digest.update(chunk)
                remaining -= len(chunk)
            if source.read(1) or _identity(os.fstat(source.fileno())) != opened:
                raise AdapterCompileError(f"{prefix}_changed")
    except AdapterCompileError:
        raise
    except OSError as error:
        raise AdapterCompileError(f"{prefix}_read_failed") from error
    return digest.hexdigest()


def _validate_standalone_npy(path: Path, member: ZipMemberContract) -> None:
    try:
        with path.open("rb") as source:
            header = _read_npy_header(source, member.file_bytes, "waveform")
    except AdapterCompileError:
        raise
    except OSError as error:
        raise AdapterCompileError("waveform_output_read_failed") from error
    _validate_npy_extent(header, member.file_bytes, "waveform")
    if header.dtype != member.dtype or header.shape != member.shape:
        raise AdapterCompileError("waveform_shape_or_dtype_mismatch")


def _try_reuse(
    waveform_path: Path,
    adapter_path: Path,
    contract: ArchiveContract,
    labels: LabelFacts,
) -> Optional[Dict[str, Any]]:
    if not waveform_path.exists() or not adapter_path.exists():
        return None
    try:
        waveform_before = _identity(waveform_path.lstat())
        if stat.S_IMODE(adapter_path.lstat().st_mode) != 0o600:
            return None
        adapter = _parse_json_file(adapter_path, MAX_ADAPTER_BYTES, "adapter")
        if not isinstance(adapter, Mapping):
            return None
        source = adapter.get("waveform_source")
        if not isinstance(source, Mapping) or set(source) != {
            "file_bytes",
            "sha256",
            "rows",
            "samples_per_row",
            "dtype",
        }:
            return None
        digest = _sha256_file(
            waveform_path, contract.waveform.file_bytes, "waveform_output"
        )
        if digest != source.get("sha256"):
            return None
        _validate_standalone_npy(waveform_path, contract.waveform)
        if _identity(waveform_path.lstat()) != waveform_before:
            return None
        expected = _adapter_document(contract, labels, digest)
        if adapter != expected:
            return None
        return expected
    except (AdapterCompileError, OSError):
        return None


def _validate_destination(
    path: Path, archive_path: Path, archive_identity: FileIdentity, prefix: str
) -> None:
    if os.path.abspath(os.fspath(path)) == os.path.abspath(os.fspath(archive_path)):
        raise AdapterCompileError(f"{prefix}_aliases_archive")
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        raise AdapterCompileError(f"{prefix}_unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise AdapterCompileError(f"unsafe_{prefix}_path")
    if (metadata.st_dev, metadata.st_ino) == (
        archive_identity.device,
        archive_identity.inode,
    ):
        raise AdapterCompileError(f"{prefix}_aliases_archive")


def _stream_waveform_to_temp(
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    contract: ZipMemberContract,
    output_directory: Path,
    output_name: str,
) -> Tuple[str, str]:
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{output_name}.", dir=output_directory
    )
    digest = hashlib.sha256()
    total = 0
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            try:
                with archive.open(member, "r") as waveform_source:
                    header = _read_npy_header(
                        waveform_source, member.file_size, "waveform"
                    )
                    _validate_npy_extent(header, member.file_size, "waveform")
                    if header.dtype != contract.dtype or header.shape != contract.shape:
                        raise AdapterCompileError("waveform_shape_or_dtype_mismatch")
                    output.write(header.encoded)
                    digest.update(header.encoded)
                    total = len(header.encoded)
                    remaining = member.file_size - total
                    while remaining:
                        chunk = waveform_source.read(min(READ_CHUNK_BYTES, remaining))
                        if not chunk:
                            raise AdapterCompileError("truncated_waveform_payload")
                        output.write(chunk)
                        digest.update(chunk)
                        total += len(chunk)
                        remaining -= len(chunk)
                    if waveform_source.read(1):
                        raise AdapterCompileError("waveform_extent_mismatch")
            except AdapterCompileError:
                raise
            except (OSError, RuntimeError, zipfile.BadZipFile, zlib.error) as error:
                raise AdapterCompileError("waveform_member_read_failed") from error
            if total != contract.file_bytes:
                raise AdapterCompileError("waveform_extent_mismatch")
            output.flush()
            os.fsync(output.fileno())
            if _identity(os.fstat(output.fileno())).size != contract.file_bytes:
                raise AdapterCompileError("waveform_output_extent_mismatch")
        return temporary, digest.hexdigest()
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def _write_temp(path: Path, encoded: bytes) -> str:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        return temporary
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError as error:
        raise AdapterCompileError("output_directory_sync_failed") from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise AdapterCompileError("output_directory_sync_failed") from error
    finally:
        os.close(descriptor)


def compile_row_adapter(
    archive_path: Path,
    receipt_path: Path,
    waveform_path: Path,
    adapter_path: Path,
    contract: ArchiveContract = PRODUCTION_CONTRACT,
) -> Tuple[Dict[str, Any], bool]:
    """Compile or verify one receipt-bound adapter and waveform extraction."""

    _validate_contract(contract)
    if archive_path.name != contract.filename:
        raise AdapterCompileError("archive_filename_mismatch")
    if waveform_path.suffix.lower() != ".npy":
        raise AdapterCompileError("waveform_output_must_be_npy")
    if os.path.abspath(os.fspath(waveform_path)) == os.path.abspath(
        os.fspath(adapter_path)
    ):
        raise AdapterCompileError("output_paths_alias")
    waveform_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    adapter_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    source, identity = _open_archive(archive_path, contract)
    waveform_temporary: Optional[str] = None
    adapter_temporary: Optional[str] = None
    try:
        _validate_destination(waveform_path, archive_path, identity, "waveform_output")
        _validate_destination(adapter_path, archive_path, identity, "adapter_output")
        md5, sha256 = _digest_archive(source, identity)
        if md5 != contract.archive_md5 or sha256 != contract.archive_sha256:
            raise AdapterCompileError("archive_digest_mismatch")
        _validate_receipt(receipt_path, contract, md5, sha256)
        try:
            archive = zipfile.ZipFile(source, "r")
        except (OSError, zipfile.BadZipFile) as error:
            raise AdapterCompileError("invalid_zip_archive") from error
        with archive:
            members = _inspect_members(archive, source, contract)
            labels = _read_labels(archive, members[contract.label.name], contract)
            _require_unchanged(source, identity)
            existing = _try_reuse(waveform_path, adapter_path, contract, labels)
            if existing is not None:
                _require_unchanged(source, identity)
                return existing, True
            waveform_temporary, waveform_sha256 = _stream_waveform_to_temp(
                archive,
                members[contract.waveform.name],
                contract.waveform,
                waveform_path.parent,
                waveform_path.name,
            )
        _require_unchanged(source, identity)
        adapter = _adapter_document(contract, labels, waveform_sha256)
        adapter_temporary = _write_temp(adapter_path, render_adapter(adapter))
        _require_unchanged(source, identity)
        os.replace(waveform_temporary, waveform_path)
        waveform_temporary = None
        _fsync_directory(waveform_path.parent)
        os.replace(adapter_temporary, adapter_path)
        adapter_temporary = None
        _fsync_directory(adapter_path.parent)
        return adapter, False
    except AdapterCompileError:
        raise
    except OSError as error:
        raise AdapterCompileError("output_commit_failed") from error
    finally:
        source.close()
        for temporary in (waveform_temporary, adapter_temporary):
            if temporary is not None:
                with suppress(FileNotFoundError):
                    os.unlink(temporary)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive",
        type=Path,
        default=ROOT / "data" / "raw" / PRODUCTION_CONTRACT.filename,
        help="receipt-paired pinned one-meter archive",
    )
    parser.add_argument(
        "--receipt",
        type=Path,
        default=(
            ROOT
            / "data"
            / "receipts"
            / "public-eval-corpus"
            / f"{PRODUCTION_CONTRACT.filename}.json"
        ),
        help="central ignored fetch receipt for the pinned archive",
    )
    parser.add_argument(
        "--waveforms-output",
        type=Path,
        default=(
            ROOT / "data" / "derived" / "eval" / "ruff-uwb-one-meter-waveforms.npy"
        ),
        help="ignored standalone mmap-able waveform NPY",
    )
    parser.add_argument(
        "--adapter-output",
        type=Path,
        default=(
            ROOT / "data" / "derived" / "eval" / "ruff-uwb-one-meter-row-adapter.json"
        ),
        help="ignored path-free row adapter manifest",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        adapter, reused = compile_row_adapter(
            args.archive,
            args.receipt,
            args.waveforms_output,
            args.adapter_output,
        )
    except AdapterCompileError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "pass",
                "adapter_id": adapter["adapter_id"],
                "rows": adapter["counts"]["rows"],
                "spans": adapter["counts"]["spans"],
                "reused": reused,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
