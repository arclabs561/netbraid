#!/usr/bin/env python3
"""Profile bounded aggregate SigMF metadata from the downloaded OSU LoRa tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Sequence
from urllib.parse import unquote_to_bytes, urlsplit

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.osu_lora_sigmf_profile.v0"

MAX_DIRECTORIES = 2_048
MAX_FILES = 25_000
MAX_DEPTH = 8
MAX_COMPONENT_BYTES = 255
MAX_RELATIVE_PATH_BYTES = 1_024
MAX_FILE_BYTES = 4 * GIB
MAX_METADATA_FILE_BYTES = MIB
MAX_TOTAL_METADATA_BYTES = 128 * MIB
DEFAULT_MAX_TOTAL_TREE_BYTES = 320 * GIB
HARD_MAX_TOTAL_TREE_BYTES = 512 * GIB
MAX_ARRAY_ITEMS = 10_000
MAX_TEXT_BYTES = 4 * KIB
MAX_DISTINCT_LABELS = 50_000
MAX_REPORT_BYTES = 256 * KIB

SETUP_TOKENS = frozenset(
    {
        "configurations",
        "days-indoor",
        "days-outdoor",
        "days-wired",
        "distances",
        "locations",
        "receivers",
    }
)
WRAPPER_KEYS = frozenset({"version", "schema", "_metadata", "data_file"})
METADATA_KEYS = frozenset({"global", "captures", "annotations"})
GLOBAL_KEYS = frozenset(
    {"core:author", "core:datatype", "core:description", "core:sample_rate"}
)
CAPTURE_KEYS = frozenset({"core:date", "core:sample_start", "frequency"})
ANNOTATION_KEYS = frozenset(
    {
        "core:sample_count",
        "core:sample_start",
        "wines:reciever",
        "wines:transmitter",
    }
)
RECEIVER_KEYS = frozenset({"antenna", "model"})
TRANSMITTER_KEYS = frozenset({"ID", "antenna", "model"})
TRANSMITTER_ID_KEYS = frozenset({"Transmission ID", "Transmitter ID"})
ANTENNA_KEYS = frozenset({"gain", "model", "type"})

VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
DATATYPE_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}")
SAMPLE_RATE_PATTERN = re.compile(r"[0-9]+(?:\.[0-9]+)?\s*(?:[kMGT]?S/s|[kMGT]?Hz)")
DISTANCE_PATTERN = re.compile(r"(?:0|[1-9][0-9]{0,3})(?:\.[0-9]+)?m")
CF32_PATTERN = re.compile(r"cf32(?:_(?:le|be))?", re.IGNORECASE)
MALFORMED_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")


class ProfileError(RuntimeError):
    """Stable failure at a local traversal or metadata boundary."""


class DuplicateKeyError(ValueError):
    """A JSON object repeated a key."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class FileRecord:
    path: Path
    relative: Path
    identity: FileIdentity
    kind: str


@dataclass(frozen=True)
class DirectoryRecord:
    path: Path
    identity: FileIdentity


@dataclass(frozen=True)
class TreeInventory:
    directories: tuple[DirectoryRecord, ...]
    files: tuple[FileRecord, ...]
    total_bytes: int
    metadata_bytes: int


@dataclass(frozen=True)
class MetadataFacts:
    version: str
    datatype: str
    sample_rate: str
    captures: int
    annotations: int
    sample_count: int
    receiver_labels: tuple[str, ...]
    transmitter_labels: tuple[str, ...]
    declaration_kind: str
    declaration_matches_stem: bool


@dataclass(frozen=True)
class SourceErratum:
    source_bytes: int
    source_sha256: str


class RepairedMetadata(dict[str, Any]):
    """Strictly parsed metadata carrying a source-erratum proof."""

    def __init__(self, value: dict[str, Any], source_erratum: SourceErratum):
        super().__init__(value)
        self.source_erratum = source_erratum


SOURCE_ERRATA = {
    (
        "receivers/Diff_Receivers_Setup_Indoor_SameTx/RX2/Device1_FFT.sigmf-meta"
    ): SourceErratum(
        source_bytes=4_057,
        source_sha256="afaec1310788dc79cc84dff736e247fa92284e6b87cf60441e7726c5d84d9b2c",
    ),
    (
        "receivers/Diff_Receivers_Setup_Outdoor_DiffTx/RX2/Device1_FFT.sigmf-meta"
    ): SourceErratum(
        source_bytes=4_065,
        source_sha256="8f9ded39bc5374fb03d97cef42e3003fdf064194dc95b7af3fd9c8e97392b9be",
    ),
    (
        "receivers/Diff_Receivers_Setup_Outdoor_SameTx/RX2/Device1_FFT.sigmf-meta"
    ): SourceErratum(
        source_bytes=4_059,
        source_sha256="55a76bb1b15c50834619245ba739a930d07c14f80cfaf3ca47eb0803e03d7018",
    ),
}
SOURCE_ERRATUM_RECEIPT_DOMAIN = "netbraid.osu_lora_sigmf.source_errata.v0"
SOURCE_ERRATUM_REPAIR_OPERATION = "prepend_opening_object_brace"


def file_identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _safe_component(name: str) -> int:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ProfileError("unsafe_path_component") from error
    if (
        not encoded
        or len(encoded) > MAX_COMPONENT_BYTES
        or name in {".", ".."}
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise ProfileError("unsafe_path_component")
    return len(encoded)


def _entry_stat(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise ProfileError("tree_entry_unavailable") from error


def _bounded_total_tree_bytes(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProfileError("invalid_total_tree_byte_limit")
    if value > HARD_MAX_TOTAL_TREE_BYTES:
        raise ProfileError("total_tree_byte_limit_exceeds_hard_ceiling")
    return value


def _parse_total_tree_bytes(value: str) -> int:
    try:
        parsed = int(value, 10)
        return _bounded_total_tree_bytes(parsed)
    except (ProfileError, ValueError) as error:
        raise argparse.ArgumentTypeError(
            f"must be an integer from 1 through {HARD_MAX_TOTAL_TREE_BYTES}"
        ) from error


def inventory_tree(
    root: Path, *, max_total_bytes: int = DEFAULT_MAX_TOTAL_TREE_BYTES
) -> TreeInventory:
    max_total_bytes = _bounded_total_tree_bytes(max_total_bytes)
    root_metadata = _entry_stat(root)
    if stat.S_ISLNK(root_metadata.st_mode):
        raise ProfileError("symlink_rejected")
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise ProfileError("root_is_not_a_directory")

    directories = [DirectoryRecord(root, file_identity(root_metadata))]
    files: list[FileRecord] = []
    seen_paths: set[str] = set()
    stack: list[tuple[Path, int]] = [(root, 0)]
    total_bytes = 0
    metadata_bytes = 0

    while stack:
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as source:
                entries = sorted(source, key=lambda entry: os.fsencode(entry.name))
        except OSError as error:
            raise ProfileError("directory_traversal_failed") from error

        child_directories: list[tuple[Path, int]] = []
        for entry in entries:
            _safe_component(entry.name)
            path = Path(entry.path)
            relative = path.relative_to(root)
            relative_text = relative.as_posix()
            try:
                relative_bytes = relative_text.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ProfileError("unsafe_relative_path") from error
            if len(relative_bytes) > MAX_RELATIVE_PATH_BYTES:
                raise ProfileError("relative_path_limit_exceeded")
            folded = relative_text.casefold()
            if folded in seen_paths:
                raise ProfileError("duplicate_or_case_colliding_path")
            seen_paths.add(folded)

            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise ProfileError("tree_entry_unavailable") from error
            mode = metadata.st_mode
            if stat.S_ISLNK(mode):
                raise ProfileError("symlink_rejected")
            if stat.S_ISDIR(mode):
                if depth + 1 > MAX_DEPTH:
                    raise ProfileError("directory_depth_limit_exceeded")
                directories.append(DirectoryRecord(path, file_identity(metadata)))
                if len(directories) - 1 > MAX_DIRECTORIES:
                    raise ProfileError("directory_count_limit_exceeded")
                child_directories.append((path, depth + 1))
                continue
            if not stat.S_ISREG(mode):
                raise ProfileError("non_regular_entry_rejected")

            identity = file_identity(metadata)
            if identity.size < 0 or identity.size > MAX_FILE_BYTES:
                raise ProfileError("file_byte_limit_exceeded")
            kind = (
                "metadata"
                if entry.name.endswith(".sigmf-meta")
                else "data"
                if entry.name.endswith(".dat")
                else "other"
            )
            if kind == "metadata":
                if identity.size > MAX_METADATA_FILE_BYTES:
                    raise ProfileError("metadata_file_byte_limit_exceeded")
                metadata_bytes += identity.size
                if metadata_bytes > MAX_TOTAL_METADATA_BYTES:
                    raise ProfileError("metadata_total_byte_limit_exceeded")
            total_bytes += identity.size
            if total_bytes > max_total_bytes:
                raise ProfileError("tree_total_byte_limit_exceeded")
            files.append(FileRecord(path, relative, identity, kind))
            if len(files) > MAX_FILES:
                raise ProfileError("file_count_limit_exceeded")

        stack.extend(reversed(child_directories))

    files.sort(key=lambda record: os.fsencode(record.relative.as_posix()))
    directories.sort(key=lambda record: os.fsencode(str(record.path.relative_to(root))))
    return TreeInventory(
        directories=tuple(directories),
        files=tuple(files),
        total_bytes=total_bytes,
        metadata_bytes=metadata_bytes,
    )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def strict_json(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_float=Decimal,
            parse_constant=_reject_json_constant,
        )
    except DuplicateKeyError as error:
        raise ProfileError("duplicate_json_key") from error
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as error:
        raise ProfileError("invalid_metadata_json") from error
    if not isinstance(value, dict):
        raise ProfileError("metadata_root_is_not_an_object")
    return value


def _same_identity(metadata: os.stat_result, expected: FileIdentity) -> bool:
    return file_identity(metadata) == expected


def _open_metadata(record: FileRecord) -> tuple[BinaryIO, FileIdentity]:
    before = _entry_stat(record.path)
    if not stat.S_ISREG(before.st_mode) or not _same_identity(before, record.identity):
        raise ProfileError("metadata_changed_before_read")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(record.path, flags)
    except OSError as error:
        raise ProfileError("metadata_open_failed") from error
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or not _same_identity(
            after, record.identity
        ):
            raise ProfileError("metadata_changed_before_read")
        return os.fdopen(descriptor, "rb"), record.identity
    except BaseException:
        os.close(descriptor)
        raise


def _source_errata_receipt(repairs: Sequence[SourceErratum]) -> str:
    digest = hashlib.sha256()
    digest.update(SOURCE_ERRATUM_RECEIPT_DOMAIN.encode("ascii") + b"\0")
    for repair in sorted(
        repairs, key=lambda item: (item.source_sha256, item.source_bytes)
    ):
        record = json.dumps(
            {
                "operation": SOURCE_ERRATUM_REPAIR_OPERATION,
                "source_bytes": repair.source_bytes,
                "source_sha256": repair.source_sha256,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        digest.update(len(record).to_bytes(8, "big"))
        digest.update(record)
    return digest.hexdigest()


def _read_metadata(record: FileRecord) -> dict[str, Any]:
    source, expected = _open_metadata(record)
    with source:
        remaining = expected.size
        chunks: list[bytes] = []
        while remaining:
            chunk = source.read(min(64 * KIB, remaining))
            if not chunk:
                raise ProfileError("metadata_changed_during_read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if source.read(1):
            raise ProfileError("metadata_exceeded_byte_fence")
        if not _same_identity(os.fstat(source.fileno()), expected):
            raise ProfileError("metadata_changed_during_read")
    data = b"".join(chunks)
    source_erratum = SOURCE_ERRATA.get(record.relative.as_posix())
    if source_erratum is None:
        return strict_json(data)

    source_sha256 = hashlib.sha256(data).hexdigest()
    if (
        len(data) == source_erratum.source_bytes
        and source_sha256 == source_erratum.source_sha256
    ):
        document = strict_json(b"{" + data)
        return RepairedMetadata(document, source_erratum)

    try:
        return strict_json(data)
    except ProfileError as error:
        raise ProfileError("source_erratum_pin_mismatch") from error


def _exact_object(value: Any, keys: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProfileError("metadata_schema_mismatch")
    return value


def _bounded_string(value: Any) -> str:
    if not isinstance(value, str):
        raise ProfileError("metadata_value_type_mismatch")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ProfileError("metadata_string_is_invalid") from error
    if len(encoded) > MAX_TEXT_BYTES:
        raise ProfileError("metadata_string_limit_exceeded")
    return value


def _nonnegative_integer(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProfileError("metadata_integer_mismatch")
    return value


def _validate_antenna(value: Any) -> None:
    antenna = _exact_object(value, ANTENNA_KEYS)
    _bounded_string(antenna["model"])
    _bounded_string(antenna["type"])
    _nonnegative_integer(antenna["gain"])


def _validate_label(value: Any, *, transmitter: bool) -> str:
    keys = TRANSMITTER_KEYS if transmitter else RECEIVER_KEYS
    label = _exact_object(value, keys)
    _bounded_string(label["model"])
    _validate_antenna(label["antenna"])
    if transmitter:
        identifiers = _exact_object(label["ID"], TRANSMITTER_ID_KEYS)
        for item in identifiers.values():
            if isinstance(item, bool) or not isinstance(item, (int, str)):
                raise ProfileError("metadata_value_type_mismatch")
            if isinstance(item, int):
                _nonnegative_integer(item)
            else:
                _bounded_string(item)
    return json.dumps(label, sort_keys=True, separators=(",", ":"))


def _decoded_url_segments(path: str) -> tuple[str, ...]:
    if not path.startswith("/") or MALFORMED_PERCENT.search(path):
        raise ProfileError("unsafe_data_file_declaration")
    raw_segments = path.split("/")[1:]
    if not raw_segments or any(not segment for segment in raw_segments):
        raise ProfileError("unsafe_data_file_declaration")
    decoded: list[str] = []
    for raw_segment in raw_segments:
        try:
            segment = unquote_to_bytes(raw_segment).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProfileError("unsafe_data_file_declaration") from error
        if (
            segment in {"", ".", ".."}
            or "/" in segment
            or "\\" in segment
            or any(
                ord(character) < 32 or ord(character) == 127 for character in segment
            )
        ):
            raise ProfileError("unsafe_data_file_declaration")
        _safe_component(segment)
        decoded.append(segment)
    return tuple(decoded)


def _data_file_declaration(value: Any, local_stem: str) -> tuple[str, bool]:
    declaration = _bounded_string(value)
    try:
        parts = urlsplit(declaration)
        port = parts.port
    except ValueError as error:
        raise ProfileError("unsafe_data_file_declaration") from error

    if parts.scheme or parts.netloc:
        if (
            parts.scheme != "https"
            or not parts.netloc
            or parts.hostname is None
            or parts.username is not None
            or parts.password is not None
            or port not in {None, 443}
            or parts.query
            or parts.fragment
        ):
            raise ProfileError("unsafe_data_file_declaration")
        name = _decoded_url_segments(parts.path)[-1]
    else:
        if parts.query or parts.fragment or "/" in parts.path or "\\" in parts.path:
            raise ProfileError("unsafe_data_file_declaration")
        _safe_component(parts.path)
        name = PurePosixPath(parts.path).name

    suffixes = (
        (".sigmf-meta", "metadata"),
        (".signmf-meta", "metadata_typo"),
        (".dat", "data"),
    )
    for suffix, kind in suffixes:
        if name.endswith(suffix):
            return kind, name.removesuffix(suffix) == local_stem
    raise ProfileError("unsupported_data_file_declaration")


def parse_metadata(
    value: dict[str, Any],
    local_stem: str,
    *,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_TREE_BYTES,
) -> MetadataFacts:
    max_total_samples = _bounded_total_tree_bytes(max_total_bytes) // 8
    wrapper = _exact_object(value, WRAPPER_KEYS)
    version = _bounded_string(wrapper["version"])
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ProfileError("metadata_version_mismatch")

    schema = _exact_object(wrapper["schema"], METADATA_KEYS)
    if any(not isinstance(item, dict) for item in schema.values()):
        raise ProfileError("metadata_schema_mismatch")
    metadata = _exact_object(wrapper["_metadata"], METADATA_KEYS)
    global_metadata = _exact_object(metadata["global"], GLOBAL_KEYS)
    _bounded_string(global_metadata["core:author"])
    _bounded_string(global_metadata["core:description"])
    datatype = _bounded_string(global_metadata["core:datatype"])
    sample_rate = _bounded_string(global_metadata["core:sample_rate"])
    if DATATYPE_PATTERN.fullmatch(datatype) is None:
        raise ProfileError("unsafe_datatype_token")
    if SAMPLE_RATE_PATTERN.fullmatch(sample_rate) is None:
        raise ProfileError("unsafe_sample_rate_token")

    captures = metadata["captures"]
    annotations = metadata["annotations"]
    if (
        not isinstance(captures, list)
        or not isinstance(annotations, list)
        or not captures
        or not annotations
        or len(captures) > MAX_ARRAY_ITEMS
        or len(annotations) > MAX_ARRAY_ITEMS
    ):
        raise ProfileError("metadata_array_mismatch")

    for raw_capture in captures:
        capture = _exact_object(raw_capture, CAPTURE_KEYS)
        _bounded_string(capture["core:date"])
        _nonnegative_integer(capture["core:sample_start"])
        _bounded_string(capture["frequency"])

    sample_count = 0
    receiver_labels: list[str] = []
    transmitter_labels: list[str] = []
    for raw_annotation in annotations:
        annotation = _exact_object(raw_annotation, ANNOTATION_KEYS)
        _nonnegative_integer(annotation["core:sample_start"])
        count = _nonnegative_integer(annotation["core:sample_count"])
        sample_count += count
        if sample_count > max_total_samples:
            raise ProfileError("sample_count_limit_exceeded")
        receiver_labels.append(
            _validate_label(annotation["wines:reciever"], transmitter=False)
        )
        transmitter_labels.append(
            _validate_label(annotation["wines:transmitter"], transmitter=True)
        )

    declaration_kind, declaration_matches = _data_file_declaration(
        wrapper["data_file"], local_stem
    )
    return MetadataFacts(
        version=version,
        datatype=datatype,
        sample_rate=sample_rate,
        captures=len(captures),
        annotations=len(annotations),
        sample_count=sample_count,
        receiver_labels=tuple(receiver_labels),
        transmitter_labels=tuple(transmitter_labels),
        declaration_kind=declaration_kind,
        declaration_matches_stem=declaration_matches,
    )


def _fence_record(record: FileRecord) -> None:
    current = _entry_stat(record.path)
    if not stat.S_ISREG(current.st_mode) or not _same_identity(
        current, record.identity
    ):
        raise ProfileError("tree_file_changed_during_profile")


def _fence_inventory(inventory: TreeInventory) -> None:
    for record in inventory.files:
        _fence_record(record)
    for record in inventory.directories:
        current = _entry_stat(record.path)
        if not stat.S_ISDIR(current.st_mode) or not _same_identity(
            current, record.identity
        ):
            raise ProfileError("tree_directory_changed_during_profile")


def _setup_token(record: FileRecord) -> str:
    if len(record.relative.parts) < 2 or record.relative.parts[0] not in SETUP_TOKENS:
        raise ProfileError("unsupported_setup_path")
    return record.relative.parts[0]


def profile_tree(
    root: Path, *, max_total_bytes: int = DEFAULT_MAX_TOTAL_TREE_BYTES
) -> dict[str, Any]:
    max_total_bytes = _bounded_total_tree_bytes(max_total_bytes)
    max_total_samples = max_total_bytes // 8
    inventory = inventory_tree(root, max_total_bytes=max_total_bytes)
    metadata_records = tuple(
        record for record in inventory.files if record.kind == "metadata"
    )
    data_records = tuple(record for record in inventory.files if record.kind == "data")
    data_by_relative = {record.relative: record for record in data_records}
    if len(data_by_relative) != len(data_records):
        raise ProfileError("duplicate_data_path")

    setup_tokens: set[str] = set()
    distance_tokens: set[str] = set()
    versions: set[str] = set()
    datatypes: set[str] = set()
    sample_rates: set[str] = set()
    receiver_labels: set[str] = set()
    transmitter_labels: set[str] = set()
    declaration_kinds: Counter[str] = Counter()
    expected_data_paths: set[Path] = set()

    captures = 0
    annotations = 0
    aggregate_sample_count = 0
    paired = 0
    cf32_checked = 0
    cf32_matched = 0
    extent_skipped = 0
    source_erratum_repairs: list[SourceErratum] = []
    failures: Counter[str] = Counter()

    for record in metadata_records:
        setup = _setup_token(record)
        setup_tokens.add(setup)
        if setup == "distances":
            if len(record.relative.parts) < 3:
                raise ProfileError("invalid_distance_path")
            distance = record.relative.parts[1]
            if DISTANCE_PATTERN.fullmatch(distance) is None:
                raise ProfileError("invalid_distance_token")
            distance_tokens.add(distance)

        local_stem = record.path.name.removesuffix(".sigmf-meta")
        document = _read_metadata(record)
        if isinstance(document, RepairedMetadata):
            source_erratum_repairs.append(document.source_erratum)
        facts = parse_metadata(
            document,
            local_stem,
            max_total_bytes=max_total_bytes,
        )
        versions.add(facts.version)
        datatypes.add(facts.datatype)
        sample_rates.add(facts.sample_rate)
        captures += facts.captures
        annotations += facts.annotations
        aggregate_sample_count += facts.sample_count
        if aggregate_sample_count > max_total_samples:
            raise ProfileError("sample_count_limit_exceeded")
        receiver_labels.update(facts.receiver_labels)
        transmitter_labels.update(facts.transmitter_labels)
        if (
            len(receiver_labels) > MAX_DISTINCT_LABELS
            or len(transmitter_labels) > MAX_DISTINCT_LABELS
        ):
            raise ProfileError("distinct_label_limit_exceeded")
        declaration_kinds[facts.declaration_kind] += 1
        if not facts.declaration_matches_stem:
            failures["data_file_mismatches"] += 1

        expected_relative = record.relative.with_name(f"{local_stem}.dat")
        expected_data_paths.add(expected_relative)
        data_record = data_by_relative.get(expected_relative)
        if data_record is None:
            failures["missing_data_files"] += 1
            continue
        paired += 1
        if CF32_PATTERN.fullmatch(facts.datatype):
            cf32_checked += 1
            expected_bytes = facts.sample_count * 8
            if data_record.identity.size == expected_bytes:
                cf32_matched += 1
            else:
                failures["extent_mismatches"] += 1
        else:
            extent_skipped += 1

    for record in data_records:
        _setup_token(record)
    failures["orphan_data_files"] = len(set(data_by_relative) - expected_data_paths)
    _fence_inventory(inventory)

    failure_counts = {
        key: failures[key]
        for key in (
            "data_file_mismatches",
            "extent_mismatches",
            "missing_data_files",
            "orphan_data_files",
        )
    }
    total_failures = sum(failure_counts.values())
    data_bytes = sum(record.identity.size for record in data_records)
    other_files = len(inventory.files) - len(metadata_records) - len(data_records)
    return {
        "schema": SCHEMA,
        "status": "pass" if total_failures == 0 else "fail",
        "inventory": {
            "directories": len(inventory.directories) - 1,
            "files": len(inventory.files),
            "metadata_files": len(metadata_records),
            "data_files": len(data_records),
            "other_files": other_files,
            "metadata_bytes": inventory.metadata_bytes,
            "data_bytes": data_bytes,
            "total_bytes": inventory.total_bytes,
        },
        "wrapper": {
            "exact_shape_files": len(metadata_records),
            "distinct_versions": len(versions),
            "data_file_declarations": {
                "data": declaration_kinds["data"],
                "metadata": declaration_kinds["metadata"],
                "metadata_typo": declaration_kinds["metadata_typo"],
            },
        },
        "aggregate_metadata": {
            "captures": captures,
            "annotations": annotations,
            "core_sample_count": aggregate_sample_count,
            "datatypes": sorted(datatypes),
            "sample_rates": sorted(sample_rates),
            "receiver_labels": {
                "distinct_composite_labels": len(receiver_labels),
                "values_retained": 0,
            },
            "transmitter_labels": {
                "distinct_composite_labels": len(transmitter_labels),
                "values_retained": 0,
            },
        },
        "setup": {
            "tokens": sorted(setup_tokens),
            "distance_tokens": sorted(distance_tokens),
        },
        "pairing": {
            "paired_metadata_data_files": paired,
            "local_pairing_rule": "same-directory stem with .dat suffix",
        },
        "cf32_extent_validation": {
            "bytes_per_complex_sample": 8,
            "checked": cf32_checked,
            "matched": cf32_matched,
            "skipped_non_cf32": extent_skipped,
            "iq_payload_bytes_read": 0,
        },
        "source_errata": {
            "normalized_metadata_files": len(source_erratum_repairs),
            "repair_receipt": {
                "algorithm": "sha256",
                "domain": SOURCE_ERRATUM_RECEIPT_DOMAIN,
                "digest": _source_errata_receipt(source_erratum_repairs),
            },
            "repository_relative_paths_retained": 0,
        },
        "validation": {
            "failures": failure_counts,
            "total_failures": total_failures,
        },
        "interpretation": {
            "data_file": (
                "source declaration stem is validated; IQ pairing uses only the "
                "local sibling stem"
            ),
            "cf32": (
                "extent only; byte order is not inferred when the datatype omits it"
            ),
        },
        "privacy": {
            "absolute_paths_retained": 0,
            "authors_retained": 0,
            "label_values_retained": 0,
            "source_urls_retained": 0,
        },
        "limits": {
            "directories": MAX_DIRECTORIES,
            "files": MAX_FILES,
            "depth": MAX_DEPTH,
            "bytes_per_file": MAX_FILE_BYTES,
            "bytes_per_metadata_file": MAX_METADATA_FILE_BYTES,
            "total_metadata_bytes": MAX_TOTAL_METADATA_BYTES,
            "total_tree_bytes": max_total_bytes,
            "total_tree_bytes_hard_ceiling": HARD_MAX_TOTAL_TREE_BYTES,
            "array_items_per_metadata_field": MAX_ARRAY_ITEMS,
            "distinct_labels_per_role": MAX_DISTINCT_LABELS,
            "report_bytes": MAX_REPORT_BYTES,
        },
    }


def render_report(report: dict[str, Any]) -> bytes:
    rendered = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(rendered) > MAX_REPORT_BYTES:
        raise ProfileError("report_byte_limit_exceeded")
    return rendered


def write_report(path: Path, rendered: bytes) -> None:
    if len(rendered) > MAX_REPORT_BYTES:
        raise ProfileError("report_byte_limit_exceeded")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_metadata = _entry_stat(path.parent)
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
        parent_metadata.st_mode
    ):
        raise ProfileError("unsafe_report_directory")
    if path.is_symlink():
        raise ProfileError("unsafe_report_path")
    if path.exists() and not stat.S_ISREG(path.lstat().st_mode):
        raise ProfileError("unsafe_report_path")

    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        directory_descriptor = os.open(path.parent, directory_flags)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT / "data" / "raw" / "osu-lora",
        help="downloaded OSU LoRa setup tree",
    )
    parser.add_argument(
        "--max-total-bytes",
        type=_parse_total_tree_bytes,
        default=DEFAULT_MAX_TOTAL_TREE_BYTES,
        help=(
            "selected total-tree byte bound "
            f"(default: {DEFAULT_MAX_TOTAL_TREE_BYTES}; "
            f"hard ceiling: {HARD_MAX_TOTAL_TREE_BYTES})"
        ),
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "data" / "derived" / "eval" / "osu-lora-sigmf-profile.json",
        help="atomic deterministic aggregate JSON output",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    report = profile_tree(
        arguments.root.expanduser().absolute(),
        max_total_bytes=arguments.max_total_bytes,
    )
    rendered = render_report(report)
    write_report(arguments.report.expanduser().absolute(), rendered)
    sys.stdout.buffer.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
