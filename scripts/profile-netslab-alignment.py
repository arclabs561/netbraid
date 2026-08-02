#!/usr/bin/env python3
"""Profile aggregate metadata from the pinned public NetsLab fusion artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import stat
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Sequence
from urllib.parse import quote

MIB = 1024 * 1024
GIB = 1024 * MIB
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.netslab_alignment_profile.v0"
CATALOG_DOI = "10.1109/IEEEDATA.2025.3614167"

DEFAULT_MMAP_BYTES = 256 * MIB
MAX_MMAP_BYTES = GIB
MAX_ARTIFACT_BYTES = 8 * GIB
MAX_ARCHIVE_MEMBERS = 1024
MAX_CENTRAL_DIRECTORY_BYTES = MIB
MAX_MEMBER_NAME_BYTES = 256
MAX_TOTAL_MEMBER_NAME_BYTES = 256 * 1024
MAX_MEMBER_EXTRA_BYTES = 4 * 1024
MAX_MEMBER_COMMENT_BYTES = 1024
MAX_ARCHIVE_COMMENT_BYTES = 1024
MAX_MEMBER_BYTES = 8 * GIB
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 40 * GIB
MAX_COMPRESSION_RATIO = 100
MAX_SQLITE_ROWS = 10_000_000
MAX_REPORT_BYTES = 256 * 1024
DIGEST_CHUNK_BYTES = MIB
MD5_PATTERN = re.compile(r"[0-9a-f]{32}")
SAFE_FILENAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SAFE_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

EOCD_SIGNATURE = b"PK\x05\x06"
ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
CENTRAL_HEADER_SIGNATURE = b"PK\x01\x02"
LOCAL_HEADER_SIGNATURE = b"PK\x03\x04"
ZIP64_EXTRA_ID = 0x0001
ALLOWED_COMPRESSION = {0: "stored", 8: "deflated"}


@dataclass(frozen=True)
class ArtifactContract:
    filename: str
    expected_bytes: int
    expected_md5: str


@dataclass(frozen=True)
class CorpusContract:
    archive: ArtifactContract
    lower_database: ArtifactContract
    network_database: ArtifactContract


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


@dataclass(frozen=True)
class TableContract:
    name: str
    columns: tuple[tuple[str, str], ...]
    time_column: str | None
    category_columns: tuple[str, ...]


@dataclass(frozen=True)
class CentralDirectoryLocation:
    entries: int
    size: int
    offset: int
    zip64: bool


PRODUCTION_CONTRACT = CorpusContract(
    archive=ArtifactContract(
        "netslab-5g-oran-benign.zip",
        5_936_426_197,
        "3739c67aab617d0937629ac29633992b",
    ),
    lower_database=ArtifactContract(
        "netslab-5g-oran-lower-layer.db",
        5_402_624,
        "c3af05f535b12c547a4dbaf858a25458",
    ),
    network_database=ArtifactContract(
        "netslab-5g-oran-network.db",
        210_690_048,
        "03a235bd089cc2e7c01f96f82b14f065",
    ),
)

LOWER_TABLE = TableContract(
    "lower_layer_data",
    (
        ("dlBytes", "INTEGER"),
        ("dlMcs", "INTEGER"),
        ("dlBler", "REAL"),
        ("ulBytes", "INTEGER"),
        ("ulMcs", "INTEGER"),
        ("ulBler", "REAL"),
        ("ri", "INTEGER"),
        ("phr", "INTEGER"),
        ("pcmax", "INTEGER"),
        ("rsrq", "REAL"),
        ("sinr", "REAL"),
        ("rsrp", "INTEGER"),
        ("rssi", "REAL"),
        ("cqi", "INTEGER"),
        ("pucchSnr", "REAL"),
        ("puschSnr", "REAL"),
        ("ue_id", "REAL"),
        ("timestamp", "REAL"),
        ("cellid", "REAL"),
        ("in_sync", "REAL"),
        ("rnti", "TEXT"),
        ("pmi", "TEXT"),
        ("traffic_type", "INTEGER"),
        ("attack_category", "TEXT"),
        ("attack_subcategory", "TEXT"),
    ),
    "timestamp",
    ("traffic_type", "attack_category", "attack_subcategory"),
)

NETWORK_TABLE = TableContract(
    "network_data",
    (
        ("uid", "TEXT"),
        ("src_ip", "TEXT"),
        ("src_port", "INTEGER"),
        ("dst_ip", "TEXT"),
        ("dst_port", "INTEGER"),
        ("proto", "TEXT"),
        ("service", "TEXT"),
        ("duration", "REAL"),
        ("src_bytes", "REAL"),
        ("dst_bytes", "REAL"),
        ("conn_state", "TEXT"),
        ("missed_bytes", "INTEGER"),
        ("history", "TEXT"),
        ("src_pkts", "INTEGER"),
        ("src_ip_bytes", "INTEGER"),
        ("dst_pkts", "INTEGER"),
        ("dst_ip_bytes", "INTEGER"),
        ("ip_proto", "INTEGER"),
        ("http_trans_depth", "INTEGER"),
        ("attack_category", "TEXT"),
        ("attack_type", "TEXT"),
        ("files_total_bytes", "REAL"),
        ("is_GET_mthd", "INTEGER"),
        ("http_status_error", "INTEGER"),
        ("is_file_transfered", "INTEGER"),
        ("traffic_type", "INTEGER"),
    ),
    None,
    ("traffic_type", "attack_category", "attack_type"),
)


def file_identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def parse_artifact_contract(contract: ArtifactContract) -> ArtifactContract:
    if (
        not SAFE_FILENAME_PATTERN.fullmatch(contract.filename)
        or Path(contract.filename).name != contract.filename
        or not 0 < contract.expected_bytes <= MAX_ARTIFACT_BYTES
        or not MD5_PATTERN.fullmatch(contract.expected_md5)
    ):
        raise RuntimeError("invalid NetsLab artifact contract")
    return contract


def open_artifact(
    directory: Path, contract: ArtifactContract
) -> tuple[BinaryIO, FileIdentity]:
    contract = parse_artifact_contract(contract)
    path = directory / contract.filename
    try:
        before = path.lstat()
    except OSError as error:
        raise RuntimeError("pinned NetsLab artifact is unavailable") from error
    if not stat.S_ISREG(before.st_mode) or before.st_size != contract.expected_bytes:
        raise RuntimeError(
            "pinned NetsLab artifact path or byte count failed validation"
        )

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError(
            "pinned NetsLab artifact could not be opened safely"
        ) from error
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or file_identity(after) != file_identity(
            before
        ):
            raise RuntimeError("pinned NetsLab artifact changed before opening")
        return os.fdopen(descriptor, "rb"), file_identity(after)
    except BaseException:
        os.close(descriptor)
        raise


def require_unchanged(source: BinaryIO, expected: FileIdentity) -> None:
    if file_identity(os.fstat(source.fileno())) != expected:
        raise RuntimeError("pinned NetsLab artifact changed during inspection")


def verify_digest(
    source: BinaryIO, identity: FileIdentity, contract: ArtifactContract
) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    source.seek(0)
    remaining = identity.size
    while remaining:
        chunk = source.read(min(DIGEST_CHUNK_BYTES, remaining))
        if not chunk:
            raise RuntimeError("pinned NetsLab artifact changed while hashing")
        digest.update(chunk)
        remaining -= len(chunk)
    if source.read(1):
        raise RuntimeError("pinned NetsLab artifact exceeded its byte contract")
    require_unchanged(source, identity)
    observed = digest.hexdigest()
    if observed != contract.expected_md5:
        raise RuntimeError("pinned NetsLab artifact MD5 failed validation")
    source.seek(0)
    return observed


def read_exact_at(source: BinaryIO, offset: int, length: int, label: str) -> bytes:
    if offset < 0 or length < 0:
        raise RuntimeError(f"invalid {label} bounds")
    source.seek(offset)
    data = source.read(length)
    if len(data) != length:
        raise RuntimeError(f"truncated {label}")
    return data


def find_eocd(source: BinaryIO, identity: FileIdentity) -> tuple[int, tuple[int, ...]]:
    tail_size = min(identity.size, 22 + 65_535)
    tail_offset = identity.size - tail_size
    tail = read_exact_at(source, tail_offset, tail_size, "ZIP trailer")
    search_end = len(tail)
    while True:
        position = tail.rfind(EOCD_SIGNATURE, 0, search_end)
        if position < 0:
            raise RuntimeError("ZIP end-of-central-directory record is absent")
        if position + 22 <= len(tail):
            values = struct.unpack_from("<4H2LH", tail, position + 4)
            comment_bytes = values[6]
            if position + 22 + comment_bytes == len(tail):
                if comment_bytes > MAX_ARCHIVE_COMMENT_BYTES:
                    raise RuntimeError("ZIP archive comment exceeds its bound")
                return tail_offset + position, values
        search_end = position


def central_directory_location(
    source: BinaryIO, identity: FileIdentity
) -> CentralDirectoryLocation:
    eocd_offset, values = find_eocd(source, identity)
    disk, central_disk, entries_disk, entries, size32, offset32, _ = values
    sentinel = (
        disk == 0xFFFF
        or central_disk == 0xFFFF
        or entries_disk == 0xFFFF
        or entries == 0xFFFF
        or size32 == 0xFFFFFFFF
        or offset32 == 0xFFFFFFFF
    )
    if not sentinel:
        if disk != 0 or central_disk != 0 or entries_disk != entries:
            raise RuntimeError("multi-disk ZIP archives are unsupported")
        location = CentralDirectoryLocation(entries, size32, offset32, False)
        expected_end = eocd_offset
    else:
        locator_offset = eocd_offset - 20
        locator = read_exact_at(source, locator_offset, 20, "ZIP64 locator")
        signature, locator_disk, record_offset, total_disks = struct.unpack(
            "<4sLQL", locator
        )
        if (
            signature != ZIP64_LOCATOR_SIGNATURE
            or locator_disk != 0
            or total_disks != 1
        ):
            raise RuntimeError("invalid or multi-disk ZIP64 locator")
        prefix = read_exact_at(source, record_offset, 56, "ZIP64 EOCD")
        fields = struct.unpack("<4sQ2H2L4Q", prefix)
        (
            signature,
            record_size,
            _made_by,
            _needed,
            zip64_disk,
            zip64_central_disk,
            zip64_entries_disk,
            zip64_entries,
            zip64_size,
            zip64_offset,
        ) = fields
        if (
            signature != ZIP64_EOCD_SIGNATURE
            or record_size < 44
            or record_size > 1024
            or zip64_disk != 0
            or zip64_central_disk != 0
            or zip64_entries_disk != zip64_entries
            or record_offset + 12 + record_size != locator_offset
        ):
            raise RuntimeError("invalid ZIP64 end-of-central-directory record")
        if entries != 0xFFFF and entries != zip64_entries:
            raise RuntimeError("inconsistent ZIP64 member count")
        if entries_disk != 0xFFFF and entries_disk != zip64_entries_disk:
            raise RuntimeError("inconsistent ZIP64 disk member count")
        if size32 != 0xFFFFFFFF and size32 != zip64_size:
            raise RuntimeError("inconsistent ZIP64 central-directory size")
        if offset32 != 0xFFFFFFFF and offset32 != zip64_offset:
            raise RuntimeError("inconsistent ZIP64 central-directory offset")
        location = CentralDirectoryLocation(
            zip64_entries, zip64_size, zip64_offset, True
        )
        expected_end = record_offset

    if (
        not 0 < location.entries <= MAX_ARCHIVE_MEMBERS
        or not 0 < location.size <= MAX_CENTRAL_DIRECTORY_BYTES
        or location.offset < 0
        or location.offset + location.size != expected_end
    ):
        raise RuntimeError("ZIP central directory exceeds or violates its bounds")
    return location


def parse_extra_fields(extra: bytes) -> dict[int, bytes]:
    fields: dict[int, bytes] = {}
    offset = 0
    while offset < len(extra):
        if offset + 4 > len(extra):
            raise RuntimeError("truncated ZIP extra-field header")
        field_id, size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        if offset + size > len(extra) or field_id in fields:
            raise RuntimeError("invalid or duplicate ZIP extra field")
        fields[field_id] = extra[offset : offset + size]
        offset += size
    return fields


def resolve_zip64_values(
    compressed32: int,
    uncompressed32: int,
    local_offset32: int,
    disk_start32: int,
    extra: bytes,
) -> tuple[int, int, int, int]:
    needed = (
        uncompressed32 == 0xFFFFFFFF,
        compressed32 == 0xFFFFFFFF,
        local_offset32 == 0xFFFFFFFF,
        disk_start32 == 0xFFFF,
    )
    values = [uncompressed32, compressed32, local_offset32, disk_start32]
    if not any(needed):
        return values[1], values[0], values[2], values[3]
    payload = parse_extra_fields(extra).get(ZIP64_EXTRA_ID)
    if payload is None:
        raise RuntimeError("ZIP64 member metadata is absent")
    offset = 0
    for index, required in enumerate(needed):
        if not required:
            continue
        width = 4 if index == 3 else 8
        if offset + width > len(payload):
            raise RuntimeError("truncated ZIP64 member metadata")
        values[index] = int.from_bytes(payload[offset : offset + width], "little")
        offset += width
    return values[1], values[0], values[2], values[3]


def safe_member_name(raw_name: bytes) -> tuple[str, int]:
    try:
        name = raw_name.decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeError("ZIP member name is not bounded ASCII") from error
    is_directory = name.endswith("/")
    canonical = name[:-1] if is_directory else name
    parts = canonical.split("/")
    if (
        not canonical
        or name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in parts)
        or parts[0].endswith(":")
        or len(raw_name) > MAX_MEMBER_NAME_BYTES
    ):
        raise RuntimeError("unsafe or overlong ZIP member path")
    return name, len(raw_name)


def inspect_central_directory(
    source: BinaryIO, identity: FileIdentity
) -> dict[str, Any]:
    location = central_directory_location(source, identity)
    data = read_exact_at(
        source, location.offset, location.size, "ZIP central directory"
    )
    offset = 0
    names: set[str] = set()
    casefolded_names: set[str] = set()
    total_name_bytes = 0
    compressed_bytes = 0
    uncompressed_bytes = 0
    file_count = 0
    directory_count = 0
    compression_counts = {label: 0 for label in ALLOWED_COMPRESSION.values()}

    for _ in range(location.entries):
        if (
            offset + 46 > len(data)
            or data[offset : offset + 4] != CENTRAL_HEADER_SIGNATURE
        ):
            raise RuntimeError("invalid ZIP central-directory entry")
        fields = struct.unpack_from("<6H3L5H2L", data, offset + 4)
        (
            _made_by,
            _needed,
            flags,
            compression,
            _modified_time,
            _modified_date,
            _crc32,
            compressed32,
            uncompressed32,
            name_length,
            extra_length,
            comment_length,
            disk_start32,
            _internal_attributes,
            external_attributes,
            local_offset32,
        ) = fields
        entry_end = offset + 46 + name_length + extra_length + comment_length
        if entry_end > len(data):
            raise RuntimeError("truncated ZIP central-directory entry")
        raw_name = data[offset + 46 : offset + 46 + name_length]
        extra_start = offset + 46 + name_length
        extra = data[extra_start : extra_start + extra_length]
        name, name_bytes = safe_member_name(raw_name)
        if (
            extra_length > MAX_MEMBER_EXTRA_BYTES
            or comment_length > MAX_MEMBER_COMMENT_BYTES
            or flags & 0x41
            or compression not in ALLOWED_COMPRESSION
            or name in names
            or name.casefold() in casefolded_names
        ):
            raise RuntimeError("unsafe or unsupported ZIP central-directory entry")
        total_name_bytes += name_bytes
        if total_name_bytes > MAX_TOTAL_MEMBER_NAME_BYTES:
            raise RuntimeError("ZIP member names exceed their aggregate bound")
        names.add(name)
        casefolded_names.add(name.casefold())

        compressed, uncompressed, local_offset, disk_start = resolve_zip64_values(
            compressed32,
            uncompressed32,
            local_offset32,
            disk_start32,
            extra,
        )
        if disk_start != 0 or not 0 <= local_offset < location.offset:
            raise RuntimeError("invalid ZIP member disk or local-header offset")
        if (
            read_exact_at(source, local_offset, 4, "ZIP local header")
            != LOCAL_HEADER_SIGNATURE
        ):
            raise RuntimeError("ZIP local-header signature mismatch")
        if uncompressed > MAX_MEMBER_BYTES or compressed > identity.size:
            raise RuntimeError("ZIP member exceeds its size bound")
        if uncompressed and compressed == 0:
            raise RuntimeError("ZIP member has an invalid compression ratio")
        if compressed and uncompressed / compressed > MAX_COMPRESSION_RATIO:
            raise RuntimeError("ZIP member exceeds its compression-ratio bound")

        mode = (external_attributes >> 16) & 0xFFFF
        kind = stat.S_IFMT(mode)
        if name.endswith("/"):
            if kind not in {0, stat.S_IFDIR} or uncompressed != 0:
                raise RuntimeError("invalid ZIP directory member")
            directory_count += 1
        else:
            if kind not in {0, stat.S_IFREG}:
                raise RuntimeError("non-regular ZIP member")
            file_count += 1
        compressed_bytes += compressed
        uncompressed_bytes += uncompressed
        if uncompressed_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise RuntimeError("ZIP contents exceed the aggregate size bound")
        compression_counts[ALLOWED_COMPRESSION[compression]] += 1
        offset = entry_end

    if offset != len(data):
        raise RuntimeError("unexpected data in ZIP central directory")
    require_unchanged(source, identity)
    return {
        "compressed_member_bytes": compressed_bytes,
        "compression_method_counts": compression_counts,
        "directories": directory_count,
        "files": file_count,
        "members": location.entries,
        "uncompressed_bytes": uncompressed_bytes,
        "zip64": location.zip64,
    }


def quote_identifier(identifier: str) -> str:
    if not SAFE_IDENTIFIER_PATTERN.fullmatch(identifier):
        raise RuntimeError("invalid SQLite schema contract")
    return f'"{identifier}"'


def bounded_mmap_bytes(value: int) -> int:
    if isinstance(value, bool) or not 0 <= value <= MAX_MMAP_BYTES:
        raise RuntimeError("SQLite mmap size is outside its configured bound")
    return value


def apply_mmap_size(connection: Any, requested_bytes: int) -> int:
    requested_bytes = bounded_mmap_bytes(requested_bytes)
    try:
        row = connection.execute(f"PRAGMA mmap_size = {requested_bytes}").fetchone()
    except sqlite3.DatabaseError:
        return 0
    if (
        row is None
        or len(row) != 1
        or isinstance(row[0], bool)
        or not isinstance(row[0], int)
        or not 0 <= row[0] <= requested_bytes
    ):
        return 0
    return row[0]


def descriptor_uri(descriptor: int, fallback_path: Path) -> str:
    for root in (Path("/proc/self/fd"), Path("/dev/fd")):
        if root.is_dir():
            return f"file:{quote(str(root / str(descriptor)), safe='/')}?mode=ro&immutable=1"
    return f"file:{quote(str(fallback_path.absolute()), safe='/')}?mode=ro&immutable=1"


def configure_connection(connection: sqlite3.Connection, mmap_bytes: int) -> int:
    if hasattr(connection, "enable_load_extension"):
        connection.enable_load_extension(False)
    connection.execute("PRAGMA query_only = ON")
    query_only = connection.execute("PRAGMA query_only").fetchone()
    if query_only != (1,):
        raise RuntimeError("SQLite query-only mode could not be established")
    connection.execute("PRAGMA trusted_schema = OFF")
    connection.execute("PRAGMA temp_store = MEMORY")
    connection.execute("PRAGMA cache_size = -8192")
    connection.execute("PRAGMA cell_size_check = ON")
    if hasattr(connection, "setlimit"):
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, MIB)
        connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, 64 * 1024)
        connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 128)
    return apply_mmap_size(connection, mmap_bytes)


def validate_schema(connection: sqlite3.Connection, contract: TableContract) -> None:
    objects = connection.execute(
        "SELECT type, name, tbl_name FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    if objects != [("table", contract.name, contract.name)]:
        raise RuntimeError(f"{contract.name} SQLite object schema drifted")
    table = quote_identifier(contract.name)
    columns = connection.execute(f"PRAGMA table_xinfo({table})").fetchall()
    observed = tuple(
        (row[0], row[1], row[2].upper(), row[3], row[4], row[5], row[6])
        for row in columns
    )
    expected = tuple(
        (index, name, kind, 0, None, 0, 0)
        for index, (name, kind) in enumerate(contract.columns)
    )
    if observed != expected:
        raise RuntimeError(f"{contract.name} SQLite column schema drifted")


def aggregate_table(
    connection: sqlite3.Connection, contract: TableContract
) -> dict[str, Any]:
    table = quote_identifier(contract.name)
    column_names = [name for name, _ in contract.columns]
    null_expressions = [
        f"SUM({quote_identifier(name)} IS NULL)" for name in column_names
    ]
    category_expressions = [
        f"COUNT(DISTINCT {quote_identifier(name)})"
        for name in contract.category_columns
    ]
    query = f"SELECT COUNT(*), {', '.join(null_expressions + category_expressions)} FROM {table}"
    row = connection.execute(query).fetchone()
    expected_values = 1 + len(column_names) + len(contract.category_columns)
    if row is None or len(row) != expected_values:
        raise RuntimeError(f"{contract.name} aggregate query returned an invalid shape")
    values = tuple(0 if value is None else value for value in row)
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in values
    ):
        raise RuntimeError(f"{contract.name} aggregate query returned an invalid count")
    rows = values[0]
    if rows > MAX_SQLITE_ROWS:
        raise RuntimeError(f"{contract.name} exceeds the row-count bound")
    null_values = values[1 : 1 + len(column_names)]
    if any(value > rows for value in null_values):
        raise RuntimeError(f"{contract.name} aggregate null count is invalid")
    category_values = values[1 + len(column_names) :]
    null_counts = dict(zip(column_names, null_values))
    time_axis: dict[str, Any]
    if contract.time_column is None:
        time_axis = {"available": False}
    else:
        time_nulls = null_counts[contract.time_column]
        time_axis = {
            "available": True,
            "non_null_rows": rows - time_nulls,
            "null_rows": time_nulls,
        }
    return {
        "category_cardinalities": dict(zip(contract.category_columns, category_values)),
        "columns": len(column_names),
        "null_counts": null_counts,
        "rows": rows,
        "schema_validation": "exact",
        "table": contract.name,
        "time_axis": time_axis,
    }


def profile_archive(directory: Path, contract: ArtifactContract) -> dict[str, Any]:
    source, identity = open_artifact(directory, contract)
    with source:
        digest = verify_digest(source, identity, contract)
        inventory = inspect_central_directory(source, identity)
    return {"bytes": identity.size, "central_directory": inventory, "md5": digest}


def profile_database(
    directory: Path,
    artifact: ArtifactContract,
    table: TableContract,
    mmap_bytes: int,
) -> dict[str, Any]:
    source, identity = open_artifact(directory, artifact)
    with source:
        digest = verify_digest(source, identity, artifact)
        path = directory / artifact.filename
        uri = descriptor_uri(source.fileno(), path)
        try:
            connection = sqlite3.connect(
                uri,
                uri=True,
                isolation_level=None,
                timeout=1.0,
                cached_statements=0,
            )
        except sqlite3.Error as error:
            raise RuntimeError(
                "pinned NetsLab SQLite artifact is unreadable"
            ) from error
        try:
            effective_mmap = configure_connection(connection, mmap_bytes)
            validate_schema(connection, table)
            aggregates = aggregate_table(connection, table)
        except sqlite3.Error as error:
            raise RuntimeError("pinned NetsLab SQLite metadata query failed") from error
        finally:
            connection.close()
        require_unchanged(source, identity)
    return {
        "bytes": identity.size,
        "md5": digest,
        "sqlite": {
            **aggregates,
            "mmap": {
                "effective_bytes": effective_mmap,
                "fallback": effective_mmap < mmap_bytes,
                "requested_bytes": mmap_bytes,
            },
            "query_only": True,
        },
    }


def profile_corpus(
    directory: Path,
    contract: CorpusContract = PRODUCTION_CONTRACT,
    mmap_bytes: int = DEFAULT_MMAP_BYTES,
) -> dict[str, Any]:
    mmap_bytes = bounded_mmap_bytes(mmap_bytes)
    archive = profile_archive(directory, contract.archive)
    lower = profile_database(
        directory, contract.lower_database, LOWER_TABLE, mmap_bytes
    )
    network = profile_database(
        directory, contract.network_database, NETWORK_TABLE, mmap_bytes
    )
    if network["sqlite"]["time_axis"]["available"]:
        raise RuntimeError("network_data unexpectedly acquired a time axis")
    return {
        "artifacts": {
            "benign_archive": archive,
            "lower_layer_summary": lower,
            "network_summary": network,
        },
        "catalog": {
            "doi": CATALOG_DOI,
            "validation": "exact_size_and_md5",
        },
        "cross_layer_alignment": {
            "established": False,
            "reason": "network_data lacks timestamp; cross-layer join is not established.",
        },
        "limits": {
            "archive_members": MAX_ARCHIVE_MEMBERS,
            "central_directory_bytes": MAX_CENTRAL_DIRECTORY_BYTES,
            "maximum_mmap_bytes": MAX_MMAP_BYTES,
            "maximum_report_bytes": MAX_REPORT_BYTES,
            "maximum_sqlite_rows": MAX_SQLITE_ROWS,
            "member_paths_retained": 0,
            "row_values_retained": 0,
        },
        "not_established": [
            "cross_layer_join",
            "endpoint_correspondence",
            "identifier_correspondence",
            "shared_clock_or_offset",
        ],
        "schema": SCHEMA,
        "status": "pass",
    }


def render_report(report: dict[str, Any]) -> bytes:
    rendered = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(rendered) > MAX_REPORT_BYTES:
        raise RuntimeError("NetsLab metadata report exceeds its size bound")
    return rendered


def write_report(path: Path, rendered: bytes) -> None:
    if len(rendered) > MAX_REPORT_BYTES:
        raise RuntimeError("NetsLab metadata report exceeds its size bound")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
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
        "--artifact-dir",
        type=Path,
        default=ROOT / "eval-data",
        help="directory containing the three pinned public NetsLab artifacts",
    )
    parser.add_argument(
        "--mmap-bytes",
        type=int,
        default=DEFAULT_MMAP_BYTES,
        help="requested SQLite mmap size, bounded to at most 1 GiB",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "eval-data" / "netslab-alignment-profile.json",
        help="atomic deterministic JSON output",
    )
    return parser.parse_args(argv)


def main() -> int:
    args = parse_args()
    report = profile_corpus(
        args.artifact_dir.expanduser().absolute(), mmap_bytes=args.mmap_bytes
    )
    rendered = render_report(report)
    write_report(args.report.expanduser().absolute(), rendered)
    sys.stdout.buffer.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
