#!/usr/bin/env python3
"""Profile bounded cross-modal alignment evidence in the pinned Data4Cyber ZIP."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Dict, Optional, Sequence, Tuple

MIB = 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.data4cyber_alignment_profile.v0"
ARCHIVE_NAME = "data4cyber_dataset.zip"
ARCHIVE_BYTES = 134_034_872
ARCHIVE_MD5 = "a540979c63120c9a0295ff974933580f"
CATALOG_DOI = "10.5281/zenodo.19965384"
ROOT_MEMBER = "data4cyber_dataset"

# This lock mirrors data/fetch/fetch-public-eval-corpus.py:SOURCES["data4cyber"].
EXPECTED_SCENARIOS = (
    "S0_benign_baseline",
    "S1_industroyer_pv",
    "S1_industroyer_pv_alt",
    "S2_industroyer_bss",
    "S3_arp_spoof_bss_meter_half_values",
    "S4_arp_spoof_loads_pv_two_phase",
    "S5_arp_spoof_loads_pv_bss_two_phase",
    "S6_mqtt_supply_chain_compromise",
)

SCENARIO_FILES = (
    "README.md",
    "attack-phases.json",
    "attacker_only.pcapng",
    "attacker_only_meta.json",
    "benign_only.pcapng",
    "benign_only_meta.json",
    "dataset.csv",
    "dataset_attack.csv",
    "dataset_benign.csv",
    "experiment_overview.json",
    "ip_device_mapping.csv",
    "metadata.json",
    "modbus_variable_mapping.csv",
    "network_tap.pcapng",
    "plots/01_power_timeseries.pdf",
    "plots/02_context_and_communication.pdf",
    "scenario_definition.json",
    "state.jsonl.gz",
)
SCENARIO_DIRECTORIES = ("plots/",)
DATASET_TABLES = ("dataset.csv", "dataset_attack.csv", "dataset_benign.csv")
CAPTURES = (
    ("full", "network_tap.pcapng"),
    ("benign_split", "benign_only.pcapng"),
    ("attack_split", "attacker_only.pcapng"),
)

MAX_ARCHIVE_MEMBERS = 256
MAX_MEMBER_NAME_BYTES = 256
MAX_TOTAL_MEMBER_NAME_BYTES = 64 * 1024
MAX_MEMBER_EXTRA_BYTES = 4 * 1024
MAX_MEMBER_COMMENT_BYTES = 1024
MAX_TOTAL_CENTRAL_METADATA_BYTES = 256 * 1024
MAX_MEMBER_BYTES = 64 * MIB
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 1024 * MIB
MAX_COMPRESSION_RATIO = 100
MAX_README_BYTES = 64 * 1024
MAX_CSV_HEADER_BYTES = 64 * 1024
MAX_CSV_COLUMNS = 512
MAX_COLUMN_NAME_BYTES = 256
MAX_PCAP_SCAN_BYTES = 2 * MIB
MAX_PCAP_BLOCK_BYTES = 16 * MIB
MAX_PCAP_BLOCKS = 4096
MAX_REPORT_BYTES = 256 * 1024
DIGEST_CHUNK_BYTES = MIB
ALLOWED_COMPRESSION_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
MD5_PATTERN = re.compile(r"[0-9a-f]{32}")
SECTION_HEADER_BYTES = b"\x0a\x0d\x0d\x0a"
BYTE_ORDER_MAGIC = 0x1A2B3C4D
INTERFACE_DESCRIPTION_BLOCK = 1
PACKET_BLOCK_TYPES = {2, 3, 6}
TIMESTAMPED_PACKET_BLOCK_TYPES = {2, 6}


@dataclass(frozen=True)
class ArchiveContract:
    expected_bytes: int
    expected_md5: str
    expected_scenarios: Tuple[str, ...]
    pcap_scan_bytes: int = MAX_PCAP_SCAN_BYTES


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


@dataclass(frozen=True)
class ArchiveInventory:
    members: Dict[str, zipfile.ZipInfo]
    file_count: int
    directory_count: int
    compressed_bytes: int
    uncompressed_bytes: int


PRODUCTION_CONTRACT = ArchiveContract(
    expected_bytes=ARCHIVE_BYTES,
    expected_md5=ARCHIVE_MD5,
    expected_scenarios=EXPECTED_SCENARIOS,
)


def file_identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
    )


def open_archive(
    path: Path, contract: ArchiveContract
) -> Tuple[BinaryIO, FileIdentity]:
    try:
        before = path.lstat()
    except OSError as error:
        raise RuntimeError("Data4Cyber archive is unavailable") from error
    if not stat.S_ISREG(before.st_mode) or before.st_size != contract.expected_bytes:
        raise RuntimeError("Data4Cyber archive path or byte count failed validation")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError("Data4Cyber archive could not be opened safely") from error
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or file_identity(after) != file_identity(
            before
        ):
            raise RuntimeError("Data4Cyber archive changed before opening")
        return os.fdopen(descriptor, "rb"), file_identity(after)
    except BaseException:
        os.close(descriptor)
        raise


def require_unchanged(
    source: BinaryIO, expected: FileIdentity, label: str = "Data4Cyber archive"
) -> None:
    if file_identity(os.fstat(source.fileno())) != expected:
        raise RuntimeError(f"{label} changed while being inspected")


def digest_archive(source: BinaryIO, expected: FileIdentity) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    source.seek(0)
    remaining = expected.size
    while remaining:
        chunk = source.read(min(DIGEST_CHUNK_BYTES, remaining))
        if not chunk:
            raise RuntimeError("Data4Cyber archive changed while hashing")
        digest.update(chunk)
        remaining -= len(chunk)
    if source.read(1):
        raise RuntimeError("Data4Cyber archive exceeded its byte contract")
    require_unchanged(source, expected)
    source.seek(0)
    return digest.hexdigest()


def parse_contract(contract: ArchiveContract) -> ArchiveContract:
    if (
        contract.expected_bytes <= 0
        or not MD5_PATTERN.fullmatch(contract.expected_md5)
        or not contract.expected_scenarios
        or len(set(contract.expected_scenarios)) != len(contract.expected_scenarios)
        or not 28 <= contract.pcap_scan_bytes <= MAX_PCAP_SCAN_BYTES
    ):
        raise RuntimeError("invalid Data4Cyber archive contract")
    for scenario in contract.expected_scenarios:
        if not re.fullmatch(r"[A-Za-z0-9_]+", scenario):
            raise RuntimeError("invalid Data4Cyber scenario contract")
    return contract


def safe_member_name(info: zipfile.ZipInfo) -> Tuple[str, int]:
    if info.orig_filename != info.filename:
        raise RuntimeError("ZIP member name was truncated")
    name = info.filename
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError as error:
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
        or len(encoded) > MAX_MEMBER_NAME_BYTES
    ):
        raise RuntimeError("unsafe or overlong ZIP member path")
    return name, len(encoded)


def inspect_central_directory(archive: zipfile.ZipFile) -> ArchiveInventory:
    infos = archive.infolist()
    if not 0 < len(infos) <= MAX_ARCHIVE_MEMBERS:
        raise RuntimeError("Data4Cyber archive exceeds its member-count bound")
    if len(archive.comment) > MAX_MEMBER_COMMENT_BYTES:
        raise RuntimeError("Data4Cyber archive comment is overlong")

    members: Dict[str, zipfile.ZipInfo] = {}
    casefolded_names: set[str] = set()
    total_name_bytes = 0
    total_central_metadata_bytes = 0
    total_compressed = 0
    total_uncompressed = 0
    file_count = 0
    directory_count = 0

    for info in infos:
        name, name_bytes = safe_member_name(info)
        total_name_bytes += name_bytes
        total_central_metadata_bytes += name_bytes + len(info.extra) + len(info.comment)
        if total_name_bytes > MAX_TOTAL_MEMBER_NAME_BYTES:
            raise RuntimeError("ZIP member names exceed their aggregate bound")
        if (
            len(info.extra) > MAX_MEMBER_EXTRA_BYTES
            or len(info.comment) > MAX_MEMBER_COMMENT_BYTES
            or total_central_metadata_bytes > MAX_TOTAL_CENTRAL_METADATA_BYTES
        ):
            raise RuntimeError("ZIP central metadata exceeds its bound")
        if name in members or name.casefold() in casefolded_names:
            raise RuntimeError("duplicate ZIP member path")
        members[name] = info
        casefolded_names.add(name.casefold())

        mode = (info.external_attr >> 16) & 0xFFFF
        kind = stat.S_IFMT(mode)
        if info.is_dir():
            if kind not in {0, stat.S_IFDIR} or info.file_size != 0:
                raise RuntimeError("invalid ZIP directory member")
            directory_count += 1
        else:
            if kind not in {0, stat.S_IFREG}:
                raise RuntimeError("non-regular ZIP member")
            file_count += 1

        if info.flag_bits & 0x1:
            raise RuntimeError("encrypted ZIP members are unsupported")
        if info.compress_type not in ALLOWED_COMPRESSION_METHODS:
            raise RuntimeError("unsupported ZIP compression method")
        if info.file_size > MAX_MEMBER_BYTES:
            raise RuntimeError("ZIP member exceeds its size bound")
        if info.file_size and info.compress_size == 0:
            raise RuntimeError("ZIP member has an invalid compression ratio")
        if (
            info.compress_size
            and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
        ):
            raise RuntimeError("ZIP member exceeds its compression-ratio bound")

        total_compressed += info.compress_size
        total_uncompressed += info.file_size
        if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise RuntimeError("ZIP contents exceed the aggregate size bound")

    return ArchiveInventory(
        members=members,
        file_count=file_count,
        directory_count=directory_count,
        compressed_bytes=total_compressed,
        uncompressed_bytes=total_uncompressed,
    )


def expected_member_names(scenarios: Sequence[str]) -> set[str]:
    names = {
        f"{ROOT_MEMBER}/",
        f"{ROOT_MEMBER}/LICENSE.txt",
        f"{ROOT_MEMBER}/README.md",
    }
    for scenario in scenarios:
        prefix = f"{ROOT_MEMBER}/{scenario}/"
        names.add(prefix)
        names.update(prefix + directory for directory in SCENARIO_DIRECTORIES)
        names.update(prefix + filename for filename in SCENARIO_FILES)
    return names


def require_archive_schema(
    inventory: ArchiveInventory, scenarios: Sequence[str]
) -> None:
    if set(inventory.members) != expected_member_names(scenarios):
        raise RuntimeError("Data4Cyber archive member schema mismatch")


def read_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    maximum_bytes: int,
    label: str,
) -> bytes:
    if info.is_dir() or not 0 < info.file_size <= maximum_bytes:
        raise RuntimeError(f"{label} violates its size contract")
    with archive.open(info, "r") as source:
        data = source.read(maximum_bytes + 1)
    if len(data) != info.file_size or len(data) > maximum_bytes:
        raise RuntimeError(f"{label} changed while being read")
    return data


def parse_readme(data: bytes, *, require_alignment_terms: bool) -> Dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RuntimeError("Data4Cyber README is not UTF-8") from error
    if any(ord(character) < 32 and character not in "\n\r\t" for character in text):
        raise RuntimeError("Data4Cyber README contains control characters")

    lowered = text.casefold()
    mentions = {
        "capture_artifact": "network_tap.pcapng" in lowered,
        "synchronization": "synchron" in lowered,
        "tabular_artifact": "dataset.csv" in lowered,
    }
    if require_alignment_terms and not all(mentions.values()):
        raise RuntimeError("Data4Cyber scenario README schema mismatch")
    return {
        "bytes": len(data),
        "headings": sum(line.lstrip().startswith("#") for line in text.splitlines()),
        "lines": len(text.splitlines()),
        "mentions": mentions,
    }


def read_csv_header(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> Tuple[str, ...]:
    if info.is_dir() or not 0 < info.file_size <= MAX_MEMBER_BYTES:
        raise RuntimeError("Data4Cyber dataset table violates its size contract")
    collected = bytearray()
    with archive.open(info, "r") as source:
        while len(collected) <= MAX_CSV_HEADER_BYTES:
            chunk = source.read(min(4096, MAX_CSV_HEADER_BYTES + 1 - len(collected)))
            if not chunk:
                break
            collected.extend(chunk)
            newline = collected.find(b"\n")
            if newline >= 0:
                del collected[newline + 1 :]
                break
    if len(collected) > MAX_CSV_HEADER_BYTES or b"\n" not in collected:
        raise RuntimeError("Data4Cyber CSV header exceeds its read bound")
    try:
        line = bytes(collected).decode("utf-8-sig")
        rows = list(csv.reader(io.StringIO(line, newline=""), strict=True))
    except (UnicodeDecodeError, csv.Error) as error:
        raise RuntimeError("Data4Cyber CSV header is malformed") from error
    if len(rows) != 1:
        raise RuntimeError("Data4Cyber CSV header spans multiple records")

    header = tuple(column.strip() for column in rows[0])
    if (
        not 0 < len(header) <= MAX_CSV_COLUMNS
        or len(set(header)) != len(header)
        or any(
            not column
            or len(column.encode("utf-8")) > MAX_COLUMN_NAME_BYTES
            or any(ord(character) < 32 for character in column)
            for column in header
        )
    ):
        raise RuntimeError("Data4Cyber CSV header schema mismatch")
    return header


def parse_dataset_headers(
    archive: zipfile.ZipFile,
    inventory: ArchiveInventory,
    scenario: str,
) -> Dict[str, Any]:
    headers = []
    for table in DATASET_TABLES:
        name = f"{ROOT_MEMBER}/{scenario}/{table}"
        headers.append(read_csv_header(archive, inventory.members[name]))
    if any(header != headers[0] for header in headers[1:]):
        raise RuntimeError("Data4Cyber dataset table headers disagree")

    normalized = {column.casefold() for column in headers[0]}
    required = {"timestamp", "attack_active", "attack_phase"}
    if not required.issubset(normalized):
        raise RuntimeError("Data4Cyber dataset alignment schema mismatch")
    return {
        "alignment_fields": {
            "binary_label": "attack_active" in normalized,
            "overlap_phase_label": "attack_phase_all" in normalized,
            "single_phase_label": "attack_phase" in normalized,
            "time_axis": "timestamp" in normalized,
        },
        "columns": len(headers[0]),
        "headers_identical": True,
        "tables": len(headers),
    }


def read_exact(source: BinaryIO, size: int, label: str) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = source.read(size - len(chunks))
        if not chunk:
            raise RuntimeError(f"truncated {label}")
        chunks.extend(chunk)
    return bytes(chunks)


def discard_and_validate_block_tail(
    source: BinaryIO, bytes_after_prefix: int, byte_order: str, total_length: int
) -> int:
    if bytes_after_prefix < 4:
        raise RuntimeError("PCAPNG block is shorter than its trailer")
    remaining = bytes_after_prefix - 4
    discarded = 0
    while remaining:
        chunk = source.read(min(64 * 1024, remaining))
        if not chunk:
            raise RuntimeError("truncated PCAPNG block body")
        remaining -= len(chunk)
        discarded += len(chunk)
    trailer = read_exact(source, 4, "PCAPNG block trailer")
    if struct.unpack(f"{byte_order}I", trailer)[0] != total_length:
        raise RuntimeError("PCAPNG block length trailer mismatch")
    return discarded + 4


def scan_pcapng(
    source: BinaryIO,
    declared_bytes: int,
    *,
    maximum_bytes: int,
) -> Dict[str, Any]:
    if declared_bytes < 28 or maximum_bytes < 28:
        raise RuntimeError("PCAPNG member is too small for a section header")

    bytes_scanned = 0
    blocks = 0
    sections = 0
    interfaces = 0
    packet_blocks = 0
    timestamped_packet_blocks = 0
    other_blocks = 0
    byte_order: Optional[str] = None
    stop_reason: Optional[str] = None

    while bytes_scanned < declared_bytes:
        if blocks >= MAX_PCAP_BLOCKS:
            stop_reason = "block_limit"
            break
        block_start = bytes_scanned
        file_remaining = declared_bytes - block_start
        budget_remaining = maximum_bytes - block_start
        if budget_remaining < 8:
            stop_reason = "byte_limit"
            break
        if file_remaining < 8:
            raise RuntimeError("truncated PCAPNG block header")

        header = read_exact(source, 8, "PCAPNG block header")
        bytes_scanned += 8
        is_section = header[:4] == SECTION_HEADER_BYTES

        if is_section:
            if file_remaining < 12:
                raise RuntimeError("truncated PCAPNG section header")
            if maximum_bytes - bytes_scanned < 4:
                stop_reason = "byte_limit"
                break
            magic_bytes = read_exact(source, 4, "PCAPNG byte-order magic")
            bytes_scanned += 4
            if magic_bytes == struct.pack(">I", BYTE_ORDER_MAGIC):
                candidate_order = ">"
            elif magic_bytes == struct.pack("<I", BYTE_ORDER_MAGIC):
                candidate_order = "<"
            else:
                raise RuntimeError("invalid PCAPNG byte-order magic")
            total_length = struct.unpack(f"{candidate_order}I", header[4:])[0]
            minimum_length = 28
            prefix_bytes = 12
        else:
            if byte_order is None:
                raise RuntimeError("PCAPNG does not begin with a section header")
            candidate_order = byte_order
            total_length = struct.unpack(f"{candidate_order}I", header[4:])[0]
            minimum_length = 12
            prefix_bytes = 8

        if (
            total_length < minimum_length
            or total_length % 4 != 0
            or total_length > MAX_PCAP_BLOCK_BYTES
            or total_length > file_remaining
        ):
            raise RuntimeError("invalid PCAPNG block length")
        if total_length > maximum_bytes - block_start:
            stop_reason = "byte_limit"
            break

        bytes_scanned += discard_and_validate_block_tail(
            source,
            total_length - prefix_bytes,
            candidate_order,
            total_length,
        )
        blocks += 1
        if is_section:
            byte_order = candidate_order
            sections += 1
            continue

        block_type = struct.unpack(f"{candidate_order}I", header[:4])[0]
        if block_type == INTERFACE_DESCRIPTION_BLOCK:
            interfaces += 1
        elif block_type in PACKET_BLOCK_TYPES:
            packet_blocks += 1
            if block_type in TIMESTAMPED_PACKET_BLOCK_TYPES:
                timestamped_packet_blocks += 1
        else:
            other_blocks += 1

    complete = bytes_scanned == declared_bytes
    if complete:
        stop_reason = None
    if sections == 0 or interfaces == 0:
        raise RuntimeError("PCAPNG structural metadata is incomplete")
    return {
        "blocks_scanned": blocks,
        "bytes_scanned": bytes_scanned,
        "interface_descriptions": interfaces,
        "other_blocks": other_blocks,
        "packet_blocks": packet_blocks,
        "scan_complete": complete,
        "sections": sections,
        "stop_reason": stop_reason,
        "timestamped_packet_blocks": timestamped_packet_blocks,
    }


def profile_capture(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    role: str,
    maximum_bytes: int,
) -> Dict[str, Any]:
    if info.is_dir() or not 28 <= info.file_size <= MAX_MEMBER_BYTES:
        raise RuntimeError("Data4Cyber capture violates its size contract")
    with archive.open(info, "r") as source:
        structure = scan_pcapng(
            source,
            info.file_size,
            maximum_bytes=maximum_bytes,
        )
    return {
        "declared_bytes": info.file_size,
        "role": role,
        "structure": structure,
    }


def scenario_inventory(inventory: ArchiveInventory, scenario: str) -> Dict[str, int]:
    prefix = f"{ROOT_MEMBER}/{scenario}/"
    infos = [
        info for name, info in inventory.members.items() if name.startswith(prefix)
    ]
    return {
        "compressed_bytes": sum(info.compress_size for info in infos),
        "directories": sum(info.is_dir() for info in infos),
        "files": sum(not info.is_dir() for info in infos),
        "members": len(infos),
        "uncompressed_bytes": sum(info.file_size for info in infos),
    }


def profile_scenario(
    archive: zipfile.ZipFile,
    inventory: ArchiveInventory,
    scenario: str,
    pcap_scan_bytes: int,
) -> Dict[str, Any]:
    prefix = f"{ROOT_MEMBER}/{scenario}/"
    readme = parse_readme(
        read_member(
            archive,
            inventory.members[prefix + "README.md"],
            MAX_README_BYTES,
            "Data4Cyber scenario README",
        ),
        require_alignment_terms=True,
    )
    dataset_headers = parse_dataset_headers(archive, inventory, scenario)
    captures = [
        profile_capture(
            archive,
            inventory.members[prefix + filename],
            role,
            pcap_scan_bytes,
        )
        for role, filename in CAPTURES
    ]
    return {
        "alignment_evidence": {
            "full_capture_timestamp_records_observed": captures[0]["structure"][
                "timestamped_packet_blocks"
            ]
            > 0,
            "readme_declares_synchronization": readme["mentions"]["synchronization"],
            "tabular_time_axis_present": dataset_headers["alignment_fields"][
                "time_axis"
            ],
        },
        "archive_inventory": scenario_inventory(inventory, scenario),
        "dataset_headers": dataset_headers,
        "pcapng": captures,
        "readme": readme,
        "scenario": scenario,
    }


def profile_open_archive(
    source: BinaryIO,
    identity: FileIdentity,
    contract: ArchiveContract,
) -> Dict[str, Any]:
    observed_md5 = digest_archive(source, identity)
    if observed_md5 != contract.expected_md5:
        raise RuntimeError("Data4Cyber archive MD5 failed validation")

    try:
        with zipfile.ZipFile(source, "r") as archive:
            inventory = inspect_central_directory(archive)
            require_archive_schema(inventory, contract.expected_scenarios)
            root_readme = parse_readme(
                read_member(
                    archive,
                    inventory.members[f"{ROOT_MEMBER}/README.md"],
                    MAX_README_BYTES,
                    "Data4Cyber root README",
                ),
                require_alignment_terms=False,
            )
            scenarios = [
                profile_scenario(
                    archive,
                    inventory,
                    scenario,
                    contract.pcap_scan_bytes,
                )
                for scenario in contract.expected_scenarios
            ]
    except zipfile.BadZipFile as error:
        raise RuntimeError("Data4Cyber artifact is not a valid ZIP archive") from error
    require_unchanged(source, identity)

    return {
        "archive": {
            "compressed_member_bytes": inventory.compressed_bytes,
            "directories": inventory.directory_count,
            "files": inventory.file_count,
            "md5": observed_md5,
            "members": len(inventory.members),
            "uncompressed_bytes": inventory.uncompressed_bytes,
            "zip_bytes": identity.size,
        },
        "catalog": {
            "doi": CATALOG_DOI,
            "filename": ARCHIVE_NAME,
            "validation": "exact_size_and_md5",
        },
        "claims": [
            "archive_backed_scenario_inventory",
            "co_shipped_tabular_and_capture_artifacts",
            "readme_declared_synchronization",
            "tabular_alignment_fields_present",
            "pcapng_timestamp_record_structure_observed",
        ],
        "limits": {
            "csv_header_bytes_per_table": MAX_CSV_HEADER_BYTES,
            "member_payload_rows_retained": 0,
            "pcapng_blocks_per_capture": MAX_PCAP_BLOCKS,
            "pcapng_bytes_per_capture": contract.pcap_scan_bytes,
            "readme_bytes_per_member": MAX_README_BYTES,
        },
        "not_established": [
            "cross_modal_clock_offset",
            "event_level_correspondence",
            "network_or_device_identity",
            "packet_payload_semantics",
            "telemetry_values",
        ],
        "root_readme": root_readme,
        "scenarios": scenarios,
        "schema": SCHEMA,
        "status": "pass",
    }


def profile_archive(
    path: Path, contract: ArchiveContract = PRODUCTION_CONTRACT
) -> Dict[str, Any]:
    parsed_contract = parse_contract(contract)
    source, identity = open_archive(path, parsed_contract)
    with source:
        return profile_open_archive(source, identity, parsed_contract)


def write_report(path: Path, rendered: bytes) -> None:
    if len(rendered) > MAX_REPORT_BYTES:
        raise RuntimeError("Data4Cyber report exceeds its size bound")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive", type=Path, default=ROOT / "data" / "raw" / ARCHIVE_NAME
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="optional path for an atomic copy of the JSON report",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = profile_archive(args.archive.expanduser().absolute())
    rendered = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(rendered) > MAX_REPORT_BYTES:
        raise RuntimeError("Data4Cyber report exceeds its size bound")
    if args.report is not None:
        write_report(args.report.expanduser().absolute(), rendered)
    sys.stdout.buffer.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
