#!/usr/bin/env python3
"""Profile XRF55 ZIP metadata without hashing or opening member payloads."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import struct
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, BinaryIO

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RAW_DIR = ROOT / "data" / "raw"
DEFAULT_RECEIPT_DIR = ROOT / "data" / "receipts" / "xrf55"
DEFAULT_REPORT = ROOT / "data" / "derived" / "eval" / "xrf55-layout-profile.json"
SCHEMA = "netbraid.xrf55_layout_profile.v0"

EOCD_SIGNATURE = b"PK\x05\x06"
ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
MAX_ARCHIVE_BYTES = 100 * 1024**3
MAX_ARCHIVE_COMMENT_BYTES = 4096
MAX_CENTRAL_DIRECTORY_BYTES = 64 * 1024**2
MAX_MEMBERS = 200_000
MAX_MEMBER_NAME_BYTES = 1024
MAX_TOTAL_NAME_BYTES = 64 * 1024**2
MAX_MEMBER_BYTES = 2 * 1024**4
MAX_TOTAL_MEMBER_BYTES = 4 * 1024**4
MAX_COMPRESSION_RATIO = 10_000

ALLOWED_COMPRESSION = {
    zipfile.ZIP_STORED: "stored",
    zipfile.ZIP_DEFLATED: "deflated",
    zipfile.ZIP_BZIP2: "bzip2",
    zipfile.ZIP_LZMA: "lzma",
}
FORMAT_CLASSES = {
    ".bin": "binary",
    ".csv": "csv",
    ".dat": "data",
    ".h5": "hdf5",
    ".hdf5": "hdf5",
    ".json": "json",
    ".mat": "mat",
    ".md": "text",
    ".npy": "npy",
    ".npz": "npz",
    ".parquet": "parquet",
    ".pcap": "pcap",
    ".pcapng": "pcapng",
    ".pickle": "pickle",
    ".pkl": "pickle",
    ".sigmf-data": "sigmf-data",
    ".sigmf-meta": "sigmf-meta",
    ".tsv": "tsv",
    ".txt": "text",
    ".wav": "wav",
}
OBSERVATION_PATTERN = re.compile(
    r"(?P<subject>[0-9]{2})_(?P<action>[0-9]{2})_"
    r"(?P<repetition>[0-9]{2})[.]npy\Z"
)
MODALITY_COMPONENTS = {
    "wifi": "wifi",
    "wificsi": "wifi",
    "rfid": "rfid",
    "mmwave": "mmwave",
    "radar": "mmwave",
}
PROCESSED_CONTRACTS = {
    "part1": {
        "subject_groups": 20,
        "scenes": frozenset(range(1, 5)),
        "actions": frozenset(range(1, 56)),
        "repetitions": frozenset(range(1, 21)),
    },
    "part2": {
        "subject_groups": 19,
        "scenes": frozenset({1}),
        "actions": frozenset(range(1, 56)),
        "repetitions": frozenset(range(1, 21)),
    },
}


class Xrf55ProfileError(RuntimeError):
    """Stable failure at the local receipt or ZIP metadata boundary."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class CentralDirectory:
    entries: int
    size: int
    offset: int
    zip64: bool


@dataclass(frozen=True)
class ArchiveInspection:
    identity: FileIdentity
    report: Mapping[str, Any]
    member_hashes: frozenset[bytes]
    stem_hashes: frozenset[bytes]
    subject_groups: frozenset[tuple[int, int]]
    observations: frozenset[tuple[int, int, int, int]]


def _load_fetcher() -> ModuleType:
    path = ROOT / "data" / "fetch" / "fetch-xrf55.py"
    spec = importlib.util.spec_from_file_location("_xrf55_fetcher", path)
    if spec is None or spec.loader is None:
        raise Xrf55ProfileError("fetcher_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


FETCH = _load_fetcher()


def _identity(value: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=value.st_dev,
        inode=value.st_ino,
        size=value.st_size,
        modified_ns=value.st_mtime_ns,
        changed_ns=value.st_ctime_ns,
    )


def _open_regular(path: Path, expected_bytes: int) -> tuple[BinaryIO, FileIdentity]:
    try:
        before = path.lstat()
    except OSError as error:
        raise Xrf55ProfileError("archive_unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise Xrf55ProfileError("archive_not_regular")
    if before.st_size != expected_bytes or not 0 < before.st_size <= MAX_ARCHIVE_BYTES:
        raise Xrf55ProfileError("archive_size_mismatch")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Xrf55ProfileError("archive_open_failed") from error
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or _identity(before) != _identity(after):
            raise Xrf55ProfileError("archive_identity_changed")
        return os.fdopen(descriptor, "rb"), _identity(after)
    except BaseException:
        os.close(descriptor)
        raise


def _require_unchanged(source: BinaryIO, expected: FileIdentity) -> None:
    if _identity(os.fstat(source.fileno())) != expected:
        raise Xrf55ProfileError("archive_changed_during_profile")


def _read_exact(source: BinaryIO, offset: int, length: int, label: str) -> bytes:
    if offset < 0 or length < 0:
        raise Xrf55ProfileError(f"invalid_{label}_bounds")
    source.seek(offset)
    value = source.read(length)
    if len(value) != length:
        raise Xrf55ProfileError(f"truncated_{label}")
    return value


def _find_eocd(source: BinaryIO, size: int) -> tuple[int, tuple[int, ...]]:
    tail_size = min(size, 22 + 65_535)
    tail_offset = size - tail_size
    tail = _read_exact(source, tail_offset, tail_size, "zip_trailer")
    search_end = len(tail)
    while True:
        position = tail.rfind(EOCD_SIGNATURE, 0, search_end)
        if position < 0:
            raise Xrf55ProfileError("zip_eocd_absent")
        if position + 22 <= len(tail):
            values = struct.unpack_from("<4H2LH", tail, position + 4)
            comment_bytes = values[6]
            if position + 22 + comment_bytes == len(tail):
                if comment_bytes > MAX_ARCHIVE_COMMENT_BYTES:
                    raise Xrf55ProfileError("archive_comment_limit")
                return tail_offset + position, values
        search_end = position


def _central_directory(source: BinaryIO, size: int) -> CentralDirectory:
    eocd_offset, values = _find_eocd(source, size)
    disk, central_disk, entries_disk, entries, size32, offset32, _ = values
    sentinel = any(
        value == limit
        for value, limit in (
            (disk, 0xFFFF),
            (central_disk, 0xFFFF),
            (entries_disk, 0xFFFF),
            (entries, 0xFFFF),
            (size32, 0xFFFFFFFF),
            (offset32, 0xFFFFFFFF),
        )
    )
    if not sentinel:
        if disk != 0 or central_disk != 0 or entries_disk != entries:
            raise Xrf55ProfileError("multi_disk_zip_unsupported")
        location = CentralDirectory(entries, size32, offset32, False)
        expected_end = eocd_offset
    else:
        locator_offset = eocd_offset - 20
        locator = _read_exact(source, locator_offset, 20, "zip64_locator")
        signature, locator_disk, record_offset, total_disks = struct.unpack(
            "<4sLQL", locator
        )
        if (
            signature != ZIP64_LOCATOR_SIGNATURE
            or locator_disk != 0
            or total_disks != 1
        ):
            raise Xrf55ProfileError("invalid_zip64_locator")
        record = _read_exact(source, record_offset, 56, "zip64_eocd")
        fields = struct.unpack("<4sQ2H2L4Q", record)
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
            or not 44 <= record_size <= 1024
            or zip64_disk != 0
            or zip64_central_disk != 0
            or zip64_entries_disk != zip64_entries
            or record_offset + 12 + record_size != locator_offset
        ):
            raise Xrf55ProfileError("invalid_zip64_eocd")
        if (
            entries != 0xFFFF
            and entries != zip64_entries
            or entries_disk != 0xFFFF
            and entries_disk != zip64_entries_disk
            or size32 != 0xFFFFFFFF
            and size32 != zip64_size
            or offset32 != 0xFFFFFFFF
            and offset32 != zip64_offset
        ):
            raise Xrf55ProfileError("inconsistent_zip64_eocd")
        location = CentralDirectory(zip64_entries, zip64_size, zip64_offset, True)
        expected_end = record_offset
    if (
        not 0 < location.entries <= MAX_MEMBERS
        or not 0 < location.size <= MAX_CENTRAL_DIRECTORY_BYTES
        or location.offset < 0
        or location.offset + location.size != expected_end
    ):
        raise Xrf55ProfileError("central_directory_limit")
    return location


def safe_member_name(name: str) -> tuple[tuple[str, ...], int]:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise Xrf55ProfileError("unsafe_member_name") from error
    canonical = name[:-1] if name.endswith("/") else name
    parts = tuple(canonical.split("/"))
    if (
        not encoded
        or len(encoded) > MAX_MEMBER_NAME_BYTES
        or name.startswith("/")
        or "\\" in name
        or not canonical
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise Xrf55ProfileError("unsafe_member_name")
    return parts, len(encoded)


def _format_class(name: str) -> str:
    return FORMAT_CLASSES.get(PurePosixPath(name).suffix.casefold(), "other")


def processed_observation(
    parts: tuple[str, ...], contract: Mapping[str, Any]
) -> tuple[int, int, int, int, str]:
    match = OBSERVATION_PATTERN.fullmatch(parts[-1])
    if match is None:
        raise Xrf55ProfileError("unsupported_processed_observation_name")
    subject = int(match.group("subject"))
    action = int(match.group("action"))
    repetition = int(match.group("repetition"))
    if action not in contract["actions"] or repetition not in contract["repetitions"]:
        raise Xrf55ProfileError("processed_observation_axis_out_of_range")
    scene_component = re.sub(r"[^a-z0-9]", "", parts[0].casefold())
    scene_match = re.match(r"scene(?P<scene>[1-9][0-9]*)", scene_component)
    if scene_match is None:
        raise Xrf55ProfileError("unsupported_processed_scene_path")
    scene = int(scene_match.group("scene"))
    if scene not in contract["scenes"]:
        raise Xrf55ProfileError("processed_scene_out_of_range")
    candidates = {
        MODALITY_COMPONENTS[normalized]
        for component in parts[:-1]
        if (normalized := re.sub(r"[^a-z0-9]", "", component.casefold()))
        in MODALITY_COMPONENTS
    }
    if len(candidates) != 1:
        raise Xrf55ProfileError("unsupported_processed_modality_path")
    return scene, subject, action, repetition, candidates.pop()


def profile_archive(
    path: Path,
    expected_bytes: int,
    processed_contract: Mapping[str, Any] | None = None,
) -> ArchiveInspection:
    source, identity = _open_regular(path, expected_bytes)
    with source:
        location = _central_directory(source, identity.size)
        try:
            archive = zipfile.ZipFile(source, mode="r", allowZip64=True)
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
            raise Xrf55ProfileError("invalid_zip_archive") from error

        names: set[str] = set()
        folded_names: set[str] = set()
        member_hashes: set[bytes] = set()
        stem_hashes: set[bytes] = set()
        stem_formats: defaultdict[bytes, set[str]] = defaultdict(set)
        format_counts: Counter[str] = Counter()
        compression_counts: Counter[str] = Counter()
        depth_counts: Counter[int] = Counter()
        top_levels: set[bytes] = set()
        total_name_bytes = 0
        total_compressed_bytes = 0
        total_uncompressed_bytes = 0
        files = 0
        directories = 0
        processed_modalities: defaultdict[tuple[int, int, int, int], set[str]] = (
            defaultdict(set)
        )

        with archive:
            if archive.start_dir != location.offset:
                raise Xrf55ProfileError("central_directory_offset_mismatch")
            members = archive.infolist()
            if len(members) != location.entries:
                raise Xrf55ProfileError("central_directory_count_mismatch")
            for member in members:
                parts, name_bytes = safe_member_name(member.orig_filename)
                if member.orig_filename != member.filename:
                    raise Xrf55ProfileError("unsafe_member_name")
                if (
                    member.filename in names
                    or member.filename.casefold() in folded_names
                ):
                    raise Xrf55ProfileError("duplicate_member_name")
                names.add(member.filename)
                folded_names.add(member.filename.casefold())
                total_name_bytes += name_bytes
                if total_name_bytes > MAX_TOTAL_NAME_BYTES:
                    raise Xrf55ProfileError("member_name_total_limit")
                if member.flag_bits & (0x0001 | 0x0040 | 0x2000):
                    raise Xrf55ProfileError("encrypted_member_unsupported")
                compression = ALLOWED_COMPRESSION.get(member.compress_type)
                if compression is None:
                    raise Xrf55ProfileError("compression_unsupported")
                if (
                    member.header_offset < 0
                    or member.header_offset >= location.offset
                    or member.file_size > MAX_MEMBER_BYTES
                    or member.compress_size > identity.size
                    or member.file_size
                    and member.compress_size == 0
                    or member.compress_size
                    and member.file_size / member.compress_size > MAX_COMPRESSION_RATIO
                ):
                    raise Xrf55ProfileError("member_size_limit")
                unix_kind = 0
                if member.create_system == 3:
                    unix_kind = stat.S_IFMT(member.external_attr >> 16)
                if member.is_dir():
                    if unix_kind not in {0, stat.S_IFDIR} or member.file_size != 0:
                        raise Xrf55ProfileError("invalid_directory_member")
                    directories += 1
                else:
                    if unix_kind not in {0, stat.S_IFREG}:
                        raise Xrf55ProfileError("non_regular_member")
                    files += 1
                    format_name = _format_class(member.filename)
                    format_counts[format_name] += 1
                    if processed_contract is not None:
                        if format_name != "npy":
                            raise Xrf55ProfileError(
                                "unsupported_processed_member_format"
                            )
                        scene, subject, action, repetition, modality = (
                            processed_observation(parts, processed_contract)
                        )
                        key = (scene, subject, action, repetition)
                        if modality in processed_modalities[key]:
                            raise Xrf55ProfileError(
                                "duplicate_processed_observation_modality"
                            )
                        processed_modalities[key].add(modality)
                    depth_counts[len(parts)] += 1
                    encoded_name = member.filename.encode("utf-8")
                    member_hashes.add(
                        hashlib.sha256(b"member\0" + encoded_name).digest()
                    )
                    stem = str(PurePosixPath(member.filename).with_suffix(""))
                    stem_digest = hashlib.sha256(
                        b"stem\0" + stem.encode("utf-8")
                    ).digest()
                    stem_hashes.add(stem_digest)
                    stem_formats[stem_digest].add(format_name)
                    top_levels.add(
                        hashlib.sha256(b"top\0" + parts[0].encode("utf-8")).digest()
                    )
                compression_counts[compression] += 1
                total_compressed_bytes += member.compress_size
                total_uncompressed_bytes += member.file_size
                if total_uncompressed_bytes > MAX_TOTAL_MEMBER_BYTES:
                    raise Xrf55ProfileError("total_member_size_limit")
        _require_unchanged(source, identity)

    subject_groups = {(key[0], key[1]) for key in processed_modalities}
    scenes = {key[0] for key in processed_modalities}
    actions = {key[2] for key in processed_modalities}
    repetitions = {key[3] for key in processed_modalities}
    if processed_contract is not None:
        if (
            len(subject_groups) != processed_contract["subject_groups"]
            or scenes != processed_contract["scenes"]
            or actions != processed_contract["actions"]
            or repetitions != processed_contract["repetitions"]
            or any(
                modalities != {"mmwave", "rfid", "wifi"}
                for modalities in processed_modalities.values()
            )
            or len(processed_modalities)
            != len(subject_groups) * len(actions) * len(repetitions)
        ):
            raise Xrf55ProfileError("incomplete_processed_observation_grid")
    co_stem = Counter(
        "+".join(sorted(formats))
        for formats in stem_formats.values()
        if len(formats) > 1
    )
    report = {
        "archive_bytes": identity.size,
        "central_directory_bytes": location.size,
        "compression_counts": dict(sorted(compression_counts.items())),
        "directories": directories,
        "file_format_counts": dict(sorted(format_counts.items())),
        "file_path_depth_counts": {
            str(key): value for key, value in sorted(depth_counts.items())
        },
        "files": files,
        "members": location.entries,
        "multi_format_stem_counts": dict(sorted(co_stem.items())),
        "top_level_groups": len(top_levels),
        "total_compressed_member_bytes": total_compressed_bytes,
        "total_uncompressed_member_bytes": total_uncompressed_bytes,
        "zip64": location.zip64,
    }
    if processed_contract is not None:
        train_repetitions = {value for value in repetitions if value <= 14}
        test_repetitions = repetitions - train_repetitions
        report["publisher_observation_grid"] = {
            "action_classes": len(actions),
            "complete_trimodal_events": len(processed_modalities),
            "modality_files_per_event": 3,
            "publisher_subject_groups": len(subject_groups),
            "repetitions": len(repetitions),
            "scene_groups": len(scenes),
            "test_events": len(subject_groups) * len(actions) * len(test_repetitions),
            "train_events": len(subject_groups) * len(actions) * len(train_repetitions),
        }
    return ArchiveInspection(
        identity=identity,
        report=report,
        member_hashes=frozenset(member_hashes),
        stem_hashes=frozenset(stem_hashes),
        subject_groups=frozenset(subject_groups),
        observations=frozenset(processed_modalities),
    )


def profile_corpus(
    raw_dir: Path,
    receipt_dir: Path,
    sources: Mapping[str, Mapping[str, Any]] | None = None,
    processed_contracts: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    sources = FETCH.SOURCES if sources is None else sources
    processed_contracts = (
        PROCESSED_CONTRACTS if processed_contracts is None else processed_contracts
    )
    status = FETCH.local_status(sources, raw_dir, receipt_dir)
    archives: dict[str, Any] = {}
    path_sets: dict[str, set[bytes]] = {}
    stem_sets: dict[str, set[bytes]] = {}
    subjects_by_archive: dict[str, set[tuple[int, int]]] = {}
    observations_by_archive: dict[str, set[tuple[int, int, int, int]]] = {}
    for name, spec in sources.items():
        observed = status["datasets"][name]
        valid_receipt = (
            observed["central_receipt_state"] == "valid"
            or observed["legacy_receipt_state"] == "valid"
        )
        if observed["archive_state"] != "present" or not valid_receipt:
            raise Xrf55ProfileError("archive_or_receipt_metadata_unready")
        inspection = profile_archive(
            raw_dir / str(spec["filename"]),
            int(spec["archive_bytes"]),
            processed_contracts.get(name),
        )
        receipt_location = (
            "central" if observed["central_receipt_state"] == "valid" else "legacy"
        )
        archives[name] = {**inspection.report, "receipt_location": receipt_location}
        path_sets[name] = set(inspection.member_hashes)
        stem_sets[name] = set(inspection.stem_hashes)
        subjects_by_archive[name] = set(inspection.subject_groups)
        observations_by_archive[name] = set(inspection.observations)

    processed_names = sorted(processed_contracts)
    if any(name not in subjects_by_archive for name in processed_names):
        raise Xrf55ProfileError("processed_archive_contract_missing")
    subject_intersection = set.intersection(
        *(subjects_by_archive[name] for name in processed_names)
    )
    observation_intersection = set.intersection(
        *(observations_by_archive[name] for name in processed_names)
    )
    if subject_intersection or observation_intersection:
        raise Xrf55ProfileError("processed_archive_group_overlap")
    processed_events = sum(
        len(observations_by_archive[name]) for name in processed_names
    )

    pairwise = []
    names = sorted(sources)
    for index, left in enumerate(names):
        for right in names[index + 1 :]:
            pairwise.append(
                {
                    "left": left,
                    "right": right,
                    "exact_member_path_overlap": len(
                        path_sets[left] & path_sets[right]
                    ),
                    "exact_stem_path_overlap": len(stem_sets[left] & stem_sets[right]),
                }
            )
    return {
        "schema": SCHEMA,
        "archives": archives,
        "cross_archive": {
            "pairwise_exact_path_counts": pairwise,
            "interpretation": "path equality is alignment evidence, not identity truth",
        },
        "publisher_processed_alignment": {
            "complete_trimodal_events": processed_events,
            "part_subject_group_intersection": len(subject_intersection),
            "part_event_intersection": len(observation_intersection),
            "reference": "publisher subject_action_repetition filename grammar",
            "relation_scope": "performer group and synchronized action event; not radio device or source identity",
        },
        "integrity": {
            "archive_payload_digest_verified": False,
            "receipt_metadata_validation": "exact",
            "zip_central_directory_validation": "bounded",
        },
        "privacy": {
            "member_names_retained": 0,
            "member_paths_retained": 0,
            "member_payload_bytes_read": 0,
            "source_urls_retained": 0,
        },
        "limits": {
            "maximum_archive_bytes": MAX_ARCHIVE_BYTES,
            "maximum_central_directory_bytes": MAX_CENTRAL_DIRECTORY_BYTES,
            "maximum_members_per_archive": MAX_MEMBERS,
            "maximum_total_uncompressed_bytes_per_archive": MAX_TOTAL_MEMBER_BYTES,
        },
    }


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise Xrf55ProfileError("unsafe_report_directory")
    if os.path.lexists(path):
        target = path.lstat()
        if stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode):
            raise Xrf55ProfileError("unsafe_report_path")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPT_DIR)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        report = profile_corpus(arguments.raw_dir, arguments.receipt_dir)
        _write_report(arguments.report, report)
    except (OSError, ValueError, zipfile.BadZipFile, Xrf55ProfileError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
