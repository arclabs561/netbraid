#!/usr/bin/env python3
"""Profile the pinned GNSS RFF ZIP without opening member payload streams.

The archive is read once as opaque bytes for publisher-MD5 verification. All
layout evidence then comes from the ZIP central directory: MAT and H5 members
are never opened, extracted, decrypted, or deserialized, and no password is
accepted by this program.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import stat
import struct
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

KIB = 1024
MIB = 1024 * KIB
GIB = 1024 * MIB
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.gnss_rff_layout_profile.v0"

ARCHIVE_FILENAME = "gnss-rff-Data.zip"
PUBLISHER_BYTES = 6_358_035_306
PUBLISHER_MD5 = "e6ded5b0cb014265d321f61a801686c4"

MAX_ARCHIVE_BYTES = 7 * GIB
MAX_MEMBERS = 20_000
MAX_MEMBER_BYTES = 256 * MIB
MAX_TOTAL_MEMBER_BYTES = 8 * GIB
MAX_NAME_BYTES = 512
MAX_COMPONENT_BYTES = 255
MAX_COMPRESSION_RATIO = 200
MAX_SEQUENCE_DIGITS = 9
READ_CHUNK_BYTES = 4 * MIB

DAYS = ("oct_18", "oct_19")
SCENARIOS = ("clean", "spoof")
CATEGORIES = {
    1: "baseline",
    2: "multipath",
    3: "high_sampling_rate",
    4: "low_quantization",
}
EXPECTED_DIRECTORIES = frozenset({"data/", "data/oct_18/", "data/oct_19/", "models/"})
EXPECTED_MODEL_CELLS = frozenset(
    (day, category) for day in DAYS for category in CATEGORIES
)

DATA_MEMBER_PATTERN = re.compile(
    r"data/(?P<day>oct_(?:18|19))/(?P<prefix>SS|S)"
    r"(?P<category>[1-4])_"
    rf"(?P<sequence>[1-9][0-9]{{0,{MAX_SEQUENCE_DIGITS - 1}}})[.]mat\Z"
)
MODEL_MEMBER_PATTERN = re.compile(
    r"models/Fully_connected(?P<day>18|19)_C(?P<category>[1-4])_"
    r"SS20000_same_samples_lr001_red_1_samplemean[.]h5\Z"
)
MD5_PATTERN = re.compile(r"[0-9a-f]{32}\Z")

ALLOWED_COMPRESSIONS = {
    zipfile.ZIP_STORED: "stored",
    zipfile.ZIP_DEFLATED: "deflated",
}
ALLOWED_FLAG_BITS = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0800
STRONG_ENCRYPTION_FLAG = 0x0040
MASKED_HEADER_FLAG = 0x2000
AES_EXTRA_FIELD = 0x9901


class LayoutProfileError(RuntimeError):
    """Stable fail-closed reason for an unsafe or unsupported archive."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


def _identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _open_regular(path: Path) -> tuple[BinaryIO, FileIdentity]:
    try:
        before = path.lstat()
    except OSError as error:
        raise LayoutProfileError("archive_unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise LayoutProfileError("archive_not_regular")
    if not 0 < before.st_size <= MAX_ARCHIVE_BYTES:
        raise LayoutProfileError("archive_size_limit")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise LayoutProfileError("archive_open_failed") from error
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or _identity(before) != _identity(after):
            raise LayoutProfileError("archive_identity_changed")
        return os.fdopen(descriptor, "rb"), _identity(after)
    except BaseException:
        os.close(descriptor)
        raise


def _require_unchanged(source: BinaryIO, expected: FileIdentity) -> None:
    if _identity(os.fstat(source.fileno())) != expected:
        raise LayoutProfileError("archive_changed_during_profile")


def _publisher_digest(source: BinaryIO) -> str:
    digest = hashlib.md5(usedforsecurity=False)
    source.seek(0)
    while True:
        chunk = source.read(READ_CHUNK_BYTES)
        if not chunk:
            break
        digest.update(chunk)
    source.seek(0)
    return digest.hexdigest()


def _safe_member_name(name: str) -> None:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise LayoutProfileError("unsafe_member_name") from error
    if (
        not encoded
        or len(encoded) > MAX_NAME_BYTES
        or name.startswith("/")
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise LayoutProfileError("unsafe_member_name")

    components = name[:-1].split("/") if name.endswith("/") else name.split("/")
    if not components or any(component in {"", ".", ".."} for component in components):
        raise LayoutProfileError("unsafe_member_name")
    for component in components:
        try:
            component_bytes = component.encode("utf-8")
        except UnicodeEncodeError as error:
            raise LayoutProfileError("unsafe_member_name") from error
        if len(component_bytes) > MAX_COMPONENT_BYTES:
            raise LayoutProfileError("unsafe_member_name")


def _extra_field_ids(extra: bytes) -> set[int]:
    identifiers: set[int] = set()
    offset = 0
    while offset < len(extra):
        if len(extra) - offset < 4:
            raise LayoutProfileError("malformed_member_extra_field")
        identifier, size = struct.unpack_from("<HH", extra, offset)
        offset += 4
        if size > len(extra) - offset:
            raise LayoutProfileError("malformed_member_extra_field")
        identifiers.add(identifier)
        offset += size
    return identifiers


def _member_kind(
    member: zipfile.ZipInfo,
) -> tuple[str, tuple[str, int, str] | None]:
    name = member.filename
    if member.is_dir():
        if name not in EXPECTED_DIRECTORIES:
            raise LayoutProfileError("unsupported_directory_member")
        return "directory", None

    match = DATA_MEMBER_PATTERN.fullmatch(name)
    if match is not None:
        scenario = "spoof" if match.group("prefix") == "SS" else "clean"
        return (
            "data_mat",
            (match.group("day"), int(match.group("category")), scenario),
        )

    match = MODEL_MEMBER_PATTERN.fullmatch(name)
    if match is not None:
        return (
            "model_h5",
            (f"oct_{match.group('day')}", int(match.group("category")), "model"),
        )
    if name == "demo.py":
        return "demo_python", None
    raise LayoutProfileError("unsupported_member_name")


def _check_member_metadata(member: zipfile.ZipInfo, archive_bytes: int) -> None:
    if member.comment:
        raise LayoutProfileError("unsupported_member_comment")
    if member.header_offset < 0 or member.header_offset >= archive_bytes:
        raise LayoutProfileError("invalid_member_header_offset")
    if member.compress_type not in ALLOWED_COMPRESSIONS:
        raise LayoutProfileError("unsupported_compression")
    if member.flag_bits & (STRONG_ENCRYPTION_FLAG | MASKED_HEADER_FLAG):
        raise LayoutProfileError("unsupported_encryption")
    if AES_EXTRA_FIELD in _extra_field_ids(member.extra):
        raise LayoutProfileError("unsupported_encryption")
    if member.flag_bits & ~ALLOWED_FLAG_BITS:
        raise LayoutProfileError("unsupported_member_flags")
    if member.compress_type == zipfile.ZIP_STORED and member.flag_bits & 0x0006:
        raise LayoutProfileError("unsupported_member_flags")

    unix_kind = 0
    if member.create_system == 3:
        unix_kind = stat.S_IFMT(member.external_attr >> 16)
    if unix_kind not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise LayoutProfileError("unsupported_member_kind")
    if member.is_dir():
        if member.flag_bits & 0x0001:
            raise LayoutProfileError("encrypted_directory_member")
        if member.file_size != 0 or member.compress_size != 0:
            raise LayoutProfileError("invalid_directory_member")
        if unix_kind not in {0, stat.S_IFDIR}:
            raise LayoutProfileError("unsupported_member_kind")
        return

    if unix_kind not in {0, stat.S_IFREG}:
        raise LayoutProfileError("unsupported_member_kind")
    if not 0 < member.file_size <= MAX_MEMBER_BYTES:
        raise LayoutProfileError("member_size_limit")
    if not 0 < member.compress_size <= MAX_MEMBER_BYTES:
        raise LayoutProfileError("compressed_member_size_limit")
    if member.file_size > member.compress_size * MAX_COMPRESSION_RATIO:
        raise LayoutProfileError("compression_ratio_limit")


def _size_bounds(values: list[tuple[int, int]]) -> dict[str, int]:
    return {
        "members": len(values),
        "minimum_uncompressed_bytes": min(item[0] for item in values),
        "maximum_uncompressed_bytes": max(item[0] for item in values),
        "minimum_compressed_bytes": min(item[1] for item in values),
        "maximum_compressed_bytes": max(item[1] for item in values),
    }


def profile_archive(
    path: Path,
    *,
    expected_md5: str = PUBLISHER_MD5,
    expected_bytes: int | None = PUBLISHER_BYTES,
) -> dict[str, Any]:
    """Verify and aggregate one archive without opening a member stream."""

    if MD5_PATTERN.fullmatch(expected_md5) is None:
        raise LayoutProfileError("invalid_digest_contract")
    if expected_bytes is not None and not 0 < expected_bytes <= MAX_ARCHIVE_BYTES:
        raise LayoutProfileError("invalid_size_contract")

    source, identity = _open_regular(path)
    try:
        if expected_bytes is not None and identity.size != expected_bytes:
            raise LayoutProfileError("archive_size_mismatch")
        observed_md5 = _publisher_digest(source)
        if observed_md5 != expected_md5:
            raise LayoutProfileError("archive_digest_mismatch")
        _require_unchanged(source, identity)

        try:
            archive = zipfile.ZipFile(source, mode="r", allowZip64=True)
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
            raise LayoutProfileError("invalid_zip_archive") from error

        names: set[str] = set()
        folded_names: set[str] = set()
        directories: set[str] = set()
        model_cells: set[tuple[str, int]] = set()
        data_counts: Counter[tuple[str, int, str]] = Counter()
        sequences: defaultdict[tuple[str, int, str], set[str]] = defaultdict(set)
        encrypted_by_kind: Counter[str] = Counter()
        sizes_by_kind: defaultdict[str, list[tuple[int, int]]] = defaultdict(list)
        compression_counts: Counter[str] = Counter()
        demo_members = 0
        total_member_bytes = 0
        total_compressed_bytes = 0

        with archive:
            if archive.comment:
                raise LayoutProfileError("unsupported_archive_comment")
            members = archive.infolist()
            if not 1 <= len(members) <= MAX_MEMBERS:
                raise LayoutProfileError("archive_member_count_limit")

            for member in members:
                _safe_member_name(member.orig_filename)
                if member.orig_filename != member.filename:
                    raise LayoutProfileError("unsafe_member_name")
                folded = member.filename.casefold()
                if member.filename in names:
                    raise LayoutProfileError("duplicate_member_name")
                if folded in folded_names:
                    raise LayoutProfileError("case_colliding_member_name")
                names.add(member.filename)
                folded_names.add(folded)

                _check_member_metadata(member, identity.size)
                kind, cell = _member_kind(member)
                compression_counts[ALLOWED_COMPRESSIONS[member.compress_type]] += 1
                if member.flag_bits & 0x0001:
                    encrypted_by_kind[kind] += 1

                if kind == "directory":
                    directories.add(member.filename)
                    continue

                total_member_bytes += member.file_size
                total_compressed_bytes += member.compress_size
                if total_member_bytes > MAX_TOTAL_MEMBER_BYTES:
                    raise LayoutProfileError("total_member_size_limit")
                sizes_by_kind[kind].append((member.file_size, member.compress_size))

                if kind == "data_mat":
                    if cell is None:
                        raise LayoutProfileError("invalid_member_classification")
                    data_counts[cell] += 1
                    match = DATA_MEMBER_PATTERN.fullmatch(member.filename)
                    if match is None:
                        raise LayoutProfileError("invalid_member_classification")
                    sequences[cell].add(match.group("sequence"))
                elif kind == "model_h5":
                    if cell is None:
                        raise LayoutProfileError("invalid_member_classification")
                    model_cells.add((cell[0], cell[1]))
                else:
                    demo_members += 1

        _require_unchanged(source, identity)

        if directories != EXPECTED_DIRECTORIES:
            raise LayoutProfileError("incomplete_directory_member_set")
        if model_cells != EXPECTED_MODEL_CELLS:
            raise LayoutProfileError("incomplete_model_member_set")
        if demo_members != 1:
            raise LayoutProfileError("incomplete_demo_member_set")
        if not data_counts or any(
            not any(key[0] == day for key in data_counts) for day in DAYS
        ):
            raise LayoutProfileError("incomplete_data_day_set")
        if any(len(sequences[cell]) != count for cell, count in data_counts.items()):
            raise LayoutProfileError("duplicate_sequence_token")

        matrix = []
        for day in DAYS:
            for category, category_name in CATEGORIES.items():
                for scenario in SCENARIOS:
                    matrix.append(
                        {
                            "category": category,
                            "category_name": category_name,
                            "controlled_scenario": scenario,
                            "day": day,
                            "members": data_counts[(day, category, scenario)],
                        }
                    )

        by_day = []
        for day in DAYS:
            clean = sum(
                data_counts[(day, category, "clean")] for category in CATEGORIES
            )
            spoof = sum(
                data_counts[(day, category, "spoof")] for category in CATEGORIES
            )
            by_day.append(
                {
                    "day": day,
                    "members": clean + spoof,
                    "controlled_scenarios": {"clean": clean, "spoof": spoof},
                    "categories_with_clean_members": sum(
                        data_counts[(day, category, "clean")] > 0
                        for category in CATEGORIES
                    ),
                    "categories_with_spoof_members": sum(
                        data_counts[(day, category, "spoof")] > 0
                        for category in CATEGORIES
                    ),
                }
            )

        by_category = []
        for category, category_name in CATEGORIES.items():
            clean = sum(data_counts[(day, category, "clean")] for day in DAYS)
            spoof = sum(data_counts[(day, category, "spoof")] for day in DAYS)
            by_category.append(
                {
                    "category": category,
                    "category_name": category_name,
                    "members": clean + spoof,
                    "controlled_scenarios": {"clean": clean, "spoof": spoof},
                }
            )

        cross_day_rows = []
        for category, category_name in CATEGORIES.items():
            for scenario in SCENARIOS:
                left = sequences[("oct_18", category, scenario)]
                right = sequences[("oct_19", category, scenario)]
                cross_day_rows.append(
                    {
                        "category": category,
                        "category_name": category_name,
                        "controlled_scenario": scenario,
                        "covered_on_both_days": bool(left and right),
                        "days_with_members": int(bool(left)) + int(bool(right)),
                        "shared_sequence_token_count": len(left.intersection(right)),
                    }
                )
        covered_both = sum(row["covered_on_both_days"] for row in cross_day_rows)

        encrypted_members = sum(encrypted_by_kind.values())
        data_members = sum(data_counts.values())
        file_members = data_members + len(model_cells) + demo_members
        return {
            "schema": SCHEMA,
            "status": "pass",
            "archive": {
                "bytes": identity.size,
                "members": len(names),
                "file_members": file_members,
                "directory_members": len(directories),
                "publisher_md5": observed_md5,
                "publisher_md5_verified": True,
                "member_bytes": total_member_bytes,
                "compressed_member_bytes": total_compressed_bytes,
            },
            "layout": {
                "data_members": {
                    "total": data_members,
                    "by_day": by_day,
                    "by_category": by_category,
                    "by_day_category_and_controlled_scenario": matrix,
                },
                "model_members": {
                    "total": len(model_cells),
                    "by_training_day_and_category": [
                        {
                            "category": category,
                            "category_name": CATEGORIES[category],
                            "members": int((day, category) in model_cells),
                            "training_day": day,
                        }
                        for day in DAYS
                        for category in CATEGORIES
                    ],
                },
                "demo_members": demo_members,
                "cross_day_coverage": {
                    "category_scenario_pairs": cross_day_rows,
                    "pairs_covered_on_both_days": covered_both,
                    "pairs_total": len(CATEGORIES) * len(SCENARIOS),
                },
            },
            "encryption": {
                "encrypted_members": encrypted_members,
                "unencrypted_members": len(names) - encrypted_members,
                "by_kind": {
                    kind: encrypted_by_kind[kind]
                    for kind in ("data_mat", "model_h5", "demo_python", "directory")
                },
            },
            "compression": {
                "by_method": {
                    method: compression_counts[method]
                    for method in ("stored", "deflated")
                }
            },
            "observed_bounds": {
                kind: _size_bounds(sizes_by_kind[kind])
                for kind in ("data_mat", "model_h5", "demo_python")
            },
            "privacy": {
                "member_paths_emitted": 0,
                "sequence_values_emitted": 0,
                "member_payload_streams_opened": 0,
                "mat_payload_bytes_decompressed": 0,
                "h5_payload_bytes_decompressed": 0,
                "password_values_used": 0,
                "raw_archive_bytes_hashed_for_md5": identity.size,
            },
            "interpretation": {
                "spoof_label_scope": (
                    "spoof labels are controlled-scenario oracles only; they do not "
                    "establish physical-source identity, tamper, actor identity, or "
                    "malicious intent"
                ),
                "sequence_overlap_scope": (
                    "shared sequence-token counts establish filename coverage only, "
                    "not event identity or physical-source identity"
                ),
                "archive_digest_scope": (
                    "the archive MD5 establishes transfer integrity only; it is not "
                    "a tamper label or scenario oracle"
                ),
            },
            "limits": {
                "max_archive_bytes": MAX_ARCHIVE_BYTES,
                "max_members": MAX_MEMBERS,
                "max_member_bytes": MAX_MEMBER_BYTES,
                "max_total_member_bytes": MAX_TOTAL_MEMBER_BYTES,
                "max_name_bytes": MAX_NAME_BYTES,
                "max_component_bytes": MAX_COMPONENT_BYTES,
                "max_compression_ratio": MAX_COMPRESSION_RATIO,
                "max_sequence_digits": MAX_SEQUENCE_DIGITS,
            },
        }
    finally:
        source.close()


def render_report(report: dict[str, Any]) -> bytes:
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_report(path: Path, rendered: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive",
        type=Path,
        default=ROOT / "data" / "raw" / ARCHIVE_FILENAME,
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "data" / "derived" / "eval" / "gnss-rff-layout-profile.json",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        report = profile_archive(arguments.archive)
        rendered = render_report(report)
        write_report(arguments.report, rendered)
    except (LayoutProfileError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
