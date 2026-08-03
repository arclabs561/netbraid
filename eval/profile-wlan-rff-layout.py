#!/usr/bin/env python3
"""Profile label-free layout evidence from the public WLAN RFF archives.

Only the ZIP central directory and archive digests are read. NPZ members are
never opened or extracted, and filename label values are reduced to counts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Optional

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.wlan_rff_layout_profile.v0"
MIB = 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * MIB
MAX_MEMBERS = 1_000
MAX_MEMBER_BYTES = 8 * MIB
MAX_TOTAL_MEMBER_BYTES = 512 * MIB
MAX_NAME_BYTES = 255
MAX_COMPRESSION_RATIO = 100
READ_CHUNK_BYTES = MIB

ARCHIVES = {
    "anechoic_chamber": {
        "filename": "wlan-rff-anechoic_chamber.zip",
        "md5": "9af7491dc891d89969832f0efdee89de",
    },
    "office_room": {
        "filename": "wlan-rff-office_room.zip",
        "md5": "8cb50121448016a6c7a1293051b26e1b",
    },
}

MEMBER_PATTERN = re.compile(
    r"(?P<device>[0-9]{3})_"
    r"(?P<session>[0-9]{4}(?:_[0-9]{2}){5})_"
    r"(?P<segment>[0-9]+)_"
    r"(?P<environment>anechoic_chamber|office_room)\.npz\Z"
)


class LayoutProfileError(RuntimeError):
    """Stable fail-closed reason for an unsafe or unsupported archive."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class ArchiveFacts:
    environment: str
    archive_bytes: int
    archive_md5: str
    archive_sha256: str
    members: int
    member_bytes: int
    compressed_member_bytes: int
    devices: frozenset[str]
    sessions: frozenset[str]
    observations_by_device: tuple[int, ...]
    observations_by_session: tuple[int, ...]


def _identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _open_regular(path: Path) -> tuple[BinaryIO, FileIdentity]:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise LayoutProfileError("archive_not_regular")
    if not 0 < before.st_size <= MAX_ARCHIVE_BYTES:
        raise LayoutProfileError("archive_size_limit")
    source = path.open("rb")
    after = os.fstat(source.fileno())
    if _identity(before) != _identity(after):
        source.close()
        raise LayoutProfileError("archive_identity_changed")
    return source, _identity(after)


def _require_unchanged(source: BinaryIO, expected: FileIdentity) -> None:
    if _identity(os.fstat(source.fileno())) != expected:
        raise LayoutProfileError("archive_changed_during_profile")


def _digests(source: BinaryIO) -> tuple[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    source.seek(0)
    while True:
        chunk = source.read(READ_CHUNK_BYTES)
        if not chunk:
            break
        md5.update(chunk)
        sha256.update(chunk)
    source.seek(0)
    return md5.hexdigest(), sha256.hexdigest()


def _safe_member_name(name: str) -> None:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise LayoutProfileError("unsafe_member_name") from error
    if (
        not encoded
        or len(encoded) > MAX_NAME_BYTES
        or "/" in name
        or "\\" in name
        or name in {".", ".."}
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise LayoutProfileError("unsafe_member_name")


def profile_archive(
    path: Path, environment: str, expected_md5: Optional[str] = None
) -> ArchiveFacts:
    if environment not in ARCHIVES:
        raise LayoutProfileError("unsupported_environment")
    source, identity = _open_regular(path)
    try:
        observed_md5, observed_sha256 = _digests(source)
        if expected_md5 is not None and observed_md5 != expected_md5:
            raise LayoutProfileError("archive_digest_mismatch")

        devices: set[str] = set()
        sessions: set[str] = set()
        by_device: Counter[str] = Counter()
        by_session: Counter[str] = Counter()
        names: set[str] = set()
        member_bytes = 0
        compressed_bytes = 0

        try:
            archive = zipfile.ZipFile(source)
        except (OSError, zipfile.BadZipFile) as error:
            raise LayoutProfileError("invalid_zip_archive") from error
        with archive:
            members = archive.infolist()
            if not 1 <= len(members) <= MAX_MEMBERS:
                raise LayoutProfileError("archive_member_count_limit")
            for member in members:
                _safe_member_name(member.filename)
                if member.filename in names:
                    raise LayoutProfileError("duplicate_member_name")
                names.add(member.filename)
                if member.is_dir() or member.flag_bits & 0x1:
                    raise LayoutProfileError("unsupported_member_kind")
                if member.compress_type not in {
                    zipfile.ZIP_STORED,
                    zipfile.ZIP_DEFLATED,
                }:
                    raise LayoutProfileError("unsupported_compression")
                if not 0 < member.file_size <= MAX_MEMBER_BYTES:
                    raise LayoutProfileError("member_size_limit")
                if not 0 < member.compress_size <= MAX_MEMBER_BYTES:
                    raise LayoutProfileError("invalid_compressed_size")
                if member.file_size > member.compress_size * MAX_COMPRESSION_RATIO:
                    raise LayoutProfileError("compression_ratio_limit")
                member_bytes += member.file_size
                compressed_bytes += member.compress_size
                if member_bytes > MAX_TOTAL_MEMBER_BYTES:
                    raise LayoutProfileError("total_member_size_limit")

                match = MEMBER_PATTERN.fullmatch(member.filename)
                if match is None or match.group("environment") != environment:
                    raise LayoutProfileError("unsupported_member_name")
                device = match.group("device")
                session = match.group("session")
                devices.add(device)
                sessions.add(session)
                by_device[device] += 1
                by_session[session] += 1

        _require_unchanged(source, identity)
        return ArchiveFacts(
            environment=environment,
            archive_bytes=identity.size,
            archive_md5=observed_md5,
            archive_sha256=observed_sha256,
            members=len(names),
            member_bytes=member_bytes,
            compressed_member_bytes=compressed_bytes,
            devices=frozenset(devices),
            sessions=frozenset(sessions),
            observations_by_device=tuple(sorted(by_device.values())),
            observations_by_session=tuple(sorted(by_session.values())),
        )
    finally:
        source.close()


def profile_archives(
    anechoic_path: Path,
    office_path: Path,
    *,
    verify_publisher_digests: bool = True,
) -> dict[str, Any]:
    facts = tuple(
        profile_archive(
            archive_path,
            environment,
            ARCHIVES[environment]["md5"] if verify_publisher_digests else None,
        )
        for environment, archive_path in (
            ("anechoic_chamber", anechoic_path),
            ("office_room", office_path),
        )
    )
    by_environment = {item.environment: item for item in facts}
    anechoic = by_environment["anechoic_chamber"]
    office = by_environment["office_room"]
    shared_devices = anechoic.devices.intersection(office.devices)

    return {
        "schema": SCHEMA,
        "status": "pass",
        "archives": [
            {
                "environment": item.environment,
                "archive_bytes": item.archive_bytes,
                "archive_md5": item.archive_md5,
                "archive_sha256": item.archive_sha256,
                "members": item.members,
                "member_bytes": item.member_bytes,
                "compressed_member_bytes": item.compressed_member_bytes,
                "distinct_device_tokens": len(item.devices),
                "distinct_session_tokens": len(item.sessions),
                "observations_per_device": {
                    "minimum": min(item.observations_by_device),
                    "maximum": max(item.observations_by_device),
                },
                "observations_per_session": {
                    "minimum": min(item.observations_by_session),
                    "maximum": max(item.observations_by_session),
                },
            }
            for item in facts
        ],
        "cross_environment": {
            "shared_device_tokens": len(shared_devices),
            "device_tokens_in_union": len(anechoic.devices.union(office.devices)),
            "same_token_set": anechoic.devices == office.devices,
            "shared_session_tokens": len(
                anechoic.sessions.intersection(office.sessions)
            ),
        },
        "interpretation": {
            "established": (
                "the strict filename grammar reuses device tokens across the two "
                "publisher environment archives"
            ),
            "not_established": [
                "physical_device_identity",
                "physical_source_identity",
                "event_identity",
                "malicious_intent",
            ],
            "admission": (
                "cross-environment token grouping is a candidate oracle that still "
                "requires publisher documentation before physical-source evaluation"
            ),
        },
        "privacy": {
            "paths_retained": 0,
            "device_token_values_retained": 0,
            "session_token_values_retained": 0,
            "npz_payload_bytes_read": 0,
        },
        "limits": {
            "max_archive_bytes": MAX_ARCHIVE_BYTES,
            "max_members": MAX_MEMBERS,
            "max_member_bytes": MAX_MEMBER_BYTES,
            "max_total_member_bytes": MAX_TOTAL_MEMBER_BYTES,
            "max_compression_ratio": MAX_COMPRESSION_RATIO,
        },
    }


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--anechoic",
        type=Path,
        default=ROOT / "data" / "raw" / ARCHIVES["anechoic_chamber"]["filename"],
    )
    parser.add_argument(
        "--office",
        type=Path,
        default=ROOT / "data" / "raw" / ARCHIVES["office_room"]["filename"],
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "data" / "derived" / "eval" / "wlan-rff-layout-profile.json",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        report = profile_archives(arguments.anechoic, arguments.office)
        _write_report(arguments.report, report)
    except (LayoutProfileError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    json.dump(report, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
