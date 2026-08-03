#!/usr/bin/env python3
"""Archive a fixed set of legacy derived outputs misplaced in ``data/raw``.

The migration recognizes a complete fresh state, a complete verified archive,
or a verified relocation split between the previous and current archive
locations. It never selects files by pattern and never replaces an existing
file. Receipt entries intentionally contain basenames and local integrity
metadata only because the original derivation provenance is unknown.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT_RAW_DIR = REPOSITORY / "data" / "raw"
DEFAULT_ARCHIVE_DIR = REPOSITORY / "data" / "archive" / "legacy-derived-unknown"
DEFAULT_LEGACY_ARCHIVE_DIR = (
    REPOSITORY / "data" / "derived" / "archive" / "legacy-unscripted"
)
RECEIPT_BASENAME = "migration-receipt.json"
RECEIPT_SCHEMA = "netbraid.legacy_unscripted_derived.v1"
PROVENANCE_STATUS = "legacy/unknown"
CHUNK_BYTES = 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024

ALLOWLIST = (
    "caez-alignment-profile-repeat.json",
    "caez-alignment-profile.json",
    "caez-csi-profile-repeat.json",
    "caez-csi-profile.json",
    "corpus-report.json",
    "data4cyber-alignment-profile-repeat.json",
    "data4cyber-alignment-profile.json",
    "iot23-flow-lineage-report-repeat.json",
    "iot23-flow-lineage-report-v2-repeat.json",
    "iot23-flow-lineage-report-v2.json",
    "iot23-flow-lineage-report.json",
    "iot23v2-hakai-flow-v0-repeat.tsv",
    "iot23v2-hakai-flow-v0.tsv",
    "netslab-alignment-profile-repeat.json",
    "netslab-alignment-profile.json",
    "operanet-layout-profile-repeat.json",
    "operanet-layout-profile.json",
    "public-corpus-eval-report.json",
    "public-corpus-inventory.json",
    "sorbonne-campus-rssi-inventory.json",
    "sorbonne-same-event-report-a.json",
    "sorbonne-same-event-report-b.json",
    "sorbonne-same-event-report-py39.json",
    "sorbonne-same-event-report.json",
    "sorbonne-structural-reducer-report-repeat.json",
    "sorbonne-structural-reducer-report.json",
)

Fingerprint = tuple[int, int, int, int, int, int]


class MigrationError(RuntimeError):
    """A stable, path-free migration failure."""


@dataclass(frozen=True)
class FileRecord:
    basename: str
    bytes: int
    sha256: str
    fingerprint: Fingerprint

    def receipt_entry(self) -> dict[str, str | int]:
        return {
            "basename": self.basename,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "status": PROVENANCE_STATUS,
        }


@dataclass(frozen=True)
class RelocationEntry:
    basename: str
    legacy_fingerprint: Fingerprint | None
    archive_fingerprint: Fingerprint | None


def _lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _fingerprint(metadata: os.stat_result) -> Fingerprint:
    return (
        metadata.st_mode,
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_nlink,
    )


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_mode,
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _require_directory(path: Path, error_code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise MigrationError(error_code) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise MigrationError(error_code)


def _ensure_directory(path: Path) -> None:
    missing: list[Path] = []
    cursor = path
    while not _lexists(cursor):
        missing.append(cursor)
        parent = cursor.parent
        if parent == cursor:
            raise MigrationError("unsafe_archive_directory")
        cursor = parent
    _require_directory(cursor, "unsafe_archive_directory")
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as error:
            raise MigrationError("archive_directory_create_failed") from error
        _require_directory(directory, "unsafe_archive_directory")


def _regular_metadata(path: Path, error_code: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise MigrationError(error_code) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise MigrationError(error_code)
    return metadata


def _digest_regular(path: Path, expected: os.stat_result) -> tuple[int, str]:
    if expected.st_size > MAX_FILE_BYTES:
        raise MigrationError("file_size_limit_exceeded")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise MigrationError("unsafe_or_changed_file") from error
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or _fingerprint(before) != _fingerprint(
                expected
            ):
                raise MigrationError("unsafe_or_changed_file")
            while chunk := source.read(CHUNK_BYTES):
                size += len(chunk)
                if size > MAX_FILE_BYTES:
                    raise MigrationError("file_size_limit_exceeded")
                digest.update(chunk)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise MigrationError("file_read_failed") from error
    if size != before.st_size or _fingerprint(after) != _fingerprint(before):
        raise MigrationError("file_changed_during_digest")
    return size, digest.hexdigest()


def _inventory(directory: Path) -> list[FileRecord]:
    records: list[FileRecord] = []
    total_bytes = 0
    for basename in ALLOWLIST:
        path = directory / basename
        metadata = _regular_metadata(path, "unsafe_or_missing_file")
        size, sha256 = _digest_regular(path, metadata)
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise MigrationError("total_size_limit_exceeded")
        records.append(FileRecord(basename, size, sha256, _fingerprint(metadata)))
    return records


def _receipt(records: list[FileRecord]) -> dict[str, Any]:
    return {
        "files": [record.receipt_entry() for record in records],
        "schema": RECEIPT_SCHEMA,
    }


def _archive_entries(archive_dir: Path) -> set[str]:
    if not _lexists(archive_dir):
        return set()
    _require_directory(archive_dir, "unsafe_archive_directory")
    try:
        with os.scandir(archive_dir) as iterator:
            entries = list(iterator)
    except OSError as error:
        raise MigrationError("archive_scan_failed") from error
    names: set[str] = set()
    expected = {*ALLOWLIST, RECEIPT_BASENAME}
    for entry in entries:
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as error:
            raise MigrationError("archive_scan_failed") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise MigrationError("unsafe_archive_entry")
        if entry.name not in expected:
            raise MigrationError("archive_conflict")
        names.add(entry.name)
    return names


def _relocation_entry(
    legacy_archive_dir: Path,
    archive_dir: Path,
    basename: str,
    legacy_names: set[str],
    archive_names: set[str],
    error_code: str,
) -> RelocationEntry:
    legacy_metadata = (
        _regular_metadata(legacy_archive_dir / basename, error_code)
        if basename in legacy_names
        else None
    )
    archive_metadata = (
        _regular_metadata(archive_dir / basename, error_code)
        if basename in archive_names
        else None
    )
    if legacy_metadata is None and archive_metadata is None:
        raise MigrationError("incomplete_or_conflicting_state")
    if (
        legacy_metadata is not None
        and archive_metadata is not None
        and _identity(legacy_metadata) != _identity(archive_metadata)
    ):
        raise MigrationError("incomplete_or_conflicting_state")
    return RelocationEntry(
        basename=basename,
        legacy_fingerprint=(
            _fingerprint(legacy_metadata) if legacy_metadata is not None else None
        ),
        archive_fingerprint=(
            _fingerprint(archive_metadata) if archive_metadata is not None else None
        ),
    )


def _read_receipt(path: Path) -> dict[str, Any]:
    expected = _regular_metadata(path, "unsafe_or_missing_receipt")
    if expected.st_size > MAX_RECEIPT_BYTES:
        raise MigrationError("receipt_size_limit_exceeded")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise MigrationError("unsafe_or_missing_receipt") from error
    try:
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or _fingerprint(before) != _fingerprint(
                expected
            ):
                raise MigrationError("unsafe_or_missing_receipt")
            payload = source.read(MAX_RECEIPT_BYTES + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise MigrationError("receipt_read_failed") from error
    if (
        len(payload) > MAX_RECEIPT_BYTES
        or len(payload) != before.st_size
        or _fingerprint(after) != _fingerprint(before)
    ):
        raise MigrationError("receipt_changed_during_read")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MigrationError("invalid_receipt") from error
    if not isinstance(value, dict):
        raise MigrationError("invalid_receipt")
    return value


def _sync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise MigrationError("directory_sync_failed") from error


def _write_receipt_new(path: Path, value: dict[str, Any]) -> None:
    if _lexists(path):
        raise MigrationError("receipt_conflict")
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent
        )
    except OSError as error:
        raise MigrationError("receipt_write_failed") from error
    temporary = Path(temporary_name)
    try:
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(value, output, ensure_ascii=True, indent=2, sort_keys=True)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.link(temporary, path, follow_symlinks=False)
            _sync_directory(path.parent)
        except FileExistsError as error:
            raise MigrationError("receipt_conflict") from error
        except OSError as error:
            raise MigrationError("receipt_write_failed") from error
    finally:
        with suppress(OSError):
            temporary.unlink()


def _move_new(source: Path, target: Path, expected: Fingerprint) -> None:
    if _lexists(target):
        raise MigrationError("destination_conflict")
    current = _regular_metadata(source, "unsafe_or_missing_file")
    if _fingerprint(current) != expected:
        raise MigrationError("source_changed_before_move")
    try:
        os.link(source, target, follow_symlinks=False)
    except FileExistsError as error:
        raise MigrationError("destination_conflict") from error
    except OSError as error:
        raise MigrationError("move_link_failed") from error

    linked_source = _regular_metadata(source, "source_changed_during_move")
    linked_target = _regular_metadata(target, "destination_changed_during_move")
    if (
        _identity(linked_source) != _identity(current)
        or _identity(linked_target) != _identity(current)
        or linked_source.st_nlink != current.st_nlink + 1
        or linked_target.st_nlink != linked_source.st_nlink
    ):
        raise MigrationError("file_changed_during_move")
    try:
        source.unlink()
    except OSError as error:
        raise MigrationError("source_retire_failed") from error
    moved = _regular_metadata(target, "destination_changed_during_move")
    if _identity(moved) != _identity(current) or moved.st_nlink != current.st_nlink:
        raise MigrationError("file_changed_during_move")


def _verified_archive(directory: Path) -> tuple[list[FileRecord], Fingerprint]:
    records = _inventory(directory)
    receipt_path = directory / RECEIPT_BASENAME
    receipt_metadata = _regular_metadata(receipt_path, "unsafe_or_missing_receipt")
    receipt = _read_receipt(receipt_path)
    receipt_after = _regular_metadata(receipt_path, "unsafe_or_missing_receipt")
    if _fingerprint(receipt_after) != _fingerprint(receipt_metadata):
        raise MigrationError("receipt_changed_during_verification")
    if receipt != _receipt(records):
        raise MigrationError("archive_receipt_mismatch")
    return records, _fingerprint(receipt_after)


def _verified_relocation(
    legacy_archive_dir: Path,
    archive_dir: Path,
    legacy_names: set[str],
    archive_names: set[str],
) -> tuple[list[FileRecord], list[RelocationEntry], RelocationEntry]:
    records: list[FileRecord] = []
    entries: list[RelocationEntry] = []
    total_bytes = 0
    for basename in ALLOWLIST:
        entry = _relocation_entry(
            legacy_archive_dir,
            archive_dir,
            basename,
            legacy_names,
            archive_names,
            "unsafe_or_missing_file",
        )
        selected_path = (
            archive_dir / basename
            if entry.archive_fingerprint is not None
            else legacy_archive_dir / basename
        )
        selected_fingerprint = (
            entry.archive_fingerprint
            if entry.archive_fingerprint is not None
            else entry.legacy_fingerprint
        )
        metadata = _regular_metadata(selected_path, "unsafe_or_missing_file")
        if _fingerprint(metadata) != selected_fingerprint:
            raise MigrationError("unsafe_or_changed_file")
        size, sha256 = _digest_regular(selected_path, metadata)
        total_bytes += size
        if total_bytes > MAX_TOTAL_BYTES:
            raise MigrationError("total_size_limit_exceeded")
        records.append(FileRecord(basename, size, sha256, _fingerprint(metadata)))
        entries.append(entry)

    receipt_entry = _relocation_entry(
        legacy_archive_dir,
        archive_dir,
        RECEIPT_BASENAME,
        legacy_names,
        archive_names,
        "unsafe_or_missing_receipt",
    )
    receipt_path = (
        archive_dir / RECEIPT_BASENAME
        if receipt_entry.archive_fingerprint is not None
        else legacy_archive_dir / RECEIPT_BASENAME
    )
    receipt_fingerprint = (
        receipt_entry.archive_fingerprint
        if receipt_entry.archive_fingerprint is not None
        else receipt_entry.legacy_fingerprint
    )
    receipt = _read_receipt(receipt_path)
    receipt_after = _regular_metadata(receipt_path, "unsafe_or_missing_receipt")
    if _fingerprint(receipt_after) != receipt_fingerprint:
        raise MigrationError("receipt_changed_during_verification")
    if receipt != _receipt(records):
        raise MigrationError("archive_receipt_mismatch")
    return records, entries, receipt_entry


def _complete_relocation_entry(
    legacy_archive_dir: Path,
    archive_dir: Path,
    entry: RelocationEntry,
) -> None:
    source = legacy_archive_dir / entry.basename
    target = archive_dir / entry.basename
    if entry.legacy_fingerprint is None:
        if _lexists(source):
            raise MigrationError("relocation_state_changed")
        target_metadata = _regular_metadata(target, "destination_changed_during_move")
        if _fingerprint(target_metadata) != entry.archive_fingerprint:
            raise MigrationError("destination_changed_during_move")
        return
    if entry.archive_fingerprint is None:
        _move_new(source, target, entry.legacy_fingerprint)
        return

    source_metadata = _regular_metadata(source, "source_changed_during_move")
    target_metadata = _regular_metadata(target, "destination_changed_during_move")
    if (
        _fingerprint(source_metadata) != entry.legacy_fingerprint
        or _fingerprint(target_metadata) != entry.archive_fingerprint
        or _identity(source_metadata) != _identity(target_metadata)
        or target_metadata.st_nlink < 2
    ):
        raise MigrationError("file_changed_during_move")
    try:
        source.unlink()
    except OSError as error:
        raise MigrationError("source_retire_failed") from error
    moved = _regular_metadata(target, "destination_changed_during_move")
    if (
        _identity(moved) != _identity(target_metadata)
        or moved.st_nlink != target_metadata.st_nlink - 1
    ):
        raise MigrationError("file_changed_during_move")


def _relocate_verified_archive(
    legacy_archive_dir: Path,
    archive_dir: Path,
    records: list[FileRecord],
    entries: list[RelocationEntry],
    receipt_entry: RelocationEntry,
) -> list[FileRecord]:
    _ensure_directory(archive_dir)
    for entry in entries:
        _complete_relocation_entry(legacy_archive_dir, archive_dir, entry)
    _complete_relocation_entry(legacy_archive_dir, archive_dir, receipt_entry)
    _sync_directory(legacy_archive_dir)
    _sync_directory(archive_dir)

    relocated_records, _receipt_fingerprint = _verified_archive(archive_dir)
    if _receipt(relocated_records) != _receipt(records):
        raise MigrationError("post_relocation_verification_failed")
    if _archive_entries(legacy_archive_dir):
        raise MigrationError("legacy_archive_cleanup_conflict")
    try:
        legacy_archive_dir.rmdir()
    except OSError as error:
        raise MigrationError("legacy_archive_cleanup_failed") from error
    _sync_directory(legacy_archive_dir.parent)
    return relocated_records


def migrate(
    raw_dir: Path,
    archive_dir: Path,
    legacy_archive_dir: Path,
) -> dict[str, str | int]:
    _require_directory(raw_dir, "unsafe_raw_directory")
    if archive_dir == legacy_archive_dir:
        raise MigrationError("archive_locations_conflict")

    archive_exists = _lexists(archive_dir)
    legacy_archive_exists = _lexists(legacy_archive_dir)
    archive_names = _archive_entries(archive_dir)
    legacy_archive_names = _archive_entries(legacy_archive_dir)
    source_presence = [_lexists(raw_dir / basename) for basename in ALLOWLIST]
    expected_archive_names = {*ALLOWLIST, RECEIPT_BASENAME}

    fresh = all(source_presence) and not archive_exists and not legacy_archive_exists
    archived = (
        not any(source_presence)
        and archive_names == expected_archive_names
        and not legacy_archive_exists
    )
    relocatable = (
        not any(source_presence)
        and legacy_archive_exists
        and archive_names | legacy_archive_names == expected_archive_names
    )
    if archived:
        records, _receipt_fingerprint = _verified_archive(archive_dir)
        return {"files": len(records), "status": "verified"}
    if relocatable:
        records, entries, receipt_entry = _verified_relocation(
            legacy_archive_dir,
            archive_dir,
            legacy_archive_names,
            archive_names,
        )
        relocated_records = _relocate_verified_archive(
            legacy_archive_dir,
            archive_dir,
            records,
            entries,
            receipt_entry,
        )
        return {"files": len(relocated_records), "status": "relocated"}
    if not fresh:
        raise MigrationError("incomplete_or_conflicting_state")

    records = _inventory(raw_dir)
    _ensure_directory(archive_dir)
    for record in records:
        _move_new(
            raw_dir / record.basename,
            archive_dir / record.basename,
            record.fingerprint,
        )
    _sync_directory(raw_dir)
    _sync_directory(archive_dir)
    archived_records = _inventory(archive_dir)
    if _receipt(archived_records) != _receipt(records):
        raise MigrationError("post_move_verification_failed")
    receipt_path = archive_dir / RECEIPT_BASENAME
    _write_receipt_new(receipt_path, _receipt(archived_records))
    return {"files": len(records), "status": "migrated"}


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument("--archive-dir", type=Path, default=DEFAULT_ARCHIVE_DIR)
    parser.add_argument(
        "--legacy-archive-dir", type=Path, default=DEFAULT_LEGACY_ARCHIVE_DIR
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        result = migrate(
            arguments.raw_dir,
            arguments.archive_dir,
            arguments.legacy_archive_dir,
        )
    except MigrationError as error:
        print(
            json.dumps({"error": str(error), "status": "error"}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
