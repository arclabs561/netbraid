#!/usr/bin/env python3
"""Compile bounded observation oracles for Zenodo record 6516954.

Only the 80 pinned filenames and transfer-integrity metadata are interpreted.
MAT payload bytes are hashed but are never parsed or deserialized.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mmap
import os
import re
import secrets
import stat
import sys
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.mmwave_jamming_observation_oracles.v0"
MANIFEST_SCHEMA = "netbraid.controlled_jamming_artifacts.v1"
RECEIPT_SCHEMA = "local.netbraid_controlled_jamming_artifact.v1"
SELECTED_RECORD_ID = 6_516_954

KIB = 1024
MIB = 1024 * KIB
MAX_MANIFEST_BYTES = 2 * MIB
MAX_RECEIPT_BYTES = 64 * KIB
MAX_SELECTED_ARTIFACT_BYTES = 32 * MIB
MAX_OUTPUT_BYTES = 2 * MIB
MAX_RAW_DIRECTORY_ENTRIES = 96
MAX_RECEIPT_DIRECTORY_ENTRIES = 96
READ_CHUNK_BYTES = MIB
MMAP_MIN_BYTES = 4 * MIB

TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "publisher",
        "expected_record_count",
        "expected_artifact_count",
        "expected_total_bytes",
        "records",
    }
)
RECORD_KEYS = frozenset(
    {
        "record_id",
        "api_url",
        "doi",
        "license",
        "license_id",
        "expected_artifact_count",
        "expected_total_bytes",
        "artifacts",
    }
)
ARTIFACT_KEYS = frozenset({"filename", "content_url", "bytes", "md5"})
RECEIPT_KEYS = frozenset({"schema", "source", "integrity"})
INTEGRITY_KEYS = frozenset({"bytes", "md5", "sha256"})

MD5_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
OPAQUE_ID_PATTERN = SHA256_PATTERN
FILENAME_PATTERN = re.compile(
    r"Receiver_(?P<receiver>[1-4])_"
    r"(?P<regime>SRR|USRR)_"
    r"(?P<condition>with|without)_jammer_"
    r"(?P<target>one_target|two_targets|three_targets|four_targets|five_targets)"
    r"\.mat\Z"
)

TARGET_COUNTS = {
    "one_target": 1,
    "two_targets": 2,
    "three_targets": 3,
    "four_targets": 4,
    "five_targets": 5,
}
RADAR_REGIMES = {
    "SRR": "short_range_radar",
    "USRR": "ultra_short_range_radar",
}
JAMMING_CAUSES = {
    "with": "controlled_jammer_present",
    "without": "controlled_jammer_absent",
}
REQUIRED_SPLIT_GROUPS = (
    "paired_cell_group",
    "receiver_group",
    "radar_regime_group",
    "radar_configuration_group",
    "target_count_group",
)
ABSTENTION_STATES = {
    "event": "not_observed",
    "session": "not_observed",
    "physical_source": "not_observed",
    "physical_device": "not_observed",
    "variant": "not_observed",
    "actor_identity": "not_observed",
    "tamper": "unsupported",
    "malicious_intent": "unsupported",
}


class OracleCompileError(RuntimeError):
    """Stable fail-closed rejection at an input, integrity, or output boundary."""


@dataclass(frozen=True, order=True)
class Cell:
    """The complete admissible meaning of one pinned filename."""

    receiver_element: int
    radar_regime: str
    controlled_jamming_cause: str
    target_count: int


@dataclass(frozen=True)
class ArtifactPin:
    """One validated manifest artifact and its parsed cell."""

    filename: str
    content_url: str
    byte_count: int
    md5: str
    cell: Cell

    def source(self) -> dict[str, Any]:
        return {
            "record_id": SELECTED_RECORD_ID,
            "doi": f"10.5281/zenodo.{SELECTED_RECORD_ID}",
            "license": "CC BY 4.0",
            "license_id": "cc-by-4.0",
            "filename": self.filename,
            "content_url": self.content_url,
            "bytes": self.byte_count,
            "md5": self.md5,
        }


@dataclass(frozen=True)
class RecordPin:
    """Order-independent semantic pin for one record in the tracked manifest."""

    record_id: int
    artifact_count: int
    total_bytes: int
    artifact_pinset_sha256: str


@dataclass(frozen=True)
class CatalogPins:
    """Exact aggregate and record pins expected from a manifest."""

    record_count: int
    artifact_count: int
    total_bytes: int
    records: tuple[RecordPin, ...]


@dataclass(frozen=True)
class FileIdentity:
    """Descriptor identity used to reject replacement or mutation during a read."""

    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


PRODUCTION_PINS = CatalogPins(
    record_count=2,
    artifact_count=112,
    total_bytes=119_191_308_440,
    records=(
        RecordPin(
            record_id=SELECTED_RECORD_ID,
            artifact_count=80,
            total_bytes=738_542_988,
            artifact_pinset_sha256=(
                "ea9a7ffb4d2eaa125001184995a49bc3eb2e621a08f22e4acecee499781f75c5"
            ),
        ),
        RecordPin(
            record_id=7_119_040,
            artifact_count=32,
            total_bytes=118_452_765_452,
            artifact_pinset_sha256=(
                "f14fe852a72a88f089fd70a5e6ffe4312d161f24a2e5615a4819cc9c3e157026"
            ),
        ),
    ),
)


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise OracleCompileError("duplicate_json_key")
        value[key] = item
    return value


def _identity(descriptor: int) -> FileIdentity:
    metadata = os.fstat(descriptor)
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _required_open_flags(*, directory: bool = False) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise OracleCompileError("platform_missing_no_follow")
    flags = os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0)
    if directory:
        directory_flag = getattr(os, "O_DIRECTORY", None)
        if directory_flag is None:
            raise OracleCompileError("platform_missing_directory_open")
        flags |= directory_flag
    else:
        flags |= getattr(os, "O_NONBLOCK", 0)
    return flags


def _open_directory(path: Path, error_code: str) -> int:
    try:
        descriptor = os.open(path, _required_open_flags(directory=True))
    except OSError as error:
        raise OracleCompileError(error_code) from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise OracleCompileError(error_code)
    return descriptor


def _open_or_create_directory(path: Path, error_code: str) -> int:
    """Walk and create a directory without following component symlinks."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if not parts or parts[0] != os.path.sep:
        raise OracleCompileError(error_code)
    try:
        descriptor = os.open(os.path.sep, _required_open_flags(directory=True))
    except OSError as error:
        raise OracleCompileError(error_code) from error
    try:
        for component in parts[1:]:
            if component in {"", ".", ".."}:
                raise OracleCompileError(error_code)
            try:
                os.mkdir(component, mode=0o700, dir_fd=descriptor)
            except FileExistsError:
                pass
            except OSError as error:
                raise OracleCompileError(error_code) from error
            try:
                child = os.open(
                    component,
                    _required_open_flags(directory=True),
                    dir_fd=descriptor,
                )
            except OSError as error:
                raise OracleCompileError(error_code) from error
            os.close(descriptor)
            descriptor = child
        return descriptor
    except OracleCompileError:
        os.close(descriptor)
        raise


def _read_descriptor(
    descriptor: int, before: FileIdentity, limit: int, error_code: str
) -> bytes:
    if before.size < 0 or before.size > limit:
        raise OracleCompileError(error_code)
    chunks: list[bytes] = []
    remaining = before.size
    try:
        while remaining:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, remaining))
            if not chunk:
                raise OracleCompileError(error_code)
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OracleCompileError(error_code)
    except OSError as error:
        raise OracleCompileError(error_code) from error
    if _identity(descriptor) != before:
        raise OracleCompileError(error_code)
    return b"".join(chunks)


def _read_json_path(path: Path, limit: int, error_code: str) -> Mapping[str, Any]:
    try:
        descriptor = os.open(path, _required_open_flags())
    except OSError as error:
        raise OracleCompileError(error_code) from error
    try:
        before = _identity(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OracleCompileError(error_code)
        payload = _read_descriptor(descriptor, before, limit, error_code)
    finally:
        os.close(descriptor)
    return _decode_json(payload, error_code)


def _read_json_at(
    directory_descriptor: int, filename: str, limit: int, error_code: str
) -> tuple[Mapping[str, Any], FileIdentity]:
    try:
        descriptor = os.open(
            filename,
            _required_open_flags(),
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        raise OracleCompileError(error_code) from error
    try:
        before = _identity(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OracleCompileError(error_code)
        payload = _read_descriptor(descriptor, before, limit, error_code)
    finally:
        os.close(descriptor)
    return _decode_json(payload, error_code), before


def _decode_json(payload: bytes, error_code: str) -> Mapping[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_strict_object)
    except OracleCompileError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OracleCompileError(error_code) from error
    if not isinstance(value, Mapping):
        raise OracleCompileError(error_code)
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], error_code: str
) -> None:
    if set(value) != expected:
        raise OracleCompileError(error_code)


def _positive_int(value: Any, error_code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise OracleCompileError(error_code)
    return value


def _safe_filename(value: Any) -> str:
    if not isinstance(value, str):
        raise OracleCompileError("invalid_artifact_filename")
    if (
        value in {"", ".", ".."}
        or value.startswith(".")
        or "/" in value
        or "\\" in value
        or len(value.encode("utf-8", errors="surrogatepass")) > 255
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(unicodedata.category(character) == "Cs" for character in value)
    ):
        raise OracleCompileError("invalid_artifact_filename")
    return value


def parse_cell(filename: str) -> Cell:
    """Parse exactly one of the 80 supported filename cells."""

    match = FILENAME_PATTERN.fullmatch(filename)
    if match is None:
        raise OracleCompileError("malformed_filename_cell")
    return Cell(
        receiver_element=int(match.group("receiver")),
        radar_regime=RADAR_REGIMES[match.group("regime")],
        controlled_jamming_cause=JAMMING_CAUSES[match.group("condition")],
        target_count=TARGET_COUNTS[match.group("target")],
    )


def expected_cells() -> frozenset[Cell]:
    """Return the exact Cartesian product admitted for record 6516954."""

    return frozenset(
        Cell(receiver, regime, condition, target_count)
        for receiver in range(1, 5)
        for regime in RADAR_REGIMES.values()
        for condition in JAMMING_CAUSES.values()
        for target_count in range(1, 6)
    )


def _validated_content_url(value: Any, record_id: int, filename: str) -> str:
    if not isinstance(value, str):
        raise OracleCompileError("invalid_content_url")
    parts = urlsplit(value)
    expected_path = f"/api/records/{record_id}/files/{quote(filename, safe='')}/content"
    if (
        parts.scheme != "https"
        or parts.netloc != "zenodo.org"
        or parts.path != expected_path
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise OracleCompileError("invalid_content_url")
    return value


def _artifact_pinset_digest(artifacts: Sequence[Mapping[str, Any]]) -> str:
    normalized = sorted(
        (dict(item) for item in artifacts), key=lambda item: item["filename"]
    )
    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (KeyError, TypeError, ValueError) as error:
        raise OracleCompileError("invalid_artifact_pinset") from error
    return hashlib.sha256(encoded).hexdigest()


def load_artifacts(
    manifest_path: Path, *, pins: CatalogPins = PRODUCTION_PINS
) -> tuple[ArtifactPin, ...]:
    """Strictly validate the manifest and return the selected 80 pins."""

    value = _read_json_path(
        manifest_path, MAX_MANIFEST_BYTES, "manifest_missing_or_unsafe"
    )
    _require_exact_keys(value, TOP_LEVEL_KEYS, "manifest_schema_drift")
    if value.get("schema") != MANIFEST_SCHEMA or value.get("publisher") != "Zenodo":
        raise OracleCompileError("unsupported_manifest_schema")
    if (
        value.get("expected_record_count") != pins.record_count
        or value.get("expected_artifact_count") != pins.artifact_count
        or value.get("expected_total_bytes") != pins.total_bytes
    ):
        raise OracleCompileError("manifest_aggregate_pin_mismatch")
    raw_records = value.get("records")
    if not isinstance(raw_records, list) or len(raw_records) != pins.record_count:
        raise OracleCompileError("manifest_record_count_mismatch")

    pin_by_record = {pin.record_id: pin for pin in pins.records}
    if (
        len(pin_by_record) != len(pins.records)
        or len(pin_by_record) != pins.record_count
    ):
        raise OracleCompileError("invalid_catalog_pins")
    seen_records: set[int] = set()
    seen_urls: set[str] = set()
    selected: list[ArtifactPin] = []
    total_artifacts = 0
    total_bytes = 0

    for raw_record in raw_records:
        if not isinstance(raw_record, Mapping):
            raise OracleCompileError("manifest_schema_drift")
        _require_exact_keys(raw_record, RECORD_KEYS, "manifest_schema_drift")
        record_id = _positive_int(
            raw_record.get("record_id"), "invalid_record_identity"
        )
        if record_id in seen_records:
            raise OracleCompileError("duplicate_record")
        seen_records.add(record_id)
        record_pin = pin_by_record.get(record_id)
        if record_pin is None:
            raise OracleCompileError("unexpected_record")
        if (
            raw_record.get("api_url") != f"https://zenodo.org/api/records/{record_id}"
            or raw_record.get("doi") != f"10.5281/zenodo.{record_id}"
            or raw_record.get("license") != "CC BY 4.0"
            or raw_record.get("license_id") != "cc-by-4.0"
        ):
            raise OracleCompileError("record_identity_pin_mismatch")
        if (
            raw_record.get("expected_artifact_count") != record_pin.artifact_count
            or raw_record.get("expected_total_bytes") != record_pin.total_bytes
        ):
            raise OracleCompileError("record_aggregate_pin_mismatch")
        raw_artifacts = raw_record.get("artifacts")
        if not isinstance(raw_artifacts, list):
            raise OracleCompileError("manifest_schema_drift")

        local_names: set[str] = set()
        record_bytes = 0
        for raw_artifact in raw_artifacts:
            if not isinstance(raw_artifact, Mapping):
                raise OracleCompileError("manifest_schema_drift")
            _require_exact_keys(raw_artifact, ARTIFACT_KEYS, "manifest_schema_drift")
            filename = _safe_filename(raw_artifact.get("filename"))
            local_name = filename.casefold()
            if local_name in local_names:
                raise OracleCompileError("duplicate_artifact_filename")
            local_names.add(local_name)
            content_url = _validated_content_url(
                raw_artifact.get("content_url"), record_id, filename
            )
            if content_url in seen_urls:
                raise OracleCompileError("duplicate_content_url")
            seen_urls.add(content_url)
            byte_count = _positive_int(
                raw_artifact.get("bytes"), "invalid_artifact_bytes"
            )
            md5 = raw_artifact.get("md5")
            if not isinstance(md5, str) or MD5_PATTERN.fullmatch(md5) is None:
                raise OracleCompileError("invalid_artifact_md5")
            record_bytes += byte_count
            if record_id == SELECTED_RECORD_ID:
                if byte_count > MAX_SELECTED_ARTIFACT_BYTES:
                    raise OracleCompileError("selected_artifact_size_limit")
                selected.append(
                    ArtifactPin(
                        filename=filename,
                        content_url=content_url,
                        byte_count=byte_count,
                        md5=md5,
                        cell=parse_cell(filename),
                    )
                )
        if (
            len(raw_artifacts) != record_pin.artifact_count
            or record_bytes != record_pin.total_bytes
        ):
            raise OracleCompileError("record_artifact_pin_mismatch")
        if _artifact_pinset_digest(raw_artifacts) != record_pin.artifact_pinset_sha256:
            raise OracleCompileError("record_artifact_pinset_mismatch")
        total_artifacts += len(raw_artifacts)
        total_bytes += record_bytes

    if seen_records != set(pin_by_record):
        raise OracleCompileError("missing_record")
    if total_artifacts != pins.artifact_count or total_bytes != pins.total_bytes:
        raise OracleCompileError("manifest_aggregate_pin_mismatch")
    cells = [artifact.cell for artifact in selected]
    if len(cells) != 80:
        raise OracleCompileError("selected_artifact_count_mismatch")
    if len(set(cells)) != len(cells):
        raise OracleCompileError("duplicate_filename_cell")
    if set(cells) != expected_cells():
        raise OracleCompileError("missing_filename_cell")
    return tuple(sorted(selected, key=lambda artifact: artifact.cell))


def _directory_names(
    directory_descriptor: int, limit: int, error_code: str
) -> frozenset[str]:
    names: list[str] = []
    try:
        with os.scandir(directory_descriptor) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > limit:
                    raise OracleCompileError(error_code)
    except OSError as error:
        raise OracleCompileError(error_code) from error
    if len(set(names)) != len(names):
        raise OracleCompileError(error_code)
    return frozenset(names)


def _stream_digest(descriptor: int) -> tuple[str, str]:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        md5 = hashlib.md5(usedforsecurity=False)
        sha256 = hashlib.sha256()
        while chunk := os.read(descriptor, READ_CHUNK_BYTES):
            md5.update(chunk)
            sha256.update(chunk)
    except OSError as error:
        raise OracleCompileError("artifact_read_failed") from error
    return md5.hexdigest(), sha256.hexdigest()


def _digest_artifact(
    descriptor: int,
    before: FileIdentity,
    *,
    mmap_min_bytes: int = MMAP_MIN_BYTES,
) -> tuple[str, str]:
    if (
        isinstance(mmap_min_bytes, bool)
        or not isinstance(mmap_min_bytes, int)
        or mmap_min_bytes < 0
    ):
        raise OracleCompileError("invalid_mmap_threshold")
    digests: tuple[str, str] | None = None
    if before.size >= mmap_min_bytes and before.size > 0:
        try:
            with mmap.mmap(descriptor, 0, access=mmap.ACCESS_READ) as mapped:
                md5 = hashlib.md5(usedforsecurity=False)
                sha256 = hashlib.sha256()
                md5.update(mapped)
                sha256.update(mapped)
                digests = (md5.hexdigest(), sha256.hexdigest())
        except (OSError, ValueError):
            digests = None
        except (MemoryError, OverflowError) as error:
            raise OracleCompileError("artifact_mmap_resource_limit") from error
    if digests is None:
        digests = _stream_digest(descriptor)
    if _identity(descriptor) != before:
        raise OracleCompileError("artifact_changed_during_verification")
    return digests


def _open_artifact_at(
    directory_descriptor: int, artifact: ArtifactPin
) -> tuple[int, FileIdentity]:
    try:
        descriptor = os.open(
            artifact.filename,
            _required_open_flags(),
            dir_fd=directory_descriptor,
        )
    except OSError as error:
        raise OracleCompileError("artifact_missing_or_unsafe") from error
    before = _identity(descriptor)
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or before.size != artifact.byte_count
        or before.size > MAX_SELECTED_ARTIFACT_BYTES
    ):
        os.close(descriptor)
        raise OracleCompileError("artifact_size_or_type_mismatch")
    return descriptor, before


def _expected_receipt(artifact: ArtifactPin, sha256: str) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "source": artifact.source(),
        "integrity": {
            "bytes": artifact.byte_count,
            "md5": artifact.md5,
            "sha256": sha256,
        },
    }


def _validate_receipt(
    receipt: Mapping[str, Any], artifact: ArtifactPin, sha256: str
) -> None:
    _require_exact_keys(receipt, RECEIPT_KEYS, "receipt_schema_drift")
    source = receipt.get("source")
    integrity = receipt.get("integrity")
    if not isinstance(source, Mapping) or not isinstance(integrity, Mapping):
        raise OracleCompileError("receipt_schema_drift")
    _require_exact_keys(source, frozenset(artifact.source()), "receipt_schema_drift")
    _require_exact_keys(integrity, INTEGRITY_KEYS, "receipt_schema_drift")
    receipt_sha256 = integrity.get("sha256")
    if (
        not isinstance(receipt_sha256, str)
        or SHA256_PATTERN.fullmatch(receipt_sha256) is None
    ):
        raise OracleCompileError("invalid_receipt_sha256")
    if receipt != _expected_receipt(artifact, sha256):
        raise OracleCompileError("local_receipt_verification_failed")


def admit_artifacts(
    artifacts: Sequence[ArtifactPin],
    raw_dir: Path,
    receipt_dir: Path,
    *,
    mmap_min_bytes: int = MMAP_MIN_BYTES,
) -> tuple[Cell, ...]:
    """Admit all and only exact regular files with exact local receipts."""

    expected_names = frozenset(artifact.filename for artifact in artifacts)
    expected_receipts = frozenset(f"{name}.json" for name in expected_names)
    if len(expected_names) != 80 or len(expected_receipts) != 80:
        raise OracleCompileError("artifact_name_collision")
    raw_descriptor = _open_directory(raw_dir, "raw_directory_missing_or_unsafe")
    try:
        receipt_descriptor = _open_directory(
            receipt_dir, "receipt_directory_missing_or_unsafe"
        )
    except OracleCompileError:
        os.close(raw_descriptor)
        raise
    try:
        if (
            _directory_names(
                raw_descriptor,
                MAX_RAW_DIRECTORY_ENTRIES,
                "raw_directory_entry_limit",
            )
            != expected_names
        ):
            raise OracleCompileError("raw_directory_cell_mismatch")
        if (
            _directory_names(
                receipt_descriptor,
                MAX_RECEIPT_DIRECTORY_ENTRIES,
                "receipt_directory_entry_limit",
            )
            != expected_receipts
        ):
            raise OracleCompileError("receipt_directory_cell_mismatch")

        artifact_identities: set[tuple[int, int]] = set()
        receipt_identities: set[tuple[int, int]] = set()
        admitted: list[Cell] = []
        for artifact in sorted(artifacts, key=lambda item: item.cell):
            descriptor, before = _open_artifact_at(raw_descriptor, artifact)
            try:
                identity_key = (before.device, before.inode)
                if identity_key in artifact_identities:
                    raise OracleCompileError("artifact_file_collision")
                artifact_identities.add(identity_key)
                md5, sha256 = _digest_artifact(
                    descriptor, before, mmap_min_bytes=mmap_min_bytes
                )
            finally:
                os.close(descriptor)
            if md5 != artifact.md5:
                raise OracleCompileError("artifact_md5_mismatch")
            receipt, receipt_identity = _read_json_at(
                receipt_descriptor,
                f"{artifact.filename}.json",
                MAX_RECEIPT_BYTES,
                "receipt_missing_or_unsafe",
            )
            receipt_identity_key = (receipt_identity.device, receipt_identity.inode)
            if receipt_identity_key in receipt_identities:
                raise OracleCompileError("receipt_file_collision")
            receipt_identities.add(receipt_identity_key)
            _validate_receipt(receipt, artifact, sha256)
            admitted.append(artifact.cell)
        if (
            _directory_names(
                raw_descriptor,
                MAX_RAW_DIRECTORY_ENTRIES,
                "raw_directory_entry_limit",
            )
            != expected_names
        ):
            raise OracleCompileError("raw_directory_changed_during_admission")
        if (
            _directory_names(
                receipt_descriptor,
                MAX_RECEIPT_DIRECTORY_ENTRIES,
                "receipt_directory_entry_limit",
            )
            != expected_receipts
        ):
            raise OracleCompileError("receipt_directory_changed_during_admission")
    finally:
        os.close(receipt_descriptor)
        os.close(raw_descriptor)
    if tuple(admitted) != tuple(sorted(expected_cells())):
        raise OracleCompileError("admitted_cell_mismatch")
    return tuple(admitted)


def _opaque_id(domain: str, *components: object) -> str:
    digest = hashlib.sha256()
    namespace = b"netbraid.mmwave-jamming-oracle-id.v0"
    digest.update(len(namespace).to_bytes(4, "big"))
    digest.update(namespace)
    domain_bytes = domain.encode("utf-8")
    digest.update(len(domain_bytes).to_bytes(4, "big"))
    digest.update(domain_bytes)
    for component in components:
        if isinstance(component, bool):
            raise OracleCompileError("unsupported_id_component")
        if isinstance(component, int):
            if component < 0:
                raise OracleCompileError("unsupported_id_component")
            payload = b"i" + component.to_bytes(8, "big")
        elif isinstance(component, str):
            payload = b"s" + component.encode("utf-8")
        else:
            raise OracleCompileError("unsupported_id_component")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


class OpaqueIdentifiers:
    """Issue reusable namespace-separated IDs while rejecting collisions."""

    def __init__(self) -> None:
        self._claims: dict[str, tuple[str, tuple[object, ...]]] = {}

    def issue(self, domain: str, *components: object) -> str:
        identifier = _opaque_id(domain, *components)
        if OPAQUE_ID_PATTERN.fullmatch(identifier) is None:
            raise OracleCompileError("invalid_generated_opaque_id")
        claim = (domain, components)
        previous = self._claims.get(identifier)
        if previous is not None and previous != claim:
            raise OracleCompileError("opaque_id_collision")
        self._claims[identifier] = claim
        return identifier


def _known(group_id: str) -> dict[str, str]:
    return {"state": "known", "group_id": group_id}


def _abstention(state: str) -> dict[str, str]:
    if state not in {"not_observed", "unsupported"}:
        raise OracleCompileError("invalid_abstention_state")
    return {"state": state}


def build_inventory(cells: Sequence[Cell], total_bytes: int) -> dict[str, Any]:
    """Build deterministic opaque records from the admitted filename cells."""

    ordered = tuple(sorted(cells))
    if ordered != tuple(sorted(expected_cells())):
        raise OracleCompileError("inventory_cell_mismatch")
    identifiers = OpaqueIdentifiers()
    observations: list[dict[str, Any]] = []
    pair_members: dict[str, set[str]] = defaultdict(set)
    receiver_groups: set[str] = set()
    regime_groups: set[str] = set()
    configuration_groups: set[str] = set()
    target_groups: set[str] = set()

    for cell in ordered:
        observation_id = identifiers.issue(
            "observation",
            cell.receiver_element,
            cell.radar_regime,
            cell.controlled_jamming_cause,
            cell.target_count,
        )
        receiver_group = identifiers.issue("receiver", cell.receiver_element)
        regime_group = identifiers.issue("radar_regime", cell.radar_regime)
        configuration_group = identifiers.issue(
            "radar_configuration", cell.receiver_element, cell.radar_regime
        )
        target_group = identifiers.issue("target_count", cell.target_count)
        pair_group = identifiers.issue(
            "paired_cell",
            cell.receiver_element,
            cell.radar_regime,
            cell.target_count,
        )
        receiver_groups.add(receiver_group)
        regime_groups.add(regime_group)
        configuration_groups.add(configuration_group)
        target_groups.add(target_group)
        pair_members[pair_group].add(cell.controlled_jamming_cause)
        observation = {
            "observation_id": observation_id,
            "receiver_element": cell.receiver_element,
            "radar_regime": cell.radar_regime,
            "radar_configuration": {
                "receiver_element": cell.receiver_element,
                "radar_regime": cell.radar_regime,
            },
            "controlled_jamming_cause": cell.controlled_jamming_cause,
            "target_count": cell.target_count,
            "receiver_group": _known(receiver_group),
            "radar_regime_group": _known(regime_group),
            "radar_configuration_group": _known(configuration_group),
            "target_count_group": _known(target_group),
            "paired_cell_group": _known(pair_group),
            **{axis: _abstention(state) for axis, state in ABSTENTION_STATES.items()},
        }
        observations.append(observation)

    expected_causes = set(JAMMING_CAUSES.values())
    if len(pair_members) != 40 or any(
        causes != expected_causes for causes in pair_members.values()
    ):
        raise OracleCompileError("unsafe_paired_cell_grouping")
    observation_ids = {item["observation_id"] for item in observations}
    if len(observation_ids) != 80:
        raise OracleCompileError("observation_id_collision")
    if (
        len(receiver_groups) != 4
        or len(regime_groups) != 2
        or len(configuration_groups) != 8
        or len(target_groups) != 5
    ):
        raise OracleCompileError("split_group_collision")

    condition_counts = Counter(
        item["controlled_jamming_cause"] for item in observations
    )
    axis_states = {
        axis: {
            "not_observed": 80 if state == "not_observed" else 0,
            "unsupported": 80 if state == "unsupported" else 0,
        }
        for axis, state in ABSTENTION_STATES.items()
    }
    inventory = {
        "schema": SCHEMA,
        "inventory_id": identifiers.issue(
            "inventory", *(item["observation_id"] for item in observations)
        ),
        "status": "pass",
        "provenance": {
            "publisher": "Zenodo",
            "record_id": SELECTED_RECORD_ID,
            "doi": f"10.5281/zenodo.{SELECTED_RECORD_ID}",
            "manifest_schema": MANIFEST_SCHEMA,
            "receipt_schema": RECEIPT_SCHEMA,
            "admission": "exact_size_md5_sha256_and_local_receipt",
        },
        "assignment": {
            "partitions_assigned": 0,
            "train_test_assignment": "not_assigned",
        },
        "required_split_groups": list(REQUIRED_SPLIT_GROUPS),
        "counts": {
            "observations": 80,
            "paired_cells": 40,
            "members_per_paired_cell": 2,
            "receiver_elements": 4,
            "radar_regimes": 2,
            "radar_configurations": 8,
            "target_counts": 5,
            "controlled_jamming_causes": {
                cause: condition_counts[cause] for cause in sorted(expected_causes)
            },
            "axis_states": axis_states,
        },
        "privacy": {
            "absolute_paths_retained": 0,
            "relative_paths_retained": 0,
            "filenames_retained": 0,
            "source_urls_retained": 0,
            "digests_retained": 0,
            "mat_payloads_parsed": 0,
            "mat_payloads_deserialized": 0,
            "mat_payload_bytes_interpreted": 0,
            "integrity_bytes_hashed": total_bytes,
        },
        "observations": observations,
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


def compile_inventory(
    manifest_path: Path,
    raw_dir: Path,
    receipt_dir: Path,
    *,
    pins: CatalogPins = PRODUCTION_PINS,
    mmap_min_bytes: int = MMAP_MIN_BYTES,
) -> dict[str, Any]:
    """Compile the inventory after complete manifest, file, and receipt admission."""

    artifacts = load_artifacts(manifest_path, pins=pins)
    cells = admit_artifacts(
        artifacts,
        raw_dir,
        receipt_dir,
        mmap_min_bytes=mmap_min_bytes,
    )
    inventory = build_inventory(cells, sum(item.byte_count for item in artifacts))
    encoded = render_inventory(inventory).decode("ascii")
    forbidden = [
        *(item.filename for item in artifacts),
        os.path.abspath(os.fspath(manifest_path)),
        os.path.abspath(os.fspath(raw_dir)),
        os.path.abspath(os.fspath(receipt_dir)),
    ]
    if any(value and value in encoded for value in forbidden):
        raise OracleCompileError("private_source_value_retained")
    return inventory


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    written = 0
    try:
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OracleCompileError("output_write_failed")
            written += count
    except OSError as error:
        raise OracleCompileError("output_write_failed") from error


def write_inventory(path: Path, inventory: Mapping[str, Any]) -> None:
    """Atomically write a bounded inventory without following output symlinks."""

    encoded = render_inventory(inventory)
    if path.name in {"", ".", ".."} or path.name.startswith("."):
        raise OracleCompileError("unsafe_output_path")
    parent_descriptor = _open_or_create_directory(
        path.parent, "unsafe_output_directory"
    )
    temporary_name: str | None = None
    try:
        try:
            existing = os.stat(
                path.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
        except FileNotFoundError:
            existing = None
        except OSError as error:
            raise OracleCompileError("unsafe_output_path") from error
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise OracleCompileError("unsafe_output_path")
        for _ in range(16):
            candidate = f".{path.name}.{secrets.token_hex(8)}"
            try:
                descriptor = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _required_open_flags(),
                    0o600,
                    dir_fd=parent_descriptor,
                )
            except FileExistsError:
                continue
            except OSError as error:
                raise OracleCompileError("output_temp_create_failed") from error
            temporary_name = candidate
            break
        else:
            raise OracleCompileError("output_temp_collision_limit")
        try:
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(
            temporary_name,
            path.name,
            src_dir_fd=parent_descriptor,
            dst_dir_fd=parent_descriptor,
        )
        temporary_name = None
        os.fsync(parent_descriptor)
    except OSError as error:
        raise OracleCompileError("output_replace_failed") from error
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
        os.close(parent_descriptor)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=(ROOT / "data" / "catalog" / "controlled-jamming-artifacts-v1.json"),
        help="tracked exact Zenodo artifact manifest",
    )
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=(
            ROOT / "data" / "raw" / "controlled-jamming" / str(SELECTED_RECORD_ID)
        ),
        help="ignored directory containing exactly the 80 pinned MAT files",
    )
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=(
            ROOT / "data" / "receipts" / "controlled-jamming" / str(SELECTED_RECORD_ID)
        ),
        help="ignored directory containing the 80 local SHA-256 receipts",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=(
            ROOT
            / "data"
            / "derived"
            / "eval"
            / "mmwave-jamming-observation-oracles.json"
        ),
        help="ignored deterministic oracle output",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        inventory = compile_inventory(
            arguments.manifest,
            arguments.raw_dir,
            arguments.receipt_dir,
        )
        write_inventory(arguments.output, inventory)
    except OracleCompileError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "inventory_id": inventory["inventory_id"],
                "observations": inventory["counts"]["observations"],
                "paired_cells": inventory["counts"]["paired_cells"],
                "status": "pass",
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
