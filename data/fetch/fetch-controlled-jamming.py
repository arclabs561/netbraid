#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["truststore==0.10.4"]
# ///

"""Fetch exact pinned controlled-scenario Zenodo artifacts.

The tracked manifest is the acquisition boundary. This tool lists it, verifies
ignored local files, or downloads one complete record (or both records)
without extracting or deserializing any payload.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import stat
import sys
import tempfile
import unicodedata
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import truststore

REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    REPOSITORY / "data" / "catalog" / "controlled-jamming-artifacts-v1.json"
)
DEFAULT_RAW_DIR = REPOSITORY / "data" / "raw" / "controlled-jamming"
DEFAULT_RECEIPT_DIR = REPOSITORY / "data" / "receipts" / "controlled-jamming"
MANIFEST_SCHEMA = "netbraid.controlled_jamming_artifacts.v1"
RECEIPT_SCHEMA = "local.netbraid_controlled_jamming_artifact.v1"
MANIFEST_BYTE_LIMIT = 2 * 1024 * 1024
RECEIPT_BYTE_LIMIT = 64 * 1024
CHUNK_BYTES = 4 * 1024 * 1024
DEFAULT_WORKERS = 2
MAX_WORKERS = 8
DEFAULT_MAX_TOTAL_BYTES = 128 * 1024**3
DEFAULT_MAX_FILE_BYTES = 8 * 1024**3
DOWNLOAD_TIMEOUT_SECONDS = 120
MD5 = re.compile(r"[0-9a-f]{32}\Z")
CONTENT_RANGE = re.compile(
    r"bytes (?P<start>[0-9]+)-(?P<end>[0-9]+)/(?P<total>[0-9]+)\Z"
)
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


class FetchError(RuntimeError):
    """Stable failure at a manifest, network, or local-integrity boundary."""


@dataclass(frozen=True)
class Artifact:
    """One exact artifact pin inherited from a validated record."""

    record_id: int
    doi: str
    license: str
    license_id: str
    filename: str
    content_url: str
    bytes: int
    md5: str

    def source(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "doi": self.doi,
            "license": self.license,
            "license_id": self.license_id,
            "filename": self.filename,
            "content_url": self.content_url,
            "bytes": self.bytes,
            "md5": self.md5,
        }


@dataclass(frozen=True)
class Record:
    """A validated Zenodo record and all of its pinned artifacts."""

    record_id: int
    api_url: str
    doi: str
    license: str
    license_id: str
    expected_artifact_count: int
    expected_total_bytes: int
    artifacts: tuple[Artifact, ...]

    def listing(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "api_url": self.api_url,
            "doi": self.doi,
            "license": self.license,
            "license_id": self.license_id,
            "expected_artifact_count": self.expected_artifact_count,
            "expected_total_bytes": self.expected_total_bytes,
            "artifacts": [
                {
                    "filename": artifact.filename,
                    "content_url": artifact.content_url,
                    "bytes": artifact.bytes,
                    "md5": artifact.md5,
                }
                for artifact in self.artifacts
            ],
        }


@dataclass(frozen=True)
class Catalog:
    """A strictly parsed artifact catalog."""

    publisher: str
    expected_record_count: int
    expected_artifact_count: int
    expected_total_bytes: int
    records: tuple[Record, ...]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise FetchError("duplicate_json_key")
        value[key] = item
    return value


def _read_regular_bytes(path: Path, limit: int, error_code: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FetchError(error_code) from error
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise FetchError(error_code)
        payload = source.read(limit + 1)
        after = os.fstat(source.fileno())
    if len(payload) > limit or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise FetchError(error_code)
    return payload


def _load_json(path: Path, limit: int, error_code: str) -> Mapping[str, Any]:
    payload = _read_regular_bytes(path, limit, error_code)
    try:
        value = json.loads(payload, object_pairs_hook=_strict_object)
    except FetchError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FetchError(error_code) from error
    if not isinstance(value, Mapping):
        raise FetchError(error_code)
    return value


def _require_exact_keys(
    value: Mapping[str, Any], expected: frozenset[str], error_code: str
) -> None:
    if set(value) != expected:
        raise FetchError(error_code)


def _positive_int(value: Any, error_code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise FetchError(error_code)
    return value


def _safe_filename(value: Any) -> str:
    if not isinstance(value, str):
        raise FetchError("invalid_artifact_filename")
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
        raise FetchError("invalid_artifact_filename")
    return value


def _content_url(
    value: Any,
    record_id: int,
    filename: str,
    *,
    allow_loopback_http: bool,
) -> str:
    if not isinstance(value, str):
        raise FetchError("invalid_content_url")
    parts = urlsplit(value)
    expected_path = f"/api/records/{record_id}/files/{quote(filename, safe='')}/content"
    zenodo = (
        parts.scheme == "https"
        and parts.netloc == "zenodo.org"
        and parts.path == expected_path
    )
    loopback = (
        allow_loopback_http
        and parts.scheme == "http"
        and parts.hostname in {"127.0.0.1", "::1", "localhost"}
        and parts.port is not None
        and parts.path == expected_path
    )
    if (
        not (zenodo or loopback)
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
    ):
        raise FetchError("invalid_content_url")
    return value


def load_catalog(
    path: Path = DEFAULT_MANIFEST, *, allow_loopback_http: bool = False
) -> Catalog:
    """Load a catalog while rejecting duplicate keys and all schema drift."""

    value = _load_json(path, MANIFEST_BYTE_LIMIT, "invalid_manifest")
    _require_exact_keys(value, TOP_LEVEL_KEYS, "manifest_schema_drift")
    if value.get("schema") != MANIFEST_SCHEMA or value.get("publisher") != "Zenodo":
        raise FetchError("manifest_schema_drift")
    expected_record_count = _positive_int(
        value.get("expected_record_count"), "invalid_manifest_aggregates"
    )
    expected_artifact_count = _positive_int(
        value.get("expected_artifact_count"), "invalid_manifest_aggregates"
    )
    expected_total_bytes = _positive_int(
        value.get("expected_total_bytes"), "invalid_manifest_aggregates"
    )
    raw_records = value.get("records")
    if not isinstance(raw_records, list):
        raise FetchError("manifest_schema_drift")

    records: list[Record] = []
    record_ids: set[int] = set()
    content_urls: set[str] = set()
    for raw_record in raw_records:
        if not isinstance(raw_record, Mapping):
            raise FetchError("manifest_schema_drift")
        _require_exact_keys(raw_record, RECORD_KEYS, "manifest_schema_drift")
        record_id = _positive_int(
            raw_record.get("record_id"), "invalid_record_identity"
        )
        if record_id in record_ids:
            raise FetchError("duplicate_record")
        record_ids.add(record_id)
        api_url = raw_record.get("api_url")
        doi = raw_record.get("doi")
        license_name = raw_record.get("license")
        license_id = raw_record.get("license_id")
        if (
            api_url != f"https://zenodo.org/api/records/{record_id}"
            or doi != f"10.5281/zenodo.{record_id}"
            or license_name != "CC BY 4.0"
            or license_id != "cc-by-4.0"
        ):
            raise FetchError("invalid_record_identity")
        record_artifact_count = _positive_int(
            raw_record.get("expected_artifact_count"),
            "invalid_record_aggregates",
        )
        record_total_bytes = _positive_int(
            raw_record.get("expected_total_bytes"), "invalid_record_aggregates"
        )
        raw_artifacts = raw_record.get("artifacts")
        if not isinstance(raw_artifacts, list):
            raise FetchError("manifest_schema_drift")

        artifacts: list[Artifact] = []
        local_names: set[str] = set()
        for raw_artifact in raw_artifacts:
            if not isinstance(raw_artifact, Mapping):
                raise FetchError("manifest_schema_drift")
            _require_exact_keys(raw_artifact, ARTIFACT_KEYS, "manifest_schema_drift")
            filename = _safe_filename(raw_artifact.get("filename"))
            local_name = unicodedata.normalize("NFC", filename).casefold()
            if local_name in local_names:
                raise FetchError("duplicate_artifact_filename")
            local_names.add(local_name)
            content_url = _content_url(
                raw_artifact.get("content_url"),
                record_id,
                filename,
                allow_loopback_http=allow_loopback_http,
            )
            if content_url in content_urls:
                raise FetchError("duplicate_content_url")
            content_urls.add(content_url)
            artifact_bytes = _positive_int(
                raw_artifact.get("bytes"), "invalid_artifact_bytes"
            )
            md5 = raw_artifact.get("md5")
            if not isinstance(md5, str) or MD5.fullmatch(md5) is None:
                raise FetchError("invalid_artifact_md5")
            artifacts.append(
                Artifact(
                    record_id=record_id,
                    doi=doi,
                    license=license_name,
                    license_id=license_id,
                    filename=filename,
                    content_url=content_url,
                    bytes=artifact_bytes,
                    md5=md5,
                )
            )
        if [item.filename for item in artifacts] != sorted(
            item.filename for item in artifacts
        ):
            raise FetchError("artifacts_not_sorted")
        if (
            len(artifacts) != record_artifact_count
            or sum(item.bytes for item in artifacts) != record_total_bytes
        ):
            raise FetchError("invalid_record_aggregates")
        records.append(
            Record(
                record_id=record_id,
                api_url=api_url,
                doi=doi,
                license=license_name,
                license_id=license_id,
                expected_artifact_count=record_artifact_count,
                expected_total_bytes=record_total_bytes,
                artifacts=tuple(artifacts),
            )
        )
    if [record.record_id for record in records] != sorted(
        record.record_id for record in records
    ):
        raise FetchError("records_not_sorted")
    if (
        len(records) != expected_record_count
        or sum(len(record.artifacts) for record in records) != expected_artifact_count
        or sum(artifact.bytes for record in records for artifact in record.artifacts)
        != expected_total_bytes
    ):
        raise FetchError("invalid_manifest_aggregates")
    return Catalog(
        publisher="Zenodo",
        expected_record_count=expected_record_count,
        expected_artifact_count=expected_artifact_count,
        expected_total_bytes=expected_total_bytes,
        records=tuple(records),
    )


def _select(catalog: Catalog, selection: str) -> tuple[Record, ...]:
    if selection == "all":
        return catalog.records
    try:
        record_id = int(selection)
    except ValueError as error:
        raise FetchError("unknown_record") from error
    selected = tuple(
        record for record in catalog.records if record.record_id == record_id
    )
    if not selected:
        raise FetchError("unknown_record")
    return selected


def _artifacts(records: Sequence[Record]) -> tuple[Artifact, ...]:
    return tuple(artifact for record in records for artifact in record.artifacts)


def _ensure_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = path.lstat()
    except OSError as error:
        raise FetchError("unsafe_local_directory") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise FetchError("unsafe_local_directory")


def _paths(
    artifact: Artifact, raw_dir: Path, receipt_dir: Path
) -> tuple[Path, Path, Path]:
    record_name = str(artifact.record_id)
    target = raw_dir / record_name / artifact.filename
    partial = target.with_name(f".{target.name}.part")
    receipt = receipt_dir / record_name / f"{artifact.filename}.json"
    return target, partial, receipt


def _digest_regular(path: Path) -> tuple[int, str, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FetchError("unsafe_local_file") from error
    size = 0
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise FetchError("unsafe_local_file")
        while chunk := source.read(CHUNK_BYTES):
            size += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
        after = os.fstat(source.fileno())
    if size != before.st_size or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise FetchError("local_file_changed_during_verification")
    return size, md5.hexdigest(), sha256.hexdigest()


def _receipt(artifact: Artifact, sha256: str) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "source": artifact.source(),
        "integrity": {
            "bytes": artifact.bytes,
            "md5": artifact.md5,
            "sha256": sha256,
        },
    }


def _read_receipt(path: Path) -> Mapping[str, Any]:
    return _load_json(path, RECEIPT_BYTE_LIMIT, "receipt_missing_or_unsafe")


def _write_receipt(path: Path, value: Mapping[str, Any]) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise FetchError("receipt_appeared_during_download") from error
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary)


def _verify_existing(
    target: Path,
    receipt_path: Path,
    artifact: Artifact,
    *,
    create_missing_receipt: bool,
) -> str:
    size, md5, sha256 = _digest_regular(target)
    if size != artifact.bytes:
        raise FetchError("artifact_size_mismatch")
    if md5 != artifact.md5:
        raise FetchError("artifact_md5_mismatch")
    expected = _receipt(artifact, sha256)
    if not os.path.lexists(receipt_path):
        if not create_missing_receipt:
            raise FetchError("receipt_missing_or_unsafe")
        _write_receipt(receipt_path, expected)
        return sha256
    if _read_receipt(receipt_path) != expected:
        raise FetchError("local_receipt_verification_failed")
    return sha256


def _partial_state(partial: Path, expected_bytes: int) -> tuple[bool, int, Any, Any]:
    if not os.path.lexists(partial):
        return (
            False,
            0,
            hashlib.md5(usedforsecurity=False),
            hashlib.sha256(),
        )
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(partial, flags)
    except OSError as error:
        raise FetchError("unsafe_partial_file") from error
    size = 0
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > expected_bytes:
            raise FetchError("invalid_partial_size")
        while chunk := source.read(CHUNK_BYTES):
            size += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
        after = os.fstat(source.fileno())
    if size != before.st_size or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise FetchError("partial_changed_during_verification")
    return True, size, md5, sha256


def _finalize(
    partial: Path,
    target: Path,
    receipt_path: Path,
    artifact: Artifact,
    size: int,
    md5: Any,
    sha256: Any,
) -> None:
    if size != artifact.bytes:
        raise FetchError("download_incomplete")
    if md5.hexdigest() != artifact.md5:
        raise FetchError("artifact_md5_mismatch")
    try:
        os.link(partial, target, follow_symlinks=False)
    except FileExistsError as error:
        raise FetchError("target_appeared_during_download") from error
    os.unlink(partial)
    _write_receipt(receipt_path, _receipt(artifact, sha256.hexdigest()))


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise FetchError("redirect_rejected")


def _ssl_context() -> ssl.SSLContext:
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cert_file = os.environ.get("SSL_CERT_FILE")
    cert_dir = os.environ.get("SSL_CERT_DIR")
    if cert_file or cert_dir:
        context.load_verify_locations(cafile=cert_file, capath=cert_dir)
    return context


def _open(request: urllib.request.Request, *, timeout: int) -> Any:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(),
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=_ssl_context()),
        _RejectRedirects(),
    )
    return opener.open(request, timeout=timeout)  # noqa: S310


def _request(artifact: Artifact, offset: int) -> urllib.request.Request:
    headers = {
        "Accept-Encoding": "identity",
        "User-Agent": "netbraid-controlled-jamming-fetcher/1",
    }
    if offset:
        headers["Range"] = f"bytes={offset}-"
    return urllib.request.Request(  # noqa: S310
        artifact.content_url,
        headers=headers,
        method="GET",
    )


def _status_code(response: Any) -> int | None:
    status_code = getattr(response, "status", None)
    if status_code is None and hasattr(response, "getcode"):
        status_code = response.getcode()
    return status_code


def _header(response: Any, name: str) -> str | None:
    value = response.headers.get(name)
    return None if value is None else str(value).strip()


def _content_length(response: Any) -> int:
    value = _header(response, "Content-Length")
    if value is None or not value.isascii() or not value.isdigit():
        raise FetchError("missing_or_invalid_content_length")
    return int(value)


def _validate_response(response: Any, artifact: Artifact, offset: int) -> None:
    if not hasattr(response, "geturl") or response.geturl() != artifact.content_url:
        raise FetchError("response_url_mismatch")
    remaining = artifact.bytes - offset
    if offset == 0:
        if _status_code(response) != 200:
            raise FetchError("full_download_requires_http_200")
        if _header(response, "Content-Range") is not None:
            raise FetchError("unexpected_content_range")
    else:
        if _status_code(response) != 206:
            raise FetchError("resume_requires_http_206")
        match = CONTENT_RANGE.fullmatch(_header(response, "Content-Range") or "")
        if (
            match is None
            or int(match.group("start")) != offset
            or int(match.group("end")) != artifact.bytes - 1
            or int(match.group("total")) != artifact.bytes
        ):
            raise FetchError("invalid_content_range")
    if _content_length(response) != remaining:
        raise FetchError("download_content_length_mismatch")


def _result(
    artifact: Artifact,
    *,
    present: bool,
    verified: bool,
    downloaded: bool,
    partial_bytes: int | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "record_id": artifact.record_id,
        "filename": artifact.filename,
        "expected_bytes": artifact.bytes,
        "present": present,
        "verified": verified,
        "downloaded": downloaded,
        "partial_bytes": partial_bytes,
        "error": error,
    }


def _acquire(artifact: Artifact, raw_dir: Path, receipt_dir: Path) -> dict[str, Any]:
    raw_record = raw_dir / str(artifact.record_id)
    receipt_record = receipt_dir / str(artifact.record_id)
    _ensure_directory(raw_dir)
    _ensure_directory(receipt_dir)
    _ensure_directory(raw_record)
    _ensure_directory(receipt_record)
    target, partial, receipt_path = _paths(artifact, raw_dir, receipt_dir)
    if os.path.lexists(target):
        _verify_existing(
            target,
            receipt_path,
            artifact,
            create_missing_receipt=True,
        )
        return _result(
            artifact,
            present=True,
            verified=True,
            downloaded=False,
        )
    if os.path.lexists(receipt_path):
        raise FetchError("orphan_receipt")

    partial_exists, offset, md5, sha256 = _partial_state(partial, artifact.bytes)
    if offset == artifact.bytes:
        _finalize(
            partial,
            target,
            receipt_path,
            artifact,
            offset,
            md5,
            sha256,
        )
        return _result(
            artifact,
            present=True,
            verified=True,
            downloaded=True,
        )

    try:
        with _open(
            _request(artifact, offset),
            timeout=DOWNLOAD_TIMEOUT_SECONDS,
        ) as response:
            _validate_response(response, artifact, offset)
            flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
            if partial_exists:
                flags |= os.O_APPEND
            else:
                flags |= os.O_CREAT | os.O_EXCL
            descriptor = os.open(partial, flags, 0o600)
            with os.fdopen(descriptor, "ab" if partial_exists else "wb") as output:
                metadata = os.fstat(output.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != offset:
                    raise FetchError("partial_changed_before_append")
                os.fchmod(output.fileno(), 0o600)
                received = offset
                while chunk := response.read(CHUNK_BYTES):
                    received += len(chunk)
                    if received > artifact.bytes:
                        raise FetchError("download_exceeded_declared_bytes")
                    output.write(chunk)
                    md5.update(chunk)
                    sha256.update(chunk)
                output.flush()
                os.fsync(output.fileno())
    except FetchError:
        raise
    except (OSError, urllib.error.URLError) as error:
        raise FetchError("download_request_failed") from error
    _finalize(
        partial,
        target,
        receipt_path,
        artifact,
        received,
        md5,
        sha256,
    )
    return _result(
        artifact,
        present=True,
        verified=True,
        downloaded=True,
    )


def _status_one(artifact: Artifact, raw_dir: Path, receipt_dir: Path) -> dict[str, Any]:
    target, partial, receipt_path = _paths(artifact, raw_dir, receipt_dir)
    if os.path.lexists(target):
        try:
            _verify_existing(
                target,
                receipt_path,
                artifact,
                create_missing_receipt=False,
            )
        except FetchError as error:
            return _result(
                artifact,
                present=True,
                verified=False,
                downloaded=False,
                error=str(error),
            )
        return _result(
            artifact,
            present=True,
            verified=True,
            downloaded=False,
        )
    if os.path.lexists(receipt_path):
        return _result(
            artifact,
            present=False,
            verified=False,
            downloaded=False,
            error="orphan_receipt",
        )
    try:
        partial_exists, partial_bytes, _, _ = _partial_state(partial, artifact.bytes)
    except FetchError as error:
        return _result(
            artifact,
            present=False,
            verified=False,
            downloaded=False,
            error=str(error),
        )
    return _result(
        artifact,
        present=False,
        verified=False,
        downloaded=False,
        partial_bytes=partial_bytes if partial_exists else None,
    )


def _summary(results: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "artifacts": len(results),
        "present": sum(bool(result["present"]) for result in results),
        "verified": sum(bool(result["verified"]) for result in results),
        "downloaded": sum(bool(result["downloaded"]) for result in results),
        "partial": sum(result["partial_bytes"] is not None for result in results),
        "missing": sum(
            not result["present"]
            and result["partial_bytes"] is None
            and result["error"] is None
            for result in results
        ),
        "failed": sum(result["error"] is not None for result in results),
    }


def status_records(
    records: Sequence[Record], raw_dir: Path, receipt_dir: Path
) -> list[dict[str, Any]]:
    """Return deterministic, network-free local status."""

    return [
        _status_one(artifact, raw_dir, receipt_dir) for artifact in _artifacts(records)
    ]


def fetch_records(
    records: Sequence[Record],
    *,
    raw_dir: Path,
    receipt_dir: Path,
    workers: int,
    max_total_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Fetch all selected artifacts and retain every per-artifact outcome."""

    if not 1 <= workers <= MAX_WORKERS:
        raise FetchError(f"workers_must_be_between_1_and_{MAX_WORKERS}")
    if max_total_bytes <= 0 or max_file_bytes <= 0:
        raise FetchError("byte_limits_must_be_positive")
    artifacts = _artifacts(records)
    if any(artifact.bytes > max_file_bytes for artifact in artifacts):
        raise FetchError("max_file_bytes_exceeded")
    if sum(artifact.bytes for artifact in artifacts) > max_total_bytes:
        raise FetchError("max_total_bytes_exceeded")

    def acquire(artifact: Artifact) -> dict[str, Any]:
        try:
            return _acquire(artifact, raw_dir, receipt_dir)
        except FetchError as error:
            target, _, _ = _paths(artifact, raw_dir, receipt_dir)
            return _result(
                artifact,
                present=os.path.lexists(target),
                verified=False,
                downloaded=False,
                error=str(error),
            )

    worker_count = min(workers, len(artifacts))
    if worker_count == 0:
        return []
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        return list(executor.map(acquire, artifacts))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPT_DIR)
    parser.add_argument(
        "--allow-loopback-http",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name in ("list", "status"):
        command = subcommands.add_parser(name)
        command.add_argument("record", nargs="?", default="all")
    fetch = subcommands.add_parser("fetch")
    fetch.add_argument("record", nargs="?", default="all")
    fetch.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    fetch.add_argument(
        "--max-total-bytes",
        type=int,
        default=DEFAULT_MAX_TOTAL_BYTES,
    )
    fetch.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
    )
    return parser


def _render(value: Mapping[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        catalog = load_catalog(
            arguments.manifest,
            allow_loopback_http=arguments.allow_loopback_http,
        )
        records = _select(catalog, arguments.record)
        if arguments.command == "list":
            _render(
                {
                    "schema": MANIFEST_SCHEMA,
                    "publisher": catalog.publisher,
                    "records": [record.listing() for record in records],
                    "summary": {
                        "records": len(records),
                        "artifacts": sum(
                            record.expected_artifact_count for record in records
                        ),
                        "expected_bytes": sum(
                            record.expected_total_bytes for record in records
                        ),
                    },
                }
            )
            return 0
        if arguments.command == "status":
            results = status_records(
                records,
                arguments.raw_dir,
                arguments.receipt_dir,
            )
            summary = _summary(results)
            _render({"command": "status", "results": results, "summary": summary})
            return 0 if summary["verified"] == summary["artifacts"] else 1
        results = fetch_records(
            records,
            raw_dir=arguments.raw_dir,
            receipt_dir=arguments.receipt_dir,
            workers=arguments.workers,
            max_total_bytes=arguments.max_total_bytes,
            max_file_bytes=arguments.max_file_bytes,
        )
        summary = _summary(results)
        _render({"command": "fetch", "results": results, "summary": summary})
        if summary["failed"]:
            print(
                f"fetch-controlled-jamming: {summary['failed']} artifact(s) failed",
                file=sys.stderr,
            )
            return 1
        return 0
    except FetchError as error:
        print(f"fetch-controlled-jamming: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
