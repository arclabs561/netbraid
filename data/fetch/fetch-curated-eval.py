#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["truststore==0.10.4"]
# ///

"""List, inspect, or fetch exact artifacts from the curated Zenodo manifest.

The tracked manifest is the only acquisition authority. Payloads are never
extracted or parsed: verified bytes live under the ignored raw tree, and local
SHA-256 receipts live under the ignored receipts tree.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
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
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import truststore

REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = REPOSITORY / "data" / "catalog" / "curated-eval-artifacts-v1.json"
DEFAULT_RAW_DIR = REPOSITORY / "data" / "raw" / "curated-eval"
DEFAULT_RECEIPT_DIR = REPOSITORY / "data" / "receipts" / "curated-eval"

MANIFEST_SCHEMA = "netbraid.curated_eval_artifacts.v1"
RECEIPT_SCHEMA = "local.netbraid_curated_eval_artifact.v1"
MANIFEST_BYTE_LIMIT = 2 * 1024 * 1024
RECEIPT_BYTE_LIMIT = 64 * 1024
CHUNK_BYTES = 4 * 1024 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 120
DEFAULT_MAX_TOTAL_BYTES = 8 * 1024**3
DEFAULT_MAX_FILE_BYTES = 2 * 1024**3

EXPECTED_RECORDS = {
    1193563: ("10.5281/zenodo.1193563", "CC BY 4.0", "cc-by-4.0", 3, 77069096),
    7108614: ("10.21227/fj7s-f281", "CC BY 4.0", "cc-by-4.0", 14, 1087237270),
    7396485: ("10.5281/zenodo.7396485", "CC BY 4.0", "cc-by-4.0", 1, 1495738620),
    15005190: (
        "10.5281/zenodo.15005190",
        "CC BY-NC 4.0",
        "cc-by-nc-4.0",
        2,
        69726725,
    ),
    15989282: (
        "10.5281/zenodo.15989282",
        "CC BY 4.0",
        "cc-by-4.0",
        26,
        2103062670,
    ),
    17347695: (
        "10.5281/zenodo.17347695",
        "CC BY 4.0",
        "cc-by-4.0",
        4,
        29707691,
    ),
}
EXPECTED_RECORD_IDS = tuple(sorted(EXPECTED_RECORDS))
EXPECTED_ARTIFACT_COUNT = 50
EXPECTED_TOTAL_BYTES = 4_862_542_072

MD5 = re.compile(r"[0-9a-f]{32}\Z")
API_UPDATED = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]+)?\+00:00\Z"
)
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
        "record_url",
        "api_updated",
        "title",
        "version",
        "doi",
        "license",
        "license_id",
        "task_rationale",
        "difficulty_rationale",
        "grouping_warning",
        "expected_artifact_count",
        "expected_total_bytes",
        "artifacts",
    }
)
ARTIFACT_KEYS = frozenset({"filename", "bytes", "md5", "content_url"})


class FetchError(RuntimeError):
    """Stable failure at a manifest, network, or local-integrity boundary."""


@dataclass(frozen=True)
class Artifact:
    """One exact publisher artifact plus its inherited record metadata."""

    record_id: int
    api_url: str
    record_url: str
    api_updated: str
    title: str
    version: str | None
    doi: str
    license: str
    license_id: str
    filename: str
    bytes: int
    md5: str
    content_url: str

    def source(self) -> dict[str, Any]:
        """Return the complete deterministic source pin for a receipt."""

        return {
            "record_id": self.record_id,
            "api_url": self.api_url,
            "record_url": self.record_url,
            "api_updated": self.api_updated,
            "title": self.title,
            "version": self.version,
            "doi": self.doi,
            "license": self.license,
            "license_id": self.license_id,
            "filename": self.filename,
            "bytes": self.bytes,
            "md5": self.md5,
            "content_url": self.content_url,
        }


@dataclass(frozen=True)
class Record:
    """One strictly validated record and its complete artifact inventory."""

    record_id: int
    api_url: str
    record_url: str
    api_updated: str
    title: str
    version: str | None
    doi: str
    license: str
    license_id: str
    task_rationale: str
    difficulty_rationale: str
    grouping_warning: str
    expected_artifact_count: int
    expected_total_bytes: int
    artifacts: tuple[Artifact, ...]

    def listing(self, selected: frozenset[Artifact]) -> dict[str, Any]:
        artifacts = [artifact for artifact in self.artifacts if artifact in selected]
        return {
            "record_id": self.record_id,
            "api_url": self.api_url,
            "record_url": self.record_url,
            "api_updated": self.api_updated,
            "title": self.title,
            "version": self.version,
            "doi": self.doi,
            "license": self.license,
            "license_id": self.license_id,
            "task_rationale": self.task_rationale,
            "difficulty_rationale": self.difficulty_rationale,
            "grouping_warning": self.grouping_warning,
            "artifacts": [artifact.source() for artifact in artifacts],
            "selected_artifact_count": len(artifacts),
            "selected_total_bytes": sum(artifact.bytes for artifact in artifacts),
        }


@dataclass(frozen=True)
class Catalog:
    """The validated tracked acquisition boundary."""

    records: tuple[Record, ...]
    expected_artifact_count: int
    expected_total_bytes: int

    @property
    def artifacts(self) -> tuple[Artifact, ...]:
        return tuple(
            artifact for record in self.records for artifact in record.artifacts
        )


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise FetchError("duplicate_json_key")
        value[key] = item
    return value


def _read_regular_bytes(
    path: Path,
    *,
    limit: int,
    error_code: str,
    required_mode: int | None = None,
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FetchError(error_code) from error
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > limit
            or (
                required_mode is not None
                and stat.S_IMODE(before.st_mode) != required_mode
            )
        ):
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


def _load_json(
    path: Path,
    *,
    limit: int,
    error_code: str,
    required_mode: int | None = None,
) -> Mapping[str, Any]:
    payload = _read_regular_bytes(
        path,
        limit=limit,
        error_code=error_code,
        required_mode=required_mode,
    )
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


def _required_text(value: Any, error_code: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
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
        or len(value.encode("utf-8", errors="surrogatepass")) > 200
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or any(unicodedata.category(character) == "Cs" for character in value)
    ):
        raise FetchError("invalid_artifact_filename")
    return value


def _content_url(value: Any, record_id: int, filename: str) -> str:
    if not isinstance(value, str):
        raise FetchError("invalid_content_url")
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
        raise FetchError("invalid_content_url")
    return value


def load_catalog(path: Path = DEFAULT_MANIFEST) -> Catalog:
    """Load the tracked schema while rejecting all unrecognized drift."""

    value = _load_json(path, limit=MANIFEST_BYTE_LIMIT, error_code="invalid_manifest")
    _require_exact_keys(value, TOP_LEVEL_KEYS, "manifest_schema_drift")
    if value.get("schema") != MANIFEST_SCHEMA or value.get("publisher") != "Zenodo":
        raise FetchError("manifest_schema_drift")
    if value.get("expected_record_count") != len(EXPECTED_RECORDS):
        raise FetchError("invalid_manifest_aggregates")
    if value.get("expected_artifact_count") != EXPECTED_ARTIFACT_COUNT:
        raise FetchError("invalid_manifest_aggregates")
    if value.get("expected_total_bytes") != EXPECTED_TOTAL_BYTES:
        raise FetchError("invalid_manifest_aggregates")
    raw_records = value.get("records")
    if not isinstance(raw_records, list):
        raise FetchError("manifest_schema_drift")

    records: list[Record] = []
    content_urls: set[str] = set()
    target_keys: set[tuple[int, str]] = set()
    for raw_record in raw_records:
        if not isinstance(raw_record, Mapping):
            raise FetchError("manifest_schema_drift")
        _require_exact_keys(raw_record, RECORD_KEYS, "manifest_schema_drift")
        record_id = _positive_int(
            raw_record.get("record_id"), "invalid_record_identity"
        )
        expected = EXPECTED_RECORDS.get(record_id)
        if expected is None:
            raise FetchError("invalid_record_identity")
        doi, license_name, license_id, artifact_count, total_bytes = expected
        api_url = raw_record.get("api_url")
        record_url = raw_record.get("record_url")
        api_updated = raw_record.get("api_updated")
        title = _required_text(raw_record.get("title"), "invalid_record_metadata")
        version = raw_record.get("version")
        if version is not None:
            version = _required_text(version, "invalid_record_metadata")
        if (
            api_url != f"https://zenodo.org/api/records/{record_id}"
            or record_url != f"https://zenodo.org/records/{record_id}"
            or not isinstance(api_updated, str)
            or API_UPDATED.fullmatch(api_updated) is None
            or raw_record.get("doi") != doi
            or raw_record.get("license") != license_name
            or raw_record.get("license_id") != license_id
            or raw_record.get("expected_artifact_count") != artifact_count
            or raw_record.get("expected_total_bytes") != total_bytes
        ):
            raise FetchError("invalid_record_metadata")
        task_rationale = _required_text(
            raw_record.get("task_rationale"), "invalid_record_rationale"
        )
        difficulty_rationale = _required_text(
            raw_record.get("difficulty_rationale"), "invalid_record_rationale"
        )
        grouping_warning = _required_text(
            raw_record.get("grouping_warning"), "invalid_record_rationale"
        )
        raw_artifacts = raw_record.get("artifacts")
        if not isinstance(raw_artifacts, list):
            raise FetchError("manifest_schema_drift")

        artifacts: list[Artifact] = []
        for raw_artifact in raw_artifacts:
            if not isinstance(raw_artifact, Mapping):
                raise FetchError("manifest_schema_drift")
            _require_exact_keys(raw_artifact, ARTIFACT_KEYS, "manifest_schema_drift")
            filename = _safe_filename(raw_artifact.get("filename"))
            target_key = (record_id, filename.casefold())
            if target_key in target_keys:
                raise FetchError("duplicate_artifact_target")
            target_keys.add(target_key)
            artifact_url = _content_url(
                raw_artifact.get("content_url"), record_id, filename
            )
            if artifact_url in content_urls:
                raise FetchError("duplicate_content_url")
            content_urls.add(artifact_url)
            artifact_bytes = _positive_int(
                raw_artifact.get("bytes"), "invalid_artifact_bytes"
            )
            artifact_md5 = raw_artifact.get("md5")
            if not isinstance(artifact_md5, str) or MD5.fullmatch(artifact_md5) is None:
                raise FetchError("invalid_artifact_md5")
            artifacts.append(
                Artifact(
                    record_id=record_id,
                    api_url=api_url,
                    record_url=record_url,
                    api_updated=api_updated,
                    title=title,
                    version=version,
                    doi=doi,
                    license=license_name,
                    license_id=license_id,
                    filename=filename,
                    bytes=artifact_bytes,
                    md5=artifact_md5,
                    content_url=artifact_url,
                )
            )
        if [artifact.filename for artifact in artifacts] != sorted(
            artifact.filename for artifact in artifacts
        ):
            raise FetchError("artifacts_not_sorted")
        if (
            len(artifacts) != artifact_count
            or sum(artifact.bytes for artifact in artifacts) != total_bytes
        ):
            raise FetchError("invalid_record_aggregates")
        records.append(
            Record(
                record_id=record_id,
                api_url=api_url,
                record_url=record_url,
                api_updated=api_updated,
                title=title,
                version=version,
                doi=doi,
                license=license_name,
                license_id=license_id,
                task_rationale=task_rationale,
                difficulty_rationale=difficulty_rationale,
                grouping_warning=grouping_warning,
                expected_artifact_count=artifact_count,
                expected_total_bytes=total_bytes,
                artifacts=tuple(artifacts),
            )
        )

    if tuple(record.record_id for record in records) != EXPECTED_RECORD_IDS:
        raise FetchError("records_missing_duplicate_or_unsorted")
    artifacts = tuple(artifact for record in records for artifact in record.artifacts)
    if (
        len(artifacts) != EXPECTED_ARTIFACT_COUNT
        or sum(artifact.bytes for artifact in artifacts) != EXPECTED_TOTAL_BYTES
    ):
        raise FetchError("invalid_manifest_aggregates")
    return Catalog(
        records=tuple(records),
        expected_artifact_count=EXPECTED_ARTIFACT_COUNT,
        expected_total_bytes=EXPECTED_TOTAL_BYTES,
    )


def select_artifacts(catalog: Catalog, selector: str) -> tuple[Artifact, ...]:
    """Resolve ``all``, a record ID, or ``RECORD_ID/FILENAME`` exactly."""

    if selector == "all":
        return catalog.artifacts
    record_text, separator, filename = selector.partition("/")
    try:
        record_id = int(record_text)
    except ValueError as error:
        raise FetchError("unknown_selection") from error
    record = next(
        (
            candidate
            for candidate in catalog.records
            if candidate.record_id == record_id
        ),
        None,
    )
    if record is None:
        raise FetchError("unknown_selection")
    if not separator:
        return record.artifacts
    selected = tuple(
        artifact for artifact in record.artifacts if artifact.filename == filename
    )
    if len(selected) != 1:
        raise FetchError("unknown_selection")
    return selected


def _ensure_directory(path: Path) -> None:
    _check_path_ancestors(path)
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = path.lstat()
    except OSError as error:
        raise FetchError("unsafe_local_directory") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_mode & 0o022
    ):
        raise FetchError("unsafe_local_directory")


def _check_existing_directory(path: Path) -> None:
    _check_path_ancestors(path)
    if not os.path.lexists(path):
        return
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FetchError("unsafe_local_directory") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_mode & 0o022
    ):
        raise FetchError("unsafe_local_directory")


def _check_path_ancestors(path: Path) -> None:
    absolute = path.absolute()
    component = absolute
    while True:
        if os.path.lexists(component):
            try:
                metadata = component.lstat()
            except OSError as error:
                raise FetchError("unsafe_local_directory") from error
            if stat.S_ISLNK(metadata.st_mode) or (
                component != absolute and not stat.S_ISDIR(metadata.st_mode)
            ):
                raise FetchError("unsafe_local_directory")
        if component == component.parent:
            return
        component = component.parent


def _paths(
    artifact: Artifact, raw_dir: Path, receipt_dir: Path
) -> tuple[Path, Path, Path, Path]:
    raw_record = raw_dir / str(artifact.record_id)
    target = raw_record / artifact.filename
    partial = raw_record / f".{artifact.filename}.part"
    receipt = receipt_dir / str(artifact.record_id) / f"{artifact.filename}.json"
    lock = raw_record / f".{artifact.filename}.lock"
    return target, partial, receipt, lock


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


def _write_receipt(path: Path, value: Mapping[str, Any]) -> None:
    if os.path.lexists(path):
        raise FetchError("receipt_appeared_during_acquisition")
    descriptor = -1
    temporary = ""
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            descriptor = -1
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        if os.path.lexists(path):
            raise FetchError("receipt_appeared_during_acquisition")
        os.replace(temporary, path)
        temporary = ""
    except FetchError:
        raise
    except OSError as error:
        raise FetchError("receipt_write_failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary:
            with suppress(FileNotFoundError):
                os.unlink(temporary)


def _read_receipt(path: Path) -> Mapping[str, Any]:
    return _load_json(
        path,
        limit=RECEIPT_BYTE_LIMIT,
        error_code="receipt_missing_or_unsafe",
        required_mode=0o600,
    )


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
    elif _read_receipt(receipt_path) != expected:
        raise FetchError("local_receipt_verification_failed")
    return sha256


def _partial_state(partial: Path, expected_bytes: int) -> tuple[int, Any, Any]:
    if not os.path.lexists(partial):
        return 0, hashlib.md5(usedforsecurity=False), hashlib.sha256()
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
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > expected_bytes
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise FetchError("unsafe_partial_file")
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
    return size, md5, sha256


def _finalize_partial(
    partial: Path,
    target: Path,
    receipt_path: Path,
    artifact: Artifact,
    size: int,
    md5: Any,
    sha256: Any,
) -> str:
    if size != artifact.bytes:
        raise FetchError("download_incomplete")
    if md5.hexdigest() != artifact.md5:
        raise FetchError("artifact_md5_mismatch")
    if os.path.lexists(target):
        raise FetchError("target_appeared_during_acquisition")
    try:
        os.replace(partial, target)
    except OSError as error:
        raise FetchError("atomic_promotion_failed") from error
    digest = sha256.hexdigest()
    _write_receipt(receipt_path, _receipt(artifact, digest))
    return digest


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
        "Accept": "*/*",
        "Accept-Encoding": "identity",
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
    encoding = _header(response, "Content-Encoding")
    if encoding not in {None, "identity"}:
        raise FetchError("unexpected_content_encoding")
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
        raise FetchError("remote_size_drift")


def _acquire_lock(path: Path) -> tuple[int, tuple[int, int]]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        metadata = os.fstat(descriptor)
    except OSError as error:
        raise FetchError("artifact_locked_or_unsafe") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        os.close(descriptor)
        raise FetchError("artifact_locked_or_unsafe")
    return descriptor, (metadata.st_dev, metadata.st_ino)


def _release_lock(path: Path, descriptor: int, identity: tuple[int, int]) -> None:
    os.close(descriptor)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if (metadata.st_dev, metadata.st_ino) == identity:
        os.unlink(path)


def acquire_artifact(
    artifact: Artifact, *, raw_dir: Path, receipt_dir: Path
) -> dict[str, Any]:
    """Acquire or verify one artifact without extracting its payload."""

    raw_record = raw_dir / str(artifact.record_id)
    receipt_record = receipt_dir / str(artifact.record_id)
    _ensure_directory(raw_dir)
    _ensure_directory(receipt_dir)
    _ensure_directory(raw_record)
    _ensure_directory(receipt_record)
    target, partial, receipt_path, lock_path = _paths(artifact, raw_dir, receipt_dir)
    descriptor, identity = _acquire_lock(lock_path)
    try:
        if os.path.lexists(target):
            if os.path.lexists(partial):
                raise FetchError("target_and_partial_both_present")
            sha256 = _verify_existing(
                target,
                receipt_path,
                artifact,
                create_missing_receipt=True,
            )
            return {
                "record_id": artifact.record_id,
                "filename": artifact.filename,
                "bytes": artifact.bytes,
                "sha256": sha256,
                "downloaded": False,
                "verified": True,
            }
        if os.path.lexists(receipt_path):
            raise FetchError("orphan_receipt")

        offset, md5, sha256 = _partial_state(partial, artifact.bytes)
        if offset == artifact.bytes:
            digest = _finalize_partial(
                partial,
                target,
                receipt_path,
                artifact,
                offset,
                md5,
                sha256,
            )
            return {
                "record_id": artifact.record_id,
                "filename": artifact.filename,
                "bytes": artifact.bytes,
                "sha256": digest,
                "downloaded": True,
                "verified": True,
            }

        request = _request(artifact, offset)
        try:
            with _open(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
                _validate_response(response, artifact, offset)
                flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
                if offset:
                    flags |= os.O_APPEND
                else:
                    flags |= os.O_CREAT | os.O_EXCL
                output_descriptor = os.open(partial, flags, 0o600)
                with os.fdopen(output_descriptor, "ab" if offset else "wb") as output:
                    metadata = os.fstat(output.fileno())
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != offset:
                        raise FetchError("partial_changed_before_write")
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
        except (
            OSError,
            urllib.error.URLError,
            http.client.HTTPException,
        ) as error:
            raise FetchError("download_request_failed") from error
        digest = _finalize_partial(
            partial,
            target,
            receipt_path,
            artifact,
            received,
            md5,
            sha256,
        )
        return {
            "record_id": artifact.record_id,
            "filename": artifact.filename,
            "bytes": artifact.bytes,
            "sha256": digest,
            "downloaded": True,
            "verified": True,
        }
    finally:
        _release_lock(lock_path, descriptor, identity)


def fetch_artifacts(
    artifacts: Sequence[Artifact],
    *,
    raw_dir: Path,
    receipt_dir: Path,
    max_total_bytes: int,
    max_file_bytes: int,
) -> list[dict[str, Any]]:
    """Preflight byte bounds, then acquire selected artifacts in order."""

    if max_total_bytes <= 0 or max_file_bytes <= 0:
        raise FetchError("byte_limits_must_be_positive")
    if any(artifact.bytes > max_file_bytes for artifact in artifacts):
        raise FetchError("max_file_bytes_exceeded")
    if sum(artifact.bytes for artifact in artifacts) > max_total_bytes:
        raise FetchError("max_total_bytes_exceeded")
    return [
        acquire_artifact(artifact, raw_dir=raw_dir, receipt_dir=receipt_dir)
        for artifact in artifacts
    ]


def _status_one(
    artifact: Artifact, *, raw_dir: Path, receipt_dir: Path
) -> dict[str, Any]:
    target, partial, receipt_path, lock_path = _paths(artifact, raw_dir, receipt_dir)
    result = {
        "record_id": artifact.record_id,
        "filename": artifact.filename,
        "expected_bytes": artifact.bytes,
        "present": False,
        "verified": False,
        "partial_bytes": None,
        "error": None,
    }
    try:
        _check_existing_directory(raw_dir)
        _check_existing_directory(receipt_dir)
        _check_existing_directory(raw_dir / str(artifact.record_id))
        _check_existing_directory(receipt_dir / str(artifact.record_id))
        if os.path.lexists(lock_path):
            raise FetchError("artifact_locked_or_unsafe")
        if os.path.lexists(target):
            result["present"] = True
            if os.path.lexists(partial):
                raise FetchError("target_and_partial_both_present")
            _verify_existing(
                target,
                receipt_path,
                artifact,
                create_missing_receipt=False,
            )
            result["verified"] = True
            return result
        if os.path.lexists(receipt_path):
            raise FetchError("orphan_receipt")
        partial_bytes, _, _ = _partial_state(partial, artifact.bytes)
        if os.path.lexists(partial):
            result["partial_bytes"] = partial_bytes
        return result
    except FetchError as error:
        result["error"] = str(error)
        return result


def status_artifacts(
    artifacts: Sequence[Artifact], *, raw_dir: Path, receipt_dir: Path
) -> list[dict[str, Any]]:
    """Return deterministic local integrity status without network access."""

    return [
        _status_one(artifact, raw_dir=raw_dir, receipt_dir=receipt_dir)
        for artifact in artifacts
    ]


def _summary(results: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        "artifacts": len(results),
        "present": sum(bool(result.get("present", True)) for result in results),
        "verified": sum(bool(result["verified"]) for result in results),
        "downloaded": sum(bool(result.get("downloaded", False)) for result in results),
        "partial": sum(result.get("partial_bytes") is not None for result in results),
        "failed": sum(result.get("error") is not None for result in results),
    }


def listing(
    catalog: Catalog, selector: str, artifacts: Sequence[Artifact]
) -> dict[str, Any]:
    selected = frozenset(artifacts)
    records = [
        record.listing(selected)
        for record in catalog.records
        if any(artifact in selected for artifact in record.artifacts)
    ]
    return {
        "schema": MANIFEST_SCHEMA,
        "publisher": "Zenodo",
        "selection": selector,
        "records": records,
        "summary": {
            "records": len(records),
            "artifacts": len(artifacts),
            "expected_bytes": sum(artifact.bytes for artifact in artifacts),
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    list_command = subcommands.add_parser("list")
    list_command.add_argument("selection", nargs="?", default="all")
    status_command = subcommands.add_parser("status")
    status_command.add_argument("selection", nargs="?", default="all")
    fetch_command = subcommands.add_parser("fetch")
    fetch_command.add_argument("selection")
    fetch_command.add_argument(
        "--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES
    )
    fetch_command.add_argument(
        "--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES
    )
    return parser


def _render(value: Mapping[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        catalog = load_catalog()
        artifacts = select_artifacts(catalog, arguments.selection)
        if arguments.command == "list":
            _render(listing(catalog, arguments.selection, artifacts))
            return 0
        if arguments.command == "status":
            results = status_artifacts(
                artifacts,
                raw_dir=DEFAULT_RAW_DIR,
                receipt_dir=DEFAULT_RECEIPT_DIR,
            )
            summary = _summary(results)
            _render({"command": "status", "results": results, "summary": summary})
            return 0 if summary["verified"] == summary["artifacts"] else 1
        results = fetch_artifacts(
            artifacts,
            raw_dir=DEFAULT_RAW_DIR,
            receipt_dir=DEFAULT_RECEIPT_DIR,
            max_total_bytes=arguments.max_total_bytes,
            max_file_bytes=arguments.max_file_bytes,
        )
        _render(
            {
                "command": "fetch",
                "results": results,
                "summary": _summary(results),
            }
        )
        return 0
    except FetchError as error:
        print(f"fetch-curated-eval: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
