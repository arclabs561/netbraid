#!/usr/bin/env python3
"""Fetch pinned XRF55 Kaggle bundles without extracting or tracking raw data.

Kaggle does not publish an artifact digest through its dataset metadata API.
The first acquisition is therefore pinned by dataset ref, version, and exact
byte count. It writes a local SHA-256 receipt; every later reuse verifies that
digest before accepting the bundle. Receipts default to the ignored
``data/receipts/xrf55/`` directory.
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
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, BinaryIO

REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT_RAW_DIR = REPOSITORY / "data" / "raw"
DEFAULT_RECEIPT_DIR = REPOSITORY / "data" / "receipts" / "xrf55"
OFFICIAL_PAGE = "https://aiotgroup.github.io/XRF55/"
LICENSE = "CC BY-NC 4.0"
METADATA_LIMIT = 1_000_000
RECEIPT_LIMIT = 64 * 1024
CHUNK_BYTES = 8 * 1024 * 1024
CONTENT_RANGE = re.compile(
    r"bytes (?P<start>[0-9]+)-(?P<end>[0-9]+)/(?P<total>[0-9]+)\Z"
)
SOURCES: dict[str, dict[str, Any]] = {
    "part1": {
        "kaggle_ref": "xrfdataset/xrf55",
        "version": 3,
        "metadata_bytes": 97_148_480_000,
        "archive_bytes": 86_334_807_153,
        "archive_md5": "e637608020c9dca1165d09d55ae20c91",
        "filename": "xrf55-part1-v3.zip",
    },
    "part2": {
        "kaggle_ref": "whisperyi/xrf55-2",
        "version": 1,
        "metadata_bytes": 92_291_056_000,
        "archive_bytes": 81_963_525_329,
        "archive_md5": "4f2094698b1d0164fef0c62833c2aead",
        "filename": "xrf55-part2-v1.zip",
    },
    "raw": {
        "kaggle_ref": "xrfdataset/xrf55-rawdata",
        "version": 1,
        "metadata_bytes": 46_057_035_505,
        "archive_bytes": 27_597_836_462,
        "archive_md5": "3820ac43b0f4e6bf96b685ea73c825a5",
        "filename": "xrf55-wifi-rfid-raw-v1.zip",
    },
}


class FetchError(RuntimeError):
    """Stable failure at the remote-metadata or artifact boundary."""


def metadata_url(spec: Mapping[str, Any]) -> str:
    return f"https://www.kaggle.com/api/v1/datasets/view/{spec['kaggle_ref']}"


def download_url(spec: Mapping[str, Any]) -> str:
    return (
        "https://www.kaggle.com/api/v1/datasets/download/"
        f"{spec['kaggle_ref']}?datasetVersionNumber={spec['version']}"
    )


def _request(url: str, *, offset: int | None = None) -> urllib.request.Request:
    headers = {"User-Agent": "netbraid-xrf55-fetcher/1"}
    if offset is not None:
        headers["Range"] = f"bytes={offset}-"
    return urllib.request.Request(url, headers=headers)


def _bounded_json(response: BinaryIO) -> Mapping[str, Any]:
    payload = response.read(METADATA_LIMIT + 1)
    if len(payload) > METADATA_LIMIT:
        raise FetchError("metadata_response_too_large")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FetchError("invalid_metadata_json") from error
    if not isinstance(value, Mapping):
        raise FetchError("invalid_metadata_schema")
    return value


def validate_remote_metadata(spec: Mapping[str, Any]) -> None:
    try:
        with urllib.request.urlopen(
            _request(metadata_url(spec)), timeout=30
        ) as response:
            value = _bounded_json(response)
    except (OSError, urllib.error.URLError) as error:
        raise FetchError("metadata_request_failed") from error
    expected = {
        "ref": spec["kaggle_ref"],
        "currentVersionNumber": spec["version"],
        "totalBytes": spec["metadata_bytes"],
        "isPrivate": False,
    }
    if any(
        value.get(name) != expected_value for name, expected_value in expected.items()
    ):
        raise FetchError("remote_metadata_drift")


def digest_file(path: Path) -> tuple[int, str]:
    size = 0
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FetchError("unsafe_archive_path") from error
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise FetchError("unsafe_archive_path")
        while chunk := source.read(CHUNK_BYTES):
            size += len(chunk)
            digest.update(chunk)
        after = os.fstat(source.fileno())
    if size != before.st_size or (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
        raise FetchError("archive_changed_during_verification")
    return size, digest.hexdigest()


def legacy_receipt_path(archive: Path) -> Path:
    return archive.with_suffix(archive.suffix + ".json")


def receipt_path(archive: Path, receipt_dir: Path) -> Path:
    return receipt_dir / f"{archive.name}.json"


def source_receipt(spec: Mapping[str, Any], size: int, sha256: str) -> dict[str, Any]:
    return {
        "schema": "local.xrf55_archive.v1",
        "source": {
            "official_page": OFFICIAL_PAGE,
            "kaggle_ref": spec["kaggle_ref"],
            "version": spec["version"],
            "metadata_bytes": spec["metadata_bytes"],
            "archive_bytes": spec["archive_bytes"],
            "archive_md5": spec["archive_md5"],
            "license": LICENSE,
        },
        "integrity": {
            "first_acquisition": "kaggle_version_metadata_and_archive_md5",
            "subsequent_reuse": "sha256_receipt",
        },
        "bytes": size,
        "sha256": sha256,
        "archive": spec["filename"],
    }


def _ensure_safe_directory(path: Path, error_message: str) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = path.lstat()
    except OSError as error:
        raise FetchError(error_message) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise FetchError(error_message)


def _read_receipt(path: Path) -> Mapping[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FetchError("receipt_missing_or_unsafe") from error
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > RECEIPT_LIMIT:
            raise FetchError("receipt_missing_or_unsafe")
        payload = source.read(RECEIPT_LIMIT + 1)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FetchError("invalid_receipt") from error
    if not isinstance(value, Mapping):
        raise FetchError("invalid_receipt")
    return value


def write_receipt(archive: Path, receipt_dir: Path, value: Mapping[str, Any]) -> None:
    _ensure_safe_directory(receipt_dir, "unsafe_receipt_directory")
    target = receipt_path(archive, receipt_dir)
    if os.path.lexists(target):
        raise FetchError("receipt_appeared_during_download")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=target.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, target, follow_symlinks=False)
        except FileExistsError as error:
            raise FetchError("receipt_appeared_during_download") from error
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def verify_existing(archive: Path, spec: Mapping[str, Any], receipt_dir: Path) -> None:
    if archive.is_symlink() or not archive.is_file():
        raise FetchError("unsafe_archive_path")
    target = receipt_path(archive, receipt_dir)
    legacy = legacy_receipt_path(archive)
    if os.path.lexists(target):
        receipt = target
    elif legacy != target and os.path.lexists(legacy):
        receipt = legacy
    else:
        raise FetchError("receipt_missing_or_unsafe")
    value = _read_receipt(receipt)
    size, sha256 = digest_file(archive)
    expected = source_receipt(spec, size, sha256)
    if value != expected:
        raise FetchError("archive_or_receipt_verification_failed")
    if receipt == legacy and target != legacy:
        write_receipt(archive, receipt_dir, expected)


def _resume_state(partial: Path, expected_bytes: int) -> tuple[int, Any, Any]:
    if partial.is_symlink():
        raise FetchError("unsafe_partial_path")
    if not partial.exists():
        return 0, hashlib.sha256(), hashlib.md5(usedforsecurity=False)
    if not partial.is_file():
        raise FetchError("unsafe_partial_path")
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(partial, flags)
    except OSError as error:
        raise FetchError("unsafe_partial_path") from error
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > expected_bytes:
            raise FetchError("invalid_partial_size")
        size = 0
        while chunk := source.read(CHUNK_BYTES):
            size += len(chunk)
            sha256.update(chunk)
            md5.update(chunk)
        after = os.fstat(source.fileno())
        if size != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise FetchError("partial_changed_during_verification")
    return size, sha256, md5


def _finalize_partial(
    partial: Path,
    archive: Path,
    receipt_dir: Path,
    spec: Mapping[str, Any],
    size: int,
    sha256: Any,
    md5: Any,
) -> Path:
    if size != spec["archive_bytes"]:
        raise FetchError("download_incomplete")
    if md5.hexdigest() != spec["archive_md5"]:
        raise FetchError("archive_md5_mismatch")
    os.replace(partial, archive)
    write_receipt(archive, receipt_dir, source_receipt(spec, size, sha256.hexdigest()))
    print(f"downloaded and receipt-pinned: {archive}")
    return archive


def _validate_download_response(response: Any, offset: int, total: int) -> None:
    status = getattr(response, "status", None)
    if offset == 0:
        if status != 200:
            raise FetchError("full_download_requires_http_200")
        return
    if status != 206:
        raise FetchError("resume_requires_http_206")
    content_range = response.headers.get("Content-Range")
    match = CONTENT_RANGE.fullmatch(content_range or "")
    if (
        match is None
        or int(match.group("start")) != offset
        or int(match.group("total")) != total
    ):
        raise FetchError("invalid_content_range")


def download(spec: Mapping[str, Any], output_dir: Path, receipt_dir: Path) -> Path:
    _ensure_safe_directory(output_dir, "unsafe_archive_directory")
    _ensure_safe_directory(receipt_dir, "unsafe_receipt_directory")
    archive = output_dir / str(spec["filename"])
    partial = output_dir / f".{spec['filename']}.part"
    if archive.exists() or archive.is_symlink():
        verify_existing(archive, spec, receipt_dir)
        print(f"reusing verified archive: {archive}")
        return archive

    target_receipt = receipt_path(archive, receipt_dir)
    legacy_receipt = legacy_receipt_path(archive)
    if os.path.lexists(target_receipt) or (
        legacy_receipt != target_receipt and os.path.lexists(legacy_receipt)
    ):
        raise FetchError("orphan_receipt")

    validate_remote_metadata(spec)
    expected_bytes = int(spec["archive_bytes"])
    offset, sha256, md5 = _resume_state(partial, expected_bytes)
    if offset == expected_bytes:
        return _finalize_partial(
            partial, archive, receipt_dir, spec, offset, sha256, md5
        )
    try:
        with urllib.request.urlopen(
            _request(download_url(spec), offset=offset if offset else None), timeout=120
        ) as response:
            _validate_download_response(response, offset, expected_bytes)
            flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            flags |= os.O_APPEND if offset else os.O_TRUNC
            descriptor = os.open(partial, flags, 0o600)
            mode = "ab" if offset else "wb"
            with os.fdopen(descriptor, mode) as output:
                os.fchmod(output.fileno(), 0o600)
                if os.fstat(output.fileno()).st_size != offset:
                    raise FetchError("partial_changed_before_append")
                received = offset
                while chunk := response.read(CHUNK_BYTES):
                    received += len(chunk)
                    if received > expected_bytes:
                        raise FetchError("download_exceeded_declared_bytes")
                    output.write(chunk)
                    sha256.update(chunk)
                    md5.update(chunk)
                output.flush()
                os.fsync(output.fileno())
    except (OSError, urllib.error.URLError) as error:
        raise FetchError("download_request_failed") from error
    return _finalize_partial(partial, archive, receipt_dir, spec, received, sha256, md5)


def _catalog() -> dict[str, Any]:
    return {
        name: {
            **spec,
            "official_page": OFFICIAL_PAGE,
            "license": LICENSE,
            "integrity": "version+metadata+archive MD5 first; SHA-256 receipt thereafter",
        }
        for name, spec in SOURCES.items()
    }


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", choices=["list", "all", *SOURCES])
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_RAW_DIR,
        help="ignored archive directory (default: data/raw)",
    )
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=DEFAULT_RECEIPT_DIR,
        help="ignored receipt directory (default: data/receipts/xrf55)",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    if arguments.dataset == "list":
        print(json.dumps(_catalog(), indent=2, sort_keys=True))
        return 0
    selected = (
        SOURCES
        if arguments.dataset == "all"
        else {arguments.dataset: SOURCES[arguments.dataset]}
    )
    try:
        for spec in selected.values():
            download(spec, arguments.output_dir, arguments.receipt_dir)
    except FetchError as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
