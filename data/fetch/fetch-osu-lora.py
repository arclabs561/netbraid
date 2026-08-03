#!/usr/bin/env python3
"""Discover and fetch bounded slices of Oregon State's LoRa RFFI corpus.

The publisher exposes more than 1.2 TB through recursive Apache indexes. With
no arguments this tool only lists the seven release-note roots. ``discover``
builds a deterministic inventory with HEAD metadata, while ``fetch`` requires
an explicit setup selection and enforces byte, traversal, and worker limits.
No authentication, cookies, redirects, extraction, or Git-tracked data are
supported.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import os
import re
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, unquote_to_bytes, urljoin, urlsplit, urlunsplit

RELEASE_NOTE = (
    "https://research.engr.oregonstate.edu/hamdaoui/sites/"
    "research.engr.oregonstate.edu.hamdaoui/files/"
    "release_note_lora_datasets_final_oct2023_v2.pdf"
)
PUBLISHER_ORIGIN = "https://research.engr.oregonstate.edu"
PUBLISHER_ROOT = f"{PUBLISHER_ORIGIN}/hamdaoui/RFFP-dataset/LoRa-Dataset/"
SETUPS = {
    "days-indoor": {
        "title": "Different Days Indoor Scenario",
        "root": f"{PUBLISHER_ROOT}Diff_Days_Indoor_Setup/",
    },
    "days-outdoor": {
        "title": "Different Days Outdoor Scenario",
        "root": f"{PUBLISHER_ROOT}Diff_Days_Outdoor_Setup/",
    },
    "days-wired": {
        "title": "Different Days Wired Scenario",
        "root": f"{PUBLISHER_ROOT}Diff_Days_Wired_Setup/",
    },
    "distances": {
        "title": "Different Distances Scenario",
        "root": f"{PUBLISHER_ROOT}Diff_Distances_Setup/",
    },
    "configurations": {
        "title": "Different Configurations Scenario",
        "root": f"{PUBLISHER_ROOT}Diff_Configurations_Setup/",
    },
    "locations": {
        "title": "Different Locations Scenario",
        "root": f"{PUBLISHER_ROOT}Diff_Locations_Setup/",
    },
    "receivers": {
        "title": "Different Receivers Scenario",
        "root": f"{PUBLISHER_ROOT}Diff_Receivers_Setup/",
    },
}

INDEX_BYTE_LIMIT = 2_000_000
RECEIPT_BYTE_LIMIT = 1_000_000
CHUNK_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_DEPTH = 4
MAX_MAX_DEPTH = 8
DEFAULT_MAX_ENTRIES = 25_000
MAX_MAX_ENTRIES = 50_000
DEFAULT_WORKERS = min(4, os.cpu_count() or 1)
MAX_WORKERS = 8
REQUEST_ATTEMPTS = 3
REQUEST_RETRY_DELAYS_SECONDS = (0.25, 1.0)
DEFAULT_MAX_TOTAL_BYTES = 10 * 1024**3
DEFAULT_MAX_FILE_BYTES = 2 * 1024**3
CONTENT_RANGE = re.compile(
    r"bytes (?P<start>[0-9]+)-(?P<end>[0-9]+)/(?P<total>[0-9]+)\Z"
)
MALFORMED_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")


class FetchError(RuntimeError):
    """Stable failure at a traversal, metadata, or local-integrity boundary."""


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise FetchError("redirect_rejected")


# No proxy credentials, password handlers, or cookie jars are installed.
_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    _RejectRedirects(),
)


@dataclass(frozen=True, order=True)
class RemoteFile:
    setup: str
    path: str
    url: str
    bytes: int | None
    etag: str | None
    last_modified: str | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "setup": self.setup,
            "path": self.path,
            "url": self.url,
            "bytes": self.bytes,
            "etag": self.etag,
            "last_modified": self.last_modified,
        }


@dataclass(frozen=True, order=True)
class _IndexEntry:
    path: str
    url: str
    directory: bool


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a" or self._href is not None:
            return
        href = next((value for name, value in attrs if name.lower() == "href"), None)
        if href is not None:
            self._href = href
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None
            self._text = []


def _open(request: urllib.request.Request, *, timeout: int) -> Any:
    return _OPENER.open(request, timeout=timeout)


def _request(
    url: str,
    *,
    method: str,
    offset: int | None = None,
    validator: str | None = None,
) -> urllib.request.Request:
    parts = urlsplit(url)
    publisher = urlsplit(PUBLISHER_ORIGIN)
    if (
        parts.scheme != "https"
        or parts.netloc != publisher.netloc
        or parts.username is not None
        or parts.password is not None
        or parts.query
        or parts.fragment
        or method not in {"GET", "HEAD"}
        or offset is not None
        and (method != "GET" or offset < 0)
    ):
        raise FetchError("unsafe_request_url")
    path_segments = _decoded_segments(parts.path)
    allowed = any(
        path_segments[: len(root_segments)] == root_segments
        for root_segments in (
            _decoded_segments(urlsplit(str(value["root"])).path)
            for value in SETUPS.values()
        )
    )
    if not allowed:
        raise FetchError("unsafe_request_url")
    headers = {
        "Accept-Encoding": "identity",
        "User-Agent": "netbraid-osu-lora-fetcher/1",
    }
    if offset is not None:
        headers["Range"] = f"bytes={offset}-"
        if validator is not None:
            headers["If-Range"] = validator
    # S310 is satisfied by the exact HTTPS origin/root validation above.
    return urllib.request.Request(url, headers=headers, method=method)  # noqa: S310


def _response_status(response: Any) -> int | None:
    status_code = getattr(response, "status", None)
    if status_code is None and hasattr(response, "getcode"):
        status_code = response.getcode()
    return status_code


def _require_exact_response_url(response: Any, expected: str) -> None:
    if not hasattr(response, "geturl") or response.geturl() != expected:
        raise FetchError("response_url_mismatch")


def _header(response: Any, name: str) -> str | None:
    value = response.headers.get(name)
    if value is None:
        return None
    return str(value).strip()


def _decoded_segments(url_path: str) -> tuple[str, ...]:
    if not url_path.startswith("/") or MALFORMED_PERCENT.search(url_path):
        raise FetchError("unsafe_url_path")
    raw_segments = url_path.split("/")[1:]
    if raw_segments and raw_segments[-1] == "":
        raw_segments.pop()
    decoded: list[str] = []
    for raw_segment in raw_segments:
        if not raw_segment:
            raise FetchError("unsafe_url_path")
        try:
            segment = unquote_to_bytes(raw_segment).decode("utf-8")
        except UnicodeDecodeError as error:
            raise FetchError("unsafe_url_path") from error
        if (
            segment in {"", ".", ".."}
            or "/" in segment
            or "\\" in segment
            or any(
                ord(character) < 32 or ord(character) == 127 for character in segment
            )
        ):
            raise FetchError("unsafe_url_path")
        decoded.append(segment)
    return tuple(decoded)


def _canonical_url(parts: Any, segments: Sequence[str], directory: bool) -> str:
    path = "/" + "/".join(quote(segment, safe="-._~") for segment in segments)
    if directory:
        path += "/"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _validated_index_entry(
    index_url: str,
    root_url: str,
    href: str,
    link_text: str,
) -> _IndexEntry | None:
    href_parts = urlsplit(href)
    if (
        not href_parts.scheme
        and not href_parts.netloc
        and not href_parts.path
        and (href_parts.query or href_parts.fragment)
    ):
        return None

    target = urljoin(index_url, href)
    target_parts = urlsplit(target)
    root_parts = urlsplit(root_url)
    if (
        target_parts.scheme != "https"
        or target_parts.netloc != root_parts.netloc
        or target_parts.username is not None
        or target_parts.password is not None
    ):
        raise FetchError("traversal_escape")
    if target_parts.query or target_parts.fragment:
        raise FetchError("unsafe_index_link")

    target_segments = _decoded_segments(target_parts.path)
    index_segments = _decoded_segments(urlsplit(index_url).path)
    root_segments = _decoded_segments(root_parts.path)
    if link_text == "Parent Directory":
        if target_parts.path.endswith("/") and target_segments == index_segments[:-1]:
            return None
        raise FetchError("invalid_parent_link")
    if target_segments[: len(root_segments)] != root_segments:
        raise FetchError("traversal_escape")
    relative_segments = target_segments[len(root_segments) :]
    if not relative_segments:
        return None
    if (
        link_text.endswith("@")
        or " -> " in link_text
        or relative_segments[-1].endswith("@")
    ):
        raise FetchError("remote_symlink_rejected")

    directory = target_parts.path.endswith("/")
    path = PurePosixPath(*relative_segments).as_posix()
    return _IndexEntry(
        path=path,
        url=_canonical_url(target_parts, target_segments, directory),
        directory=directory,
    )


def _read_index(index_url: str, root_url: str) -> list[tuple[str, str]]:
    for attempt in range(REQUEST_ATTEMPTS):
        try:
            with _open(_request(index_url, method="GET"), timeout=30) as response:
                _require_exact_response_url(response, index_url)
                if _response_status(response) != 200:
                    raise FetchError("index_requires_http_200")
                content_type = (_header(response, "Content-Type") or "").lower()
                if (
                    "text/html" not in content_type
                    and "application/xhtml+xml" not in content_type
                ):
                    raise FetchError("index_not_html")
                payload = response.read(INDEX_BYTE_LIMIT + 1)
            break
        except FetchError:
            raise
        except (OSError, urllib.error.URLError) as error:
            if attempt + 1 == REQUEST_ATTEMPTS:
                raise FetchError("index_request_failed") from error
            time.sleep(REQUEST_RETRY_DELAYS_SECONDS[attempt])
    if len(payload) > INDEX_BYTE_LIMIT:
        raise FetchError("index_response_too_large")
    try:
        document = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise FetchError("invalid_index_encoding") from error
    parser = _LinkParser()
    parser.feed(document)
    parser.close()
    return parser.links


def _validate_discovery_limits(max_depth: int, max_entries: int, workers: int) -> None:
    if not 0 <= max_depth <= MAX_MAX_DEPTH:
        raise FetchError(f"max_depth_must_be_between_0_and_{MAX_MAX_DEPTH}")
    if not 1 <= max_entries <= MAX_MAX_ENTRIES:
        raise FetchError(f"max_entries_must_be_between_1_and_{MAX_MAX_ENTRIES}")
    if not 1 <= workers <= MAX_WORKERS:
        raise FetchError(f"workers_must_be_between_1_and_{MAX_WORKERS}")


def _discover_structure(
    setup: str,
    *,
    max_depth: int,
    max_entries: int,
) -> tuple[list[tuple[str, str]], int]:
    root_url = str(SETUPS[setup]["root"])
    queue: list[tuple[str, str, int]] = [("", root_url, 0)]
    seen_directories = {""}
    seen_paths: dict[str, tuple[str, bool]] = {}
    entry_count = 0

    while queue:
        _, index_url, depth = heapq.heappop(queue)
        parsed_entries: list[_IndexEntry] = []
        for href, link_text in _read_index(index_url, root_url):
            entry = _validated_index_entry(index_url, root_url, href, link_text)
            if entry is None:
                continue
            entry_count += 1
            if entry_count > max_entries:
                raise FetchError("max_entries_exceeded")
            parsed_entries.append(entry)

        for entry in sorted(parsed_entries):
            entry_depth = depth + 1
            if entry_depth > max_depth:
                raise FetchError("max_depth_exceeded")
            prior = seen_paths.get(entry.path)
            identity = (entry.url, entry.directory)
            if prior is not None:
                if prior != identity:
                    raise FetchError("conflicting_index_entry")
                continue
            seen_paths[entry.path] = identity
            if entry.directory and entry.path not in seen_directories:
                seen_directories.add(entry.path)
                heapq.heappush(queue, (entry.path, entry.url, entry_depth))

    files = sorted(
        (path, url) for path, (url, directory) in seen_paths.items() if not directory
    )
    return files, entry_count


def _parse_content_length(response: Any) -> int | None:
    value = _header(response, "Content-Length")
    if value is None:
        return None
    if not value.isascii() or not value.isdecimal():
        raise FetchError("invalid_content_length")
    size = int(value)
    if size < 0:
        raise FetchError("invalid_content_length")
    return size


def head_remote(setup: str, path: str, url: str) -> RemoteFile:
    for attempt in range(REQUEST_ATTEMPTS):
        try:
            with _open(_request(url, method="HEAD"), timeout=30) as response:
                _require_exact_response_url(response, url)
                if _response_status(response) != 200:
                    raise FetchError("head_requires_http_200")
                return RemoteFile(
                    setup=setup,
                    path=path,
                    url=url,
                    bytes=_parse_content_length(response),
                    etag=_header(response, "ETag"),
                    last_modified=_header(response, "Last-Modified"),
                )
        except FetchError:
            raise
        except (OSError, urllib.error.URLError) as error:
            if attempt + 1 == REQUEST_ATTEMPTS:
                raise FetchError("head_request_failed") from error
            time.sleep(REQUEST_RETRY_DELAYS_SECONDS[attempt])
    raise AssertionError("bounded request loop must return or raise")


def _selected_setups(names: Sequence[str]) -> list[str]:
    if "all" in names:
        if len(names) != 1:
            raise FetchError("all_cannot_be_combined_with_other_setups")
        return list(SETUPS)
    selected = set(names)
    return [name for name in SETUPS if name in selected]


def discover(
    setups: Sequence[str],
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    workers: int = DEFAULT_WORKERS,
) -> dict[str, Any]:
    _validate_discovery_limits(max_depth, max_entries, workers)
    selected = _selected_setups(setups)
    skeletons: list[tuple[str, str, str]] = []
    remaining = max_entries
    for setup in selected:
        files, consumed_entries = _discover_structure(
            setup,
            max_depth=max_depth,
            max_entries=remaining,
        )
        remaining -= consumed_entries
        skeletons.extend((setup, path, url) for path, url in files)
    skeletons.sort()

    def inspect(item: tuple[str, str, str]) -> RemoteFile:
        return head_remote(*item)

    if skeletons:
        worker_count = min(workers, len(skeletons))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            files = list(executor.map(inspect, skeletons))
    else:
        files = []
    files.sort()
    known_bytes = sum(item.bytes or 0 for item in files)
    unknown_sizes = sum(item.bytes is None for item in files)
    return {
        "schema": "netbraid.osu_lora_inventory.v1",
        "publisher": "Oregon State University",
        "release_note": RELEASE_NOTE,
        "roots": [
            {
                "setup": name,
                "title": SETUPS[name]["title"],
                "url": SETUPS[name]["root"],
            }
            for name in selected
        ],
        "limits": {
            "max_depth": max_depth,
            "max_entries": max_entries,
            "workers": workers,
            "index_bytes": INDEX_BYTE_LIMIT,
        },
        "summary": {
            "files": len(files),
            "known_bytes": known_bytes,
            "unknown_size_files": unknown_sizes,
        },
        "files": [item.as_dict() for item in files],
    }


def _ensure_safe_directory(path: Path) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = path.lstat()
    except OSError as error:
        raise FetchError("unsafe_local_directory") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise FetchError("unsafe_local_directory")


def _safe_parent(base: Path, setup: str, relative_parent: PurePosixPath) -> Path:
    _ensure_safe_directory(base)
    current = base
    for segment in (setup, *relative_parent.parts):
        if segment in {"", ".", ".."} or "/" in segment or "\\" in segment:
            raise FetchError("unsafe_local_path")
        current /= segment
        _ensure_safe_directory(current)
    return current


def _local_path(base: Path, remote: RemoteFile) -> Path:
    relative = PurePosixPath(remote.path)
    if relative.is_absolute() or not relative.name or ".." in relative.parts:
        raise FetchError("unsafe_local_path")
    parent = _safe_parent(base, remote.setup, relative.parent)
    return parent / relative.name


def _receipt_path(base: Path, remote: RemoteFile) -> Path:
    target = _local_path(base, remote)
    return target.with_name(f"{target.name}.json")


def _digest_regular_file(path: Path) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FetchError("unsafe_local_file") from error
    digest = hashlib.sha256()
    size = 0
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise FetchError("unsafe_local_file")
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
        raise FetchError("local_file_changed_during_verification")
    return size, digest.hexdigest()


def _receipt(remote: RemoteFile, size: int, sha256: str) -> dict[str, Any]:
    return {
        "schema": "local.osu_lora_file.v1",
        "release_note": RELEASE_NOTE,
        "source": remote.as_dict(),
        "integrity": {
            "first_acquisition": "exact_head_metadata_and_http_transfer",
            "subsequent_reuse": "exact_remote_metadata_and_local_sha256",
        },
        "bytes": size,
        "sha256": sha256,
    }


def _read_receipt(path: Path) -> Mapping[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FetchError("receipt_missing_or_unsafe") from error
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > RECEIPT_BYTE_LIMIT:
            raise FetchError("receipt_missing_or_unsafe")
        payload = source.read(RECEIPT_BYTE_LIMIT + 1)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FetchError("invalid_receipt") from error
    if not isinstance(value, Mapping):
        raise FetchError("invalid_receipt")
    return value


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


def _verify_existing(target: Path, receipt_path: Path, remote: RemoteFile) -> None:
    size, sha256 = _digest_regular_file(target)
    value = _read_receipt(receipt_path)
    source = value.get("source")
    if source != remote.as_dict():
        raise FetchError("remote_drift")
    if value != _receipt(remote, size, sha256):
        raise FetchError("local_receipt_verification_failed")


def _resume_state(partial: Path, expected_bytes: int) -> tuple[int, Any]:
    if not os.path.lexists(partial):
        return 0, hashlib.sha256()
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(partial, flags)
    except OSError as error:
        raise FetchError("unsafe_local_file") from error
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > expected_bytes:
            raise FetchError("partial_exceeds_remote_size")
        size = 0
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
        raise FetchError("partial_changed_during_verification")
    return size, digest


def _validate_download_response(
    response: Any,
    remote: RemoteFile,
    offset: int,
) -> None:
    _require_exact_response_url(response, remote.url)
    if remote.bytes is None:
        raise FetchError("missing_content_length")
    remaining = remote.bytes - offset
    if offset == 0:
        if _response_status(response) != 200:
            raise FetchError("full_download_requires_http_200")
    else:
        if _response_status(response) != 206:
            raise FetchError("resume_requires_http_206")
        match = CONTENT_RANGE.fullmatch(_header(response, "Content-Range") or "")
        if (
            match is None
            or int(match.group("start")) != offset
            or int(match.group("end")) != remote.bytes - 1
            or int(match.group("total")) != remote.bytes
        ):
            raise FetchError("invalid_content_range")
    if _parse_content_length(response) != remaining:
        raise FetchError("download_content_length_mismatch")
    for header, expected in (
        ("ETag", remote.etag),
        ("Last-Modified", remote.last_modified),
    ):
        if expected is not None and _header(response, header) != expected:
            raise FetchError("remote_drift")


def _finalize(
    partial: Path,
    target: Path,
    receipt_path: Path,
    remote: RemoteFile,
    size: int,
    digest: Any,
) -> tuple[str, Path]:
    if remote.bytes is None or size != remote.bytes:
        raise FetchError("download_incomplete")
    try:
        os.link(partial, target, follow_symlinks=False)
    except FileExistsError as error:
        raise FetchError("target_appeared_during_download") from error
    os.unlink(partial)
    _write_receipt(receipt_path, _receipt(remote, size, digest.hexdigest()))
    return "downloaded", target


def download_one(
    remote: RemoteFile,
    raw_dir: Path,
    receipt_dir: Path,
) -> tuple[str, Path]:
    live = head_remote(remote.setup, remote.path, remote.url)
    if live != remote:
        raise FetchError("remote_drift")
    if remote.bytes is None:
        raise FetchError("missing_content_length")

    target = _local_path(raw_dir, remote)
    receipt_path = _receipt_path(receipt_dir, remote)
    if os.path.lexists(target):
        _verify_existing(target, receipt_path, remote)
        return "reused", target
    if os.path.lexists(receipt_path):
        raise FetchError("orphan_receipt")

    partial = target.with_name(f".{target.name}.part")
    offset, digest = _resume_state(partial, remote.bytes)
    if offset == remote.bytes:
        return _finalize(partial, target, receipt_path, remote, offset, digest)

    validator = remote.etag or remote.last_modified
    try:
        with _open(
            _request(
                remote.url,
                method="GET",
                offset=offset if offset else None,
                validator=validator,
            ),
            timeout=120,
        ) as response:
            _validate_download_response(response, remote, offset)
            flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            flags |= os.O_APPEND if offset else os.O_TRUNC
            descriptor = os.open(partial, flags, 0o600)
            with os.fdopen(descriptor, "ab" if offset else "wb") as output:
                os.fchmod(output.fileno(), 0o600)
                if os.fstat(output.fileno()).st_size != offset:
                    raise FetchError("partial_changed_before_append")
                received = offset
                while chunk := response.read(CHUNK_BYTES):
                    received += len(chunk)
                    if received > remote.bytes:
                        raise FetchError("download_exceeded_declared_bytes")
                    output.write(chunk)
                    digest.update(chunk)
                output.flush()
                os.fsync(output.fileno())
    except FetchError:
        raise
    except (OSError, urllib.error.URLError) as error:
        raise FetchError("download_request_failed") from error
    return _finalize(partial, target, receipt_path, remote, received, digest)


def fetch_inventory(
    inventory: Mapping[str, Any],
    *,
    raw_dir: Path,
    receipt_dir: Path,
    workers: int,
    max_total_bytes: int,
    max_file_bytes: int,
) -> list[tuple[str, Path]]:
    if not 1 <= workers <= MAX_WORKERS:
        raise FetchError(f"workers_must_be_between_1_and_{MAX_WORKERS}")
    if max_total_bytes <= 0 or max_file_bytes <= 0:
        raise FetchError("byte_limits_must_be_positive")
    files = [RemoteFile(**value) for value in inventory["files"]]
    files.sort()
    if any(item.bytes is None for item in files):
        raise FetchError("missing_content_length")
    if any((item.bytes or 0) > max_file_bytes for item in files):
        raise FetchError("max_file_bytes_exceeded")
    total_bytes = sum(item.bytes or 0 for item in files)
    if total_bytes > max_total_bytes:
        raise FetchError("max_total_bytes_exceeded")

    def acquire(item: RemoteFile) -> tuple[str, Path]:
        return download_one(item, raw_dir, receipt_dir)

    if not files:
        return []
    worker_count = min(workers, len(files))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        return list(executor.map(acquire, files))


def _catalog() -> dict[str, Any]:
    return {
        "schema": "netbraid.osu_lora_roots.v1",
        "publisher": "Oregon State University",
        "release_note": RELEASE_NOTE,
        "default_action": "list",
        "setups": [
            {
                "setup": name,
                "title": value["title"],
                "root": value["root"],
            }
            for name, value in SETUPS.items()
        ],
    }


def _add_discovery_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("setups", nargs="+", choices=["all", *SETUPS])
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    subparsers.add_parser("list", help="list publisher roots without network access")
    discover_parser = subparsers.add_parser(
        "discover", help="emit a deterministic remote inventory"
    )
    _add_discovery_arguments(discover_parser)
    fetch_parser = subparsers.add_parser(
        "fetch", help="explicitly fetch all inventoried files in selected setups"
    )
    _add_discovery_arguments(fetch_parser)
    repository = Path(__file__).resolve().parents[2]
    fetch_parser.set_defaults(
        raw_dir=repository / "data" / "raw" / "osu-lora",
        receipt_dir=repository / "data" / "receipts" / "osu-lora",
    )
    fetch_parser.add_argument(
        "--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES
    )
    fetch_parser.add_argument(
        "--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES
    )
    actual_argv = list(argv) if argv is not None else sys.argv[1:]
    if not actual_argv:
        actual_argv = ["list"]
    return parser.parse_args(actual_argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    if arguments.action == "list":
        print(json.dumps(_catalog(), indent=2, sort_keys=True))
        return 0
    try:
        inventory = discover(
            arguments.setups,
            max_depth=arguments.max_depth,
            max_entries=arguments.max_entries,
            workers=arguments.workers,
        )
        if arguments.action == "discover":
            print(json.dumps(inventory, indent=2, sort_keys=True))
            return 0
        results = fetch_inventory(
            inventory,
            raw_dir=arguments.raw_dir,
            receipt_dir=arguments.receipt_dir,
            workers=arguments.workers,
            max_total_bytes=arguments.max_total_bytes,
            max_file_bytes=arguments.max_file_bytes,
        )
        for disposition, path in results:
            print(f"{disposition}: {path}")
    except (FetchError, KeyError, TypeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
