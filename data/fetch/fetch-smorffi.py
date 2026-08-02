#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["kagglehub==1.0.2"]
# ///

"""Fetch the pinned public SMoRFFI dataset into ignored local storage.

With no arguments this script verifies local state without using the network.
``list`` prints the fixed source and safety bounds, while ``fetch`` explicitly
downloads Kaggle dataset version 3 through KaggleHub. Kaggle publishes no file
checksums for this dataset, so the ignored receipt contains only a deterministic
local inventory and per-file SHA-256 digests.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import shutil
import stat
import sys
import tempfile
from collections.abc import Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

DATASET_SLUG = "yinchen1986/rffi-123-m5stack-iq-wifi-802-11g-2-4g"
DATASET_VERSION = 3
DATASET_HANDLE = f"{DATASET_SLUG}/versions/{DATASET_VERSION}"
KAGGLEHUB_VERSION = "1.0.2"
SCHEMA = "local.netbraid.smorffi.v1"
CHUNK_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_BYTES = 32 * 1024 * 1024

DEFAULT_MAX_ENTRIES = 25_000
DEFAULT_MAX_FILES = 20_000
DEFAULT_MAX_TOTAL_BYTES = 100 * 1024**3
DEFAULT_MAX_FILE_BYTES = 32 * 1024**3
DEFAULT_MAX_DEPTH = 16

HARD_MAX_ENTRIES = 100_000
HARD_MAX_FILES = 100_000
HARD_MAX_TOTAL_BYTES = 500 * 1024**3
HARD_MAX_FILE_BYTES = 100 * 1024**3
HARD_MAX_DEPTH = 32

REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT_RAW_DIR = REPOSITORY / "data" / "raw" / "smorffi-v3"
DEFAULT_RECEIPT_PATH = REPOSITORY / "data" / "receipts" / "smorffi-v3.json"


class FetchError(RuntimeError):
    """Stable failure at a local-integrity or download boundary."""


@dataclass(frozen=True)
class Bounds:
    max_entries: int = DEFAULT_MAX_ENTRIES
    max_files: int = DEFAULT_MAX_FILES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_depth: int = DEFAULT_MAX_DEPTH

    def checked(self) -> Bounds:
        limits = (
            ("max_entries", self.max_entries, HARD_MAX_ENTRIES),
            ("max_files", self.max_files, HARD_MAX_FILES),
            ("max_total_bytes", self.max_total_bytes, HARD_MAX_TOTAL_BYTES),
            ("max_file_bytes", self.max_file_bytes, HARD_MAX_FILE_BYTES),
            ("max_depth", self.max_depth, HARD_MAX_DEPTH),
        )
        for name, value, hard_maximum in limits:
            if not 1 <= value <= hard_maximum:
                raise FetchError(f"{name}_must_be_between_1_and_{hard_maximum}")
        return self


@dataclass(frozen=True)
class _FileNode:
    relative: str
    fingerprint: tuple[int, int, int, int, int, int]


def _fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_mode,
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_nlink,
    )


def _safe_name(name: str) -> None:
    try:
        name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise FetchError("unsafe_output_name") from error
    if (
        name in {"", ".", ".."}
        or "/" in name
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise FetchError("unsafe_output_name")


def _require_directory(path: Path, error_code: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FetchError(error_code) from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise FetchError(error_code)
    return metadata


def _ensure_directory(path: Path, error_code: str) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as error:
        raise FetchError(error_code) from error
    _require_directory(path, error_code)


def _scan_tree(
    root: Path, bounds: Bounds
) -> tuple[dict[str, tuple[str, tuple[int, int, int, int, int, int]]], list[_FileNode]]:
    root_metadata = _require_directory(root, "unsafe_output_root")
    snapshot = {".": ("directory", _fingerprint(root_metadata))}
    files: list[_FileNode] = []
    entry_count = 0
    total_bytes = 0

    def visit(directory: Path, relative_parent: PurePosixPath) -> None:
        nonlocal entry_count, total_bytes
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError as error:
            raise FetchError("output_changed_during_scan") from error

        for entry in entries:
            _safe_name(entry.name)
            relative = relative_parent / entry.name
            if len(relative.parts) > bounds.max_depth:
                raise FetchError("max_depth_exceeded")
            entry_count += 1
            if entry_count > bounds.max_entries:
                raise FetchError("max_entries_exceeded")
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise FetchError("output_changed_during_scan") from error
            mode = metadata.st_mode
            relative_text = relative.as_posix()
            fingerprint = _fingerprint(metadata)
            if stat.S_ISLNK(mode):
                raise FetchError("symlink_output_rejected")
            if stat.S_ISDIR(mode):
                snapshot[relative_text] = ("directory", fingerprint)
                visit(Path(entry.path), relative)
                continue
            if not stat.S_ISREG(mode):
                raise FetchError("nonregular_output_rejected")
            if metadata.st_nlink != 1:
                raise FetchError("hardlinked_output_rejected")
            if metadata.st_size > bounds.max_file_bytes:
                raise FetchError("max_file_bytes_exceeded")
            files.append(_FileNode(relative_text, fingerprint))
            total_bytes += metadata.st_size
            if len(files) > bounds.max_files:
                raise FetchError("max_files_exceeded")
            if total_bytes > bounds.max_total_bytes:
                raise FetchError("max_total_bytes_exceeded")
            snapshot[relative_text] = ("file", fingerprint)

    visit(root, PurePosixPath())
    return snapshot, files


def _digest_regular_file(
    path: Path,
    expected: tuple[int, int, int, int, int, int],
    bounds: Bounds,
) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FetchError("unsafe_or_changed_output_file") from error
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or _fingerprint(before) != expected
            ):
                raise FetchError("unsafe_or_changed_output_file")
            while chunk := source.read(CHUNK_BYTES):
                size += len(chunk)
                if size > bounds.max_file_bytes:
                    raise FetchError("max_file_bytes_exceeded")
                digest.update(chunk)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise FetchError("output_file_read_failed") from error
    if size != before.st_size or _fingerprint(after) != _fingerprint(before):
        raise FetchError("output_file_changed_during_digest")
    return size, digest.hexdigest()


def inventory_tree(root: Path, bounds: Bounds | None = None) -> dict[str, Any]:
    bounds = (bounds or Bounds()).checked()
    before, file_nodes = _scan_tree(root, bounds)
    files: list[dict[str, Any]] = []
    total_bytes = 0
    for node in file_nodes:
        path = root.joinpath(*PurePosixPath(node.relative).parts)
        size, sha256 = _digest_regular_file(path, node.fingerprint, bounds)
        total_bytes += size
        if total_bytes > bounds.max_total_bytes:
            raise FetchError("max_total_bytes_exceeded")
        files.append({"path": node.relative, "bytes": size, "sha256": sha256})
    after, _ = _scan_tree(root, bounds)
    if before != after:
        raise FetchError("output_tree_changed_during_inventory")
    if not files:
        raise FetchError("empty_dataset_rejected")
    encoded_inventory = json.dumps(
        files, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return {
        "entries": len(before) - 1,
        "directories": sum(kind == "directory" for kind, _ in before.values()) - 1,
        "files": len(files),
        "bytes": total_bytes,
        "local_inventory_sha256": hashlib.sha256(encoded_inventory).hexdigest(),
        "items": files,
    }


def source_receipt(inventory: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "source": {
            "service": "Kaggle",
            "dataset": DATASET_SLUG,
            "version": DATASET_VERSION,
            "handle": DATASET_HANDLE,
        },
        "integrity": {
            "basis": "local_sha256_after_version_pinned_download",
            "inventory": {
                name: inventory[name]
                for name in (
                    "entries",
                    "directories",
                    "files",
                    "bytes",
                    "local_inventory_sha256",
                )
            },
            "files": inventory["items"],
        },
    }


def _read_receipt(path: Path) -> dict[str, Any]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        expected = path.lstat()
        if stat.S_ISLNK(expected.st_mode) or not stat.S_ISREG(expected.st_mode):
            raise FetchError("receipt_missing_or_unsafe")
        descriptor = os.open(path, flags)
    except OSError as error:
        raise FetchError("receipt_missing_or_unsafe") from error
    try:
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or _fingerprint(before) != _fingerprint(expected)
            ):
                raise FetchError("receipt_missing_or_unsafe")
            if before.st_size > MAX_RECEIPT_BYTES:
                raise FetchError("receipt_too_large")
            payload = source.read(MAX_RECEIPT_BYTES + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise FetchError("receipt_read_failed") from error
    if len(payload) > MAX_RECEIPT_BYTES:
        raise FetchError("receipt_too_large")
    if _fingerprint(before) != _fingerprint(after) or len(payload) != before.st_size:
        raise FetchError("receipt_changed_during_read")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FetchError("invalid_receipt") from error
    if not isinstance(value, dict):
        raise FetchError("invalid_receipt")
    return value


def _write_receipt(path: Path, value: dict[str, Any]) -> None:
    _ensure_directory(path.parent, "unsafe_receipt_directory")
    if path.exists() or path.is_symlink():
        raise FetchError("refusing_to_overwrite_receipt")
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent
        )
    except OSError as error:
        raise FetchError("receipt_write_failed") from error
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
        except FileExistsError as error:
            raise FetchError("refusing_to_overwrite_receipt") from error
        except OSError as error:
            raise FetchError("receipt_write_failed") from error
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def verify_local(
    raw_dir: Path = DEFAULT_RAW_DIR,
    receipt_path: Path = DEFAULT_RECEIPT_PATH,
    bounds: Bounds | None = None,
) -> dict[str, Any]:
    bounds = (bounds or Bounds()).checked()
    raw_present = raw_dir.exists() or raw_dir.is_symlink()
    receipt_present = receipt_path.exists() or receipt_path.is_symlink()
    if not raw_present and not receipt_present:
        return {"state": "absent"}
    if not raw_present or not receipt_present:
        raise FetchError("incomplete_local_state")
    inventory = inventory_tree(raw_dir, bounds)
    expected = source_receipt(inventory)
    if _read_receipt(receipt_path) != expected:
        raise FetchError("local_data_or_receipt_mismatch")
    return {
        "state": "verified",
        "inventory": expected["integrity"]["inventory"],
    }


def _load_kagglehub() -> Any:
    try:
        return importlib.import_module("kagglehub")
    except ImportError as error:
        raise FetchError("kagglehub_import_failed") from error


def _validate_download_result(staging: Path, returned: Any) -> None:
    if not isinstance(returned, (str, os.PathLike)):
        raise FetchError("invalid_kagglehub_output_path")
    try:
        staging_resolved = staging.resolve(strict=True)
        returned_path = Path(returned)
        returned_resolved = returned_path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise FetchError("invalid_kagglehub_output_path") from error
    _require_directory(staging, "unsafe_output_root")
    if returned_resolved != staging_resolved:
        raise FetchError("kagglehub_output_escape")


def _remove_staging(staging: Path) -> None:
    try:
        metadata = staging.lstat()
    except FileNotFoundError:
        return
    try:
        if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
            shutil.rmtree(staging)
        else:
            staging.unlink()
    except OSError as error:
        raise FetchError("staging_cleanup_failed") from error


def fetch_dataset(
    raw_dir: Path = DEFAULT_RAW_DIR,
    receipt_path: Path = DEFAULT_RECEIPT_PATH,
    bounds: Bounds | None = None,
    kagglehub_module: Any | None = None,
) -> dict[str, Any]:
    bounds = (bounds or Bounds()).checked()
    local = verify_local(raw_dir, receipt_path, bounds)
    if local["state"] == "verified":
        return {"disposition": "reused", **local}

    _ensure_directory(raw_dir.parent, "unsafe_raw_directory")
    _ensure_directory(receipt_path.parent, "unsafe_receipt_directory")
    if raw_dir.exists() or raw_dir.is_symlink():
        raise FetchError("refusing_to_overwrite_raw_directory")
    if receipt_path.exists() or receipt_path.is_symlink():
        raise FetchError("refusing_to_overwrite_receipt")
    try:
        staging = Path(tempfile.mkdtemp(prefix=f".{raw_dir.name}.", dir=raw_dir.parent))
    except OSError as error:
        raise FetchError("staging_creation_failed") from error
    try:
        kagglehub = (
            kagglehub_module if kagglehub_module is not None else _load_kagglehub()
        )
        try:
            returned = kagglehub.dataset_download(
                DATASET_HANDLE,
                output_dir=str(staging),
            )
        except Exception as error:
            raise FetchError("kagglehub_download_failed") from error
        _validate_download_result(staging, returned)
        inventory = inventory_tree(staging, bounds)
        receipt = source_receipt(inventory)
        second_inventory = inventory_tree(staging, bounds)
        if second_inventory != inventory:
            raise FetchError("output_tree_changed_before_promotion")
        try:
            staging.rename(raw_dir)
        except OSError as error:
            raise FetchError("raw_directory_promotion_failed") from error
        try:
            _write_receipt(receipt_path, receipt)
        except FetchError:
            try:
                raw_dir.rename(staging)
            except OSError as error:
                raise FetchError("receipt_failure_rollback_failed") from error
            raise
    finally:
        _remove_staging(staging)
    return {
        "disposition": "downloaded",
        "state": "verified",
        "inventory": receipt["integrity"]["inventory"],
    }


def _catalog() -> dict[str, Any]:
    return {
        "dataset": DATASET_SLUG,
        "version": DATASET_VERSION,
        "handle": DATASET_HANDLE,
        "dependency": f"kagglehub=={KAGGLEHUB_VERSION}",
        "raw": "data/raw/smorffi-v3",
        "receipt": "data/receipts/smorffi-v3.json",
        "default_bounds": {
            "max_entries": DEFAULT_MAX_ENTRIES,
            "max_files": DEFAULT_MAX_FILES,
            "max_total_bytes": DEFAULT_MAX_TOTAL_BYTES,
            "max_file_bytes": DEFAULT_MAX_FILE_BYTES,
            "max_depth": DEFAULT_MAX_DEPTH,
        },
    }


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", nargs="?", choices=("status", "list", "fetch"), default="status"
    )
    parser.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-total-bytes", type=int, default=DEFAULT_MAX_TOTAL_BYTES)
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    if arguments.command == "list":
        print(json.dumps(_catalog(), indent=2, sort_keys=True))
        return 0
    bounds = Bounds(
        max_entries=arguments.max_entries,
        max_files=arguments.max_files,
        max_total_bytes=arguments.max_total_bytes,
        max_file_bytes=arguments.max_file_bytes,
        max_depth=arguments.max_depth,
    )
    try:
        result = (
            fetch_dataset(DEFAULT_RAW_DIR, DEFAULT_RECEIPT_PATH, bounds)
            if arguments.command == "fetch"
            else verify_local(DEFAULT_RAW_DIR, DEFAULT_RECEIPT_PATH, bounds)
        )
    except FetchError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
