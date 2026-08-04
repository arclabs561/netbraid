#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Compile the pinned SMoRFFI CSV corpus into mmap-ready, path-free artifacts."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RAW = ROOT / "data" / "raw" / "smorffi-v3"
DEFAULT_RECEIPT = ROOT / "data" / "receipts" / "smorffi-v3.json"
DEFAULT_OUTPUT = ROOT / "data" / "derived" / "eval"
DEFAULT_IQ = DEFAULT_OUTPUT / "smorffi-iq.npy"
DEFAULT_OFFSETS = DEFAULT_OUTPUT / "smorffi-row-offsets.npy"
DEFAULT_ADAPTER = DEFAULT_OUTPUT / "smorffi-row-adapter.json"

SCHEMA = "netbraid.smorffi_csv_iq_adapter.v0"
RECEIPT_SCHEMA = "local.netbraid.smorffi.v1"
SOURCE = {
    "service": "Kaggle",
    "dataset": "yinchen1986/rffi-123-m5stack-iq-wifi-802-11g-2-4g",
    "version": 3,
    "handle": "yinchen1986/rffi-123-m5stack-iq-wifi-802-11g-2-4g/versions/3",
}
INTEGRITY_BASIS = "local_sha256_after_version_pinned_download"
CANONICAL_HEADER = ("Device Number", "MAC_address", "preamble")
ANOMALOUS_HEADER_SHA256 = (
    "f559c6150c7f7b0cbb48e76f0e3cb5e7fcc8b9c05badb5a9fcf320808ad9154a"
)

MAX_RECEIPT_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_FILES = 1_000
MAX_ROWS = 20_000_000
MAX_SAMPLES = 2_000_000_000
MAX_SAMPLES_PER_ROW = 65_536
MAX_TOKEN_BYTES = 128
NPY_HEADER_BYTES = 246
CHUNK_BYTES = 4 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ADDRESS = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\Z")
DECIMAL = re.compile(r"[0-9]{1,9}\Z")


class AdapterCompileError(RuntimeError):
    """Stable, path-free reason for rejecting an input or output boundary."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class DuplicateJsonKeyError(ValueError):
    """Raised when a strict JSON object repeats a key."""


@dataclass(frozen=True)
class CorpusContract:
    inventory_sha256: str
    total_bytes: int
    receipt_files: int
    csv_files: int
    rows: int
    samples: int
    minimum_samples_per_row: int
    maximum_samples_per_row: int
    rows_with_288_samples: int
    sources: int
    errata_sha256: frozenset[str]


PRODUCTION_CONTRACT = CorpusContract(
    inventory_sha256="6655ce89fb0c9ef1938267f1042e7be5d633ab05ea4b2b1ad3d6d8f360c2e08f",
    total_bytes=952_050_247,
    receipt_files=124,
    csv_files=123,
    rows=122_511,
    samples=38_561_309,
    minimum_samples_per_row=288,
    maximum_samples_per_row=579,
    rows_with_288_samples=37_288,
    sources=123,
    errata_sha256=frozenset({ANOMALOUS_HEADER_SHA256}),
)


@dataclass(frozen=True)
class ReceiptItem:
    relative: PurePosixPath
    size: int
    sha256: str


class _DigestReader(io.RawIOBase):
    """Hash exact source bytes while a text decoder consumes logical records."""

    def __init__(self, source: BinaryIO):
        self.source = source
        self.digest = hashlib.sha256()
        self.size = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        chunk = self.source.read(len(buffer))
        size = len(chunk)
        if size:
            buffer[:size] = chunk
            self.digest.update(chunk)
            self.size += size
        return size


def _strict_object(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJsonKeyError(key)
        value[key] = item
    return value


def _regular_file_bytes(path: Path, limit: int, code: str) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        expected = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AdapterCompileError(code) from error
    try:
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if (
                stat.S_ISLNK(expected.st_mode)
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > limit
                or (expected.st_dev, expected.st_ino, expected.st_size)
                != (before.st_dev, before.st_ino, before.st_size)
            ):
                raise AdapterCompileError(code)
            payload = source.read(limit + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise AdapterCompileError(code) from error
    if (
        len(payload) > limit
        or len(payload) != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise AdapterCompileError(code)
    return payload


def _relative_path(value: Any) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise AdapterCompileError("invalid_receipt_item")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AdapterCompileError("invalid_receipt_item")
    return path


def _load_receipt(
    path: Path, contract: CorpusContract
) -> tuple[tuple[ReceiptItem, ...], str]:
    payload = _regular_file_bytes(path, MAX_RECEIPT_BYTES, "unsafe_receipt")
    receipt_sha256 = hashlib.sha256(payload).hexdigest()
    try:
        value = json.loads(payload, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJsonKeyError) as error:
        raise AdapterCompileError("invalid_receipt_json") from error
    if not isinstance(value, Mapping) or set(value) != {
        "schema",
        "source",
        "integrity",
    }:
        raise AdapterCompileError("invalid_receipt_schema")
    if value["schema"] != RECEIPT_SCHEMA or value["source"] != SOURCE:
        raise AdapterCompileError("receipt_source_mismatch")
    integrity = value["integrity"]
    if not isinstance(integrity, Mapping) or set(integrity) != {
        "basis",
        "inventory",
        "files",
    }:
        raise AdapterCompileError("invalid_receipt_schema")
    inventory = integrity["inventory"]
    expected_inventory_keys = {
        "entries",
        "directories",
        "files",
        "bytes",
        "local_inventory_sha256",
    }
    if (
        integrity["basis"] != INTEGRITY_BASIS
        or not isinstance(inventory, Mapping)
        or set(inventory) != expected_inventory_keys
        or inventory["files"] != contract.receipt_files
        or inventory["bytes"] != contract.total_bytes
        or inventory["local_inventory_sha256"] != contract.inventory_sha256
    ):
        raise AdapterCompileError("receipt_inventory_mismatch")
    raw_items = integrity["files"]
    if not isinstance(raw_items, list) or len(raw_items) != contract.receipt_files:
        raise AdapterCompileError("invalid_receipt_items")
    items: list[ReceiptItem] = []
    seen: set[PurePosixPath] = set()
    for raw in raw_items:
        if not isinstance(raw, Mapping) or set(raw) != {"path", "bytes", "sha256"}:
            raise AdapterCompileError("invalid_receipt_item")
        relative = _relative_path(raw["path"])
        size = raw["bytes"]
        digest = raw["sha256"]
        if (
            relative in seen
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(digest, str)
            or SHA256.fullmatch(digest) is None
        ):
            raise AdapterCompileError("invalid_receipt_item")
        seen.add(relative)
        items.append(ReceiptItem(relative, size, digest))
    canonical = json.dumps(
        [
            {
                "path": item.relative.as_posix(),
                "bytes": item.size,
                "sha256": item.sha256,
            }
            for item in items
        ],
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if hashlib.sha256(canonical).hexdigest() != contract.inventory_sha256:
        raise AdapterCompileError("receipt_inventory_digest_mismatch")
    csv_count = sum(item.relative.suffix.lower() == ".csv" for item in items)
    if csv_count != contract.csv_files:
        raise AdapterCompileError("receipt_csv_count_mismatch")
    return tuple(items), receipt_sha256


def _open_raw(root: Path, item: ReceiptItem) -> BinaryIO:
    current = root
    for part in item.relative.parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise AdapterCompileError("unsafe_raw_tree") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise AdapterCompileError("unsafe_raw_tree")
    path = root.joinpath(*item.relative.parts)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        source = os.fdopen(descriptor, "rb")
        metadata = os.fstat(source.fileno())
    except OSError as error:
        raise AdapterCompileError("unsafe_raw_file") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        source.close()
        raise AdapterCompileError("unsafe_raw_file")
    if metadata.st_size != item.size:
        source.close()
        raise AdapterCompileError("raw_size_mismatch")
    return source


def _npy_header(dtype: str, length: int) -> bytes:
    if length < 0:
        raise AdapterCompileError("invalid_npy_shape")
    dictionary = repr(
        {"descr": dtype, "fortran_order": False, "shape": (length,)}
    ).encode("latin1")
    if len(dictionary) + 1 > NPY_HEADER_BYTES:
        raise AdapterCompileError("npy_header_overflow")
    body = dictionary + b" " * (NPY_HEADER_BYTES - len(dictionary) - 1) + b"\n"
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(body)) + body


def _temporary_output(path: Path, suffix: str) -> tuple[BinaryIO, Path]:
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = path.parent.lstat()
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
            raise AdapterCompileError("unsafe_output_directory")
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise AdapterCompileError("unsafe_output_path")
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=suffix, dir=path.parent
        )
        os.fchmod(descriptor, 0o600)
        return os.fdopen(descriptor, "w+b"), Path(name)
    except AdapterCompileError:
        raise
    except OSError as error:
        raise AdapterCompileError("output_creation_failed") from error


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError as error:
        raise AdapterCompileError("output_directory_sync_failed") from error
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise AdapterCompileError("output_directory_sync_failed") from error
    finally:
        os.close(descriptor)


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_mmap_artifacts(
    iq_path: Path,
    offsets_path: Path,
    rows: int,
    samples: int,
) -> None:
    try:
        iq = np.load(iq_path, mmap_mode="r", allow_pickle=False)
        offsets = np.load(offsets_path, mmap_mode="r", allow_pickle=False)
    except (OSError, ValueError) as error:
        raise AdapterCompileError("mmap_reopen_failed") from error
    if (
        not isinstance(iq, np.memmap)
        or iq.dtype.str != "<c16"
        or iq.shape != (samples,)
        or not isinstance(offsets, np.memmap)
        or offsets.dtype.str != "<u8"
        or offsets.shape != (rows + 1,)
        or int(offsets[0]) != 0
        or int(offsets[-1]) != samples
        or not bool(np.all(offsets[1:] > offsets[:-1]))
    ):
        raise AdapterCompileError("invalid_mmap_artifacts")


def _opaque(kind: str, value: str) -> str:
    payload = f"netbraid:smorffi:{kind}:v0\0{value}".encode("ascii")
    return f"{kind}-{hashlib.sha256(payload).hexdigest()[:24]}"


def _samples(value: str, maximum: int) -> np.ndarray:
    if (
        len(value.encode("utf-8")) > MAX_LINE_BYTES
        or not value.startswith("[")
        or not value.endswith("]")
    ):
        raise AdapterCompileError("invalid_preamble")
    tokens = value[1:-1].split()
    if not tokens or len(tokens) > maximum:
        raise AdapterCompileError("invalid_sample_count")
    if any(
        len(token.encode("ascii", "ignore")) != len(token)
        or len(token) > MAX_TOKEN_BYTES
        for token in tokens
    ):
        raise AdapterCompileError("invalid_complex_token")
    try:
        samples = np.fromiter(
            (complex(token) for token in tokens), dtype="<c16", count=len(tokens)
        )
    except ValueError as error:
        raise AdapterCompileError("invalid_complex_token") from error
    if not bool(np.isfinite(samples.real).all() and np.isfinite(samples.imag).all()):
        raise AdapterCompileError("nonfinite_sample")
    return samples


def _reject_input_aliases(
    raw_root: Path,
    receipt_path: Path,
    outputs: tuple[Path, Path, Path],
) -> None:
    try:
        raw_resolved = raw_root.resolve(strict=True)
        receipt_resolved = receipt_path.resolve(strict=True)
        output_resolved = tuple(path.resolve(strict=False) for path in outputs)
    except (OSError, RuntimeError) as error:
        raise AdapterCompileError("unsafe_input_or_output_path") from error
    if len(set(output_resolved)) != len(output_resolved):
        raise AdapterCompileError("output_paths_must_be_distinct")
    for output in output_resolved:
        if (
            output == receipt_resolved
            or output == raw_resolved
            or raw_resolved in output.parents
        ):
            raise AdapterCompileError("output_aliases_input")


def _verify_non_csv(root: Path, item: ReceiptItem) -> None:
    digest = hashlib.sha256()
    size = 0
    with _open_raw(root, item) as source:
        while chunk := source.read(CHUNK_BYTES):
            size += len(chunk)
            digest.update(chunk)
    if size != item.size or digest.hexdigest() != item.sha256:
        raise AdapterCompileError("raw_digest_mismatch")


def compile_adapter(
    raw_root: Path,
    receipt_path: Path,
    iq_path: Path,
    offsets_path: Path,
    adapter_path: Path,
    contract: CorpusContract = PRODUCTION_CONTRACT,
    *,
    max_rows: int = MAX_ROWS,
    max_samples: int = MAX_SAMPLES,
    max_samples_per_row: int = MAX_SAMPLES_PER_ROW,
) -> Mapping[str, Any]:
    if len({iq_path, offsets_path, adapter_path}) != 3:
        raise AdapterCompileError("output_paths_must_be_distinct")
    _reject_input_aliases(raw_root, receipt_path, (iq_path, offsets_path, adapter_path))
    items, receipt_sha256 = _load_receipt(receipt_path, contract)
    csv_items = tuple(item for item in items if item.relative.suffix.lower() == ".csv")
    for item in items:
        if item.relative.suffix.lower() != ".csv":
            _verify_non_csv(raw_root, item)

    iq_file, iq_temp = _temporary_output(iq_path, ".npy")
    offsets_file, offsets_temp = _temporary_output(offsets_path, ".npy")
    adapter_temp: Path | None = None
    try:
        iq_file.write(_npy_header("<c16", 0))
        offsets_file.write(_npy_header("<u8", 0))
        offsets_file.write(struct.pack("<Q", 0))
        rows = 0
        sample_count = 0
        minimum_samples_per_row: int | None = None
        maximum_samples_per_row = 0
        rows_with_288_samples = 0
        spans: list[dict[str, Any]] = []
        device_to_address: dict[str, str] = {}
        address_to_device: dict[str, str] = {}
        observed_errata: set[str] = set()

        for item in csv_items:
            row_start = rows
            file_device: str | None = None
            file_address: str | None = None
            with _open_raw(raw_root, item) as source:
                digest_reader = _DigestReader(source)
                buffered = io.BufferedReader(digest_reader, buffer_size=CHUNK_BYTES)
                text = io.TextIOWrapper(buffered, encoding="utf-8-sig", newline="")
                previous_field_limit = csv.field_size_limit(MAX_LINE_BYTES)
                try:
                    reader = csv.reader(text, strict=True)
                    for record_index, raw_cells in enumerate(reader):
                        cells = tuple(raw_cells)
                        if record_index == 0:
                            if cells == CANONICAL_HEADER:
                                continue
                            repairable = (
                                item.sha256 in contract.errata_sha256
                                and len(cells) == 3
                                and cells[0] == CANONICAL_HEADER[0]
                                and ADDRESS.fullmatch(cells[1]) is not None
                                and cells[2] == CANONICAL_HEADER[2]
                            )
                            if not repairable:
                                raise AdapterCompileError("unexpected_csv_header")
                            observed_errata.add(item.sha256)
                            continue
                        if len(cells) != 3:
                            raise AdapterCompileError("invalid_csv_row")
                        device, address, preamble = cells
                        if (
                            DECIMAL.fullmatch(device) is None
                            or ADDRESS.fullmatch(address) is None
                        ):
                            raise AdapterCompileError("invalid_publisher_identity")
                        if file_device is None:
                            file_device, file_address = device, address.lower()
                        elif (device, address.lower()) != (file_device, file_address):
                            raise AdapterCompileError("mixed_identity_file")
                        samples = _samples(preamble, max_samples_per_row)
                        row_samples = int(samples.size)
                        rows += 1
                        sample_count += row_samples
                        minimum_samples_per_row = (
                            row_samples
                            if minimum_samples_per_row is None
                            else min(minimum_samples_per_row, row_samples)
                        )
                        maximum_samples_per_row = max(
                            maximum_samples_per_row, row_samples
                        )
                        rows_with_288_samples += int(row_samples == 288)
                        if rows > max_rows:
                            raise AdapterCompileError("max_rows_exceeded")
                        if sample_count > max_samples:
                            raise AdapterCompileError("max_samples_exceeded")
                        iq_file.write(samples.tobytes(order="C"))
                        offsets_file.write(struct.pack("<Q", sample_count))
                except (csv.Error, UnicodeDecodeError) as error:
                    raise AdapterCompileError("invalid_csv_record") from error
                finally:
                    csv.field_size_limit(previous_field_limit)
            if (
                digest_reader.size != item.size
                or digest_reader.digest.hexdigest() != item.sha256
            ):
                raise AdapterCompileError("raw_digest_mismatch")
            if file_device is None or file_address is None or rows == row_start:
                raise AdapterCompileError("empty_csv_file")
            prior_address = device_to_address.setdefault(file_device, file_address)
            prior_device = address_to_device.setdefault(file_address, file_device)
            if prior_address != file_address or prior_device != file_device:
                raise AdapterCompileError("publisher_identity_not_one_to_one")
            spans.append(
                {
                    "source_file": _opaque("artifact", item.sha256),
                    "physical_source": _opaque("source", file_device),
                    "row_start": row_start,
                    "row_end": rows,
                }
            )

        if observed_errata != set(contract.errata_sha256):
            raise AdapterCompileError("expected_header_erratum_not_observed")
        if (
            rows != contract.rows
            or sample_count != contract.samples
            or minimum_samples_per_row != contract.minimum_samples_per_row
            or maximum_samples_per_row != contract.maximum_samples_per_row
            or rows_with_288_samples != contract.rows_with_288_samples
            or len(device_to_address) != contract.sources
        ):
            raise AdapterCompileError("corpus_cardinality_mismatch")
        iq_file.seek(0)
        iq_file.write(_npy_header("<c16", sample_count))
        offsets_file.seek(0)
        offsets_file.write(_npy_header("<u8", rows + 1))
        for output in (iq_file, offsets_file):
            output.flush()
            os.fsync(output.fileno())
            output.close()

        _validate_mmap_artifacts(iq_temp, offsets_temp, rows, sample_count)
        iq_sha256 = _digest_file(iq_temp)
        offsets_sha256 = _digest_file(offsets_temp)
        adapter: dict[str, Any] = {
            "schema": SCHEMA,
            "provenance": {
                "dataset_version": SOURCE["version"],
                "receipt_schema": RECEIPT_SCHEMA,
                "receipt_sha256": receipt_sha256,
                "local_inventory_sha256": contract.inventory_sha256,
                "integrity_basis": INTEGRITY_BASIS,
                "publisher_checksum_available": False,
                "header_errata_applied": len(observed_errata),
            },
            "artifacts": {
                "iq": {
                    "format": "npy",
                    "dtype": "<c16",
                    "shape": [sample_count],
                    "sha256": iq_sha256,
                },
                "row_offsets": {
                    "format": "npy",
                    "dtype": "<u8",
                    "shape": [rows + 1],
                    "sha256": offsets_sha256,
                },
            },
            "axes": {
                "physical_source": {
                    "state": "publisher_claimed",
                    "groups": len(device_to_address),
                },
                "acquisition_session": {
                    "state": "unknown",
                    "reason": "not_exposed_by_publisher_metadata",
                },
                "receiver": {
                    "state": "unknown",
                    "reason": "not_exposed_by_publisher_metadata",
                },
                "location": {
                    "state": "unknown",
                    "reason": "not_exposed_by_publisher_metadata",
                },
            },
            "counts": {
                "files": len(csv_items),
                "rows": rows,
                "samples": sample_count,
                "spans": len(spans),
                "minimum_samples_per_row": minimum_samples_per_row,
                "maximum_samples_per_row": maximum_samples_per_row,
                "rows_with_288_samples": rows_with_288_samples,
            },
            "source_spans": spans,
            "privacy": {
                "absolute_paths_retained": False,
                "relative_paths_retained": False,
                "publisher_device_values_retained": False,
                "publisher_address_values_retained": False,
                "iq_values_retained_in_adapter": False,
            },
            "limitations": [
                "publisher device labels are claims, not independently verified physical identity",
                "address labels are used only for one-to-one consistency checks",
                "file boundaries and row order are not acquisition-session evidence",
                "the receipt provides local integrity after a version-pinned download, not a publisher checksum",
                "opaque identifiers are deterministic pseudonyms and can be linked by a party holding the ignored receipt",
                "observed row counts and sequence lengths differ from the publisher's nominal corpus description",
            ],
        }
        encoded = (
            json.dumps(adapter, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
        adapter_file, adapter_temp = _temporary_output(adapter_path, ".json")
        adapter_file.write(encoded)
        adapter_file.flush()
        os.fsync(adapter_file.fileno())
        adapter_file.close()
        os.replace(iq_temp, iq_path)
        _fsync_directory(iq_path.parent)
        os.replace(offsets_temp, offsets_path)
        _fsync_directory(offsets_path.parent)
        os.replace(adapter_temp, adapter_path)
        adapter_temp = None
        _fsync_directory(adapter_path.parent)
        return adapter
    except OSError as error:
        raise AdapterCompileError("output_write_failed") from error
    finally:
        with suppress(Exception):
            iq_file.close()
        with suppress(Exception):
            offsets_file.close()
        for temporary in (iq_temp, offsets_temp, adapter_temp):
            if temporary is not None:
                with suppress(FileNotFoundError):
                    temporary.unlink()


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-root", type=Path, default=DEFAULT_RAW)
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT)
    parser.add_argument("--iq", type=Path, default=DEFAULT_IQ)
    parser.add_argument("--row-offsets", type=Path, default=DEFAULT_OFFSETS)
    parser.add_argument("--adapter", type=Path, default=DEFAULT_ADAPTER)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = compile_adapter(
            args.raw_root, args.receipt, args.iq, args.row_offsets, args.adapter
        )
    except AdapterCompileError as error:
        print(error.code, file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"schema": report["schema"], "counts": report["counts"]}, sort_keys=True
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
