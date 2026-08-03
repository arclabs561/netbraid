#!/usr/bin/env python3
"""Profile bounded XRF55 NPY headers before designing a feature cache."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import itertools
import json
import math
import os
import re
import stat
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, BinaryIO

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
DEFAULT_RAW_DIR = ROOT / "data" / "raw"
DEFAULT_RECEIPT_DIR = ROOT / "data" / "receipts" / "xrf55"
DEFAULT_REPORT = ROOT / "data" / "derived" / "eval" / "xrf55-npy-shape-profile.json"
SCHEMA = "netbraid.xrf55_npy_shape_profile.v0"

MAX_MEMBER_BYTES = 64 * 1024**2
MAX_HEADER_BYTES = 64 * 1024
MAX_SIZE_CLASSES_PER_MODALITY = 16
MAX_HEADER_READS = 96
DTYPE_PATTERN = re.compile(r"[<>=|]?(?P<kind>[?biufc])(?P<bytes>1|2|4|8|16|32)\Z")


class Xrf55ShapeProfileError(RuntimeError):
    """Stable failure at the XRF55 NPY-header profiling boundary."""


@dataclass(frozen=True)
class NpyHeader:
    dtype: str
    fortran_order: bool
    shape: tuple[int, ...]
    header_bytes: int
    data_bytes: int


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Xrf55ShapeProfileError("module_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PROFILE = _load_module("_xrf55_shape_layout_profile", HERE / "profile-xrf55-layout.py")


def _read_exact(source: BinaryIO, length: int, code: str) -> bytes:
    value = source.read(length)
    if len(value) != length:
        raise Xrf55ShapeProfileError(code)
    return value


def parse_npy_header(source: BinaryIO, member_bytes: int) -> NpyHeader:
    if not 0 < member_bytes <= MAX_MEMBER_BYTES:
        raise Xrf55ShapeProfileError("npy_member_size_limit")
    if _read_exact(source, 6, "truncated_npy_magic") != b"\x93NUMPY":
        raise Xrf55ShapeProfileError("invalid_npy_magic")
    version = tuple(_read_exact(source, 2, "truncated_npy_version"))
    if version == (1, 0):
        length_bytes = 2
        encoding = "latin1"
    elif version in {(2, 0), (3, 0)}:
        length_bytes = 4
        encoding = "utf-8" if version == (3, 0) else "latin1"
    else:
        raise Xrf55ShapeProfileError("unsupported_npy_version")
    encoded_length = _read_exact(source, length_bytes, "truncated_npy_header_length")
    header_length = int.from_bytes(encoded_length, "little")
    if not 0 < header_length <= MAX_HEADER_BYTES:
        raise Xrf55ShapeProfileError("npy_header_size_limit")
    encoded_header = _read_exact(source, header_length, "truncated_npy_header")
    try:
        document = ast.literal_eval(encoded_header.decode(encoding).strip())
    except (SyntaxError, ValueError, UnicodeDecodeError) as error:
        raise Xrf55ShapeProfileError("invalid_npy_header") from error
    if not isinstance(document, Mapping) or set(document) != {
        "descr",
        "fortran_order",
        "shape",
    }:
        raise Xrf55ShapeProfileError("invalid_npy_header_schema")
    dtype = document["descr"]
    match = DTYPE_PATTERN.fullmatch(dtype) if isinstance(dtype, str) else None
    if match is None:
        raise Xrf55ShapeProfileError("unsupported_npy_dtype")
    fortran_order = document["fortran_order"]
    shape = document["shape"]
    if type(fortran_order) is not bool:
        raise Xrf55ShapeProfileError("invalid_npy_fortran_order")
    if (
        not isinstance(shape, tuple)
        or not 1 <= len(shape) <= 8
        or any(type(value) is not int or value <= 0 for value in shape)
    ):
        raise Xrf55ShapeProfileError("invalid_npy_shape")
    item_bytes = int(match.group("bytes"))
    data_bytes = math.prod(shape) * item_bytes
    header_bytes = 8 + length_bytes + header_length
    if data_bytes <= 0 or header_bytes + data_bytes != member_bytes:
        raise Xrf55ShapeProfileError("npy_member_extent_mismatch")
    return NpyHeader(
        dtype=dtype,
        fortran_order=fortran_order,
        shape=shape,
        header_bytes=header_bytes,
        data_bytes=data_bytes,
    )


def _representative_rank(name: str) -> bytes:
    return hashlib.sha256(
        b"xrf55-npy-shape-representative-v0\0" + name.encode()
    ).digest()


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def profile_shape_archive(
    path: Path,
    expected_bytes: int,
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    inspection = PROFILE.profile_archive(path, expected_bytes, contract)
    try:
        before = path.lstat()
    except OSError as error:
        raise Xrf55ShapeProfileError("archive_unavailable") from error
    expected_identity = (
        inspection.identity.device,
        inspection.identity.inode,
        inspection.identity.size,
        inspection.identity.modified_ns,
        inspection.identity.changed_ns,
    )
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or _identity(before) != expected_identity
    ):
        raise Xrf55ShapeProfileError("archive_changed_after_layout_profile")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Xrf55ShapeProfileError("archive_open_failed") from error
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != expected_identity:
            raise Xrf55ShapeProfileError("archive_identity_changed")
        source = os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise

    class_counts: defaultdict[str, Counter[int]] = defaultdict(Counter)
    representatives: dict[tuple[str, int], zipfile.ZipInfo] = {}
    with source:
        try:
            archive = zipfile.ZipFile(source, mode="r", allowZip64=True)
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
            raise Xrf55ShapeProfileError("invalid_zip_archive") from error
        with archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                parts, _ = PROFILE.safe_member_name(member.filename)
                _, _, _, _, modality = PROFILE.processed_observation(parts, contract)
                if not 0 < member.file_size <= MAX_MEMBER_BYTES:
                    raise Xrf55ShapeProfileError("npy_member_size_limit")
                class_counts[modality][member.file_size] += 1
                key = (modality, member.file_size)
                current = representatives.get(key)
                if current is None or _representative_rank(
                    member.filename
                ) < _representative_rank(current.filename):
                    representatives[key] = member
            if set(class_counts) != {"wifi", "rfid", "mmwave"}:
                raise Xrf55ShapeProfileError("processed_modality_set_mismatch")
            if any(
                len(counts) > MAX_SIZE_CLASSES_PER_MODALITY
                for counts in class_counts.values()
            ):
                raise Xrf55ShapeProfileError("too_many_npy_size_classes")
            if len(representatives) > MAX_HEADER_READS:
                raise Xrf55ShapeProfileError("npy_header_read_limit")

            headers: dict[tuple[str, int], NpyHeader] = {}
            for key in sorted(representatives):
                member = representatives[key]
                try:
                    with archive.open(member, mode="r") as payload:
                        headers[key] = parse_npy_header(payload, member.file_size)
                except Xrf55ShapeProfileError:
                    raise
                except (OSError, RuntimeError, zipfile.BadZipFile) as error:
                    raise Xrf55ShapeProfileError("npy_header_read_failed") from error
        if _identity(os.fstat(source.fileno())) != expected_identity:
            raise Xrf55ShapeProfileError("archive_changed_during_shape_profile")

    modalities = {}
    for modality in sorted(class_counts):
        size_classes = []
        for member_bytes, count in sorted(class_counts[modality].items()):
            header = headers[(modality, member_bytes)]
            size_classes.append(
                {
                    "data_bytes": header.data_bytes,
                    "dtype": header.dtype,
                    "fortran_order": header.fortran_order,
                    "header_bytes": header.header_bytes,
                    "member_bytes": member_bytes,
                    "members": count,
                    "shape": list(header.shape),
                }
            )
        modalities[modality] = {
            "members": sum(class_counts[modality].values()),
            "size_classes": size_classes,
            "total_uncompressed_member_bytes": sum(
                size * count for size, count in class_counts[modality].items()
            ),
        }
    return {
        "header_reads": len(representatives),
        "modalities": modalities,
        "member_payload_bytes_returned": sum(
            header.header_bytes for header in headers.values()
        ),
    }


def profile_corpus(raw_dir: Path, receipt_dir: Path) -> dict[str, Any]:
    selected = {
        name: PROFILE.FETCH.SOURCES[name] for name in PROFILE.PROCESSED_CONTRACTS
    }
    status = PROFILE.FETCH.local_status(selected, raw_dir, receipt_dir)
    archives = {}
    total_header_reads = 0
    total_header_bytes = 0
    event_bytes: defaultdict[str, set[int]] = defaultdict(set)
    for name, spec in selected.items():
        observed = status["datasets"][name]
        valid_receipt = (
            observed["central_receipt_state"] == "valid"
            or observed["legacy_receipt_state"] == "valid"
        )
        if observed["archive_state"] != "present" or not valid_receipt:
            raise Xrf55ShapeProfileError("archive_or_receipt_metadata_unready")
        report = profile_shape_archive(
            raw_dir / str(spec["filename"]),
            int(spec["archive_bytes"]),
            PROFILE.PROCESSED_CONTRACTS[name],
        )
        archives[name] = report
        total_header_reads += report["header_reads"]
        total_header_bytes += report["member_payload_bytes_returned"]
        for modality, modality_report in report["modalities"].items():
            event_bytes[modality].update(
                item["member_bytes"] for item in modality_report["size_classes"]
            )
    combinations = math.prod(len(values) for values in event_bytes.values())
    if combinations > 4096:
        raise Xrf55ShapeProfileError("event_byte_combination_limit")
    complete_event_bytes = {
        sum(values)
        for values in itertools.product(
            *(sorted(event_bytes[name]) for name in ("wifi", "rfid", "mmwave"))
        )
    }
    return {
        "schema": SCHEMA,
        "integrity": {
            "all_archive_bytes_freshly_rehashed": False,
            "basis": "exact_size_and_fetch_receipt_metadata_plus_bounded_npy_headers",
        },
        "archives": archives,
        "counts": {
            "archive_count": len(archives),
            "complete_event_member_bytes_max": max(complete_event_bytes),
            "complete_event_member_bytes_min": min(complete_event_bytes),
            "header_reads": total_header_reads,
            "member_payload_bytes_returned": total_header_bytes,
        },
        "privacy": {
            "array_elements_deserialized": 0,
            "member_names_retained": 0,
            "observation_identifiers_retained": 0,
            "paths_retained": 0,
        },
    }


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise Xrf55ShapeProfileError("unsafe_report_directory")
    if os.path.lexists(path):
        target = path.lstat()
        if stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode):
            raise Xrf55ShapeProfileError("unsafe_report_path")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPT_DIR)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        report = profile_corpus(arguments.raw_dir, arguments.receipt_dir)
        _write_report(arguments.report, report)
    except (
        OSError,
        ValueError,
        PROFILE.Xrf55ProfileError,
        Xrf55ShapeProfileError,
    ) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(report["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
