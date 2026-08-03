#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["h5py==3.16.0"]
# ///

"""Bounded, read-only summaries of HDF5 float64 column windows.

The public result deliberately excludes both the source path and the HDF5
dataset path. ``sum`` and ``sumsq`` include finite values only; ``zero`` is a
subset of ``finite`` and counts both signs of zero.
"""

from __future__ import annotations

import math
import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import BinaryIO

import h5py

MIB = 1024 * 1024
GIB = 1024 * MIB
MAX_SOURCE_BYTES = 8 * GIB
DEFAULT_BYTE_BUDGET = 16 * MIB
HARD_BYTE_BUDGET = 64 * MIB
READ_BLOCK_BYTES = MIB
ROWS = 2
FLOAT64_BYTES = 8


class Hdf5WindowError(ValueError):
    """Stable fail-closed reason for a rejected source or request."""


@dataclass(frozen=True)
class FileIdentity:
    """Fields that must remain stable for the lifetime of one read."""

    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


def _identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _regular_path_identity(path: Path) -> FileIdentity:
    try:
        metadata = path.lstat()
    except (OSError, ValueError) as error:
        raise Hdf5WindowError("source_unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise Hdf5WindowError("source_not_regular")
    if not 0 < metadata.st_size <= MAX_SOURCE_BYTES:
        raise Hdf5WindowError("source_size_limit")
    return _identity(metadata)


def _open_source(path: Path) -> tuple[BinaryIO, FileIdentity]:
    expected = _regular_path_identity(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise Hdf5WindowError("source_open_failed") from error
    try:
        source = os.fdopen(descriptor, "rb")
    except Exception:
        os.close(descriptor)
        raise
    try:
        opened = _identity(os.fstat(source.fileno()))
    except OSError as error:
        source.close()
        raise Hdf5WindowError("source_stat_failed") from error
    if opened != expected:
        source.close()
        raise Hdf5WindowError("source_identity_changed")
    return source, opened


def _require_source_unchanged(
    path: Path, source: BinaryIO, expected: FileIdentity
) -> None:
    try:
        opened = _identity(os.fstat(source.fileno()))
        current_metadata = path.lstat()
    except (OSError, ValueError) as error:
        raise Hdf5WindowError("source_changed_during_read") from error
    if (
        stat.S_ISLNK(current_metadata.st_mode)
        or not stat.S_ISREG(current_metadata.st_mode)
        or opened != expected
        or _identity(current_metadata) != expected
    ):
        raise Hdf5WindowError("source_changed_during_read")


def _dataset_parts(dataset_path: str) -> tuple[str, ...]:
    if not isinstance(dataset_path, str) or not dataset_path or "\x00" in dataset_path:
        raise Hdf5WindowError("invalid_dataset_path")
    normalized = dataset_path[1:] if dataset_path.startswith("/") else dataset_path
    parts = tuple(normalized.split("/"))
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise Hdf5WindowError("invalid_dataset_path")
    return parts


def _direct_dataset(root: h5py.File, dataset_path: str) -> h5py.Dataset:
    current: h5py.Group = root
    parts = _dataset_parts(dataset_path)
    for index, part in enumerate(parts):
        link = current.get(part, getlink=True)
        if type(link) is not h5py.HardLink:
            raise Hdf5WindowError("unsafe_dataset_link")
        value = current.get(part, getlink=False)
        if index == len(parts) - 1:
            if not isinstance(value, h5py.Dataset):
                raise Hdf5WindowError("dataset_not_found")
            try:
                link_count = h5py.h5o.get_info(value.id).rc
            except (RuntimeError, ValueError) as error:
                raise Hdf5WindowError("dataset_metadata_unavailable") from error
            if link_count != 1:
                raise Hdf5WindowError("unsafe_dataset_link")
            return value
        if not isinstance(value, h5py.Group):
            raise Hdf5WindowError("dataset_not_found")
        current = value
    raise Hdf5WindowError("dataset_not_found")


def _require_dataset_contract(dataset: h5py.Dataset) -> None:
    try:
        creation = dataset.id.get_create_plist()
        external_count = creation.get_external_count()
        filter_ids = tuple(
            creation.get_filter(index)[0] for index in range(creation.get_nfilters())
        )
        link_shape = dataset.shape
        chunks = dataset.chunks
        is_virtual = dataset.is_virtual
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
        raise Hdf5WindowError("dataset_metadata_unavailable") from error

    if external_count != 0 or is_virtual:
        raise Hdf5WindowError("unsafe_dataset_storage")
    if dataset.ndim != 2 or len(link_shape) != 2 or link_shape[0] != ROWS:
        raise Hdf5WindowError("invalid_dataset_shape")
    if (
        dataset.dtype.kind != "f"
        or dataset.dtype.itemsize != FLOAT64_BYTES
        or dataset.dtype.fields is not None
    ):
        raise Hdf5WindowError("invalid_dataset_dtype")
    if (
        creation.get_layout() != h5py.h5d.CHUNKED
        or chunks is None
        or len(chunks) != 2
        or dataset.compression != "gzip"
        or filter_ids != (h5py.h5z.FILTER_DEFLATE,)
    ):
        raise Hdf5WindowError("invalid_dataset_filters")
    chunk_bytes = math.prod(chunks) * FLOAT64_BYTES
    if not 0 < chunk_bytes <= HARD_BYTE_BUDGET:
        raise Hdf5WindowError("dataset_chunk_size_limit")


def _validate_request(
    column_start: int,
    column_stop: int,
    byte_budget: int,
    column_extent: int,
) -> tuple[int, int]:
    if type(column_start) is not int or type(column_stop) is not int:
        raise Hdf5WindowError("invalid_column_interval")
    if column_start < 0 or column_stop <= column_start or column_start >= column_extent:
        raise Hdf5WindowError("invalid_column_interval")
    if type(byte_budget) is not int or not 0 < byte_budget <= HARD_BYTE_BUDGET:
        raise Hdf5WindowError("invalid_byte_budget")
    selected_stop = min(column_stop, column_extent)
    selected_bytes = (selected_stop - column_start) * ROWS * FLOAT64_BYTES
    if selected_bytes > byte_budget:
        raise Hdf5WindowError("byte_budget_exceeded")
    return selected_stop, selected_bytes


def _read_hyperslab(dataset: h5py.Dataset, column_start: int, column_stop: int):
    return dataset[:, column_start:column_stop]


def _empty_row_aggregate() -> dict[str, int | float]:
    return {"finite": 0, "nonfinite": 0, "zero": 0, "sum": 0.0, "sumsq": 0.0}


def _accumulate_row(
    aggregate: dict[str, int | float], values: Iterable[object]
) -> None:
    for raw_value in values:
        value = float(raw_value)
        if not math.isfinite(value):
            aggregate["nonfinite"] += 1
            continue
        aggregate["finite"] += 1
        if value == 0.0:
            aggregate["zero"] += 1
        aggregate["sum"] += value
        aggregate["sumsq"] += value * value


def _summarize(
    dataset: h5py.Dataset, column_start: int, column_stop: int
) -> list[dict[str, int | float]]:
    aggregates = [_empty_row_aggregate() for _ in range(ROWS)]
    columns_per_block = max(1, READ_BLOCK_BYTES // (ROWS * FLOAT64_BYTES))
    cursor = column_start
    while cursor < column_stop:
        block_stop = min(cursor + columns_per_block, column_stop)
        slab = _read_hyperslab(dataset, cursor, block_stop)
        if slab.shape != (ROWS, block_stop - cursor):
            raise Hdf5WindowError("hyperslab_shape_mismatch")
        for row_index, aggregate in enumerate(aggregates):
            _accumulate_row(aggregate, slab[row_index])
        del slab
        cursor = block_stop
    return aggregates


def read_column_window(
    source_path: str | PathLike[str],
    dataset_path: str,
    column_start: int,
    column_stop: int,
    *,
    byte_budget: int = DEFAULT_BYTE_BUDGET,
) -> dict[str, object]:
    """Summarize one bounded half-open column interval from a safe dataset.

    ``column_stop`` may exceed the dataset extent; the selected interval is
    truncated and the result records that fact. The uncompressed selected
    payload must fit ``byte_budget`` and the absolute 64 MiB hard limit.
    """

    try:
        path = Path(source_path)
    except (TypeError, ValueError) as error:
        raise Hdf5WindowError("invalid_source_path") from error
    source, identity = _open_source(path)
    try:
        try:
            with h5py.File(source, "r") as hdf5:
                dataset = _direct_dataset(hdf5, dataset_path)
                _require_dataset_contract(dataset)
                selected_stop, selected_bytes = _validate_request(
                    column_start,
                    column_stop,
                    byte_budget,
                    int(dataset.shape[1]),
                )
                rows = _summarize(dataset, column_start, selected_stop)
                result: dict[str, object] = {
                    "dataset": {
                        "rank": 2,
                        "shape": [ROWS, int(dataset.shape[1])],
                        "dtype": "float64",
                        "chunks": [int(value) for value in dataset.chunks or ()],
                        "compression": "gzip",
                    },
                    "requested_interval": {
                        "start": column_start,
                        "stop": column_stop,
                    },
                    "selected_interval": {
                        "start": column_start,
                        "stop": selected_stop,
                    },
                    "selected_bytes": selected_bytes,
                    "truncated": selected_stop != column_stop,
                    "rows": rows,
                }
            _require_source_unchanged(path, source, identity)
        except Hdf5WindowError:
            raise
        except (KeyError, OSError, RuntimeError, TypeError, ValueError) as error:
            try:
                _require_source_unchanged(path, source, identity)
            except Hdf5WindowError as changed:
                raise changed from error
            raise Hdf5WindowError("hdf5_read_failed") from error
    finally:
        source.close()
    return result


__all__ = [
    "DEFAULT_BYTE_BUDGET",
    "HARD_BYTE_BUDGET",
    "MAX_SOURCE_BYTES",
    "Hdf5WindowError",
    "read_column_window",
]
