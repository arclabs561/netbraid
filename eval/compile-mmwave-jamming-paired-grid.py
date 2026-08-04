#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2", "scipy==1.17.1"]
# ///
"""Compile a fixed, pair-aligned content grid from the mmWave MAT corpus."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import stat
import sys
import tempfile
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, BinaryIO

import numpy as np
from scipy.io import loadmat, whosmat

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
SCHEMA = "netbraid.mmwave_jamming_paired_grid_cache.v0"
GRID_SHAPE = (16, 16, 8)
COMPONENTS = ("real", "imaginary")
MATRIX_DTYPE = np.dtype("<f4")
EXPECTED_OBSERVATIONS = 80
EXPECTED_PAIRS = 40
MAX_SOURCE_BYTES = 32 * 1024**2
MAX_ARRAY_BYTES = 256 * 1024**2
MAX_ADAPTER_BYTES = 256 * 1024
READ_CHUNK_BYTES = 1024**2


class PairedGridCompileError(RuntimeError):
    """Stable fail-closed rejection at the paired-grid boundary."""


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise PairedGridCompileError("module_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


COMPILER = _load_module(
    "_mmwave_jamming_oracle_compiler_for_paired_grid",
    HERE / "compile-mmwave-jamming-oracles.py",
)


@dataclass(frozen=True)
class GridInput:
    path: Path
    expected_bytes: int
    expected_md5: str
    expected_sha256: str
    observation_id: str
    pair_group_id: str


@dataclass(frozen=True)
class MatLayout:
    variable_name: str
    shape: tuple[int, int, int]


@dataclass(frozen=True)
class OutputSet:
    adapter: Path
    matrix: Path


def _validate_digest(value: str, length: int, error_code: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PairedGridCompileError(error_code)


def _validate_inputs(
    inputs: Sequence[GridInput], *, expected_pairs: int
) -> tuple[GridInput, ...]:
    if (
        type(expected_pairs) is not int
        or expected_pairs <= 0
        or len(inputs) != expected_pairs * 2
        or len(inputs) > EXPECTED_OBSERVATIONS
    ):
        raise PairedGridCompileError("invalid_pair_inventory")
    ordered = tuple(sorted(inputs, key=lambda item: item.observation_id))
    if len({item.observation_id for item in ordered}) != len(ordered):
        raise PairedGridCompileError("duplicate_observation_id")
    if len({os.fspath(item.path) for item in ordered}) != len(ordered):
        raise PairedGridCompileError("duplicate_source_path")
    pairs: dict[str, list[GridInput]] = defaultdict(list)
    for item in ordered:
        if (
            type(item.expected_bytes) is not int
            or not 0 < item.expected_bytes <= MAX_SOURCE_BYTES
        ):
            raise PairedGridCompileError("invalid_pair_inventory")
        _validate_digest(item.expected_md5, 32, "invalid_expected_md5")
        _validate_digest(item.expected_sha256, 64, "invalid_expected_sha256")
        _validate_digest(item.observation_id, 64, "invalid_observation_id")
        _validate_digest(item.pair_group_id, 64, "invalid_pair_group_id")
        pairs[item.pair_group_id].append(item)
    if len(pairs) != expected_pairs or any(
        len(members) != 2 for members in pairs.values()
    ):
        raise PairedGridCompileError("invalid_pair_inventory")
    return ordered


def _open_source(item: GridInput) -> tuple[int, Any]:
    try:
        before_path = item.path.lstat()
    except OSError as error:
        raise PairedGridCompileError("source_unavailable") from error
    if (
        not stat.S_ISREG(before_path.st_mode)
        or before_path.st_size != item.expected_bytes
    ):
        raise PairedGridCompileError("source_missing_or_unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(item.path, flags)
    except OSError as error:
        raise PairedGridCompileError("source_open_failed") from error
    try:
        identity = COMPILER._identity(descriptor)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or identity.size != item.expected_bytes
            or identity.device != before_path.st_dev
            or identity.inode != before_path.st_ino
        ):
            raise PairedGridCompileError("source_changed_before_read")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _mat_layout(source: BinaryIO) -> MatLayout:
    header = source.read(128)
    if len(header) != 128 or not header.startswith(b"MATLAB 5.0 MAT-file"):
        raise PairedGridCompileError("unsupported_mat_container")
    source.seek(0)
    try:
        variables = whosmat(source, appendmat=False)
    except Exception as error:
        raise PairedGridCompileError("mat_metadata_parse_failed") from error
    if len(variables) != 1:
        raise PairedGridCompileError("mat_variable_count_mismatch")
    variable_name, raw_shape, data_class = variables[0]
    if (
        not isinstance(variable_name, str)
        or not variable_name
        or not isinstance(raw_shape, tuple)
        or len(raw_shape) != 3
        or data_class != "double"
    ):
        raise PairedGridCompileError("mat_layout_unsupported")
    shape = tuple(int(value) for value in raw_shape)
    if any(type(value) is not int or value <= 0 for value in shape):
        raise PairedGridCompileError("mat_shape_unsupported")
    if math.prod(shape) * np.dtype("<c16").itemsize > MAX_ARRAY_BYTES:
        raise PairedGridCompileError("mat_array_byte_limit")
    return MatLayout(variable_name, shape)


def inspect_layout(item: GridInput) -> MatLayout:
    descriptor, identity = _open_source(item)
    with os.fdopen(descriptor, "rb") as source:
        layout = _mat_layout(source)
        if COMPILER._identity(source.fileno()) != identity:
            raise PairedGridCompileError("source_changed_during_metadata_read")
    return layout


def stratified_indices(extent: int, count: int) -> np.ndarray:
    """Return exact endpoint-inclusive integer indices without float rounding."""

    if type(extent) is not int or type(count) is not int or count < 2 or extent < count:
        raise PairedGridCompileError("insufficient_common_extent")
    indices = np.asarray(
        [index * (extent - 1) // (count - 1) for index in range(count)],
        dtype=np.int64,
    )
    if (
        len(set(indices.tolist())) != count
        or indices[0] != 0
        or indices[-1] != extent - 1
    ):
        raise PairedGridCompileError("invalid_stratified_indices")
    return indices


def shared_pair_indices(
    left: MatLayout, right: MatLayout
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    common_shape = tuple(
        min(a, b) for a, b in zip(left.shape, right.shape, strict=True)
    )
    return tuple(
        stratified_indices(extent, count)
        for extent, count in zip(common_shape, GRID_SHAPE, strict=True)
    )


def _verified_load(item: GridInput, layout: MatLayout) -> np.ndarray:
    descriptor, identity = _open_source(item)
    try:
        try:
            actual_md5, actual_sha256 = COMPILER._digest_artifact(
                descriptor, identity, mmap_min_bytes=COMPILER.MMAP_MIN_BYTES
            )
        except COMPILER.OracleCompileError as error:
            raise PairedGridCompileError(str(error)) from error
        if actual_md5 != item.expected_md5 or actual_sha256 != item.expected_sha256:
            raise PairedGridCompileError("source_digest_mismatch")
        os.lseek(descriptor, 0, os.SEEK_SET)
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            try:
                document = loadmat(
                    source,
                    appendmat=False,
                    variable_names=[layout.variable_name],
                    squeeze_me=False,
                    chars_as_strings=False,
                    mat_dtype=False,
                    struct_as_record=True,
                    verify_compressed_data_integrity=True,
                )
            except Exception as error:
                raise PairedGridCompileError("mat_payload_parse_failed") from error
            if COMPILER._identity(source.fileno()) != identity:
                raise PairedGridCompileError("source_changed_during_payload_read")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    array = document.get(layout.variable_name)
    if (
        not isinstance(array, np.ndarray)
        or array.shape != layout.shape
        or array.ndim != 3
        or array.dtype.kind not in {"f", "c"}
        or array.nbytes > MAX_ARRAY_BYTES
    ):
        raise PairedGridCompileError("mat_payload_layout_mismatch")
    return array


def extract_grid(
    item: GridInput,
    layout: MatLayout,
    indices: tuple[np.ndarray, np.ndarray, np.ndarray],
) -> np.ndarray:
    array = _verified_load(item, layout)
    selected = array[np.ix_(*indices)]
    if selected.shape != GRID_SHAPE or not np.isfinite(selected).all():
        raise PairedGridCompileError("selected_grid_invalid")
    grid = np.empty((*GRID_SHAPE, len(COMPONENTS)), dtype=MATRIX_DTYPE)
    grid[..., 0] = np.real(selected)
    grid[..., 1] = np.imag(selected)
    if not np.isfinite(grid).all():
        raise PairedGridCompileError("selected_grid_float32_invalid")
    return grid


def _prepare_target(path: Path) -> None:
    if path.name in {"", ".", ".."} or path.name.startswith("."):
        raise PairedGridCompileError("unsafe_output_path")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise PairedGridCompileError("unsafe_output_directory")
    if os.path.lexists(path):
        target = path.lstat()
        if stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode):
            raise PairedGridCompileError("unsafe_output_path")


def _hash_file(path: str | Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as source:
        while chunk := source.read(READ_CHUNK_BYTES):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _write_matrix_temporary(
    target: Path,
    ordered: Sequence[GridInput],
    layouts: Mapping[str, MatLayout],
) -> tuple[str, str, int]:
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=target.parent
    )
    os.fchmod(descriptor, 0o600)
    os.close(descriptor)
    matrix = None
    try:
        matrix = np.lib.format.open_memmap(
            temporary,
            mode="w+",
            dtype=MATRIX_DTYPE,
            shape=(len(ordered), *GRID_SHAPE, len(COMPONENTS)),
        )
        row_by_id = {item.observation_id: row for row, item in enumerate(ordered)}
        pairs: dict[str, list[GridInput]] = defaultdict(list)
        for item in ordered:
            pairs[item.pair_group_id].append(item)
        for pair_group_id in sorted(pairs):
            left, right = pairs[pair_group_id]
            indices = shared_pair_indices(
                layouts[left.observation_id], layouts[right.observation_id]
            )
            for item in (left, right):
                matrix[row_by_id[item.observation_id]] = extract_grid(
                    item, layouts[item.observation_id], indices
                )
        matrix.flush()
        del matrix
        matrix = None
        sync_descriptor = os.open(temporary, os.O_RDONLY)
        try:
            os.fsync(sync_descriptor)
        finally:
            os.close(sync_descriptor)
        mapped = np.load(temporary, mmap_mode="r", allow_pickle=False)
        if (
            not isinstance(mapped, np.memmap)
            or mapped.flags.writeable
            or mapped.dtype != MATRIX_DTYPE
            or mapped.shape != (len(ordered), *GRID_SHAPE, len(COMPONENTS))
            or not np.isfinite(mapped).all()
        ):
            raise PairedGridCompileError("written_matrix_verification_failed")
        del mapped
        digest, size = _hash_file(temporary)
        return temporary, digest, size
    except BaseException:
        if matrix is not None:
            del matrix
        if os.path.lexists(temporary):
            os.unlink(temporary)
        raise


def _adapter_document(
    ordered: Sequence[GridInput],
    *,
    inventory_id: str,
    oracle_schema: str,
    matrix_sha256: str,
    matrix_bytes: int,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "provenance": {
            "publisher": "Zenodo",
            "record_id": COMPILER.SELECTED_RECORD_ID,
            "doi": f"10.5281/zenodo.{COMPILER.SELECTED_RECORD_ID}",
            "oracle_schema": oracle_schema,
            "oracle_inventory_id": inventory_id,
            "admission": "exact_size_md5_sha256_and_local_receipt",
        },
        "grid_policy": {
            "source_axes": ["adc_sample", "chirp", "frame"],
            "pair_alignment": "elementwise_common_extent_then_shared_indices",
            "index_policy": "endpoint_inclusive_integer_stratification_v0",
            "grid_shape": [*GRID_SHAPE, len(COMPONENTS)],
            "components": list(COMPONENTS),
            "dtype": MATRIX_DTYPE.str,
        },
        "matrix": {
            "format": "npy",
            "shape": [len(ordered), *GRID_SHAPE, len(COMPONENTS)],
            "dtype": MATRIX_DTYPE.str,
            "sha256": matrix_sha256,
            "bytes": matrix_bytes,
            "model_values": "selected_payload_content_only",
        },
        "rows": [
            {"observation_id": item.observation_id, "row": row}
            for row, item in enumerate(ordered)
        ],
        "counts": {
            "observations": len(ordered),
            "paired_cells": len(ordered) // 2,
            "values_per_observation": math.prod(GRID_SHAPE) * len(COMPONENTS),
        },
        "privacy": {
            "condition_labels_retained": 0,
            "filenames_retained": 0,
            "local_paths_retained": 0,
            "mat_variable_names_retained": 0,
            "pair_group_ids_retained": 0,
            "source_byte_counts_retained": 0,
            "source_digests_retained": 0,
            "source_shapes_retained": 0,
            "source_urls_retained": 0,
            "storage_encodings_retained": 0,
        },
    }


def _render_adapter(document: Mapping[str, Any]) -> bytes:
    try:
        encoded = (
            json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise PairedGridCompileError("adapter_not_json_serializable") from error
    if len(encoded) > MAX_ADAPTER_BYTES:
        raise PairedGridCompileError("adapter_byte_limit")
    return encoded


def _write_adapter_temporary(target: Path, encoded: bytes) -> str:
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{target.name}.", dir=target.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        return temporary
    except BaseException:
        if os.path.lexists(temporary):
            os.unlink(temporary)
        raise


def write_cache(
    outputs: OutputSet,
    inputs: Sequence[GridInput],
    *,
    inventory_id: str,
    oracle_schema: str,
    expected_pairs: int,
) -> dict[str, Any]:
    ordered = _validate_inputs(inputs, expected_pairs=expected_pairs)
    if outputs.adapter.resolve(strict=False) == outputs.matrix.resolve(strict=False):
        raise PairedGridCompileError("duplicate_output_path")
    for path in (outputs.adapter, outputs.matrix):
        _prepare_target(path)
    layouts = {item.observation_id: inspect_layout(item) for item in ordered}
    inode_keys = {
        (
            item.path.stat(follow_symlinks=False).st_dev,
            item.path.stat(follow_symlinks=False).st_ino,
        )
        for item in ordered
    }
    if len(inode_keys) != len(ordered):
        raise PairedGridCompileError("source_file_collision")

    matrix_temporary = None
    adapter_temporary = None
    try:
        matrix_temporary, matrix_sha256, matrix_bytes = _write_matrix_temporary(
            outputs.matrix, ordered, layouts
        )
        adapter = _adapter_document(
            ordered,
            inventory_id=inventory_id,
            oracle_schema=oracle_schema,
            matrix_sha256=matrix_sha256,
            matrix_bytes=matrix_bytes,
        )
        encoded = _render_adapter(adapter)
        forbidden = [
            *(item.path.name for item in ordered),
            *(os.path.abspath(os.fspath(item.path)) for item in ordered),
            *(item.pair_group_id for item in ordered),
            *(item.expected_md5 for item in ordered),
            *(item.expected_sha256 for item in ordered),
        ]
        decoded = encoded.decode("ascii")
        if any(value and value in decoded for value in forbidden):
            raise PairedGridCompileError("private_source_value_retained")
        adapter_temporary = _write_adapter_temporary(outputs.adapter, encoded)
        os.replace(matrix_temporary, outputs.matrix)
        matrix_temporary = None
        os.replace(adapter_temporary, outputs.adapter)
        adapter_temporary = None
        return adapter
    finally:
        for temporary in (matrix_temporary, adapter_temporary):
            if temporary is not None and os.path.lexists(temporary):
                os.unlink(temporary)


def _receipt_sha256(receipt_dir: Path, artifact: Any) -> str:
    receipt = COMPILER._read_json_path(
        receipt_dir / f"{artifact.filename}.json",
        COMPILER.MAX_RECEIPT_BYTES,
        "receipt_missing_or_unsafe",
    )
    integrity = receipt.get("integrity")
    if not isinstance(integrity, Mapping):
        raise PairedGridCompileError("receipt_schema_drift")
    sha256 = integrity.get("sha256")
    if not isinstance(sha256, str):
        raise PairedGridCompileError("invalid_receipt_sha256")
    try:
        COMPILER._validate_receipt(receipt, artifact, sha256)
    except COMPILER.OracleCompileError as error:
        raise PairedGridCompileError(str(error)) from error
    return sha256


def production_inputs(
    manifest: Path, raw_dir: Path, receipt_dir: Path
) -> tuple[tuple[GridInput, ...], dict[str, Any]]:
    inventory = COMPILER.compile_inventory(manifest, raw_dir, receipt_dir)
    observations = {
        (
            item["receiver_element"],
            item["radar_regime"],
            item["controlled_jamming_cause"],
            item["target_count"],
        ): item
        for item in inventory["observations"]
    }
    inputs = []
    for artifact in COMPILER.load_artifacts(manifest):
        cell = artifact.cell
        observation = observations.get(
            (
                cell.receiver_element,
                cell.radar_regime,
                cell.controlled_jamming_cause,
                cell.target_count,
            )
        )
        if observation is None:
            raise PairedGridCompileError("oracle_artifact_mapping_mismatch")
        inputs.append(
            GridInput(
                path=raw_dir / artifact.filename,
                expected_bytes=artifact.byte_count,
                expected_md5=artifact.md5,
                expected_sha256=_receipt_sha256(receipt_dir, artifact),
                observation_id=observation["observation_id"],
                pair_group_id=observation["paired_cell_group"]["group_id"],
            )
        )
    return tuple(inputs), inventory


def compile_corpus(
    manifest: Path,
    raw_dir: Path,
    receipt_dir: Path,
    outputs: OutputSet,
) -> dict[str, Any]:
    inputs, inventory = production_inputs(manifest, raw_dir, receipt_dir)
    return write_cache(
        outputs,
        inputs,
        inventory_id=inventory["inventory_id"],
        oracle_schema=inventory["schema"],
        expected_pairs=EXPECTED_PAIRS,
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--manifest",
        type=Path,
        default=ROOT / "data" / "catalog" / "controlled-jamming-artifacts-v1.json",
    )
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=ROOT / "data" / "raw" / "controlled-jamming" / "6516954",
    )
    parser.add_argument(
        "--receipt-dir",
        type=Path,
        default=ROOT / "data" / "receipts" / "controlled-jamming" / "6516954",
    )
    parser.add_argument(
        "--adapter",
        type=Path,
        default=ROOT
        / "data"
        / "derived"
        / "eval"
        / "mmwave-jamming-paired-grid-adapter.json",
    )
    parser.add_argument(
        "--matrix",
        type=Path,
        default=ROOT / "data" / "derived" / "eval" / "mmwave-jamming-paired-grid.npy",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        adapter = compile_corpus(
            arguments.manifest,
            arguments.raw_dir,
            arguments.receipt_dir,
            OutputSet(arguments.adapter, arguments.matrix),
        )
    except (
        COMPILER.OracleCompileError,
        OSError,
        PairedGridCompileError,
        ValueError,
    ) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(adapter["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
