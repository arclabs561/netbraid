#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["scipy==1.17.1"]
# ///
"""Audit condition leakage in bounded MAT layout and storage metadata."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Sequence

from scipy.io import whosmat

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.mmwave_jamming_mat_layout_profile.v0"
MIB = 1024 * 1024
MAX_ARTIFACTS = 80
MAX_ARTIFACT_BYTES = 32 * MIB
MAX_TOTAL_BYTES = 1024 * MIB
MAX_VARIABLES_PER_ARTIFACT = 64
MAX_VARIABLE_NAME_BYTES = 128
MAX_RANK = 8
MAX_DIMENSION = 1_000_000_000
MAX_REPORT_BYTES = 128 * 1024
CLASS_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,31}\Z")

COMPILER_PATH = Path(__file__).with_name("compile-mmwave-jamming-oracles.py")
COMPILER_SPEC = importlib.util.spec_from_file_location(
    "netbraid_compile_mmwave_jamming_oracles_for_layout", COMPILER_PATH
)
if COMPILER_SPEC is None or COMPILER_SPEC.loader is None:
    raise RuntimeError("oracle_compiler_unavailable")
COMPILER = importlib.util.module_from_spec(COMPILER_SPEC)
sys.modules[COMPILER_SPEC.name] = COMPILER
COMPILER_SPEC.loader.exec_module(COMPILER)


class LayoutProfileError(RuntimeError):
    """Stable fail-closed rejection at the MAT metadata boundary."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True)
class ProfileInput:
    path: Path
    expected_bytes: int
    pair_group: str
    condition: str


@dataclass(frozen=True)
class LayoutFacts:
    signature: tuple[tuple[str, tuple[int, ...], str], ...]
    extent_bytes: int

    @property
    def extent_mib_class(self) -> int:
        return self.extent_bytes // MIB


def _identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _open_input(record: ProfileInput) -> tuple[BinaryIO, FileIdentity]:
    if (
        isinstance(record.expected_bytes, bool)
        or not isinstance(record.expected_bytes, int)
        or record.expected_bytes <= 0
        or record.expected_bytes > MAX_ARTIFACT_BYTES
    ):
        raise LayoutProfileError("artifact_byte_limit")
    try:
        before = record.path.lstat()
    except OSError as error:
        raise LayoutProfileError("artifact_unavailable") from error
    if not stat.S_ISREG(before.st_mode) or before.st_size != record.expected_bytes:
        raise LayoutProfileError("artifact_missing_or_unsafe")
    expected = _identity(before)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(record.path, flags)
    except OSError as error:
        raise LayoutProfileError("artifact_open_failed") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _identity(opened) != expected:
            raise LayoutProfileError("artifact_changed_before_read")
        return os.fdopen(descriptor, "rb"), expected
    except BaseException:
        os.close(descriptor)
        raise


def _mat_v5_header(source: BinaryIO) -> None:
    header = source.read(128)
    if len(header) != 128 or not header.startswith(b"MATLAB 5.0 MAT-file"):
        raise LayoutProfileError("unsupported_mat_container")
    source.seek(0)


def inspect_mat(record: ProfileInput) -> LayoutFacts:
    source, expected = _open_input(record)
    with source:
        _mat_v5_header(source)
        try:
            raw_variables = whosmat(source, appendmat=False)
        except Exception as error:
            raise LayoutProfileError("mat_metadata_parse_failed") from error
        if _identity(os.fstat(source.fileno())) != expected:
            raise LayoutProfileError("artifact_changed_during_read")
    if not raw_variables or len(raw_variables) > MAX_VARIABLES_PER_ARTIFACT:
        raise LayoutProfileError("mat_variable_count_limit")
    variables: list[tuple[str, tuple[int, ...], str]] = []
    names: set[str] = set()
    for name, raw_shape, data_class in raw_variables:
        try:
            name_bytes = name.encode("utf-8")
        except UnicodeEncodeError as error:
            raise LayoutProfileError("mat_variable_name_invalid") from error
        if not name_bytes or len(name_bytes) > MAX_VARIABLE_NAME_BYTES or name in names:
            raise LayoutProfileError("mat_variable_name_invalid")
        names.add(name)
        if not isinstance(raw_shape, tuple) or not 1 <= len(raw_shape) <= MAX_RANK:
            raise LayoutProfileError("mat_shape_limit")
        shape = tuple(int(dimension) for dimension in raw_shape)
        if any(dimension < 0 or dimension > MAX_DIMENSION for dimension in shape):
            raise LayoutProfileError("mat_shape_limit")
        if (
            not isinstance(data_class, str)
            or CLASS_PATTERN.fullmatch(data_class) is None
        ):
            raise LayoutProfileError("mat_class_invalid")
        variables.append((name, shape, data_class))
    return LayoutFacts(tuple(sorted(variables)), expected.size)


def _validate_inputs(inputs: Sequence[ProfileInput], expected_pairs: int) -> None:
    if (
        isinstance(expected_pairs, bool)
        or not isinstance(expected_pairs, int)
        or expected_pairs <= 0
        or len(inputs) != expected_pairs * 2
        or len(inputs) > MAX_ARTIFACTS
    ):
        raise LayoutProfileError("invalid_pair_inventory")
    if sum(item.expected_bytes for item in inputs) > MAX_TOTAL_BYTES:
        raise LayoutProfileError("corpus_byte_limit")
    paths = {os.fspath(item.path) for item in inputs}
    if len(paths) != len(inputs):
        raise LayoutProfileError("duplicate_artifact_path")
    pairs: dict[str, list[ProfileInput]] = defaultdict(list)
    for item in inputs:
        if not item.pair_group or not item.condition:
            raise LayoutProfileError("invalid_pair_inventory")
        pairs[item.pair_group].append(item)
    if len(pairs) != expected_pairs or any(
        len(members) != 2 or len({member.condition for member in members}) != 2
        for members in pairs.values()
    ):
        raise LayoutProfileError("invalid_pair_inventory")


def profile_inputs(
    inputs: Sequence[ProfileInput], *, expected_pairs: int
) -> dict[str, object]:
    _validate_inputs(inputs, expected_pairs)
    facts = {item: inspect_mat(item) for item in inputs}
    inode_keys: set[tuple[int, int]] = set()
    for item in inputs:
        metadata = item.path.stat(follow_symlinks=False)
        key = (metadata.st_dev, metadata.st_ino)
        if key in inode_keys:
            raise LayoutProfileError("artifact_file_collision")
        inode_keys.add(key)

    by_pair: dict[str, list[LayoutFacts]] = defaultdict(list)
    class_counts: Counter[str] = Counter()
    variable_counts: list[int] = []
    ranks: list[int] = []
    for item, item_facts in facts.items():
        by_pair[item.pair_group].append(item_facts)
        variable_counts.append(len(item_facts.signature))
        for _name, shape, data_class in item_facts.signature:
            class_counts[data_class] += 1
            ranks.append(len(shape))

    layout_matches = 0
    exact_extent_matches = 0
    extent_class_matches = 0
    for members in by_pair.values():
        left, right = members
        layout_matches += int(left.signature == right.signature)
        exact_extent_matches += int(left.extent_bytes == right.extent_bytes)
        extent_class_matches += int(left.extent_mib_class == right.extent_mib_class)

    reasons = []
    if layout_matches != expected_pairs:
        reasons.append("mat_layout_not_pair_invariant")
    if exact_extent_matches != expected_pairs:
        reasons.append("exact_storage_extent_not_pair_invariant")
    if extent_class_matches != expected_pairs:
        reasons.append("mib_storage_extent_not_pair_invariant")

    report: dict[str, object] = {
        "schema": SCHEMA,
        "status": "pass" if not reasons else "blocked",
        "inventory": {
            "artifacts": len(inputs),
            "paired_cells": expected_pairs,
            "source_bytes": sum(item.expected_bytes for item in inputs),
        },
        "mat_metadata": {
            "container": "mat_v5",
            "variable_count_min": min(variable_counts),
            "variable_count_max": max(variable_counts),
            "maximum_rank": max(ranks),
            "data_classes": dict(sorted(class_counts.items())),
            "array_values_materialized": 0,
        },
        "pair_invariance": {
            "mat_layout_signature": {
                "matching_pairs": layout_matches,
                "mismatching_pairs": expected_pairs - layout_matches,
            },
            "exact_storage_extent": {
                "matching_pairs": exact_extent_matches,
                "mismatching_pairs": expected_pairs - exact_extent_matches,
            },
            "mib_storage_extent_class": {
                "matching_pairs": extent_class_matches,
                "mismatching_pairs": expected_pairs - extent_class_matches,
            },
        },
        "feature_admission": {
            "status": "pass" if not reasons else "blocked",
            "reasons": reasons,
            "always_prohibited": [
                "source_filename",
                "source_path",
                "source_url",
                "artifact_byte_count",
                "mat_variable_name",
                "mat_storage_encoding",
            ],
        },
        "privacy": {
            "absolute_paths_retained": 0,
            "relative_paths_retained": 0,
            "filenames_retained": 0,
            "source_urls_retained": 0,
            "per_artifact_rows_retained": 0,
            "receiver_or_target_labels_retained": 0,
            "condition_labels_retained": 0,
            "digests_retained": 0,
        },
        "limits": {
            "max_artifacts": MAX_ARTIFACTS,
            "max_artifact_bytes": MAX_ARTIFACT_BYTES,
            "max_total_bytes": MAX_TOTAL_BYTES,
            "max_variables_per_artifact": MAX_VARIABLES_PER_ARTIFACT,
            "max_rank": MAX_RANK,
        },
    }
    render_report(report)
    return report


def _production_inputs(
    manifest: Path, raw_dir: Path, receipt_dir: Path
) -> tuple[list[ProfileInput], dict[str, object]]:
    inventory = COMPILER.compile_inventory(manifest, raw_dir, receipt_dir)
    artifacts = COMPILER.load_artifacts(manifest)
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
    for artifact in artifacts:
        cell = artifact.cell
        key = (
            cell.receiver_element,
            cell.radar_regime,
            cell.controlled_jamming_cause,
            cell.target_count,
        )
        observation = observations.get(key)
        if observation is None:
            raise LayoutProfileError("oracle_artifact_mapping_mismatch")
        inputs.append(
            ProfileInput(
                path=raw_dir / artifact.filename,
                expected_bytes=artifact.byte_count,
                pair_group=observation["paired_cell_group"]["group_id"],
                condition=cell.controlled_jamming_cause,
            )
        )
    return inputs, inventory


def profile_corpus(
    manifest: Path, raw_dir: Path, receipt_dir: Path
) -> dict[str, object]:
    inputs, inventory = _production_inputs(manifest, raw_dir, receipt_dir)
    report = profile_inputs(inputs, expected_pairs=40)
    report["provenance"] = {
        "publisher": "Zenodo",
        "record_id": COMPILER.SELECTED_RECORD_ID,
        "doi": f"10.5281/zenodo.{COMPILER.SELECTED_RECORD_ID}",
        "oracle_schema": inventory["schema"],
        "admission": "exact_size_md5_sha256_and_local_receipt",
    }
    encoded = render_report(report).decode("ascii")
    forbidden = [
        *(artifact.filename for artifact in COMPILER.load_artifacts(manifest)),
        os.path.abspath(os.fspath(manifest)),
        os.path.abspath(os.fspath(raw_dir)),
        os.path.abspath(os.fspath(receipt_dir)),
    ]
    if any(value and value in encoded for value in forbidden):
        raise LayoutProfileError("private_source_value_retained")
    return report


def render_report(report: dict[str, object]) -> bytes:
    try:
        encoded = (
            json.dumps(report, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise LayoutProfileError("report_not_json_serializable") from error
    if len(encoded) > MAX_REPORT_BYTES:
        raise LayoutProfileError("report_byte_limit")
    return encoded


def write_report(path: Path, rendered: bytes) -> None:
    if path.name in {"", ".", ".."} or path.name.startswith("."):
        raise LayoutProfileError("unsafe_report_path")
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise LayoutProfileError("unsafe_report_path")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise LayoutProfileError("unsafe_report_directory")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


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
        "--report",
        type=Path,
        default=(
            ROOT
            / "data"
            / "derived"
            / "eval"
            / "mmwave-jamming-mat-layout-profile.json"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        report = profile_corpus(
            arguments.manifest, arguments.raw_dir, arguments.receipt_dir
        )
        rendered = render_report(report)
        write_report(arguments.report, rendered)
    except (LayoutProfileError, COMPILER.OracleCompileError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
