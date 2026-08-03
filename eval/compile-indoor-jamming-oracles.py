#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["h5py==3.16.0", "xlrd==2.0.2"]
# ///

"""Compile bounded, path-free oracles for Zenodo record 7119040."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import sys
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import quote

import h5py
import xlrd

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "data" / "catalog" / "controlled-jamming-artifacts-v1.json"
DEFAULT_RAW_DIR = ROOT / "data" / "raw" / "controlled-jamming"
DEFAULT_RECEIPT_DIR = ROOT / "data" / "receipts" / "controlled-jamming"
DEFAULT_OUTPUT = (
    ROOT / "data" / "derived" / "eval" / "indoor-jamming-observation-oracles.json"
)

RECORD_ID = 7_119_040
MANIFEST_SCHEMA = "netbraid.controlled_jamming_artifacts.v1"
RECEIPT_SCHEMA = "local.netbraid_controlled_jamming_artifact.v1"
OUTPUT_SCHEMA = "netbraid.indoor_jamming_observation_oracles.v0"
ID_NAMESPACE = b"netbraid.indoor-jamming-oracle-id.v0"
EXPECTED_LICENSE = "CC BY 4.0"
EXPECTED_LICENSE_ID = "cc-by-4.0"
EXPECTED_DOI = f"10.5281/zenodo.{RECORD_ID}"
EXPECTED_API_URL = f"https://zenodo.org/api/records/{RECORD_ID}"
EXPECTED_MAT_NAMES = tuple(f"w{index}.mat" for index in range(1, 32))
EXPECTED_ARTIFACT_NAMES = frozenset(("README.xls", *EXPECTED_MAT_NAMES))
EXPECTED_DATASETS = ("Nojamming", "Sine", "Gaussian")
CAUSES = (
    ("No", "silent", "Nojamming"),
    ("Sin", "sine", "Sine"),
    ("Gauss", "gaussian", "Gaussian"),
)
EXPECTED_HEADERS = (
    "name",
    "tx",
    "rx",
    "jammer",
    "Type \nof \nJammer",
    "Relative\nJamming\npower",
    "Distance\n[meters]",
    "Duration",
)
UNSUPPORTED_IDENTITIES = (
    "event_identity",
    "physical_source_identity",
    "physical_device_identity",
    "variant_identity",
    "tamper",
    "actor_identity",
    "malicious_intent",
)
REQUIRED_SPLIT_GROUPS = (
    "file_session_group",
    "paired_condition_group",
    "tx_rx_setup_group",
    "assigned_jammer_setup_group",
    "power_setup_group",
    "distance_setup_group",
    "combined_setup_group",
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
MD5_PATTERN = re.compile(r"[0-9a-f]{32}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
GROUP_NAME_PATTERN = re.compile(r"w([1-9]|[12][0-9]|3[01])\Z")

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024
MAX_WORKBOOK_BYTES = 1024 * 1024
MAX_RECORDS = 8
MAX_ARTIFACTS = 256
MAX_ARTIFACT_BYTES = 8 * 1024**3
MAX_TOTAL_BYTES = 256 * 1024**3
MAX_WORKBOOK_ROWS = 256
MAX_DATASET_SAMPLES = 1_000_000_000
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
DIGEST_CHUNK_BYTES = 4 * 1024 * 1024


class OracleCompileError(RuntimeError):
    """Stable fail-closed reason for invalid compiler input or output."""


@dataclass(frozen=True)
class Artifact:
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
    record_id: int
    artifacts: tuple[Artifact, ...]


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    mtime_ns: int


@dataclass(frozen=True)
class WorkbookRow:
    group_index: int
    tx: int
    rx: int
    jammer: int
    cause: str
    dataset: str
    condition_power: float
    assigned_power: float
    distance_meters: float
    duration_seconds: int


def _identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OracleCompileError("duplicate_json_key")
        result[key] = value
    return result


def _open_regular(path: Path, expected_bytes: int, error_code: str) -> BinaryIO:
    try:
        before = path.lstat()
    except OSError as error:
        raise OracleCompileError(error_code) from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise OracleCompileError(error_code)
    if before.st_size != expected_bytes:
        raise OracleCompileError("artifact_size_mismatch")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OracleCompileError(error_code) from error
    source = os.fdopen(descriptor, "rb")
    if _identity(os.fstat(source.fileno())) != _identity(before):
        source.close()
        raise OracleCompileError("artifact_identity_changed")
    return source


def _require_unchanged(source: BinaryIO, identity: FileIdentity) -> None:
    if _identity(os.fstat(source.fileno())) != identity:
        raise OracleCompileError("artifact_changed_during_compile")


def _require_exact_directory(path: Path, expected_names: frozenset[str]) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise OracleCompileError("record_directory_missing_or_unsafe") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise OracleCompileError("record_directory_schema")
    names: set[str] = set()
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                names.add(entry.name)
                if len(names) > len(expected_names):
                    raise OracleCompileError("record_directory_schema")
    except OSError as error:
        raise OracleCompileError("record_directory_missing_or_unsafe") from error
    if names != expected_names:
        raise OracleCompileError("record_directory_schema")


def _read_json(path: Path, limit: int, error_code: str) -> Mapping[str, Any]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise OracleCompileError(error_code) from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or not 0 < metadata.st_size <= limit
    ):
        raise OracleCompileError(error_code)
    source = _open_regular(path, metadata.st_size, error_code)
    identity = _identity(os.fstat(source.fileno()))
    try:
        payload = source.read(limit + 1)
        _require_unchanged(source, identity)
    finally:
        source.close()
    if len(payload) > limit:
        raise OracleCompileError(error_code)
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OracleCompileError(error_code) from error
    if not isinstance(value, dict):
        raise OracleCompileError(error_code)
    return value


def _positive_int(value: Any, maximum: int, error_code: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 < value <= maximum
    ):
        raise OracleCompileError(error_code)
    return value


def _artifact_from_value(value: Any, record: Mapping[str, Any]) -> Artifact:
    if not isinstance(value, dict) or set(value) != ARTIFACT_KEYS:
        raise OracleCompileError("invalid_manifest_artifact")
    filename = value["filename"]
    artifact_bytes = value["bytes"]
    md5 = value["md5"]
    if (
        not isinstance(filename, str)
        or not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or isinstance(artifact_bytes, bool)
        or not isinstance(artifact_bytes, int)
        or not 0 < artifact_bytes <= MAX_ARTIFACT_BYTES
        or not isinstance(md5, str)
        or MD5_PATTERN.fullmatch(md5) is None
    ):
        raise OracleCompileError("invalid_manifest_artifact")
    expected_url = (
        f"https://zenodo.org/api/records/{record['record_id']}/files/"
        f"{quote(filename, safe='')}/content"
    )
    if value["content_url"] != expected_url:
        raise OracleCompileError("invalid_manifest_artifact_url")
    return Artifact(
        record_id=record["record_id"],
        doi=record["doi"],
        license=record["license"],
        license_id=record["license_id"],
        filename=filename,
        content_url=value["content_url"],
        bytes=artifact_bytes,
        md5=md5,
    )


def load_record(path: Path) -> Record:
    """Load and strictly validate the tracked manifest's target record."""

    document = _read_json(path, MAX_MANIFEST_BYTES, "manifest_missing_or_unsafe")
    if (
        set(document) != TOP_LEVEL_KEYS
        or document["schema"] != MANIFEST_SCHEMA
        or document["publisher"] != "Zenodo"
        or not isinstance(document["records"], list)
    ):
        raise OracleCompileError("invalid_manifest_schema")
    records = document["records"]
    expected_record_count = _positive_int(
        document["expected_record_count"], MAX_RECORDS, "invalid_manifest_counts"
    )
    expected_artifact_count = _positive_int(
        document["expected_artifact_count"],
        MAX_ARTIFACTS,
        "invalid_manifest_counts",
    )
    expected_total_bytes = _positive_int(
        document["expected_total_bytes"], MAX_TOTAL_BYTES, "invalid_manifest_counts"
    )
    if len(records) != expected_record_count:
        raise OracleCompileError("invalid_manifest_counts")

    parsed: list[tuple[Mapping[str, Any], tuple[Artifact, ...]]] = []
    record_ids: set[int] = set()
    all_names: set[tuple[int, str]] = set()
    for value in records:
        if not isinstance(value, dict) or set(value) != RECORD_KEYS:
            raise OracleCompileError("invalid_manifest_record")
        record_id = _positive_int(value["record_id"], 10**12, "invalid_manifest_record")
        if record_id in record_ids:
            raise OracleCompileError("duplicate_manifest_record")
        record_ids.add(record_id)
        if (
            value["api_url"] != f"https://zenodo.org/api/records/{record_id}"
            or value["doi"] != f"10.5281/zenodo.{record_id}"
            or value["license"] != EXPECTED_LICENSE
            or value["license_id"] != EXPECTED_LICENSE_ID
            or not isinstance(value["artifacts"], list)
        ):
            raise OracleCompileError("invalid_manifest_record")
        artifacts = tuple(
            _artifact_from_value(artifact, value) for artifact in value["artifacts"]
        )
        for artifact in artifacts:
            key = (record_id, artifact.filename)
            if key in all_names:
                raise OracleCompileError("duplicate_manifest_artifact")
            all_names.add(key)
        record_artifact_count = _positive_int(
            value["expected_artifact_count"],
            MAX_ARTIFACTS,
            "invalid_manifest_counts",
        )
        record_total_bytes = _positive_int(
            value["expected_total_bytes"], MAX_TOTAL_BYTES, "invalid_manifest_counts"
        )
        if (
            len(artifacts) != record_artifact_count
            or sum(artifact.bytes for artifact in artifacts) != record_total_bytes
        ):
            raise OracleCompileError("invalid_manifest_counts")
        parsed.append((value, artifacts))

    if (
        sum(len(artifacts) for _, artifacts in parsed) != expected_artifact_count
        or sum(artifact.bytes for _, artifacts in parsed for artifact in artifacts)
        != expected_total_bytes
    ):
        raise OracleCompileError("invalid_manifest_counts")
    matches = [item for item in parsed if item[0]["record_id"] == RECORD_ID]
    if len(matches) != 1:
        raise OracleCompileError("target_record_missing")
    target_value, target_artifacts = matches[0]
    if (
        target_value["api_url"] != EXPECTED_API_URL
        or target_value["doi"] != EXPECTED_DOI
        or target_value["license"] != EXPECTED_LICENSE
        or target_value["license_id"] != EXPECTED_LICENSE_ID
        or len(target_artifacts) != len(EXPECTED_ARTIFACT_NAMES)
        or {artifact.filename for artifact in target_artifacts}
        != EXPECTED_ARTIFACT_NAMES
    ):
        raise OracleCompileError("target_record_contract_mismatch")
    by_name = {artifact.filename: artifact for artifact in target_artifacts}
    ordered = (by_name["README.xls"],) + tuple(
        by_name[name] for name in EXPECTED_MAT_NAMES
    )
    return Record(record_id=RECORD_ID, artifacts=ordered)


def _expected_receipt(artifact: Artifact, sha256: str) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "source": artifact.source(),
        "integrity": {
            "bytes": artifact.bytes,
            "md5": artifact.md5,
            "sha256": sha256,
        },
    }


def _validate_receipt(path: Path, artifact: Artifact) -> str:
    receipt = _read_json(path, MAX_RECEIPT_BYTES, "receipt_missing_or_unsafe")
    integrity = receipt.get("integrity")
    sha256 = integrity.get("sha256") if isinstance(integrity, dict) else None
    if not isinstance(sha256, str) or SHA256_PATTERN.fullmatch(sha256) is None:
        raise OracleCompileError("receipt_content_mismatch")
    if receipt != _expected_receipt(artifact, sha256):
        raise OracleCompileError("receipt_content_mismatch")
    return sha256


def _digest_artifact(path: Path, artifact: Artifact) -> tuple[str, str]:
    source = _open_regular(path, artifact.bytes, "artifact_missing_or_unsafe")
    identity = _identity(os.fstat(source.fileno()))
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    try:
        remaining = artifact.bytes
        while remaining:
            chunk = source.read(min(DIGEST_CHUNK_BYTES, remaining))
            if not chunk:
                raise OracleCompileError("artifact_changed_during_digest")
            remaining -= len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
        if source.read(1):
            raise OracleCompileError("artifact_size_mismatch")
        _require_unchanged(source, identity)
    finally:
        source.close()
    return md5.hexdigest(), sha256.hexdigest()


def verify_artifact(
    path: Path,
    receipt_path: Path,
    artifact: Artifact,
    *,
    full_digest: bool,
) -> FileIdentity:
    """Validate size and exact receipt, optionally rehashing all bytes."""

    source = _open_regular(path, artifact.bytes, "artifact_missing_or_unsafe")
    identity = _identity(os.fstat(source.fileno()))
    source.close()
    receipt_sha256 = _validate_receipt(receipt_path, artifact)
    if not full_digest:
        return identity
    md5, sha256 = _digest_artifact(path, artifact)
    if md5 != artifact.md5 or sha256 != receipt_sha256:
        raise OracleCompileError("artifact_digest_mismatch")
    return identity


def _integral_number(value: Any, error_code: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value != math.floor(value)
    ):
        raise OracleCompileError(error_code)
    return int(value)


def _bounded_float(value: Any, *, minimum: float, maximum: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not minimum <= float(value) <= maximum
    ):
        raise OracleCompileError("invalid_workbook_number")
    return float(value)


def _parse_workbook(book: Any) -> tuple[WorkbookRow, ...]:
    if book.sheet_names() != ["README"]:
        raise OracleCompileError("workbook_sheet_schema")
    sheet = book.sheet_by_index(0)
    if (
        sheet.ncols != len(EXPECTED_HEADERS)
        or not 1 < sheet.nrows <= MAX_WORKBOOK_ROWS
        or tuple(sheet.row_values(0)) != EXPECTED_HEADERS
        or any(sheet.cell_type(0, column) != xlrd.XL_CELL_TEXT for column in range(8))
    ):
        raise OracleCompileError("workbook_header_schema")

    groups: list[list[tuple[int, int, int, str, float, float, str]]] = []
    current: list[tuple[int, int, int, str, float, float, str]] | None = None
    for row_index in range(1, sheet.nrows):
        types = tuple(sheet.cell_type(row_index, column) for column in range(8))
        values = tuple(sheet.cell_value(row_index, column) for column in range(8))
        if all(
            cell_type == xlrd.XL_CELL_EMPTY and value == ""
            for cell_type, value in zip(types, values)
        ):
            if current is not None:
                if len(current) != 3:
                    raise OracleCompileError("workbook_group_row_count")
                groups.append(current)
                current = None
            continue
        if any(cell_type == xlrd.XL_CELL_EMPTY for cell_type in types[1:]):
            raise OracleCompileError("workbook_partial_row")
        if types[0] == xlrd.XL_CELL_TEXT:
            match = GROUP_NAME_PATTERN.fullmatch(values[0])
            if match is None or current is not None:
                raise OracleCompileError("workbook_group_name")
            expected_index = len(groups) + 1
            if int(match.group(1)) != expected_index:
                raise OracleCompileError("workbook_group_order")
            current = []
        elif types[0] != xlrd.XL_CELL_EMPTY or values[0] != "" or current is None:
            raise OracleCompileError("workbook_group_name")
        if current is None or len(current) >= 3:
            raise OracleCompileError("workbook_group_row_count")
        if types[1:4] != (xlrd.XL_CELL_NUMBER,) * 3:
            raise OracleCompileError("workbook_setup_type")
        if (
            types[4] != xlrd.XL_CELL_TEXT
            or types[5:7] != (xlrd.XL_CELL_NUMBER,) * 2
            or types[7] != xlrd.XL_CELL_TEXT
        ):
            raise OracleCompileError("workbook_value_type")
        tx = _integral_number(values[1], "invalid_workbook_setup")
        rx = _integral_number(values[2], "invalid_workbook_setup")
        jammer = _integral_number(values[3], "invalid_workbook_setup")
        if tx <= 0 or rx <= 0 or jammer not in range(4, 9):
            raise OracleCompileError("invalid_workbook_setup")
        power = _bounded_float(values[5], minimum=0.0, maximum=1.0)
        distance = _bounded_float(values[6], minimum=0.01, maximum=100.0)
        current.append((tx, rx, jammer, values[4], power, distance, values[7]))
    if current is not None:
        if len(current) != 3:
            raise OracleCompileError("workbook_group_row_count")
        groups.append(current)
    if len(groups) != 31:
        raise OracleCompileError("workbook_group_count")

    all_setups = {(row[0], row[1]) for group in groups for row in group}
    if len(all_setups) != 1:
        raise OracleCompileError("workbook_tx_rx_not_fixed")
    parsed: list[WorkbookRow] = []
    for group_index, group in enumerate(groups, 1):
        if tuple(row[3] for row in group) != tuple(item[0] for item in CAUSES):
            raise OracleCompileError("workbook_cause_order")
        if any(row[6] != "600s" for row in group):
            raise OracleCompileError("workbook_duration")
        if len({(row[0], row[1], row[2], row[5]) for row in group}) != 1:
            raise OracleCompileError("workbook_group_setup_mismatch")
        if group[0][4] != 0.0 or not 0.0 < group[1][4] <= 1.0:
            raise OracleCompileError("workbook_power_grammar")
        if group[1][4] != group[2][4]:
            raise OracleCompileError("workbook_power_grammar")
        assigned_power = group[1][4]
        for row, (_, cause, dataset) in zip(group, CAUSES):
            parsed.append(
                WorkbookRow(
                    group_index=group_index,
                    tx=row[0],
                    rx=row[1],
                    jammer=row[2],
                    cause=cause,
                    dataset=dataset,
                    condition_power=row[4],
                    assigned_power=assigned_power,
                    distance_meters=row[5],
                    duration_seconds=600,
                )
            )
    return tuple(parsed)


def parse_workbook(
    path: Path, artifact: Artifact, expected_identity: FileIdentity
) -> tuple[WorkbookRow, ...]:
    source = _open_regular(path, artifact.bytes, "workbook_missing_or_unsafe")
    identity = _identity(os.fstat(source.fileno()))
    if identity != expected_identity:
        source.close()
        raise OracleCompileError("artifact_changed_during_compile")
    try:
        if artifact.bytes > MAX_WORKBOOK_BYTES:
            raise OracleCompileError("workbook_size_limit")
        payload = source.read(MAX_WORKBOOK_BYTES + 1)
        _require_unchanged(source, identity)
    finally:
        source.close()
    if len(payload) != artifact.bytes:
        raise OracleCompileError("artifact_size_mismatch")
    try:
        book = xlrd.open_workbook(file_contents=payload, on_demand=True)
    except (xlrd.XLRDError, OSError, ValueError) as error:
        raise OracleCompileError("invalid_workbook") from error
    try:
        return _parse_workbook(book)
    finally:
        book.release_resources()


def inspect_mat(
    path: Path, artifact: Artifact, expected_identity: FileIdentity
) -> dict[str, int]:
    """Read only HDF5/MAT metadata and return dataset sample counts."""

    source = _open_regular(path, artifact.bytes, "mat_missing_or_unsafe")
    identity = _identity(os.fstat(source.fileno()))
    if identity != expected_identity:
        source.close()
        raise OracleCompileError("artifact_changed_during_compile")
    try:
        header = source.read(128)
        if not header.startswith(b"MATLAB 7.3 MAT-file,"):
            raise OracleCompileError("unsupported_mat_header")
        source.seek(0)
        try:
            mat = h5py.File(source, "r")
        except (OSError, ValueError) as error:
            raise OracleCompileError("invalid_hdf5_mat") from error
        with mat:
            if mat.userblock_size != 512 or len(mat.attrs) != 0:
                raise OracleCompileError("invalid_hdf5_root")
            if len(mat) != 3 or set(mat.keys()) != set(EXPECTED_DATASETS):
                raise OracleCompileError("hdf5_dataset_schema")
            counts: dict[str, int] = {}
            for name in EXPECTED_DATASETS:
                dataset = mat.get(name, getlink=False)
                if not isinstance(dataset, h5py.Dataset):
                    raise OracleCompileError("hdf5_dataset_schema")
                if (
                    dataset.ndim != 2
                    or dataset.shape[0] != 2
                    or isinstance(dataset.shape[1], bool)
                    or not 0 < dataset.shape[1] <= MAX_DATASET_SAMPLES
                    or dataset.dtype.kind != "f"
                    or dataset.dtype.itemsize != 8
                    or str(dataset.dtype) != "float64"
                    or dataset.compression != "gzip"
                    or dataset.chunks is None
                    or len(dataset.chunks) != 2
                    or len(dataset.attrs) != 1
                    or set(dataset.attrs.keys()) != {"MATLAB_class"}
                    or dataset.attrs["MATLAB_class"] != b"double"
                ):
                    raise OracleCompileError("hdf5_dataset_metadata")
                counts[name] = int(dataset.shape[1])
        _require_unchanged(source, identity)
    except OracleCompileError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise OracleCompileError("hdf5_metadata_read_failed") from error
    finally:
        source.close()
    return counts


def _opaque_id(domain: str, *components: object) -> str:
    digest = hashlib.sha256()
    digest.update(len(ID_NAMESPACE).to_bytes(4, "big"))
    digest.update(ID_NAMESPACE)
    domain_bytes = domain.encode("utf-8")
    digest.update(len(domain_bytes).to_bytes(4, "big"))
    digest.update(domain_bytes)
    for component in components:
        if isinstance(component, int):
            payload = b"i" + component.to_bytes(8, "big", signed=False)
        elif isinstance(component, float):
            payload = b"f" + component.hex().encode("ascii")
        elif isinstance(component, str):
            payload = b"s" + component.encode("utf-8")
        else:
            raise OracleCompileError("unsupported_id_component")
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _known(group_id: str) -> dict[str, str]:
    return {"state": "known", "group_id": group_id}


def _unsupported() -> dict[str, str | None]:
    return {"state": "not_observed", "support": "unsupported", "group_id": None}


def _compile_observation(row: WorkbookRow, sample_count: int) -> dict[str, Any]:
    setup = (row.tx, row.rx, row.jammer, row.assigned_power, row.distance_meters)
    groups = {
        "file_session_group": _known(_opaque_id("file_session", row.group_index)),
        "paired_condition_group": _known(
            _opaque_id("paired_condition", row.group_index)
        ),
        "tx_rx_setup_group": _known(_opaque_id("tx_rx_setup", row.tx, row.rx)),
        "assigned_jammer_setup_group": _known(
            _opaque_id("assigned_jammer_setup", row.jammer)
        ),
        "power_setup_group": _known(_opaque_id("power_setup", row.assigned_power)),
        "distance_setup_group": _known(
            _opaque_id("distance_setup", row.distance_meters)
        ),
        "combined_setup_group": _known(_opaque_id("combined_setup", *setup)),
    }
    return {
        "observation_id": _opaque_id("observation", row.group_index, row.cause),
        **groups,
        "controlled_cause": row.cause,
        "condition_relative_jamming_power": row.condition_power,
        "assigned_relative_jamming_power": row.assigned_power,
        "distance_meters": row.distance_meters,
        "duration_seconds": row.duration_seconds,
        "dataset_sample_count": sample_count,
        **{field: _unsupported() for field in UNSUPPORTED_IDENTITIES},
    }


def compile_inventory(
    record: Record,
    raw_dir: Path,
    receipt_dir: Path,
    *,
    full_digest: bool = False,
) -> dict[str, Any]:
    """Compile all 93 scenario segments from the exact local record."""

    if record.record_id != RECORD_ID or len(record.artifacts) != 32:
        raise OracleCompileError("invalid_compile_record")
    by_name = {artifact.filename: artifact for artifact in record.artifacts}
    if len(by_name) != 32 or set(by_name) != EXPECTED_ARTIFACT_NAMES:
        raise OracleCompileError("invalid_compile_record")
    record_raw_dir = raw_dir / str(RECORD_ID)
    record_receipt_dir = receipt_dir / str(RECORD_ID)
    expected_receipts = frozenset(
        f"{filename}.json" for filename in EXPECTED_ARTIFACT_NAMES
    )
    _require_exact_directory(record_raw_dir, EXPECTED_ARTIFACT_NAMES)
    _require_exact_directory(record_receipt_dir, expected_receipts)
    identities: set[tuple[int, int]] = set()
    identities_by_name: dict[str, FileIdentity] = {}
    for artifact in record.artifacts:
        identity = verify_artifact(
            record_raw_dir / artifact.filename,
            record_receipt_dir / f"{artifact.filename}.json",
            artifact,
            full_digest=full_digest,
        )
        file_key = (identity.device, identity.inode)
        if file_key in identities:
            raise OracleCompileError("duplicate_artifact_file")
        identities.add(file_key)
        identities_by_name[artifact.filename] = identity

    workbook_rows = parse_workbook(
        record_raw_dir / "README.xls",
        by_name["README.xls"],
        identities_by_name["README.xls"],
    )
    metadata_by_group: dict[int, dict[str, int]] = {}
    for group_index, filename in enumerate(EXPECTED_MAT_NAMES, 1):
        metadata_by_group[group_index] = inspect_mat(
            record_raw_dir / filename,
            by_name[filename],
            identities_by_name[filename],
        )
    _require_exact_directory(record_raw_dir, EXPECTED_ARTIFACT_NAMES)
    _require_exact_directory(record_receipt_dir, expected_receipts)

    observations: list[dict[str, Any]] = []
    observation_ids: set[str] = set()
    for row in workbook_rows:
        sample_count = metadata_by_group[row.group_index][row.dataset]
        observation = _compile_observation(row, sample_count)
        if observation["observation_id"] in observation_ids:
            raise OracleCompileError("duplicate_observation_id")
        observation_ids.add(observation["observation_id"])
        observations.append(observation)
    if len(observations) != 93:
        raise OracleCompileError("observation_count_mismatch")

    cause_counts = Counter(item["controlled_cause"] for item in observations)
    inventory = {
        "schema": OUTPUT_SCHEMA,
        "inventory_id": _opaque_id(
            "inventory", *(item["observation_id"] for item in observations)
        ),
        "status": "pass",
        "provenance": {
            "record_id": RECORD_ID,
            "manifest_schema": MANIFEST_SCHEMA,
            "workbook_truth_basis": "publisher_workbook",
            "integrity_basis": (
                "full_local_md5_sha256_rehash_and_exact_fetch_receipts"
                if full_digest
                else "exact_size_and_exact_fetch_receipts_without_local_rehash"
            ),
            "all_artifact_bytes_rehashed": full_digest,
        },
        "assignment": {
            "roles_assigned": False,
            "partitions_assigned": 0,
            "train_test_split_assigned": False,
        },
        "required_split_groups": list(REQUIRED_SPLIT_GROUPS),
        "counts": {
            "artifacts": 32,
            "workbooks": 1,
            "mat_files": 31,
            "paired_three_condition_groups": 31,
            "scenario_segments": 93,
            "causes": {cause: cause_counts[cause] for cause in sorted(cause_counts)},
            "dataset_samples": sum(
                item["dataset_sample_count"] for item in observations
            ),
            "distinct_file_sessions": 31,
            "distinct_tx_rx_setups": 1,
            "distinct_assigned_jammer_setups": len(
                {
                    item["assigned_jammer_setup_group"]["group_id"]
                    for item in observations
                }
            ),
            "distinct_power_setups": len(
                {item["power_setup_group"]["group_id"] for item in observations}
            ),
            "distinct_distance_setups": len(
                {item["distance_setup_group"]["group_id"] for item in observations}
            ),
        },
        "privacy": {
            "dataset_elements_read": 0,
            "paths_retained": 0,
            "filenames_retained": 0,
            "raw_tx_rx_ids_retained": 0,
            "raw_assigned_jammer_ids_retained": 0,
        },
        "unsupported_claims": {
            field: {"state": "not_observed", "support": "unsupported"}
            for field in UNSUPPORTED_IDENTITIES
        },
        "observations": observations,
    }
    render_inventory(inventory)
    return inventory


def render_inventory(inventory: Mapping[str, Any]) -> bytes:
    try:
        encoded = (
            json.dumps(
                inventory, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise OracleCompileError("inventory_not_json_serializable") from error
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise OracleCompileError("inventory_output_size_limit")
    return encoded


def write_inventory(path: Path, inventory: Mapping[str, Any]) -> None:
    encoded = render_inventory(inventory)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.exists() and not path.is_file():
        raise OracleCompileError("unsafe_output_path")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPT_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--integrity",
        choices=("receipt-only", "full-digest"),
        default="receipt-only",
        help=(
            "receipt-only checks exact sizes and fetch receipts without rehashing; "
            "full-digest explicitly rehashes every artifact"
        ),
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        record = load_record(arguments.manifest)
        inventory = compile_inventory(
            record,
            arguments.raw_dir,
            arguments.receipt_dir,
            full_digest=arguments.integrity == "full-digest",
        )
        write_inventory(arguments.output, inventory)
    except OracleCompileError as error:
        print(str(error), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "pass",
                "inventory_id": inventory["inventory_id"],
                "scenario_segments": inventory["counts"]["scenario_segments"],
                "integrity_basis": inventory["provenance"]["integrity_basis"],
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
