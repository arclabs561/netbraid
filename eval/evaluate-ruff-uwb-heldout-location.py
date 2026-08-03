#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9,<3.10"
# dependencies = ["numpy==2.0.2"]
# ///

"""Leakage-safe held-out-location baseline harness for RUFF-UWB.

The aggregate oracle remains a zero-waveform-open evidence boundary and the
default CLI operation reports its stable blocker. When a receipt-bound
one-meter row adapter is supplied, the CLI expands its contiguous opaque spans
and runs the real held-out-location evaluation against its standalone NPY.

No report contains input paths, raw waveform rows, or source identifiers.
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
from collections import defaultdict
from contextlib import suppress
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

try:
    import numpy as np
except ModuleNotFoundError:  # The aggregate-only blocker remains runnable.
    np = None


ROOT = Path(__file__).resolve().parents[1]
CURRENT_ORACLE_SCHEMA = "netbraid.ruff_uwb_observation_oracles.v0"
ROW_ADAPTER_SCHEMA = "netbraid.ruff_uwb_row_adapter.v0"
REPORT_SCHEMA = "netbraid.ruff_uwb_heldout_location_eval.v0"
BLOCKER_SCHEMA = "netbraid.ruff_uwb_heldout_location_blocker.v0"
PINNED_ONE_METER_ARCHIVE_SHA256 = (
    "43f344b23ba4981dd8005c02091152fa1f15205703757027630f4708aaf5ba9b"
)
PINNED_ONE_METER_ARCHIVE_MD5 = "035d22d657c84b77df980a482cff47b1"
PINNED_ONE_METER_LABEL_SHA256 = (
    "6f8cf19dc00666bcc61aae08b60426107b7d1073cdefbf86af9d40dbd5e306a6"
)
RECEIPT_SCHEMA = "local.public_wireless_archive.v1"

SPLITS = ("train", "validation", "test")
SPLIT_PERCENTAGES = {"train": 80, "validation": 10, "test": 10}
PROTOTYPE_MODES = ("centroid", "template")

MIB = 1024 * 1024
GIB = 1024 * MIB
MAX_ORACLE_BYTES = 8 * MIB
MAX_ROW_ADAPTER_BYTES = 4 * MIB
MAX_REPORT_BYTES = 4 * MIB
MAX_NPY_BYTES = 4 * GIB
MAX_ROWS = 2_000_000
MAX_SOURCE_ROWS = 1_500_000
MAX_SIGNAL_SAMPLES = 65_536
MAX_LOCATIONS = 256
MAX_DEVICES = 32
MAX_IDENTIFIER_BYTES = 128
MAX_ROWS_PER_ATOMIC_GROUP = 256
MAX_WINDOWS_PER_ROW = 32
MAX_WINDOW_LENGTH = 4_096
MAX_FEATURE_VALUES = 16_000_000
MAX_ROW_SPANS = 100_000

IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
OPAQUE_ID_PATTERN = re.compile(r"[a-f0-9]{64}\Z")
SHA256_PATTERN = OPAQUE_ID_PATTERN

CURRENT_ORACLE_FIELDS = {
    "schema",
    "inventory_id",
    "status",
    "provenance",
    "manifest",
    "publisher_claims",
    "required_split_groups",
    "archives",
    "counts",
    "privacy",
    "observations",
}
CURRENT_OBSERVATION_FIELDS = {
    "observation_id",
    "observation_count",
    "event_group",
    "physical_source_group",
    "physical_device_group",
    "variant_group",
    "session_group",
    "domain_group",
    "day_group",
    "receiver_group",
    "location_group",
    "channel_group",
    "configuration_group",
    "source_location_group",
    "campaign_group",
}
CURRENT_ARCHIVE_FIELDS = {
    "archive_id",
    "campaign_group_id",
    "configuration_group_id",
    "archive_bytes",
    "archive_md5",
    "archive_sha256",
    "label_rows",
    "oracle_records",
    "distinct_sources",
    "distinct_locations",
}
REQUIRED_SPLIT_GROUPS = (
    "physical_source_group",
    "location_group",
    "source_location_group",
    "campaign_group",
    "day_group",
)
ROW_ADAPTER_FIELDS = {
    "schema",
    "adapter_id",
    "status",
    "archive",
    "label_member",
    "waveform_member",
    "waveform_source",
    "counts",
    "spans",
    "privacy",
}
ARCHIVE_BINDING_FIELDS = {
    "archive_bytes",
    "archive_md5",
    "archive_sha256",
    "receipt_schema",
}
MEMBER_BINDING_FIELDS = {
    "member_bytes",
    "compressed_bytes",
    "crc32",
    "compression",
    "flags",
    "header_offset",
    "sha256",
    "npy_version",
    "dtype",
    "fortran_order",
    "shape",
}
WAVEFORM_SOURCE_FIELDS = {
    "file_bytes",
    "sha256",
    "rows",
    "samples_per_row",
    "dtype",
}
ROW_ADAPTER_COUNT_FIELDS = {
    "rows",
    "spans",
    "distance_collections",
    "physical_sources",
    "physical_devices",
    "locations",
}
ROW_SPAN_FIELDS = {
    "row_start",
    "row_stop",
    "distance_collection",
    "physical_source",
    "physical_device",
    "location",
}
ROW_ADAPTER_PRIVACY_FIELDS = {
    "input_paths_retained",
    "filenames_retained",
    "raw_label_values_retained",
    "source_urls_retained",
}


class EvaluationInputError(ValueError):
    """Stable fail-closed reason for malformed or unsupported input."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class DuplicateJsonKeyError(ValueError):
    """Raised when strict JSON contains a duplicate object key."""


@dataclass(frozen=True)
class RowMetadata:
    """Explicit, adapter-supplied binding from one NPY row to split groups."""

    row_index: int
    distance_collection: str
    physical_source: str
    physical_device: str
    location: str

    def atomic_group(self) -> Tuple[str, str, str, str]:
        return (
            self.distance_collection,
            self.physical_source,
            self.physical_device,
            self.location,
        )


@dataclass(frozen=True)
class RowAdapterBinding:
    """Exact archive and member facts accepted by a row-adapter loader."""

    archive: Mapping[str, Any]
    label_member: Mapping[str, Any]
    waveform_member: Mapping[str, Any]


PRODUCTION_ROW_ADAPTER_BINDING = RowAdapterBinding(
    archive={
        "archive_bytes": 793_083_301,
        "archive_md5": PINNED_ONE_METER_ARCHIVE_MD5,
        "archive_sha256": PINNED_ONE_METER_ARCHIVE_SHA256,
        "receipt_schema": RECEIPT_SCHEMA,
    },
    label_member={
        "member_bytes": 12_339_840,
        "compressed_bytes": 25_488,
        "crc32": "6b9ad755",
        "compression": 8,
        "flags": 8,
        "header_offset": 793_057_475,
        "sha256": PINNED_ONE_METER_LABEL_SHA256,
        "npy_version": [1, 0],
        "dtype": "<i8",
        "fortran_order": False,
        "shape": [771_232, 2],
    },
    waveform_member={
        "member_bytes": 3_084_928_128,
        "compressed_bytes": 793_057_371,
        "crc32": "14ae6a49",
        "compression": 8,
        "flags": 8,
        "header_offset": 0,
        "npy_version": [1, 0],
        "dtype": "<c16",
        "fortran_order": False,
        "shape": [771_232, 250],
    },
)


@dataclass(frozen=True)
class EvaluationConfig:
    seed: int = 0
    max_rows_per_atomic_group: int = 8
    window_length: int = 128
    windows_per_row: int = 4

    def validate(self) -> None:
        if type(self.seed) is not int or not 0 <= self.seed < 1 << 63:
            raise EvaluationInputError("invalid_seed")
        if (
            type(self.max_rows_per_atomic_group) is not int
            or not 1 <= self.max_rows_per_atomic_group <= MAX_ROWS_PER_ATOMIC_GROUP
        ):
            raise EvaluationInputError("invalid_rows_per_atomic_group")
        if (
            type(self.window_length) is not int
            or not 2 <= self.window_length <= MAX_WINDOW_LENGTH
        ):
            raise EvaluationInputError("invalid_window_length")
        if (
            type(self.windows_per_row) is not int
            or not 1 <= self.windows_per_row <= MAX_WINDOWS_PER_ROW
        ):
            raise EvaluationInputError("invalid_windows_per_row")


@dataclass(frozen=True)
class WaveformSourceContract:
    """Adapter-supplied identity and array contract for a standalone NPY."""

    file_bytes: int
    sha256: str
    rows: int
    samples_per_row: int
    dtype: str

    def validate(self) -> None:
        if type(self.file_bytes) is not int or not 0 < self.file_bytes <= MAX_NPY_BYTES:
            raise EvaluationInputError("invalid_waveform_file_bytes")
        if (
            not isinstance(self.sha256, str)
            or SHA256_PATTERN.fullmatch(self.sha256) is None
        ):
            raise EvaluationInputError("invalid_waveform_sha256")
        if type(self.rows) is not int or not 1 <= self.rows <= MAX_SOURCE_ROWS:
            raise EvaluationInputError("invalid_waveform_row_count")
        if (
            type(self.samples_per_row) is not int
            or not 2 <= self.samples_per_row <= MAX_SIGNAL_SAMPLES
        ):
            raise EvaluationInputError("invalid_waveform_sample_count")
        if not isinstance(self.dtype, str) or not 1 <= len(self.dtype) <= 32:
            raise EvaluationInputError("invalid_waveform_dtype_contract")


@dataclass(frozen=True)
class LoadedWaveforms:
    array: Any
    mmap_used: bool
    file_bytes: int


@dataclass(frozen=True)
class LoadedRowAdapter:
    adapter_id: str
    rows: Tuple[RowMetadata, ...]
    source_contract: WaveformSourceContract


@dataclass(frozen=True)
class RowFeatures:
    metadata: RowMetadata
    windows: Any


@dataclass(frozen=True)
class PrototypeSet:
    mode: str
    labels: Tuple[str, ...]
    vectors: Any


def _strict_object(pairs: Iterable[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJsonKeyError(key)
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise DuplicateJsonKeyError("non_finite_number")


def _read_strict_json(
    path: Path, maximum_bytes: int, error_prefix: str = "oracle"
) -> Any:
    try:
        before = path.lstat()
    except OSError as error:
        raise EvaluationInputError(f"{error_prefix}_unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise EvaluationInputError(f"{error_prefix}_not_regular")
    if not 0 < before.st_size <= maximum_bytes:
        raise EvaluationInputError(f"{error_prefix}_size_limit")
    try:
        with path.open("rb") as source:
            opened = os.fstat(source.fileno())
            if (before.st_dev, before.st_ino, before.st_size) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
            ):
                raise EvaluationInputError(f"{error_prefix}_identity_changed")
            data = source.read(maximum_bytes + 1)
            after = os.fstat(source.fileno())
    except EvaluationInputError:
        raise
    except OSError as error:
        raise EvaluationInputError(f"{error_prefix}_read_failed") from error
    if (
        len(data) != opened.st_size
        or len(data) > maximum_bytes
        or (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        != (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
    ):
        raise EvaluationInputError(f"{error_prefix}_changed_during_read")
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJsonKeyError) as error:
        raise EvaluationInputError(f"{error_prefix}_invalid_json") from error


def _known_group_id(value: Any) -> str:
    if (
        not isinstance(value, Mapping)
        or set(value) != {"state", "group_id"}
        or value.get("state") != "known"
        or not isinstance(value.get("group_id"), str)
        or OPAQUE_ID_PATTERN.fullmatch(value["group_id"]) is None
    ):
        raise EvaluationInputError("oracle_required_group_not_known")
    return value["group_id"]


def validate_current_oracle(value: Any) -> Mapping[str, Any]:
    """Validate the aggregate-only v0 oracle without retaining row content."""

    if not isinstance(value, Mapping) or set(value) != CURRENT_ORACLE_FIELDS:
        raise EvaluationInputError("oracle_schema_fields")
    if value.get("schema") != CURRENT_ORACLE_SCHEMA:
        raise EvaluationInputError("unsupported_oracle_schema")
    if value.get("status") != "pass":
        raise EvaluationInputError("oracle_status_not_pass")
    if (
        not isinstance(value.get("inventory_id"), str)
        or OPAQUE_ID_PATTERN.fullmatch(value["inventory_id"]) is None
    ):
        raise EvaluationInputError("oracle_inventory_id")
    if value.get("required_split_groups") != list(REQUIRED_SPLIT_GROUPS):
        raise EvaluationInputError("oracle_split_group_contract")

    manifest = value.get("manifest")
    if (
        not isinstance(manifest, Mapping)
        or manifest.get("local_ignored_manifest") is not True
        or manifest.get("partitions_assigned") != 0
        or manifest.get("train_test_splits_assigned") is not False
    ):
        raise EvaluationInputError("oracle_manifest_contract")

    privacy = value.get("privacy")
    privacy_zero_fields = (
        "absolute_paths_retained",
        "relative_paths_retained",
        "filenames_retained",
        "source_urls_retained",
        "raw_label_values_emitted",
        "waveform_members_opened",
        "waveform_payload_bytes_read",
    )
    if not isinstance(privacy, Mapping) or any(
        privacy.get(field) != 0 for field in privacy_zero_fields
    ):
        raise EvaluationInputError("oracle_privacy_contract")

    archives = value.get("archives")
    if not isinstance(archives, list) or len(archives) != 2:
        raise EvaluationInputError("oracle_archive_count")
    archive_label_rows = 0
    one_meter_archives = 0
    for archive in archives:
        if not isinstance(archive, Mapping) or set(archive) != CURRENT_ARCHIVE_FIELDS:
            raise EvaluationInputError("oracle_archive_schema")
        if (
            type(archive.get("label_rows")) is not int
            or archive["label_rows"] <= 0
            or type(archive.get("oracle_records")) is not int
            or archive["oracle_records"] <= 0
        ):
            raise EvaluationInputError("oracle_archive_counts")
        archive_label_rows += archive["label_rows"]
        if archive.get("archive_sha256") == PINNED_ONE_METER_ARCHIVE_SHA256:
            one_meter_archives += 1
    if one_meter_archives != 1:
        raise EvaluationInputError("oracle_one_meter_archive_binding")

    observations = value.get("observations")
    if not isinstance(observations, list) or not 1 <= len(observations) <= 4_096:
        raise EvaluationInputError("oracle_observation_count")
    label_rows = 0
    observation_ids = set()
    for observation in observations:
        if (
            not isinstance(observation, Mapping)
            or set(observation) != CURRENT_OBSERVATION_FIELDS
        ):
            raise EvaluationInputError("oracle_observation_schema")
        observation_id = observation.get("observation_id")
        count = observation.get("observation_count")
        if (
            not isinstance(observation_id, str)
            or OPAQUE_ID_PATTERN.fullmatch(observation_id) is None
            or observation_id in observation_ids
            or type(count) is not int
            or count <= 0
        ):
            raise EvaluationInputError("oracle_observation_contract")
        observation_ids.add(observation_id)
        label_rows += count
        for field in REQUIRED_SPLIT_GROUPS:
            _known_group_id(observation[field])
        _known_group_id(observation["physical_device_group"])

    counts = value.get("counts")
    if (
        not isinstance(counts, Mapping)
        or counts.get("observations") != len(observations)
        or counts.get("label_rows") != label_rows
        or archive_label_rows != label_rows
    ):
        raise EvaluationInputError("oracle_count_mismatch")
    return value


def load_current_oracle(path: Path) -> Mapping[str, Any]:
    return validate_current_oracle(_read_strict_json(path, MAX_ORACLE_BYTES))


def _adapter_identifier(value: Mapping[str, Any]) -> str:
    without_identifier = {
        key: item for key, item in value.items() if key != "adapter_id"
    }
    try:
        encoded = json.dumps(
            without_identifier,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise EvaluationInputError("row_adapter_not_json_serializable") from error
    return hashlib.sha256(b"netbraid.ruff-uwb-row-adapter.v0\x00" + encoded).hexdigest()


def _validate_adapter_binding(binding: RowAdapterBinding) -> None:
    if (
        not isinstance(binding, RowAdapterBinding)
        or set(binding.archive) != ARCHIVE_BINDING_FIELDS
        or set(binding.label_member) != MEMBER_BINDING_FIELDS
        or set(binding.waveform_member) != MEMBER_BINDING_FIELDS - {"sha256"}
        or binding.archive.get("receipt_schema") != RECEIPT_SCHEMA
        or not isinstance(binding.label_member.get("shape"), list)
        or binding.label_member["shape"][-1:] != [2]
        or not isinstance(binding.waveform_member.get("shape"), list)
        or binding.label_member["shape"][:1] != binding.waveform_member["shape"][:1]
    ):
        raise EvaluationInputError("invalid_row_adapter_binding")


def validate_row_adapter(
    value: Any, binding: Optional[RowAdapterBinding] = None
) -> LoadedRowAdapter:
    """Validate and expand one bounded, gap-free row-adapter document."""

    selected_binding = binding or PRODUCTION_ROW_ADAPTER_BINDING
    _validate_adapter_binding(selected_binding)
    if not isinstance(value, Mapping) or set(value) != ROW_ADAPTER_FIELDS:
        raise EvaluationInputError("row_adapter_schema_fields")
    if value.get("schema") != ROW_ADAPTER_SCHEMA:
        raise EvaluationInputError("unsupported_row_adapter_schema")
    if value.get("status") != "pass":
        raise EvaluationInputError("row_adapter_status_not_pass")
    adapter_id = value.get("adapter_id")
    if (
        not isinstance(adapter_id, str)
        or OPAQUE_ID_PATTERN.fullmatch(adapter_id) is None
        or adapter_id != _adapter_identifier(value)
    ):
        raise EvaluationInputError("row_adapter_id_mismatch")

    archive = value.get("archive")
    if (
        not isinstance(archive, Mapping)
        or set(archive) != ARCHIVE_BINDING_FIELDS
        or archive != selected_binding.archive
    ):
        raise EvaluationInputError("row_adapter_archive_binding")
    label_member = value.get("label_member")
    if (
        not isinstance(label_member, Mapping)
        or set(label_member) != MEMBER_BINDING_FIELDS
        or label_member != selected_binding.label_member
    ):
        raise EvaluationInputError("row_adapter_label_binding")
    waveform_member = value.get("waveform_member")
    if (
        not isinstance(waveform_member, Mapping)
        or set(waveform_member) != MEMBER_BINDING_FIELDS
        or {key: item for key, item in waveform_member.items() if key != "sha256"}
        != selected_binding.waveform_member
        or not isinstance(waveform_member.get("sha256"), str)
        or SHA256_PATTERN.fullmatch(waveform_member["sha256"]) is None
    ):
        raise EvaluationInputError("row_adapter_waveform_binding")

    source = value.get("waveform_source")
    if not isinstance(source, Mapping) or set(source) != WAVEFORM_SOURCE_FIELDS:
        raise EvaluationInputError("row_adapter_waveform_source_schema")
    source_contract = WaveformSourceContract(
        file_bytes=source.get("file_bytes"),
        sha256=source.get("sha256"),
        rows=source.get("rows"),
        samples_per_row=source.get("samples_per_row"),
        dtype=source.get("dtype"),
    )
    source_contract.validate()
    if (
        source_contract.file_bytes != waveform_member["member_bytes"]
        or source_contract.sha256 != waveform_member["sha256"]
        or [source_contract.rows, source_contract.samples_per_row]
        != waveform_member["shape"]
        or source_contract.dtype != waveform_member["dtype"]
        or source_contract.rows != label_member["shape"][0]
    ):
        raise EvaluationInputError("row_adapter_waveform_source_mismatch")

    privacy = value.get("privacy")
    if (
        not isinstance(privacy, Mapping)
        or set(privacy) != ROW_ADAPTER_PRIVACY_FIELDS
        or any(privacy[field] != 0 for field in ROW_ADAPTER_PRIVACY_FIELDS)
    ):
        raise EvaluationInputError("row_adapter_privacy_contract")
    counts = value.get("counts")
    if (
        not isinstance(counts, Mapping)
        or set(counts) != ROW_ADAPTER_COUNT_FIELDS
        or any(type(counts[field]) is not int for field in ROW_ADAPTER_COUNT_FIELDS)
    ):
        raise EvaluationInputError("row_adapter_count_schema")
    spans = value.get("spans")
    if (
        not isinstance(spans, list)
        or not 1 <= len(spans) <= MAX_ROW_SPANS
        or counts["spans"] != len(spans)
    ):
        raise EvaluationInputError("row_adapter_span_count")

    rows: List[RowMetadata] = []
    expected_start = 0
    prior_group: Optional[Tuple[str, str, str, str]] = None
    source_to_device: Dict[str, str] = {}
    device_to_source: Dict[str, str] = {}
    domains = {
        "distance_collection": set(),
        "physical_source": set(),
        "physical_device": set(),
        "location": set(),
    }
    for span in spans:
        if not isinstance(span, Mapping) or set(span) != ROW_SPAN_FIELDS:
            raise EvaluationInputError("row_adapter_span_schema")
        start = span.get("row_start")
        stop = span.get("row_stop")
        if type(start) is not int or type(stop) is not int or stop <= start:
            raise EvaluationInputError("row_adapter_span_extent")
        if start < expected_start:
            raise EvaluationInputError("row_adapter_span_overlap")
        if start > expected_start:
            raise EvaluationInputError("row_adapter_span_gap")
        if stop > source_contract.rows:
            raise EvaluationInputError("row_adapter_span_extent")
        identifiers = {}
        for field in domains:
            identifier = span.get(field)
            if (
                not isinstance(identifier, str)
                or OPAQUE_ID_PATTERN.fullmatch(identifier) is None
            ):
                raise EvaluationInputError(f"row_adapter_invalid_{field}")
            identifiers[field] = identifier
            domains[field].add(identifier)
        group = (
            identifiers["distance_collection"],
            identifiers["physical_source"],
            identifiers["physical_device"],
            identifiers["location"],
        )
        if group == prior_group:
            raise EvaluationInputError("row_adapter_adjacent_equivalent_spans")
        source_id = identifiers["physical_source"]
        device_id = identifiers["physical_device"]
        if source_id in source_to_device and source_to_device[source_id] != device_id:
            raise EvaluationInputError("physical_source_device_not_bijective")
        if device_id in device_to_source and device_to_source[device_id] != source_id:
            raise EvaluationInputError("physical_source_device_not_bijective")
        source_to_device[source_id] = device_id
        device_to_source[device_id] = source_id
        rows.extend(
            RowMetadata(
                row_index=row_index,
                distance_collection=identifiers["distance_collection"],
                physical_source=source_id,
                physical_device=device_id,
                location=identifiers["location"],
            )
            for row_index in range(start, stop)
        )
        expected_start = stop
        prior_group = group
    if expected_start != source_contract.rows:
        raise EvaluationInputError("row_adapter_span_gap")
    for left_index, left in enumerate(domains):
        for right in tuple(domains)[left_index + 1 :]:
            if domains[left] & domains[right]:
                raise EvaluationInputError("row_adapter_identifier_domain_collision")
    expected_counts = {
        "rows": len(rows),
        "spans": len(spans),
        "distance_collections": len(domains["distance_collection"]),
        "physical_sources": len(domains["physical_source"]),
        "physical_devices": len(domains["physical_device"]),
        "locations": len(domains["location"]),
    }
    if counts != expected_counts or len(rows) != source_contract.rows:
        raise EvaluationInputError("row_adapter_count_mismatch")
    validated_rows = _validate_rows(rows)
    return LoadedRowAdapter(
        adapter_id=adapter_id,
        rows=validated_rows,
        source_contract=source_contract,
    )


def load_row_adapter(
    path: Path, binding: Optional[RowAdapterBinding] = None
) -> LoadedRowAdapter:
    return validate_row_adapter(
        _read_strict_json(path, MAX_ROW_ADAPTER_BYTES, "row_adapter"), binding
    )


def current_oracle_blocker(value: Mapping[str, Any]) -> Dict[str, Any]:
    """Describe why v0 cannot safely bind aggregate cells to waveform rows."""

    validate_current_oracle(value)
    return {
        "schema": BLOCKER_SCHEMA,
        "status": "blocked",
        "code": "oracle_row_mapping_unavailable",
        "oracle_schema": CURRENT_ORACLE_SCHEMA,
        "observed_contract": {
            "aggregate_observation_count": True,
            "row_indices": False,
            "row_spans": False,
            "row_order_contract": False,
            "standalone_npy_digest_binding": False,
            "pinned_one_meter_archive_present": True,
        },
        "required_adapter_contract": [
            "one explicit NPY row index per metadata record",
            "one distance-collection group per row",
            "one physical-source and physical-device group per row",
            "one location group per row",
            "a digest binding for the standalone mmap-able NPY",
        ],
        "limitations": [
            "The aggregate cell counts do not establish row order or contiguity.",
            (
                "The pinned one-meter waveform is currently a deflated ZIP member, "
                "not a standalone mmap-able NPY."
            ),
            (
                "No corpus metric is computed until an explicit row adapter "
                "satisfies the contract."
            ),
        ],
        "privacy": {"corpus_rows_retained": 0, "input_paths_retained": 0},
    }


def _identifier(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > MAX_IDENTIFIER_BYTES
        or IDENTIFIER_PATTERN.fullmatch(value) is None
    ):
        raise EvaluationInputError(code)
    return value


def _validate_rows(rows: Sequence[RowMetadata]) -> Tuple[RowMetadata, ...]:
    if (
        not isinstance(rows, Sequence)
        or isinstance(rows, (str, bytes))
        or not 1 <= len(rows) <= MAX_ROWS
    ):
        raise EvaluationInputError("invalid_row_metadata_count")
    validated: List[RowMetadata] = []
    row_indices = set()
    source_to_device: Dict[str, str] = {}
    device_to_source: Dict[str, str] = {}
    locations = set()
    devices = set()
    collections = set()
    for row in rows:
        if not isinstance(row, RowMetadata):
            raise EvaluationInputError("invalid_row_metadata")
        if (
            type(row.row_index) is not int
            or not 0 <= row.row_index < MAX_SOURCE_ROWS
            or row.row_index in row_indices
        ):
            raise EvaluationInputError("duplicate_or_invalid_row_index")
        collection = _identifier(row.distance_collection, "invalid_distance_collection")
        source = _identifier(row.physical_source, "invalid_physical_source")
        device = _identifier(row.physical_device, "invalid_physical_device")
        location = _identifier(row.location, "invalid_location")
        if source in source_to_device and source_to_device[source] != device:
            raise EvaluationInputError("physical_source_device_not_bijective")
        if device in device_to_source and device_to_source[device] != source:
            raise EvaluationInputError("physical_source_device_not_bijective")
        source_to_device[source] = device
        device_to_source[device] = source
        row_indices.add(row.row_index)
        locations.add(location)
        devices.add(device)
        collections.add(collection)
        validated.append(row)
    if len(collections) != 1:
        raise EvaluationInputError("one_npy_requires_one_distance_collection")
    if not 10 <= len(locations) <= MAX_LOCATIONS:
        raise EvaluationInputError("location_count_outside_split_bound")
    if not 2 <= len(devices) <= MAX_DEVICES:
        raise EvaluationInputError("device_count_outside_bound")
    return tuple(validated)


def _hash_parts(seed: int, domain: str, *parts: object) -> bytes:
    digest = hashlib.sha256()
    namespace = b"netbraid.ruff-uwb-heldout-location.v0"
    for value in (namespace, seed.to_bytes(8, "big"), domain.encode("utf-8")):
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    for part in parts:
        encoded = str(part).encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.digest()


def partition_rows(
    rows: Sequence[RowMetadata], seed: int
) -> Dict[str, Tuple[RowMetadata, ...]]:
    """Globally assign locations 80/10/10 before any row sampling."""

    if type(seed) is not int or not 0 <= seed < 1 << 63:
        raise EvaluationInputError("invalid_seed")
    validated = _validate_rows(rows)
    locations = sorted(
        {row.location for row in validated},
        key=lambda location: (_hash_parts(seed, "location-split", location), location),
    )
    train_count = len(locations) * SPLIT_PERCENTAGES["train"] // 100
    validation_count = len(locations) * SPLIT_PERCENTAGES["validation"] // 100
    if train_count == 0 or validation_count == 0:
        raise EvaluationInputError("empty_location_partition")
    boundaries = (train_count, train_count + validation_count)
    location_role = {
        location: (
            "train"
            if index < boundaries[0]
            else "validation"
            if index < boundaries[1]
            else "test"
        )
        for index, location in enumerate(locations)
    }
    partitions = {
        role: tuple(
            sorted(
                (row for row in validated if location_role[row.location] == role),
                key=lambda row: (row.atomic_group(), row.row_index),
            )
        )
        for role in SPLITS
    }
    if any(not partitions[role] for role in SPLITS):
        raise EvaluationInputError("empty_row_partition")
    _assert_no_split_overlap(partitions)
    return partitions


def _assert_no_split_overlap(
    partitions: Mapping[str, Sequence[RowMetadata]],
) -> None:
    for left, right in combinations(SPLITS, 2):
        left_locations = {row.location for row in partitions[left]}
        right_locations = {row.location for row in partitions[right]}
        left_groups = {row.atomic_group() for row in partitions[left]}
        right_groups = {row.atomic_group() for row in partitions[right]}
        left_rows = {row.row_index for row in partitions[left]}
        right_rows = {row.row_index for row in partitions[right]}
        if left_locations & right_locations:
            raise EvaluationInputError("location_split_overlap")
        if left_groups & right_groups:
            raise EvaluationInputError("atomic_group_split_overlap")
        if left_rows & right_rows:
            raise EvaluationInputError("row_split_overlap")


def sample_rows(
    partitions: Mapping[str, Sequence[RowMetadata]],
    config: EvaluationConfig,
) -> Dict[str, Tuple[RowMetadata, ...]]:
    """Bound rows within already-assigned atomic split groups."""

    config.validate()
    sampled: Dict[str, Tuple[RowMetadata, ...]] = {}
    for role in SPLITS:
        groups: Dict[Tuple[str, str, str, str], List[RowMetadata]] = defaultdict(list)
        for row in partitions[role]:
            groups[row.atomic_group()].append(row)
        selected: List[RowMetadata] = []
        for group, candidates in sorted(groups.items()):
            ranked = sorted(
                candidates,
                key=lambda row: (
                    _hash_parts(
                        config.seed,
                        "row-sample",
                        *group,
                        row.row_index,
                    ),
                    row.row_index,
                ),
            )
            selected.extend(ranked[: config.max_rows_per_atomic_group])
        sampled[role] = tuple(
            sorted(selected, key=lambda row: (row.atomic_group(), row.row_index))
        )
    _assert_no_split_overlap(sampled)
    return sampled


def _sha256_regular_file(path: Path, expected: os.stat_result) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            opened = os.fstat(source.fileno())
            if (expected.st_dev, expected.st_ino, expected.st_size) != (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
            ):
                raise EvaluationInputError("waveform_source_changed")
            remaining = opened.st_size
            while remaining:
                chunk = source.read(min(MIB, remaining))
                if not chunk:
                    raise EvaluationInputError("waveform_source_changed")
                digest.update(chunk)
                remaining -= len(chunk)
            if source.read(1):
                raise EvaluationInputError("waveform_source_changed")
            after = os.fstat(source.fileno())
    except EvaluationInputError:
        raise
    except OSError as error:
        raise EvaluationInputError("waveform_source_read_failed") from error
    if (opened.st_dev, opened.st_ino, opened.st_size) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
    ) or (opened.st_mtime_ns, opened.st_ctime_ns) != (
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise EvaluationInputError("waveform_source_changed")
    return digest.hexdigest()


def load_waveforms(path: Path, contract: WaveformSourceContract) -> LoadedWaveforms:
    """Open one standalone NPY read-only through NumPy mmap."""

    if np is None:
        raise EvaluationInputError("numpy_unavailable")
    if not isinstance(contract, WaveformSourceContract):
        raise EvaluationInputError("missing_waveform_source_contract")
    contract.validate()
    if path.suffix.lower() != ".npy":
        raise EvaluationInputError("waveform_source_must_be_standalone_npy")
    try:
        before = path.lstat()
    except OSError as error:
        raise EvaluationInputError("waveform_source_unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise EvaluationInputError("waveform_source_not_regular")
    if before.st_size != contract.file_bytes:
        raise EvaluationInputError("waveform_source_size_mismatch")
    if _sha256_regular_file(path, before) != contract.sha256:
        raise EvaluationInputError("waveform_source_digest_mismatch")
    try:
        array = np.load(os.fspath(path), mmap_mode="r", allow_pickle=False)
    except (OSError, ValueError, TypeError) as error:
        raise EvaluationInputError("waveform_npy_invalid") from error
    try:
        after = path.lstat()
    except OSError as error:
        raise EvaluationInputError("waveform_source_changed") from error
    if (
        stat.S_ISLNK(after.st_mode)
        or (before.st_dev, before.st_ino, before.st_size)
        != (after.st_dev, after.st_ino, after.st_size)
        or (before.st_mtime_ns, before.st_ctime_ns)
        != (after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise EvaluationInputError("waveform_source_changed")
    if not isinstance(array, np.ndarray) or array.ndim != 2:
        raise EvaluationInputError("waveform_array_must_be_2d")
    if not isinstance(array, np.memmap):
        raise EvaluationInputError("waveform_mmap_unavailable")
    if (
        not 1 <= array.shape[0] <= MAX_SOURCE_ROWS
        or not 2 <= array.shape[1] <= MAX_SIGNAL_SAMPLES
    ):
        raise EvaluationInputError("waveform_shape_outside_bound")
    if not (
        np.issubdtype(array.dtype, np.floating)
        or np.issubdtype(array.dtype, np.complexfloating)
    ):
        raise EvaluationInputError("waveform_dtype_not_real_or_complex")
    if (
        array.shape != (contract.rows, contract.samples_per_row)
        or array.dtype.str != contract.dtype
    ):
        raise EvaluationInputError("waveform_array_contract_mismatch")
    return LoadedWaveforms(array=array, mmap_used=True, file_bytes=before.st_size)


def _window_starts(signal_length: int, config: EvaluationConfig) -> Tuple[int, ...]:
    if config.window_length > signal_length:
        raise EvaluationInputError("window_exceeds_signal_length")
    available = signal_length - config.window_length + 1
    count = min(config.windows_per_row, available)
    if count == 1:
        return (0,)
    return tuple(index * (available - 1) // (count - 1) for index in range(count))


def _row_features(
    waveforms: Any, row: RowMetadata, config: EvaluationConfig
) -> RowFeatures:
    starts = _window_starts(waveforms.shape[1], config)
    dtype = np.complex128 if np.iscomplexobj(waveforms) else np.float64
    features = []
    for start in starts:
        window = np.asarray(
            waveforms[row.row_index, start : start + config.window_length],
            dtype=dtype,
        )
        if not np.all(np.isfinite(window)):
            raise EvaluationInputError("selected_window_not_finite")
        centered = window - np.mean(window)
        amplitude = float(np.sqrt(np.sum(np.abs(centered) ** 2)))
        if not np.isfinite(amplitude) or amplitude <= np.finfo(np.float64).eps:
            raise EvaluationInputError("selected_window_zero_amplitude")
        features.append(centered / amplitude)
    return RowFeatures(metadata=row, windows=np.stack(features, axis=0))


def _featurize(
    waveforms: Any,
    sampled: Mapping[str, Sequence[RowMetadata]],
    config: EvaluationConfig,
) -> Dict[str, Tuple[RowFeatures, ...]]:
    selected_rows = sum(len(sampled[role]) for role in SPLITS)
    feature_values = selected_rows * config.windows_per_row * config.window_length
    if feature_values > MAX_FEATURE_VALUES:
        raise EvaluationInputError("feature_memory_bound")
    return {
        role: tuple(_row_features(waveforms, row, config) for row in sampled[role])
        for role in SPLITS
    }


def _normalized(vector: Any) -> Any:
    amplitude = float(np.sqrt(np.sum(np.abs(vector) ** 2)))
    if not np.isfinite(amplitude) or amplitude <= np.finfo(np.float64).eps:
        raise EvaluationInputError("prototype_zero_amplitude")
    return vector / amplitude


def fit_prototypes(train_rows: Sequence[RowFeatures], mode: str) -> PrototypeSet:
    """Fit one centroid or centroid-nearest template per device on train only."""

    if mode not in PROTOTYPE_MODES:
        raise EvaluationInputError("invalid_prototype_mode")
    by_device: Dict[str, List[Any]] = defaultdict(list)
    for row in train_rows:
        by_device[row.metadata.physical_device].extend(row.windows)
    labels = tuple(sorted(by_device))
    if len(labels) < 2:
        raise EvaluationInputError("training_requires_multiple_devices")
    vectors = []
    for label in labels:
        samples = np.stack(by_device[label], axis=0)
        centroid = _normalized(np.mean(samples, axis=0))
        if mode == "centroid":
            vectors.append(centroid)
            continue
        distances = np.sum(np.abs(samples - centroid) ** 2, axis=1)
        vectors.append(samples[int(np.argmin(distances))])
    return PrototypeSet(mode=mode, labels=labels, vectors=np.stack(vectors, axis=0))


def predict_rows(
    rows: Sequence[RowFeatures], prototypes: PrototypeSet
) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    truths = []
    predictions = []
    for row in rows:
        distances = np.mean(
            np.sum(
                np.abs(row.windows[:, np.newaxis, :] - prototypes.vectors) ** 2,
                axis=2,
            ),
            axis=0,
        )
        truths.append(row.metadata.physical_device)
        predictions.append(prototypes.labels[int(np.argmin(distances))])
    return tuple(truths), tuple(predictions)


def _metric_summary(
    truths: Sequence[str], predictions: Sequence[str], labels: Sequence[str]
) -> Dict[str, Any]:
    if len(truths) != len(predictions) or not truths:
        raise EvaluationInputError("metric_input_count")
    label_index = {label: index for index, label in enumerate(labels)}
    if len(label_index) != len(labels) or any(
        truth not in label_index or prediction not in label_index
        for truth, prediction in zip(truths, predictions)
    ):
        raise EvaluationInputError("metric_unknown_device")
    matrix = [[0 for _ in labels] for _ in labels]
    for truth, prediction in zip(truths, predictions):
        matrix[label_index[truth]][label_index[prediction]] += 1
    if any(sum(row) == 0 for row in matrix):
        raise EvaluationInputError("split_missing_device_support")

    recalls = []
    f1_scores = []
    for index in range(len(labels)):
        true_positive = matrix[index][index]
        support = sum(matrix[index])
        predicted = sum(row[index] for row in matrix)
        recall = true_positive / support
        precision = true_positive / predicted if predicted else 0.0
        f1 = (
            2.0 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )
        recalls.append(recall)
        f1_scores.append(f1)
    return {
        "macro_f1": round(sum(f1_scores) / len(f1_scores), 12),
        "balanced_accuracy": round(sum(recalls) / len(recalls), 12),
        "recalls": tuple(round(value, 12) for value in recalls),
        "confusion_matrix": matrix,
        "evaluated_rows": len(truths),
    }


def _digest_values(domain: str, values: Iterable[object]) -> str:
    digest = hashlib.sha256(domain.encode("utf-8"))
    for value in sorted(str(item) for item in values):
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _split_receipt(
    assigned: Sequence[RowMetadata], sampled: Sequence[RowMetadata]
) -> Dict[str, Any]:
    assigned_groups = {row.atomic_group() for row in assigned}
    locations = {row.location for row in assigned}
    return {
        "location_count": len(locations),
        "atomic_group_count": len(assigned_groups),
        "source_row_count": len(assigned),
        "sampled_row_count": len(sampled),
        "location_receipt": _digest_values("locations", locations),
        "atomic_group_receipt": _digest_values("atomic-groups", assigned_groups),
        "sampled_row_receipt": _digest_values(
            "sampled-rows", (row.row_index for row in sampled)
        ),
    }


def _overlap_receipts(
    partitions: Mapping[str, Sequence[RowMetadata]],
) -> List[Dict[str, Any]]:
    receipts = []
    for left, right in combinations(SPLITS, 2):
        receipts.append(
            {
                "splits": [left, right],
                "location_overlap": len(
                    {row.location for row in partitions[left]}
                    & {row.location for row in partitions[right]}
                ),
                "atomic_group_overlap": len(
                    {row.atomic_group() for row in partitions[left]}
                    & {row.atomic_group() for row in partitions[right]}
                ),
                "row_overlap": len(
                    {row.row_index for row in partitions[left]}
                    & {row.row_index for row in partitions[right]}
                ),
            }
        )
    return receipts


def evaluate_rows(
    rows: Sequence[RowMetadata],
    waveform_path: Path,
    source_contract: WaveformSourceContract,
    config: Optional[EvaluationConfig] = None,
) -> Dict[str, Any]:
    """Evaluate explicit row bindings without consulting held-out data in fit."""

    selected_config = config or EvaluationConfig()
    selected_config.validate()

    # This order is part of the leakage contract.
    assigned = partition_rows(rows, selected_config.seed)
    sampled = sample_rows(assigned, selected_config)
    loaded = load_waveforms(waveform_path, source_contract)
    if any(
        row.row_index >= loaded.array.shape[0]
        for role in SPLITS
        for row in assigned[role]
    ):
        raise EvaluationInputError("row_index_outside_waveform_array")
    features = _featurize(loaded.array, sampled, selected_config)

    expected_devices = {
        row.physical_device for role in SPLITS for row in assigned[role]
    }
    for role in SPLITS:
        if {row.metadata.physical_device for row in features[role]} != expected_devices:
            raise EvaluationInputError("sampled_split_missing_device")

    candidates = {}
    prototype_sets = {}
    for mode in PROTOTYPE_MODES:
        prototypes = fit_prototypes(features["train"], mode)
        truths, predictions = predict_rows(features["validation"], prototypes)
        metrics = _metric_summary(truths, predictions, prototypes.labels)
        prototype_sets[mode] = prototypes
        candidates[mode] = {
            "macro_f1": metrics["macro_f1"],
            "balanced_accuracy": metrics["balanced_accuracy"],
            "evaluated_rows": metrics["evaluated_rows"],
        }
    chosen_mode = min(
        PROTOTYPE_MODES,
        key=lambda mode: (
            -candidates[mode]["macro_f1"],
            -candidates[mode]["balanced_accuracy"],
            PROTOTYPE_MODES.index(mode),
        ),
    )
    chosen = prototype_sets[chosen_mode]
    test_truths, test_predictions = predict_rows(features["test"], chosen)
    test_metrics = _metric_summary(test_truths, test_predictions, chosen.labels)

    aliases = {
        label: f"device-{index + 1:03d}" for index, label in enumerate(chosen.labels)
    }
    split_receipts = {
        role: {
            **_split_receipt(assigned[role], sampled[role]),
            "window_count": sum(len(row.windows) for row in features[role]),
        }
        for role in SPLITS
    }
    report = {
        "schema": REPORT_SCHEMA,
        "status": "pass",
        "task": "closed_set_physical_device_classification_at_held_out_locations",
        "operation_order": [
            "global_location_partition_80_10_10",
            "bounded_row_sampling_within_atomic_groups",
            "deterministic_windowing",
            "train_only_prototype_fit",
            "validation_only_configuration_selection",
            "test_only_closed_set_evaluation",
        ],
        "configuration": {
            "seed": selected_config.seed,
            "location_split_percentages": SPLIT_PERCENTAGES,
            "max_rows_per_atomic_group": selected_config.max_rows_per_atomic_group,
            "window_length": selected_config.window_length,
            "windows_per_row": selected_config.windows_per_row,
            "normalization": "per_window_center_then_l2_amplitude_normalize",
            "selected_prototype_mode": chosen_mode,
            "closed_set_rejection_threshold": None,
        },
        "source_receipt": {
            "array_rows": loaded.array.shape[0],
            "samples_per_row": loaded.array.shape[1],
            "dtype": loaded.array.dtype.str,
            "file_bytes": loaded.file_bytes,
            "sha256": source_contract.sha256,
            "numpy_mmap": loaded.mmap_used,
            "input_path_retained": False,
        },
        "split_receipts": split_receipts,
        "leakage_checks": {
            "atomic_group_fields": [
                "distance_collection",
                "physical_source",
                "physical_device",
                "location",
            ],
            "pairwise_overlap": _overlap_receipts(assigned),
            "prototype_fit_split": "train",
            "configuration_selection_split": "validation",
            "final_evaluation_split": "test",
            "all_checks_passed": True,
        },
        "fit_receipt": {
            "split": "train",
            "sampled_row_receipt": split_receipts["train"]["sampled_row_receipt"],
            "device_count": len(chosen.labels),
        },
        "validation_selection": {
            "split": "validation",
            "candidate_metrics": candidates,
            "selected_prototype_mode": chosen_mode,
        },
        "test_metrics": {
            "macro_f1": test_metrics["macro_f1"],
            "balanced_accuracy": test_metrics["balanced_accuracy"],
            "per_device_recall": {
                aliases[label]: test_metrics["recalls"][index]
                for index, label in enumerate(chosen.labels)
            },
            "confusion_matrix": {
                "labels": [aliases[label] for label in chosen.labels],
                "rows_true_columns_predicted": test_metrics["confusion_matrix"],
            },
            "evaluated_rows": test_metrics["evaluated_rows"],
        },
        "limitations": [
            (
                "The evaluator requires an explicit row-index adapter; aggregate "
                "cell counts are insufficient."
            ),
            "Results are closed-set and do not measure rejection of unseen devices.",
            (
                "Held-out locations within one distance collection do not establish "
                "cross-distance robustness."
            ),
            "The baseline uses centered amplitude-normalized waveform shape only.",
            "No uncertainty interval or population-level claim is produced.",
        ],
        "privacy": {
            "corpus_rows_retained": 0,
            "input_paths_retained": 0,
            "raw_source_identifiers_retained": 0,
        },
    }
    render_report(report)
    return report


def render_report(report: Mapping[str, Any]) -> bytes:
    try:
        encoded = (
            json.dumps(
                report,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise EvaluationInputError("report_not_json_serializable") from error
    if len(encoded) > MAX_REPORT_BYTES:
        raise EvaluationInputError("report_size_limit")
    return encoded


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    encoded = render_report(report)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or path.exists() and not path.is_file():
        raise EvaluationInputError("unsafe_report_path")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(temporary)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--oracle",
        type=Path,
        default=(
            ROOT / "data" / "derived" / "eval" / "ruff-uwb-observation-oracles.json"
        ),
        help="compiled aggregate RUFF-UWB oracle",
    )
    parser.add_argument(
        "--row-adapter",
        type=Path,
        help="receipt-bound one-meter row adapter; enables real evaluation",
    )
    parser.add_argument(
        "--waveforms",
        type=Path,
        default=(
            ROOT / "data" / "derived" / "eval" / "ruff-uwb-one-meter-waveforms.npy"
        ),
        help="standalone pinned one-meter NPY; opened only with a valid row adapter",
    )
    parser.add_argument(
        "--report",
        type=Path,
        help="optional destination for the path-free blocker or evaluation report",
    )
    parser.add_argument(
        "--expect-blocked",
        action="store_true",
        help="return success only after writing the expected row-mapping blocker",
    )
    parser.add_argument("--seed", type=int, default=EvaluationConfig.seed)
    parser.add_argument(
        "--max-rows-per-atomic-group",
        type=int,
        default=EvaluationConfig.max_rows_per_atomic_group,
    )
    parser.add_argument(
        "--window-length", type=int, default=EvaluationConfig.window_length
    )
    parser.add_argument(
        "--windows-per-row", type=int, default=EvaluationConfig.windows_per_row
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        if args.row_adapter is None:
            oracle = load_current_oracle(args.oracle)
            report = current_oracle_blocker(oracle)
            return_code = 0 if args.expect_blocked else 2
        else:
            if args.expect_blocked:
                raise EvaluationInputError("row_adapter_expect_blocked_conflict")
            adapter = load_row_adapter(args.row_adapter)
            report = evaluate_rows(
                adapter.rows,
                args.waveforms,
                adapter.source_contract,
                EvaluationConfig(
                    seed=args.seed,
                    max_rows_per_atomic_group=args.max_rows_per_atomic_group,
                    window_length=args.window_length,
                    windows_per_row=args.windows_per_row,
                ),
            )
            return_code = 0
        if args.report is None:
            sys.stdout.buffer.write(render_report(report))
        else:
            write_report(args.report, report)
    except EvaluationInputError as error:
        sys.stderr.write(
            json.dumps(
                {"schema": BLOCKER_SCHEMA, "status": "error", "code": error.code},
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        )
        return 2
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
