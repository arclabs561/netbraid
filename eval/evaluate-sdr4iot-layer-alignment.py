#!/usr/bin/env python3
"""Evaluate packet, table, and signal alignment in the pinned SDR4IoT archive."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import io
import json
import math
import os
import re
import stat
import struct
import sys
import tarfile
import tempfile
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, BinaryIO, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARCHIVE = ROOT / "data" / "raw" / "sdr4iot-ble-zigbee-dataset.zip"
DEFAULT_REPORT = ROOT / "data" / "derived" / "eval" / "sdr4iot-layer-alignment-v0.json"
SCHEMA = "netbraid.sdr4iot_layer_alignment.v0"

MAX_RECORDS_PER_GROUP = 100_000
MAX_PACKET_BYTES = 16 * 1024 * 1024
MAX_CSV_FIELD_BYTES = 256
MAX_TAR_MEMBERS = 16
MAX_TAR_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TAR_TOTAL_BYTES = 16 * 1024 * 1024
MAX_SIGMF_METADATA_BYTES = 4 * 1024 * 1024
MAX_TAR_NAME_BYTES = 512
MAX_TEXT_BYTES = 4096
MAX_SIGNAL_SAMPLES = MAX_TAR_MEMBER_BYTES // 8
MAX_TIMING_RESIDUAL_NS = 2_000_000
READ_CHUNK_BYTES = 1024 * 1024

CSV_SCHEMAS: dict[tuple[str, ...], tuple[int, int, int, int, int]] = {
    (
        "Time",
        "Start_trame",
        "End_trame",
        "Channel_frequency",
        "Sample_rate",
    ): (0, 1, 2, 3, 4),
    (
        "Time",
        "Start_trame",
        "End_trame",
        "Channel_frequency",
        "Sample_rate",
        "Robot_node",
        "X",
        "Y",
    ): (0, 1, 2, 3, 4),
    (
        "Time",
        "Robot_Number",
        "X",
        "Y",
        "Angle",
        "Start_trame",
        "End_trame",
        "Central Frequency",
        "Sample_rate",
    ): (0, 5, 6, 7, 8),
}
CSV_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\Z"
)
SIGMF_TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z\Z"
)
INTEGER = re.compile(r"-?[0-9]+\Z")
SHA512 = re.compile(r"[0-9a-f]{128}\Z")
SIGMF_TOP_LEVEL_KEYS = {"global", "captures", "annotations"}
SIGMF_GLOBAL_KEYS = {
    "core:datatype",
    "core:description",
    "core:sha512",
    "core:version",
}
SIGMF_CAPTURE_KEYS = {
    "core:frequency",
    "core:sample_start",
    "core:sampling_rate",
    "core:time",
}
SIGMF_ANNOTATION_KEYS = {
    "core:comment",
    "core:latitude",
    "core:longitude",
    "core:sample_count",
    "core:sample_start",
}
DATATYPE_BYTES = {"cf32": 8}
STRUCTURAL_FAILURES = {
    "capture_annotation_start_mismatch",
    "csv_annotation_extent_mismatch",
    "frequency_mismatch",
    "layer_count_mismatch",
    "noncontiguous_signal_extent",
    "nonzero_count_required",
    "sample_rate_mismatch",
    "signal_data_extent_mismatch",
    "signal_data_sha512_mismatch",
}


class AlignmentEvaluationError(RuntimeError):
    """Stable fail-closed reason at the archive or output boundary."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class GroupEvaluationError(RuntimeError):
    """Stable fail-closed reason for one complete observation group."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GroupMembers:
    key: Any
    layers: Mapping[str, zipfile.ZipInfo]
    total_uncompressed_bytes: int


@dataclass(frozen=True)
class CsvRecord:
    timestamp_ns: int
    frame_start: int
    frame_end: int
    frequency: Decimal
    sample_rate: Decimal


@dataclass(frozen=True)
class SignalRecord:
    sample_start: int
    frequency: Decimal
    sample_rate: Decimal


@dataclass(frozen=True)
class AnnotationRecord:
    sample_start: int
    sample_count: int


@dataclass(frozen=True)
class SigmfSummary:
    captures: tuple[SignalRecord, ...]
    annotations: tuple[AnnotationRecord, ...]
    data_bytes: int
    bytes_per_sample: int
    declared_sha512: str
    observed_sha512: str


@dataclass(frozen=True)
class GroupSummary:
    packet_count: int
    csv_record_count: int
    capture_count: int
    annotation_count: int
    signal_data_bytes: int
    max_timing_residual_ns: int | None
    failure_reasons: tuple[str, ...]


def _load_layout_profiler() -> ModuleType:
    path = Path(__file__).resolve().with_name("profile-sdr4iot-layout.py")
    spec = importlib.util.spec_from_file_location("_sdr4iot_layout_profiler", path)
    if spec is None or spec.loader is None:
        raise AlignmentEvaluationError("layout_profiler_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except (ImportError, OSError) as error:
        raise AlignmentEvaluationError("layout_profiler_unavailable") from error
    required = (
        "LAYERS",
        "LayoutProfileError",
        "_digests",
        "_open_regular",
        "_parse_artifact",
        "_require_unchanged",
        "_safe_member_name",
        "profile_archive",
    )
    if any(not hasattr(module, name) for name in required):
        raise AlignmentEvaluationError("layout_profiler_contract_mismatch")
    return module


LAYOUT = _load_layout_profiler()


def _strict_object(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GroupEvaluationError("duplicate_json_key")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise GroupEvaluationError("invalid_sigmf_json")


def _bounded_text(value: Any, code: str, maximum: int = MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str):
        raise GroupEvaluationError(code)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise GroupEvaluationError(code) from error
    if not encoded or len(encoded) > maximum:
        raise GroupEvaluationError(code)
    return value


def _bounded_int(value: Any, minimum: int, maximum: int, code: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise GroupEvaluationError(code)
    return value


def _csv_int(value: str, minimum: int, maximum: int, code: str) -> int:
    if len(value.encode("utf-8")) > MAX_CSV_FIELD_BYTES or not INTEGER.fullmatch(value):
        raise GroupEvaluationError(code)
    parsed = int(value)
    if not minimum <= parsed <= maximum:
        raise GroupEvaluationError(code)
    return parsed


def _decimal(value: Any, code: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise GroupEvaluationError(code)
    if isinstance(value, str) and len(value.encode("utf-8")) > MAX_CSV_FIELD_BYTES:
        raise GroupEvaluationError(code)
    if isinstance(value, float) and not math.isfinite(value):
        raise GroupEvaluationError(code)
    try:
        parsed = Decimal(str(value))
    except InvalidOperation as error:
        raise GroupEvaluationError(code) from error
    if not parsed.is_finite() or not 0 < parsed <= Decimal("1000000000000"):
        raise GroupEvaluationError(code)
    return parsed


def _csv_timestamp_ns(value: str) -> int:
    if (
        len(value.encode("utf-8")) > MAX_CSV_FIELD_BYTES
        or CSV_TIMESTAMP.fullmatch(value) is None
    ):
        raise GroupEvaluationError("invalid_csv_timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
    except ValueError as error:
        raise GroupEvaluationError("invalid_csv_timestamp") from error
    epoch = datetime(1970, 1, 1)
    delta = parsed - epoch
    return (
        delta.days * 86_400 + delta.seconds
    ) * 1_000_000_000 + delta.microseconds * 1_000


def _validate_sigmf_timestamp(value: Any) -> None:
    text = _bounded_text(value, "invalid_sigmf_capture")
    if SIGMF_TIMESTAMP.fullmatch(text) is None:
        raise GroupEvaluationError("invalid_sigmf_capture")
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as error:
        raise GroupEvaluationError("invalid_sigmf_capture") from error


def _read_zip_member(archive: zipfile.ZipFile, member: zipfile.ZipInfo) -> bytes:
    try:
        with archive.open(member, "r") as source:
            payload = source.read(member.file_size + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise GroupEvaluationError("zip_member_read_error") from error
    if len(payload) != member.file_size:
        raise GroupEvaluationError("zip_member_extent_mismatch")
    return payload


def _parse_pcap(payload: bytes) -> tuple[int, ...]:
    if len(payload) < 24:
        raise GroupEvaluationError("malformed_pcap")
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1),
        b"\xa1\xb2\x3c\x4d": (">", 1),
    }
    selected = formats.get(payload[:4])
    if selected is None:
        raise GroupEvaluationError("unsupported_pcap_magic")
    byte_order, fractional_ns = selected
    try:
        major, minor, _zone, _figures, snaplen, _network = struct.unpack(
            f"{byte_order}HHiIII", payload[4:24]
        )
    except struct.error as error:
        raise GroupEvaluationError("malformed_pcap") from error
    if (major, minor) != (2, 4) or not 0 < snaplen <= MAX_PACKET_BYTES:
        raise GroupEvaluationError("invalid_pcap_header")

    timestamps: list[int] = []
    offset = 24
    fraction_limit = 1_000_000 if fractional_ns == 1_000 else 1_000_000_000
    while offset < len(payload):
        if len(payload) - offset < 16:
            raise GroupEvaluationError("trailing_pcap_data")
        try:
            seconds, fraction, included, original = struct.unpack(
                f"{byte_order}IIII", payload[offset : offset + 16]
            )
        except struct.error as error:
            raise GroupEvaluationError("malformed_pcap") from error
        offset += 16
        if (
            fraction >= fraction_limit
            or not 0 < included <= snaplen
            or included > MAX_PACKET_BYTES
            or original < included
            or len(payload) - offset < included
        ):
            raise GroupEvaluationError("malformed_pcap_record")
        offset += included
        timestamps.append(seconds * 1_000_000_000 + fraction * fractional_ns)
        if len(timestamps) > MAX_RECORDS_PER_GROUP:
            raise GroupEvaluationError("pcap_record_count_limit")
    return tuple(timestamps)


def _validate_auxiliary_csv_fields(row: Sequence[str], used: set[int]) -> None:
    for index, value in enumerate(row):
        if index in used:
            continue
        _csv_int(value, -(2**63), 2**63 - 1, "invalid_csv_field")


def _parse_csv(payload: bytes) -> tuple[CsvRecord, ...]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GroupEvaluationError("invalid_csv_encoding") from error
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        header = next(reader)
    except StopIteration as error:
        raise GroupEvaluationError("csv_schema_mismatch") from error
    except csv.Error as error:
        raise GroupEvaluationError("malformed_csv") from error
    indices = CSV_SCHEMAS.get(tuple(header))
    if indices is None:
        raise GroupEvaluationError("csv_schema_mismatch")
    time_index, start_index, end_index, frequency_index, rate_index = indices
    used = set(indices)
    records: list[CsvRecord] = []
    try:
        for row in reader:
            if not row:
                continue
            if len(row) != len(header):
                raise GroupEvaluationError("malformed_csv_row")
            if any(len(value.encode("utf-8")) > MAX_CSV_FIELD_BYTES for value in row):
                raise GroupEvaluationError("csv_field_size_limit")
            start = _csv_int(row[start_index], 0, 2**63 - 1, "invalid_csv_frame_extent")
            end = _csv_int(row[end_index], 0, 2**63 - 1, "invalid_csv_frame_extent")
            if end < start:
                raise GroupEvaluationError("invalid_csv_frame_extent")
            _validate_auxiliary_csv_fields(row, used)
            records.append(
                CsvRecord(
                    timestamp_ns=_csv_timestamp_ns(row[time_index]),
                    frame_start=start,
                    frame_end=end,
                    frequency=_decimal(row[frequency_index], "invalid_csv_frequency"),
                    sample_rate=_decimal(row[rate_index], "invalid_csv_sample_rate"),
                )
            )
            if len(records) > MAX_RECORDS_PER_GROUP:
                raise GroupEvaluationError("csv_record_count_limit")
    except csv.Error as error:
        raise GroupEvaluationError("malformed_csv") from error
    return tuple(records)


def _safe_tar_name(name: str) -> PurePosixPath:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise GroupEvaluationError("unsafe_tar_member") from error
    path = PurePosixPath(name)
    if (
        not encoded
        or len(encoded) > MAX_TAR_NAME_BYTES
        or name.startswith("/")
        or "\\" in name
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise GroupEvaluationError("unsafe_tar_member")
    return path


def _read_tar_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int
) -> bytes:
    source = archive.extractfile(member)
    if source is None:
        raise GroupEvaluationError("invalid_sigmf_tar")
    with source:
        payload = source.read(limit + 1)
    if len(payload) != member.size or len(payload) > limit:
        raise GroupEvaluationError("tar_member_extent_mismatch")
    return payload


def _sigmf_mapping(value: Any, keys: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise GroupEvaluationError(code)
    return value


def _parse_sigmf_metadata(
    payload: bytes,
) -> tuple[
    tuple[SignalRecord, ...],
    tuple[AnnotationRecord, ...],
    int,
    str,
]:
    if not 0 < len(payload) <= MAX_SIGMF_METADATA_BYTES:
        raise GroupEvaluationError("sigmf_metadata_size_limit")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_strict_object,
            parse_constant=_reject_json_constant,
        )
    except UnicodeDecodeError as error:
        raise GroupEvaluationError("invalid_sigmf_json") from error
    except json.JSONDecodeError as error:
        raise GroupEvaluationError("invalid_sigmf_json") from error
    root = _sigmf_mapping(value, SIGMF_TOP_LEVEL_KEYS, "invalid_sigmf_schema")
    global_fields = _sigmf_mapping(
        root["global"], SIGMF_GLOBAL_KEYS, "invalid_sigmf_global"
    )
    datatype = _bounded_text(global_fields["core:datatype"], "unknown_datatype", 32)
    bytes_per_sample = DATATYPE_BYTES.get(datatype)
    if bytes_per_sample is None:
        raise GroupEvaluationError("unknown_datatype")
    _bounded_text(global_fields["core:description"], "invalid_sigmf_global")
    _bounded_text(global_fields["core:version"], "invalid_sigmf_global", 64)
    declared_sha512 = _bounded_text(
        global_fields["core:sha512"], "invalid_sigmf_sha512", 128
    )
    if SHA512.fullmatch(declared_sha512) is None:
        raise GroupEvaluationError("invalid_sigmf_sha512")

    capture_values = root["captures"]
    annotation_values = root["annotations"]
    if not isinstance(capture_values, list) or not isinstance(annotation_values, list):
        raise GroupEvaluationError("invalid_sigmf_schema")
    if (
        len(capture_values) > MAX_RECORDS_PER_GROUP
        or len(annotation_values) > MAX_RECORDS_PER_GROUP
    ):
        raise GroupEvaluationError("sigmf_record_count_limit")

    captures: list[SignalRecord] = []
    for item in capture_values:
        fields = _sigmf_mapping(item, SIGMF_CAPTURE_KEYS, "invalid_sigmf_capture")
        _validate_sigmf_timestamp(fields["core:time"])
        captures.append(
            SignalRecord(
                sample_start=_bounded_int(
                    fields["core:sample_start"],
                    0,
                    MAX_SIGNAL_SAMPLES,
                    "invalid_sigmf_capture",
                ),
                frequency=_decimal(fields["core:frequency"], "invalid_sigmf_capture"),
                sample_rate=_decimal(
                    fields["core:sampling_rate"], "invalid_sigmf_capture"
                ),
            )
        )

    annotations: list[AnnotationRecord] = []
    for item in annotation_values:
        fields = _sigmf_mapping(item, SIGMF_ANNOTATION_KEYS, "invalid_sigmf_annotation")
        _bounded_text(fields["core:comment"], "invalid_sigmf_annotation")
        _bounded_int(
            fields["core:latitude"],
            -(2**63),
            2**63 - 1,
            "invalid_sigmf_annotation",
        )
        _bounded_int(
            fields["core:longitude"],
            -(2**63),
            2**63 - 1,
            "invalid_sigmf_annotation",
        )
        annotations.append(
            AnnotationRecord(
                sample_start=_bounded_int(
                    fields["core:sample_start"],
                    0,
                    MAX_SIGNAL_SAMPLES,
                    "invalid_sigmf_annotation",
                ),
                sample_count=_bounded_int(
                    fields["core:sample_count"],
                    1,
                    MAX_SIGNAL_SAMPLES,
                    "invalid_sigmf_annotation",
                ),
            )
        )
    return tuple(captures), tuple(annotations), bytes_per_sample, declared_sha512


def _parse_sigmf_bundle(payload: bytes) -> SigmfSummary:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:")
    except tarfile.TarError as error:
        raise GroupEvaluationError("invalid_sigmf_tar") from error
    with archive:
        names: set[str] = set()
        files: list[tuple[PurePosixPath, tarfile.TarInfo]] = []
        total_bytes = 0
        member_count = 0
        try:
            for member in archive:
                member_count += 1
                if member_count > MAX_TAR_MEMBERS:
                    raise GroupEvaluationError("tar_member_count_limit")
                path = _safe_tar_name(member.name.rstrip("/"))
                normalized = path.as_posix()
                if normalized in names:
                    raise GroupEvaluationError("duplicate_tar_member")
                names.add(normalized)
                if member.isdir():
                    if member.size != 0:
                        raise GroupEvaluationError("invalid_sigmf_tar")
                    continue
                if not member.isfile() or member.issparse():
                    raise GroupEvaluationError("unsafe_tar_member")
                if not 0 <= member.size <= MAX_TAR_MEMBER_BYTES:
                    raise GroupEvaluationError("tar_member_size_limit")
                total_bytes += member.size
                if total_bytes > MAX_TAR_TOTAL_BYTES:
                    raise GroupEvaluationError("tar_total_size_limit")
                files.append((path, member))
        except tarfile.TarError as error:
            raise GroupEvaluationError("invalid_sigmf_tar") from error

        metadata_files = [
            item for item in files if item[0].name.endswith(".sigmf-meta")
        ]
        data_files = [item for item in files if item[0].name.endswith(".sigmf-data")]
        if len(files) != 2 or len(metadata_files) != 1 or len(data_files) != 1:
            raise GroupEvaluationError("invalid_sigmf_tar_inventory")
        metadata_path, metadata_member = metadata_files[0]
        data_path, data_member = data_files[0]
        metadata_stem = metadata_path.as_posix()[: -len(".sigmf-meta")]
        data_stem = data_path.as_posix()[: -len(".sigmf-data")]
        if metadata_stem != data_stem:
            raise GroupEvaluationError("sigmf_pair_mismatch")

        metadata_payload = _read_tar_member(
            archive, metadata_member, MAX_SIGMF_METADATA_BYTES
        )
        captures, annotations, bytes_per_sample, declared_sha512 = (
            _parse_sigmf_metadata(metadata_payload)
        )
        source = archive.extractfile(data_member)
        if source is None:
            raise GroupEvaluationError("invalid_sigmf_tar")
        observed_bytes = 0
        digest = hashlib.sha512()
        with source:
            while chunk := source.read(READ_CHUNK_BYTES):
                observed_bytes += len(chunk)
                if observed_bytes > data_member.size:
                    raise GroupEvaluationError("tar_member_extent_mismatch")
                digest.update(chunk)
        if observed_bytes != data_member.size:
            raise GroupEvaluationError("tar_member_extent_mismatch")
    return SigmfSummary(
        captures=captures,
        annotations=annotations,
        data_bytes=observed_bytes,
        bytes_per_sample=bytes_per_sample,
        declared_sha512=declared_sha512,
        observed_sha512=digest.hexdigest(),
    )


def _timing_residual_ns(
    packet_timestamps: Sequence[int], csv_records: Sequence[CsvRecord]
) -> int:
    offset = packet_timestamps[0] - csv_records[0].timestamp_ns
    return max(
        abs(packet_time - record.timestamp_ns - offset)
        for packet_time, record in zip(packet_timestamps, csv_records)
    )


def _evaluate_group(
    packet_timestamps: tuple[int, ...],
    csv_records: tuple[CsvRecord, ...],
    sigmf: SigmfSummary,
) -> GroupSummary:
    counts = (
        len(packet_timestamps),
        len(csv_records),
        len(sigmf.captures),
        len(sigmf.annotations),
    )
    failures: set[str] = set()
    if 0 in counts:
        failures.add("nonzero_count_required")
    if len(set(counts)) != 1:
        failures.add("layer_count_mismatch")

    if len(csv_records) == len(sigmf.annotations) and csv_records:
        if any(
            record.frame_end - record.frame_start != annotation.sample_count
            for record, annotation in zip(csv_records, sigmf.annotations)
        ):
            failures.add("csv_annotation_extent_mismatch")

    if len(sigmf.captures) == len(sigmf.annotations) and sigmf.captures:
        if any(
            capture.sample_start != annotation.sample_start
            for capture, annotation in zip(sigmf.captures, sigmf.annotations)
        ):
            failures.add("capture_annotation_start_mismatch")

    expected_start = 0
    for annotation in sigmf.annotations:
        if annotation.sample_start != expected_start:
            failures.add("noncontiguous_signal_extent")
        expected_start += annotation.sample_count
        if expected_start > MAX_SIGNAL_SAMPLES:
            raise GroupEvaluationError("signal_sample_count_limit")

    if len(csv_records) == len(sigmf.captures) and csv_records:
        if any(
            record.frequency != capture.frequency
            for record, capture in zip(csv_records, sigmf.captures)
        ):
            failures.add("frequency_mismatch")
        if any(
            record.sample_rate != capture.sample_rate
            for record, capture in zip(csv_records, sigmf.captures)
        ):
            failures.add("sample_rate_mismatch")

    max_residual: int | None = None
    if len(packet_timestamps) == len(csv_records) and packet_timestamps:
        max_residual = _timing_residual_ns(packet_timestamps, csv_records)
        if max_residual > MAX_TIMING_RESIDUAL_NS:
            failures.add("timing_residual_exceeded")

    expected_data_bytes = expected_start * sigmf.bytes_per_sample
    if sigmf.data_bytes != expected_data_bytes:
        failures.add("signal_data_extent_mismatch")
    if sigmf.observed_sha512 != sigmf.declared_sha512:
        failures.add("signal_data_sha512_mismatch")

    return GroupSummary(
        packet_count=counts[0],
        csv_record_count=counts[1],
        capture_count=counts[2],
        annotation_count=counts[3],
        signal_data_bytes=sigmf.data_bytes,
        max_timing_residual_ns=max_residual,
        failure_reasons=tuple(sorted(failures)),
    )


def _partition_complete_groups(
    members: Sequence[zipfile.ZipInfo],
) -> tuple[GroupMembers, tuple[GroupMembers, ...]]:
    groups: dict[Any, dict[str, zipfile.ZipInfo]] = defaultdict(dict)
    for member in members:
        if member.is_dir():
            continue
        parsed = LAYOUT._parse_artifact(LAYOUT._safe_member_name(member.filename))
        if parsed is None or parsed.supplemental_extract:
            continue
        groups[parsed.observation][parsed.layer] = member
    required = set(LAYOUT.LAYERS.values())
    complete = [
        GroupMembers(
            key=key,
            layers=layers,
            total_uncompressed_bytes=sum(
                member.file_size for member in layers.values()
            ),
        )
        for key, layers in groups.items()
        if required <= set(layers)
    ]
    if not complete:
        raise AlignmentEvaluationError("no_complete_groups")
    ordered = sorted(
        complete, key=lambda group: (-group.total_uncompressed_bytes, group.key)
    )
    development = ordered[0]
    evaluation = tuple(sorted(ordered[1:], key=lambda group: group.key))
    if not evaluation:
        raise AlignmentEvaluationError("no_evaluation_groups")
    return development, evaluation


def _group_payload_summary(
    archive: zipfile.ZipFile, group: GroupMembers
) -> GroupSummary:
    packet_payload = _read_zip_member(archive, group.layers["packet_capture"])
    csv_payload = _read_zip_member(archive, group.layers["tabular_extract"])
    sigmf_payload = _read_zip_member(archive, group.layers["publisher_sigmf"])
    return _evaluate_group(
        _parse_pcap(packet_payload),
        _parse_csv(csv_payload),
        _parse_sigmf_bundle(sigmf_payload),
    )


def _capability_flags(summary: GroupSummary) -> tuple[bool, bool, bool]:
    counts = (
        summary.packet_count,
        summary.csv_record_count,
        summary.capture_count,
        summary.annotation_count,
    )
    populated_count_aligned = counts[0] > 0 and len(set(counts)) == 1
    failures = set(summary.failure_reasons)
    representation_structure_aligned = populated_count_aligned and not (
        failures & STRUCTURAL_FAILURES
    )
    clock_within_2ms = (
        populated_count_aligned
        and summary.max_timing_residual_ns is not None
        and summary.max_timing_residual_ns <= MAX_TIMING_RESIDUAL_NS
    )
    return (
        populated_count_aligned,
        representation_structure_aligned,
        clock_within_2ms,
    )


def _modality_report(counters: Mapping[str, Counter[str]]) -> dict[str, Any]:
    return {
        modality: {
            "evaluation_groups": counts["evaluation_groups"],
            "groups_passed_all_checks": counts["groups_passed_all_checks"],
            "groups_failed": counts["groups_failed"],
            "groups_parsed": counts["groups_parsed"],
            "groups_with_populated_equal_counts": counts[
                "groups_with_populated_equal_counts"
            ],
            "groups_with_representation_structure_alignment": counts[
                "groups_with_representation_structure_alignment"
            ],
            "groups_with_clock_residual_within_2ms": counts[
                "groups_with_clock_residual_within_2ms"
            ],
        }
        for modality, counts in sorted(counters.items())
    }


def evaluate_archive(
    path: Path, *, verify_publisher_digest: bool = True
) -> dict[str, Any]:
    layout_report = LAYOUT.profile_archive(
        path, verify_publisher_digest=verify_publisher_digest
    )
    source: BinaryIO
    source, identity = LAYOUT._open_regular(path)
    try:
        observed_md5, observed_sha256 = LAYOUT._digests(source)
        layout_source = layout_report["source"]
        if (
            identity.size != layout_source["bytes"]
            or observed_md5 != layout_source["md5"]
            or observed_sha256 != layout_source["sha256"]
        ):
            raise AlignmentEvaluationError("archive_changed_after_layout_profile")
        source.seek(0)
        try:
            archive = zipfile.ZipFile(source)
        except (OSError, zipfile.BadZipFile) as error:
            raise AlignmentEvaluationError("invalid_zip_archive") from error
        with archive:
            _development, evaluation_groups = _partition_complete_groups(
                archive.infolist()
            )
            failures: Counter[str] = Counter()
            passed = 0
            failed = 0
            packet_count = 0
            csv_record_count = 0
            capture_count = 0
            annotation_count = 0
            signal_data_bytes = 0
            residuals: list[int] = []
            modality_counts: dict[str, Counter[str]] = defaultdict(Counter)
            for group in evaluation_groups:
                modality = group.key.modality
                modality_counts[modality]["evaluation_groups"] += 1
                try:
                    summary = _group_payload_summary(archive, group)
                except GroupEvaluationError as error:
                    failed += 1
                    failures[error.code] += 1
                    modality_counts[modality]["groups_failed"] += 1
                    continue
                modality_counts[modality]["groups_parsed"] += 1
                packet_count += summary.packet_count
                csv_record_count += summary.csv_record_count
                capture_count += summary.capture_count
                annotation_count += summary.annotation_count
                signal_data_bytes += summary.signal_data_bytes
                if summary.max_timing_residual_ns is not None:
                    residuals.append(summary.max_timing_residual_ns)
                populated, structural, clock_aligned = _capability_flags(summary)
                modality_counts[modality]["groups_with_populated_equal_counts"] += int(
                    populated
                )
                modality_counts[modality][
                    "groups_with_representation_structure_alignment"
                ] += int(structural)
                modality_counts[modality]["groups_with_clock_residual_within_2ms"] += (
                    int(clock_aligned)
                )
                if summary.failure_reasons:
                    failed += 1
                    failures.update(summary.failure_reasons)
                    modality_counts[modality]["groups_failed"] += 1
                else:
                    passed += 1
                    modality_counts[modality]["groups_passed_all_checks"] += 1
        LAYOUT._require_unchanged(source, identity)
    finally:
        source.close()

    evaluation_count = len(evaluation_groups)
    return {
        "schema": SCHEMA,
        "status": "pass" if failed == 0 and passed == evaluation_count else "fail",
        "source_digests": {
            "md5": observed_md5,
            "sha256": observed_sha256,
        },
        "counts": {
            "source_bytes": identity.size,
            "complete_groups": evaluation_count + 1,
            "development_groups": 1,
            "evaluation_groups": evaluation_count,
            "evaluation_groups_passed": passed,
            "evaluation_groups_failed": failed,
            "packets": packet_count,
            "csv_records": csv_record_count,
            "sigmf_captures": capture_count,
            "sigmf_annotations": annotation_count,
            "signal_data_bytes": signal_data_bytes,
        },
        "max_timing_residual_ns": max(residuals) if residuals else None,
        "descriptive_capability_by_modality": _modality_report(modality_counts),
        "failure_reason_counts": dict(sorted(failures.items())),
    }


def render_report(report: Mapping[str, Any]) -> bytes:
    return (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _existing_lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def write_report(path: Path, payload: bytes, *, source_path: Path) -> None:
    if os.path.abspath(path) == os.path.abspath(source_path):
        raise AlignmentEvaluationError("report_aliases_source")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
        raise AlignmentEvaluationError("unsafe_report_parent")
    existing = _existing_lstat(path)
    if existing is not None:
        if (
            stat.S_ISLNK(existing.st_mode)
            or not stat.S_ISREG(existing.st_mode)
            or existing.st_nlink != 1
        ):
            raise AlignmentEvaluationError("unsafe_report_path")
        try:
            if os.path.samefile(path, source_path):
                raise AlignmentEvaluationError("report_aliases_source")
        except FileNotFoundError:
            pass
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        report = evaluate_archive(arguments.archive)
        encoded = render_report(report)
        write_report(arguments.report, encoded, source_path=arguments.archive)
    except AlignmentEvaluationError as error:
        print(error.code, file=sys.stderr)
        return 2
    except LAYOUT.LayoutProfileError as error:
        print(str(error), file=sys.stderr)
        return 2
    except OSError:
        print("io_error", file=sys.stderr)
        return 2
    print(encoded.decode("utf-8"), end="")
    # A rejected research hypothesis is a valid evaluation result. Reserve a
    # nonzero exit for malformed inputs or an incomplete run.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
