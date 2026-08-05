#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["scipy==1.17.1"]
# ///
"""Measure bounded exp018 semantic alignment across four OPERAnet modalities."""

from __future__ import annotations

import argparse
import bisect
import csv
import importlib.util
import io
import json
import os
import re
import stat
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator, Mapping, Sequence

from scipy.io import loadmat, whosmat

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = Path(__file__).with_name("fixtures") / (
    "operanet-semantic-alignment-v0.json"
)
LAYOUT_PATH = Path(__file__).with_name("profile-operanet-layout.py")
LAYOUT_SPEC = importlib.util.spec_from_file_location(
    "netbraid_profile_operanet_layout_for_semantic_alignment", LAYOUT_PATH
)
if LAYOUT_SPEC is None or LAYOUT_SPEC.loader is None:
    raise RuntimeError("operanet_layout_profiler_unavailable")
LAYOUT = importlib.util.module_from_spec(LAYOUT_SPEC)
sys.modules[LAYOUT_SPEC.name] = LAYOUT
LAYOUT_SPEC.loader.exec_module(LAYOUT)

SCHEMA = "netbraid.operanet_semantic_alignment_profile.v0"
PROTOCOL_SCHEMA = "netbraid.operanet_semantic_alignment_protocol.v0"
PUBLISHER_DESCRIPTOR_DOI = "10.1038/s41597-022-01573-2"
DATASET_DOI = "10.6084/m9.figshare.16578299.v1"
EXPERIMENT_NUMBER = 18
EXPERIMENT_TOKEN = "exp_018"
MODALITY_KEYS = ("kinect", "pwr", "uwb1", "uwb2")

MIB = 1024 * 1024
MAX_PROTOCOL_BYTES = 64 * 1024
MAX_REPORT_BYTES = 256 * 1024
MAX_MAT_MEMBER_BYTES = 64 * MIB
MAX_CSV_MEMBER_BYTES = 512 * MIB
MAX_TOTAL_SELECTED_MEMBER_BYTES = 1200 * MIB
MAX_ROWS_PER_MODALITY = 1_000_000
MAX_CSV_COLUMNS = 128
MAX_CSV_LINE_BYTES = MIB
MAX_CSV_FIELD_BYTES = 512 * 1024
MAX_TEXT_BYTES = 128
MAX_COMPRESSION_RATIO = 100
TIME_PATTERN = re.compile(
    r"(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})"
    r"\.(?P<fraction>[0-9]{3,6})\Z"
)


class SemanticProfileError(RuntimeError):
    """Stable fail-closed error at an OPERAnet input boundary."""


@dataclass(frozen=True)
class ModalityProtocol:
    key: str
    archive_key: str
    member: str
    data_format: str
    headers: tuple[str, ...]
    variable: str | None


@dataclass(frozen=True)
class AlignmentProtocol:
    labels: tuple[str, ...]
    modalities: Mapping[str, ModalityProtocol]
    grid_step_us: int
    maximum_sample_age_us: int
    transition_exclusion_us: int


@dataclass(frozen=True)
class ArchiveContract:
    layout_spec: Any
    modality: ModalityProtocol


@dataclass(frozen=True)
class FieldCardinality:
    readable: bool
    cardinality: int | None
    reason: str | None


@dataclass(frozen=True)
class Timeline:
    key: str
    times_us: tuple[int, ...]
    activities: tuple[str, ...]
    activity_counts: Mapping[str, int]
    duplicate_times: int
    duplicate_label_conflicts: int
    max_gap_us: int
    person: FieldCardinality
    room: FieldCardinality

    @property
    def duration_us(self) -> int:
        return self.times_us[-1] - self.times_us[0]

    @property
    def semantic_rows(self) -> tuple[tuple[int, str], ...]:
        return tuple(zip(self.times_us, self.activities))

    @property
    def transition_times(self) -> tuple[int, ...]:
        return tuple(
            self.times_us[index]
            for index in range(1, len(self.times_us))
            if self.activities[index] != self.activities[index - 1]
        )


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], code: str
) -> None:
    if set(value) != expected:
        raise SemanticProfileError(code)


def _object(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise SemanticProfileError(code)
    return value


def _text(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise SemanticProfileError(code)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise SemanticProfileError(code) from error
    if not encoded or len(encoded) > MAX_TEXT_BYTES or value != value.strip():
        raise SemanticProfileError(code)
    return value


def _integer(value: Any, minimum: int, maximum: int, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SemanticProfileError(code)
    if not minimum <= value <= maximum:
        raise SemanticProfileError(code)
    return value


def _string_tuple(value: Any, code: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise SemanticProfileError(code)
    result = tuple(_text(item, code) for item in value)
    if not result or len(set(result)) != len(result):
        raise SemanticProfileError(code)
    return result


def _read_protocol_bytes(path: Path) -> bytes:
    try:
        source, expected = LAYOUT.open_regular(path, 1, MAX_PROTOCOL_BYTES)
    except RuntimeError as error:
        raise SemanticProfileError("protocol_missing_or_unsafe") from error
    with source:
        data = source.read(MAX_PROTOCOL_BYTES + 1)
        try:
            LAYOUT.require_unchanged(source, expected, "semantic protocol")
        except RuntimeError as error:
            raise SemanticProfileError("protocol_changed_during_read") from error
    if len(data) != expected.size or len(data) > MAX_PROTOCOL_BYTES:
        raise SemanticProfileError("protocol_byte_limit")
    return data


def load_protocol(path: Path = PROTOCOL_PATH) -> AlignmentProtocol:
    try:
        raw = LAYOUT.strict_json(_read_protocol_bytes(path), "semantic protocol")
    except RuntimeError as error:
        raise SemanticProfileError("protocol_not_strict_json") from error
    _require_exact_keys(
        raw,
        {
            "alignment",
            "allowed_activity_labels",
            "modalities",
            "publisher",
            "schema",
            "scope",
        },
        "protocol_schema",
    )
    if raw["schema"] != PROTOCOL_SCHEMA:
        raise SemanticProfileError("protocol_schema")

    publisher = _object(raw["publisher"], "publisher_contract")
    _require_exact_keys(
        publisher,
        {
            "dataset_doi",
            "descriptor_doi",
            "same_local_ntp_server",
            "stated_synchronization_accuracy_less_than_ms",
        },
        "publisher_contract",
    )
    if (
        publisher["dataset_doi"] != DATASET_DOI
        or publisher["descriptor_doi"] != PUBLISHER_DESCRIPTOR_DOI
        or publisher["same_local_ntp_server"] is not True
        or publisher["stated_synchronization_accuracy_less_than_ms"] != 20
    ):
        raise SemanticProfileError("publisher_contract")

    scope = _object(raw["scope"], "scope_contract")
    _require_exact_keys(
        scope,
        {"development_only", "experiment_number", "experiment_token"},
        "scope_contract",
    )
    if (
        scope["development_only"] is not True
        or scope["experiment_number"] != EXPERIMENT_NUMBER
        or scope["experiment_token"] != EXPERIMENT_TOKEN
    ):
        raise SemanticProfileError("scope_contract")

    labels = _string_tuple(raw["allowed_activity_labels"], "label_contract")
    if tuple(sorted(labels)) != labels:
        raise SemanticProfileError("label_contract")

    alignment = _object(raw["alignment"], "alignment_contract")
    _require_exact_keys(
        alignment,
        {
            "fixed_grid_step_ms",
            "maximum_sample_age_ms",
            "transition_exclusion_ms",
        },
        "alignment_contract",
    )
    grid_step_ms = _integer(
        alignment["fixed_grid_step_ms"], 1, 60_000, "alignment_contract"
    )
    maximum_sample_age_ms = _integer(
        alignment["maximum_sample_age_ms"], 1, 60_000, "alignment_contract"
    )
    transition_exclusion_ms = _integer(
        alignment["transition_exclusion_ms"], 0, 60_000, "alignment_contract"
    )

    raw_modalities = _object(raw["modalities"], "modality_contract")
    if set(raw_modalities) != set(MODALITY_KEYS):
        raise SemanticProfileError("modality_contract")
    modalities: dict[str, ModalityProtocol] = {}
    for key in MODALITY_KEYS:
        item = _object(raw_modalities[key], "modality_contract")
        data_format = item.get("format")
        if key in {"pwr", "kinect"}:
            _require_exact_keys(
                item,
                {"archive_key", "format", "headers", "member", "variable"},
                "modality_contract",
            )
            if data_format != "mat_v5_cell":
                raise SemanticProfileError("modality_contract")
            headers = _string_tuple(item["headers"], "mat_header_contract")
            variable = _text(item["variable"], "mat_variable_contract")
        else:
            _require_exact_keys(
                item,
                {
                    "archive_key",
                    "cir_samples",
                    "format",
                    "headers_before_cir",
                    "member",
                },
                "modality_contract",
            )
            if data_format != "streamed_csv":
                raise SemanticProfileError("modality_contract")
            prefix = _string_tuple(item["headers_before_cir"], "csv_header_contract")
            cir_samples = _integer(
                item["cir_samples"], 1, MAX_CSV_COLUMNS, "csv_header_contract"
            )
            headers = prefix + tuple(
                f"cir{index}" for index in range(1, cir_samples + 1)
            )
            variable = None
        archive_key = _text(item["archive_key"], "modality_contract")
        member = _text(item["member"], "modality_contract")
        try:
            LAYOUT.safe_member_name(member)
        except RuntimeError as error:
            raise SemanticProfileError("member_name_contract") from error
        if archive_key != key or len(headers) > MAX_CSV_COLUMNS:
            raise SemanticProfileError("modality_contract")
        if headers[:5] != (
            "exp_no",
            "timestamp",
            "activity",
            "person_id",
            "room_no",
        ) and headers[:5] != (
            "timestamp",
            "activity",
            "exp_no",
            "person_id",
            "room_no",
        ):
            raise SemanticProfileError("semantic_header_contract")
        modalities[key] = ModalityProtocol(
            key=key,
            archive_key=archive_key,
            member=member,
            data_format=data_format,
            headers=headers,
            variable=variable,
        )

    return AlignmentProtocol(
        labels=labels,
        modalities=modalities,
        grid_step_us=grid_step_ms * 1000,
        maximum_sample_age_us=maximum_sample_age_ms * 1000,
        transition_exclusion_us=transition_exclusion_ms * 1000,
    )


def production_contracts(protocol: AlignmentProtocol) -> dict[str, ArchiveContract]:
    specs = {spec.key: spec for spec in LAYOUT.SPECS}
    contracts: dict[str, ArchiveContract] = {}
    for key in MODALITY_KEYS:
        if key not in specs:
            raise SemanticProfileError("layout_spec_missing")
        spec = specs[key]
        modality = protocol.modalities[key]
        if (
            spec.member_pattern is None
            or spec.member_pattern.fullmatch(modality.member) is None
        ):
            raise SemanticProfileError("layout_member_contract")
        contracts[key] = ArchiveContract(spec, modality)
    return contracts


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _verified_identity(
    archive_path: Path, contract: ArchiveContract, verify_receipt: bool
) -> tuple[int, int, int, int]:
    try:
        before = archive_path.lstat()
    except OSError as error:
        raise SemanticProfileError("archive_unavailable") from error
    if not stat.S_ISREG(before.st_mode):
        raise SemanticProfileError("archive_missing_or_unsafe")
    expected = _identity(before)
    try:
        if verify_receipt:
            receipt = archive_path.with_suffix(archive_path.suffix + ".json")
            LAYOUT.read_receipt(receipt, contract.layout_spec)
        LAYOUT.inspect_archive(archive_path, contract.layout_spec)
        after = archive_path.lstat()
    except (OSError, RuntimeError) as error:
        raise SemanticProfileError("archive_verification_failed") from error
    if not stat.S_ISREG(after.st_mode) or _identity(after) != expected:
        raise SemanticProfileError("archive_changed_after_verification")
    return expected


def _selected_member_limit(modality: ModalityProtocol) -> int:
    if modality.data_format == "mat_v5_cell":
        return MAX_MAT_MEMBER_BYTES
    return MAX_CSV_MEMBER_BYTES


def _check_selected_member(info: zipfile.ZipInfo, modality: ModalityProtocol) -> None:
    limit = _selected_member_limit(modality)
    if not 0 < info.file_size <= limit:
        raise SemanticProfileError("selected_member_byte_limit")
    if (
        info.compress_size <= 0
        or info.file_size > info.compress_size * MAX_COMPRESSION_RATIO
    ):
        raise SemanticProfileError("selected_member_compression_ratio")
    if info.compress_type not in LAYOUT.ALLOWED_COMPRESSION_METHODS:
        raise SemanticProfileError("selected_member_compression")


def _scalar_text(value: Any) -> str | None:
    seen: set[int] = set()
    for _depth in range(8):
        if isinstance(value, str):
            try:
                encoded = value.encode("utf-8")
            except UnicodeEncodeError:
                return None
            if (
                not encoded
                or len(encoded) > MAX_TEXT_BYTES
                or value != value.strip()
                or any(ord(character) < 32 for character in value)
            ):
                return None
            return value
        if isinstance(value, bytes):
            return None
        size = getattr(value, "size", None)
        dtype = getattr(value, "dtype", None)
        if size != 1 or getattr(dtype, "names", None) is not None:
            return None
        marker = id(value)
        if marker in seen:
            return None
        seen.add(marker)
        try:
            value = value.reshape(-1)[0]
        except (AttributeError, IndexError, TypeError):
            return None
    return None


def _timestamp_us(value: str) -> int:
    match = TIME_PATTERN.fullmatch(value)
    if match is None:
        raise SemanticProfileError("malformed_timestamp")
    hour = int(match.group("hour"))
    minute = int(match.group("minute"))
    second = int(match.group("second"))
    if hour > 23 or minute > 59 or second > 59:
        raise SemanticProfileError("malformed_timestamp")
    fraction = int(match.group("fraction").ljust(6, "0"))
    return ((hour * 60 + minute) * 60 + second) * 1_000_000 + fraction


def _identifier(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if (
        not encoded
        or len(encoded) > MAX_TEXT_BYTES
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        return None
    return value


def _field_cardinality(
    values: set[str], readable: bool, reason: str
) -> FieldCardinality:
    if readable:
        return FieldCardinality(True, len(values), None)
    return FieldCardinality(False, None, reason)


def _build_timeline(
    key: str,
    rows: Iterable[tuple[str, str, str, str | None, str | None]],
    protocol: AlignmentProtocol,
    *,
    unreadable_reason: str,
) -> Timeline:
    times: list[int] = []
    activities: list[str] = []
    activity_counts: Counter[str] = Counter()
    people: set[str] = set()
    rooms: set[str] = set()
    people_readable = True
    rooms_readable = True
    duplicate_times = 0
    duplicate_label_conflicts = 0
    max_gap_us = 0
    previous_time: int | None = None
    previous_activity: str | None = None
    allowed = set(protocol.labels)

    for row_number, (experiment, timestamp, activity, person, room) in enumerate(
        rows, start=1
    ):
        if row_number > MAX_ROWS_PER_MODALITY:
            raise SemanticProfileError("row_count_limit")
        if experiment != EXPERIMENT_TOKEN:
            raise SemanticProfileError("unexpected_experiment_token")
        if activity not in allowed:
            raise SemanticProfileError("unexpected_activity_label")
        current_time = _timestamp_us(timestamp)
        if previous_time is not None:
            if current_time < previous_time:
                raise SemanticProfileError("nonmonotonic_timestamp")
            gap = current_time - previous_time
            max_gap_us = max(max_gap_us, gap)
            if gap == 0:
                duplicate_times += 1
                duplicate_label_conflicts += int(activity != previous_activity)
        previous_time = current_time
        previous_activity = activity
        times.append(current_time)
        activities.append(activity)
        activity_counts[activity] += 1

        parsed_person = _identifier(person)
        if parsed_person is None:
            people_readable = False
        else:
            people.add(parsed_person)
        parsed_room = _identifier(room)
        if parsed_room is None:
            rooms_readable = False
        else:
            rooms.add(parsed_room)

    if not times:
        raise SemanticProfileError("empty_modality")
    return Timeline(
        key=key,
        times_us=tuple(times),
        activities=tuple(activities),
        activity_counts=dict(sorted(activity_counts.items())),
        duplicate_times=duplicate_times,
        duplicate_label_conflicts=duplicate_label_conflicts,
        max_gap_us=max_gap_us,
        person=_field_cardinality(people, people_readable, unreadable_reason),
        room=_field_cardinality(rooms, rooms_readable, unreadable_reason),
    )


def _mat_rows(
    payload: bytes, modality: ModalityProtocol
) -> Iterator[tuple[str, str, str, str | None, str | None]]:
    if not payload.startswith(b"MATLAB 5.0 MAT-file"):
        raise SemanticProfileError("unsupported_mat_container")
    source = io.BytesIO(payload)
    try:
        variables = whosmat(source, appendmat=False)
    except Exception as error:
        raise SemanticProfileError("mat_metadata_parse_failed") from error
    public = [item for item in variables if not item[0].startswith("__")]
    if not public or modality.variable is None:
        raise SemanticProfileError("unexpected_mat_schema")
    if public != [(modality.variable, public[0][1], "cell")]:
        raise SemanticProfileError("unexpected_mat_schema")
    shape = public[0][1]
    if (
        not isinstance(shape, tuple)
        or len(shape) != 2
        or shape[0] < 2
        or shape[0] > MAX_ROWS_PER_MODALITY + 1
        or shape[1] != len(modality.headers)
    ):
        raise SemanticProfileError("unexpected_mat_schema")
    source.seek(0)
    try:
        loaded = loadmat(
            source,
            appendmat=False,
            chars_as_strings=True,
            struct_as_record=True,
            squeeze_me=False,
            variable_names=[modality.variable],
            verify_compressed_data_integrity=True,
        )
    except Exception as error:
        raise SemanticProfileError("mat_payload_parse_failed") from error
    values = loaded.get(modality.variable)
    if (
        values is None
        or getattr(values, "dtype", None) is None
        or values.dtype.kind != "O"
        or values.shape != shape
    ):
        raise SemanticProfileError("unexpected_mat_schema")
    headers = tuple(_scalar_text(values[0, index]) for index in range(shape[1]))
    if headers != modality.headers:
        raise SemanticProfileError("unexpected_mat_schema")
    for index in range(1, shape[0]):
        experiment = _scalar_text(values[index, 0])
        timestamp = _scalar_text(values[index, 1])
        activity = _scalar_text(values[index, 2])
        if experiment is None or timestamp is None or activity is None:
            raise SemanticProfileError("unreadable_required_mat_field")
        yield (
            experiment,
            timestamp,
            activity,
            _scalar_text(values[index, 3]),
            _scalar_text(values[index, 4]),
        )


class _BoundedCsvLines:
    def __init__(self, source: BinaryIO) -> None:
        self.source = source
        self.first = True

    def __iter__(self) -> _BoundedCsvLines:
        return self

    def __next__(self) -> str:
        data = self.source.readline(MAX_CSV_LINE_BYTES + 1)
        if not data:
            raise StopIteration
        if len(data) > MAX_CSV_LINE_BYTES or not data.endswith((b"\n", b"\r")):
            raise SemanticProfileError("csv_line_limit_or_termination")
        encoding = "utf-8-sig" if self.first else "utf-8"
        self.first = False
        try:
            return data.decode(encoding)
        except UnicodeDecodeError as error:
            raise SemanticProfileError("csv_not_utf8") from error


def _csv_rows(
    source: BinaryIO, modality: ModalityProtocol
) -> Iterator[tuple[str, str, str, str | None, str | None]]:
    csv.field_size_limit(MAX_CSV_FIELD_BYTES)
    reader = csv.DictReader(_BoundedCsvLines(source), strict=True)
    if reader.fieldnames is None or tuple(reader.fieldnames) != modality.headers:
        raise SemanticProfileError("unexpected_csv_schema")
    try:
        for row in reader:
            if None in row or any(value is None for value in row.values()):
                raise SemanticProfileError("unexpected_csv_schema")
            yield (
                row["exp_no"],
                row["timestamp"],
                row["activity"],
                row["person_id"],
                row["room_no"],
            )
    except csv.Error as error:
        raise SemanticProfileError("malformed_csv") from error


def _read_timeline(
    archive_path: Path,
    contract: ArchiveContract,
    protocol: AlignmentProtocol,
    *,
    verify_receipt: bool,
) -> tuple[Timeline, int]:
    expected_identity = _verified_identity(archive_path, contract, verify_receipt)
    try:
        source, opened_identity = LAYOUT.open_regular(
            archive_path,
            contract.layout_spec.archive_bytes,
            contract.layout_spec.archive_bytes,
        )
    except RuntimeError as error:
        raise SemanticProfileError("archive_reopen_failed") from error
    opened_identity_tuple = (
        opened_identity.device,
        opened_identity.inode,
        opened_identity.size,
        opened_identity.modified_ns,
    )
    if opened_identity_tuple != expected_identity:
        source.close()
        raise SemanticProfileError("archive_changed_before_payload_read")
    modality = contract.modality
    try:
        with source:
            with zipfile.ZipFile(source, mode="r", allowZip64=True) as archive:
                try:
                    info = archive.getinfo(modality.member)
                except KeyError as error:
                    raise SemanticProfileError("selected_member_missing") from error
                _check_selected_member(info, modality)
                with archive.open(info, mode="r") as member:
                    if modality.data_format == "mat_v5_cell":
                        payload = member.read(MAX_MAT_MEMBER_BYTES + 1)
                        if (
                            len(payload) != info.file_size
                            or len(payload) > MAX_MAT_MEMBER_BYTES
                        ):
                            raise SemanticProfileError("selected_member_byte_limit")
                        timeline = _build_timeline(
                            modality.key,
                            _mat_rows(payload, modality),
                            protocol,
                            unreadable_reason="matlab_opaque_or_nonscalar",
                        )
                    else:
                        timeline = _build_timeline(
                            modality.key,
                            _csv_rows(member, modality),
                            protocol,
                            unreadable_reason="empty_or_nonscalar_csv_field",
                        )
                if _identity(os.fstat(source.fileno())) != expected_identity:
                    raise SemanticProfileError("archive_changed_during_payload_read")
    except SemanticProfileError:
        raise
    except (OSError, EOFError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise SemanticProfileError("archive_payload_read_failed") from error
    return timeline, info.file_size


def _cardinality_report(value: FieldCardinality) -> dict[str, object]:
    return {
        "cardinality": value.cardinality,
        "readable": value.readable,
        "unreadable_reason": value.reason,
    }


def _timeline_report(timeline: Timeline, labels: Sequence[str]) -> dict[str, object]:
    return {
        "activity_label_validation": {
            "allowed_label_count": len(labels),
            "counts": dict(timeline.activity_counts),
            "observed_label_count": len(timeline.activity_counts),
            "unexpected_labels": 0,
        },
        "duration_us": timeline.duration_us,
        "person": _cardinality_report(timeline.person),
        "room": _cardinality_report(timeline.room),
        "rows": len(timeline.times_us),
        "timestamp_quality": {
            "duplicate_label_conflicts": timeline.duplicate_label_conflicts,
            "duplicate_times": timeline.duplicate_times,
            "max_gap_us": timeline.max_gap_us,
            "monotonic_non_decreasing": True,
        },
    }


def _near_transition(value: int, transitions: Sequence[int], exclusion_us: int) -> bool:
    index = bisect.bisect_left(transitions, value)
    return any(
        abs(value - transitions[candidate]) <= exclusion_us
        for candidate in (index - 1, index)
        if 0 <= candidate < len(transitions)
    )


def _label_at(
    timeline: Timeline, grid_time: int, maximum_sample_age_us: int
) -> str | None:
    index = bisect.bisect_right(timeline.times_us, grid_time) - 1
    if index < 0 or grid_time - timeline.times_us[index] > maximum_sample_age_us:
        return None
    return timeline.activities[index]


def _fixed_grid_report(
    timelines: Mapping[str, Timeline], protocol: AlignmentProtocol
) -> dict[str, object]:
    overlap_start = max(item.times_us[0] for item in timelines.values())
    overlap_end = min(item.times_us[-1] for item in timelines.values())
    first_grid = (
        (overlap_start + protocol.grid_step_us - 1) // protocol.grid_step_us
    ) * protocol.grid_step_us
    transitions = tuple(
        sorted(
            {
                value
                for timeline in timelines.values()
                for value in timeline.transition_times
            }
        )
    )
    candidates = 0
    excluded = 0
    missing = 0
    assessed = 0
    agreements = 0
    disagreements = 0
    if first_grid <= overlap_end:
        for grid_time in range(first_grid, overlap_end + 1, protocol.grid_step_us):
            candidates += 1
            if _near_transition(
                grid_time, transitions, protocol.transition_exclusion_us
            ):
                excluded += 1
                continue
            labels = [
                _label_at(timelines[key], grid_time, protocol.maximum_sample_age_us)
                for key in MODALITY_KEYS
            ]
            if any(label is None for label in labels):
                missing += 1
                continue
            assessed += 1
            if len(set(labels)) == 1:
                agreements += 1
            else:
                disagreements += 1
    return {
        "agreement_points": agreements,
        "assessed_points": assessed,
        "candidate_points": candidates,
        "disagreement_points": disagreements,
        "grid_step_us": protocol.grid_step_us,
        "maximum_sample_age_us": protocol.maximum_sample_age_us,
        "missing_modality_points": missing,
        "transition_boundary_excluded_points": excluded,
        "transition_exclusion_us": protocol.transition_exclusion_us,
    }


def _pwr_kinect_equality(timelines: Mapping[str, Timeline]) -> dict[str, object]:
    pwr = timelines["pwr"].semantic_rows
    kinect = timelines["kinect"].semantic_rows
    matching = sum(left == right for left, right in zip(pwr, kinect))
    mismatching = max(len(pwr), len(kinect)) - matching
    return {
        "compared_fields": ["exp_no", "timestamp", "activity"],
        "exactly_equal": mismatching == 0,
        "matching_rows": matching,
        "mismatching_rows": mismatching,
        "person_and_room_comparison": "not_established_matlab_fields_unreadable",
        "rows_compared": min(len(pwr), len(kinect)),
    }


def _profile_report(
    timelines: Mapping[str, Timeline], protocol: AlignmentProtocol
) -> dict[str, object]:
    overlap_start = max(item.times_us[0] for item in timelines.values())
    overlap_end = min(item.times_us[-1] for item in timelines.values())
    union_start = min(item.times_us[0] for item in timelines.values())
    union_end = max(item.times_us[-1] for item in timelines.values())
    pwr_kinect = _pwr_kinect_equality(timelines)
    grid = _fixed_grid_report(timelines, protocol)
    blockers: list[str] = []
    if overlap_end < overlap_start:
        blockers.append("no_common_timeline")
    if not pwr_kinect["exactly_equal"]:
        blockers.append("pwr_kinect_readable_semantic_rows_differ")
    if grid["assessed_points"] == 0:
        blockers.append("fixed_grid_has_no_assessed_points")
    if grid["missing_modality_points"]:
        blockers.append("fixed_grid_missing_modality_coverage")
    if grid["disagreement_points"]:
        blockers.append("fixed_grid_activity_disagreement")
    if any(item.duplicate_label_conflicts for item in timelines.values()):
        blockers.append("duplicate_timestamp_label_conflict")

    return {
        "alignment": {
            "fixed_grid_all_modality_activity": grid,
            "pwr_kinect_readable_semantic_row_equality": pwr_kinect,
            "timeline_overlap": {
                "end_spread_us": max(item.times_us[-1] for item in timelines.values())
                - overlap_end,
                "intersection_duration_us": max(0, overlap_end - overlap_start),
                "positive_intersection": overlap_end > overlap_start,
                "start_spread_us": overlap_start
                - min(item.times_us[0] for item in timelines.values()),
                "union_duration_us": union_end - union_start,
            },
        },
        "limits": {
            "max_compression_ratio": MAX_COMPRESSION_RATIO,
            "max_csv_columns": MAX_CSV_COLUMNS,
            "max_csv_field_bytes": MAX_CSV_FIELD_BYTES,
            "max_csv_line_bytes": MAX_CSV_LINE_BYTES,
            "max_csv_member_bytes": MAX_CSV_MEMBER_BYTES,
            "max_mat_member_bytes": MAX_MAT_MEMBER_BYTES,
            "max_report_bytes": MAX_REPORT_BYTES,
            "max_rows_per_modality": MAX_ROWS_PER_MODALITY,
            "max_total_selected_member_bytes": MAX_TOTAL_SELECTED_MEMBER_BYTES,
        },
        "method": {
            "archive_verification": (
                "imported pinned OPERAnet layout specs, receipt verification, full digests, "
                "and central-directory checks"
            ),
            "fixed_grid_label_selection": "latest observation at or before each grid point",
            "joinability_basis": "measured exp018 rows and timestamps, not publisher clock claims",
            "mat_reader": "SciPy MATLAB v5 cell-array deserialization",
            "uwb_reader": "bounded streaming CSV",
        },
        "modalities": {
            key: _timeline_report(timelines[key], protocol.labels)
            for key in MODALITY_KEYS
        },
        "not_established": [
            {
                "claim": "publisher_less_than_20_ms_clock_accuracy_reproduced",
                "reason": "No independent clock reference is present in the four payloads.",
            },
            {
                "claim": "participant_or_room_equality_for_pwr_and_kinect",
                "reason": "SciPy exposes the MATLAB person and room cells as opaque values.",
            },
            {
                "claim": "semantic_joinability_outside_exp018",
                "reason": "The development checkpoint reads exp018 only.",
            },
            {
                "claim": "deployment_identity_or_causal_same_event",
                "reason": "Dataset labels and temporal overlap are evaluation evidence, not deployment identity.",
            },
        ],
        "privacy": {
            "local_or_member_paths_retained": 0,
            "participant_identifier_values_retained": 0,
            "raw_rows_retained": 0,
            "raw_timestamp_values_retained": 0,
            "room_identifier_values_retained": 0,
            "signal_values_retained": 0,
        },
        "publisher": {
            "dataset_doi": DATASET_DOI,
            "descriptor_doi": PUBLISHER_DESCRIPTOR_DOI,
            "same_local_ntp_server_stated": True,
            "stated_synchronization_accuracy_less_than_ms": 20,
            "statement_used_as_alignment_result": False,
        },
        "result": {
            "blockers": blockers,
            "joinability": "established_for_exp018"
            if not blockers
            else "not_established",
        },
        "schema": SCHEMA,
        "scope": {
            "development_only": True,
            "experiment_number": EXPERIMENT_NUMBER,
            "modalities": list(MODALITY_KEYS),
        },
        "status": "pass" if not blockers else "blocked",
    }


def profile_archives(
    archive_dir: Path,
    protocol: AlignmentProtocol,
    *,
    contracts: Mapping[str, ArchiveContract] | None = None,
    verify_receipts: bool = True,
) -> dict[str, object]:
    try:
        directory_metadata = archive_dir.lstat()
    except OSError as error:
        raise SemanticProfileError("archive_directory_unavailable") from error
    if not stat.S_ISDIR(directory_metadata.st_mode) or archive_dir.is_symlink():
        raise SemanticProfileError("archive_directory_missing_or_unsafe")
    selected = dict(contracts or production_contracts(protocol))
    if set(selected) != set(MODALITY_KEYS):
        raise SemanticProfileError("archive_contract_inventory")
    if any(selected[key].modality != protocol.modalities[key] for key in MODALITY_KEYS):
        raise SemanticProfileError("archive_contract_modality_mismatch")
    timelines: dict[str, Timeline] = {}
    total_selected_bytes = 0
    for key in MODALITY_KEYS:
        try:
            timeline, selected_bytes = _read_timeline(
                archive_dir / selected[key].layout_spec.filename,
                selected[key],
                protocol,
                verify_receipt=verify_receipts,
            )
        except SemanticProfileError as error:
            raise SemanticProfileError(f"{key}_{error}") from error
        timelines[key] = timeline
        total_selected_bytes += selected_bytes
        if total_selected_bytes > MAX_TOTAL_SELECTED_MEMBER_BYTES:
            raise SemanticProfileError("selected_member_total_byte_limit")
    return _profile_report(timelines, protocol)


def render_report(report: Mapping[str, object]) -> bytes:
    rendered = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("ascii")
    if len(rendered) > MAX_REPORT_BYTES:
        raise SemanticProfileError("report_byte_limit")
    return rendered


def _existing_ancestors(path: Path) -> Iterator[Path]:
    current = path
    while True:
        if current.exists() or current.is_symlink():
            yield current
        if current.parent == current:
            break
        current = current.parent


def ensure_output_target(path: Path, input_paths: Sequence[Path]) -> None:
    candidate = path.expanduser().absolute()
    for ancestor in _existing_ancestors(candidate):
        try:
            metadata = ancestor.lstat()
        except OSError as error:
            raise SemanticProfileError("output_inspection_failed") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise SemanticProfileError("output_symlink")
    if candidate.exists() and not candidate.is_file():
        raise SemanticProfileError("output_not_regular")
    for input_path in input_paths:
        source = input_path.expanduser().absolute()
        if candidate == source:
            raise SemanticProfileError("output_aliases_input")
        if candidate.exists() and source.exists():
            try:
                if os.path.samefile(candidate, source):
                    raise SemanticProfileError("output_aliases_input")
            except OSError as error:
                raise SemanticProfileError("output_inspection_failed") from error


def write_report(
    path: Path, rendered: bytes, *, input_paths: Sequence[Path] = ()
) -> None:
    ensure_output_target(path, input_paths)
    try:
        LAYOUT.write_report(path.expanduser().absolute(), rendered)
    except RuntimeError as error:
        raise SemanticProfileError("report_write_failed") from error


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive-dir", type=Path, default=ROOT / "data" / "raw")
    parser.add_argument("--protocol", type=Path, default=PROTOCOL_PATH)
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT
        / "data"
        / "derived"
        / "eval"
        / "operanet-semantic-alignment-v0.json",
    )
    return parser.parse_args(argv)


def run(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        protocol_path = args.protocol.expanduser().absolute()
        archive_dir = args.archive_dir.expanduser().absolute()
        report_path = args.report.expanduser().absolute()
        protocol = load_protocol(protocol_path)
        contracts = production_contracts(protocol)
        input_paths = [protocol_path]
        for contract in contracts.values():
            archive = archive_dir / contract.layout_spec.filename
            input_paths.extend((archive, archive.with_suffix(archive.suffix + ".json")))
        ensure_output_target(report_path, input_paths)
        report = profile_archives(archive_dir, protocol, contracts=contracts)
        rendered = render_report(report)
        write_report(report_path, rendered, input_paths=input_paths)
    except SemanticProfileError as error:
        print(
            json.dumps({"error": str(error), "status": "rejected"}, sort_keys=True),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "joinability": report["result"]["joinability"],
                "report_bytes": len(rendered),
                "status": report["status"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
