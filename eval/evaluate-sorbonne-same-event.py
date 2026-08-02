#!/usr/bin/env python3
"""Audit preregistered same-event oracle structure in Sorbonne's 1 m run."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple


SCHEMA_VERSION = "netbraid.sorbonne_same_event_audit.v1"
CAMPAIGN_SCHEMA = "netbraid.sorbonne_same_event_campaign.v0"
EXPECTED_ARCHIVE_SHA256 = (
    "7a650d450d339683cf7591bc24a6006238456b8dfa54e352aa1aceda8682c3f8"
)
EXPECTED_CAMPAIGN_SHA256 = (
    "216aedfc3a894e3a295e82578fd3fa0fc8b764bd521576e2495d3352fb76598e"
)
EXPECTED_STRUCTURE = {
    "comparison": "exact",
    "observations": 18_926,
    "events": 2_715,
    "multi_observer_events": 2_673,
    "all_observer_events": 455,
    "positive_cross_observer_pairs": 64_149,
    "duplicate_event_keys_within_observer": 0,
    "events_with_contradictory_invariant_metadata": 0,
}
EXPECTED_COLUMNS = (
    "Frame_number",
    "Frame_time_epoch",
    "RSSI_dBm",
    "Channel",
    "Frame_type",
    "Frame_subtype",
    "Retransmission",
    "Source_MAC_address",
    "Sequence_number",
)
EXPECTED_OBSERVERS = tuple("S{:02d}".format(index) for index in range(1, 11))
MEMBER_PATTERN = re.compile(
    r"(?:^|/)1m/csvTracesSynchronized/01m-(S\d{2})-synchronized\.txt$"
)
TIMESTAMP_PATTERN = re.compile(r"[0-9]{1,12}(?:\.[0-9]{1,9})?")
MAC_PATTERN = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")

MIB = 1024 * 1024
MAX_ARCHIVE_BYTES = 16 * MIB
MAX_ARCHIVE_MEMBERS = 512
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 64 * MIB
MAX_MEMBER_UNCOMPRESSED_BYTES = 1 * MIB
MAX_SELECTED_UNCOMPRESSED_BYTES = 16 * MIB
MAX_OBSERVERS = 10
MAX_ROWS_PER_OBSERVER = 100_000
MAX_TOTAL_OBSERVATIONS = 1_000_000
SYNCHRONIZED_TIME_WINDOW_NS = 1_000_000


class EvaluationError(RuntimeError):
    """Raised when the bounded input or evaluator contract is violated."""


class DuplicateKeyError(ValueError):
    """Raised when strict campaign JSON repeats an object key."""


@dataclass(frozen=True)
class Observation:
    observer: str
    frame_number: int
    time_ns: int
    rssi_dbm: int
    channel: int
    frame_type: int
    frame_subtype: int
    retransmission: int
    source_mac: str
    sequence_number: int

    def oracle_key(self) -> Tuple[str, int]:
        return self.source_mac, self.sequence_number

    def invariant_metadata(self) -> Tuple[int, int, int, int]:
        return (
            self.channel,
            self.frame_type,
            self.frame_subtype,
            self.retransmission,
        )


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign",
        required=True,
        type=Path,
        help="locked Sorbonne same-event campaign JSON",
    )
    parser.add_argument(
        "--archive",
        required=True,
        type=Path,
        help="Sorbonne 220211012-SU-Outdoors-Campus ZIP archive",
    )
    parser.add_argument(
        "--report",
        required=True,
        type=Path,
        help="destination for the deterministic JSON audit report",
    )
    return parser.parse_args(argv)


def bounded_int(
    value: str, field: str, observer: str, row_number: int, minimum: int, maximum: int
) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise EvaluationError(
            f"{observer} row {row_number}: {field} is not a base-10 integer"
        ) from error
    if not minimum <= parsed <= maximum:
        raise EvaluationError(
            f"{observer} row {row_number}: {field} is outside [{minimum}, {maximum}]"
        )
    return parsed


def timestamp_ns(value: str, observer: str, row_number: int) -> int:
    if TIMESTAMP_PATTERN.fullmatch(value) is None:
        raise EvaluationError(
            f"{observer} row {row_number}: Frame_time_epoch is not fixed-point seconds"
        )
    seconds, separator, fraction = value.partition(".")
    nanos = int(fraction.ljust(9, "0"), 10) if separator else 0
    return int(seconds, 10) * 1_000_000_000 + nanos


def read_archive(path: Path) -> Tuple[bytes, str, str]:
    try:
        path_state = path.lstat()
    except OSError as error:
        raise EvaluationError(f"cannot inspect archive: {path}") from error
    if not stat.S_ISREG(path_state.st_mode):
        raise EvaluationError(f"archive is not a regular non-symlink file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvaluationError(
            f"cannot open archive without following links: {path}"
        ) from error
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (before.st_dev, before.st_ino) != (path_state.st_dev, path_state.st_ino):
            raise EvaluationError("archive changed between inspection and open")
        data = source.read(MAX_ARCHIVE_BYTES + 1)
        after = os.fstat(source.fileno())
    if not 0 < before.st_size <= MAX_ARCHIVE_BYTES:
        raise EvaluationError(f"archive byte count is outside (0, {MAX_ARCHIVE_BYTES}]")
    if (
        len(data) != before.st_size
        or len(data) > MAX_ARCHIVE_BYTES
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
        or after.st_ctime_ns != before.st_ctime_ns
        or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
    ):
        raise EvaluationError("archive changed while reading")
    return data, hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest()


def strict_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(key)
        value[key] = item
    return value


def exact_keys(value: Any, expected: set[str], name: str) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise EvaluationError(f"campaign {name} fields differ from the locked schema")
    return value


def load_campaign(path: Path) -> Tuple[Dict[str, Any], str]:
    if path.is_symlink() or not path.is_file():
        raise EvaluationError(f"campaign is not a regular non-symlink file: {path}")
    data = path.read_bytes()
    if not 0 < len(data) <= 64 * 1024:
        raise EvaluationError("campaign byte count is outside its bound")
    campaign_sha256 = hashlib.sha256(data).hexdigest()
    if campaign_sha256 != EXPECTED_CAMPAIGN_SHA256:
        raise EvaluationError(
            "campaign content differs from the locked preregistration"
        )
    try:
        campaign = json.loads(data, object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKeyError) as error:
        raise EvaluationError("campaign is not strict duplicate-free JSON") from error

    top_level = exact_keys(
        campaign,
        {
            "schema",
            "campaign_id",
            "preregistration",
            "source",
            "split",
            "field_policy",
            "oracle",
            "synchronized_time_diagnostic",
            "expected_structure",
            "metrics",
            "failure_gates",
            "blockers",
            "limitations",
        },
        "top-level",
    )
    if (
        top_level["schema"] != CAMPAIGN_SCHEMA
        or top_level["campaign_id"] != "sorbonne-campus-1m-same-event-v0"
    ):
        raise EvaluationError("campaign identity differs from the locked campaign")

    preregistration = exact_keys(
        top_level["preregistration"],
        {
            "status",
            "revision",
            "revision_reason",
            "registered_against_netbraid_revision",
            "execution_state",
            "unknown_manifest_fields",
            "missing_required_fields",
        },
        "preregistration",
    )
    revision = preregistration["registered_against_netbraid_revision"]
    if (
        preregistration["status"] != "revised_before_execution"
        or preregistration["revision"] != 1
        or not isinstance(preregistration["revision_reason"], str)
        or preregistration["execution_state"] != "not_executed"
        or preregistration["unknown_manifest_fields"] != "reject"
        or preregistration["missing_required_fields"] != "reject"
        or not isinstance(revision, str)
        or re.fullmatch(r"[0-9a-f]{40}", revision) is None
    ):
        raise EvaluationError("campaign preregistration is not locked and unexecuted")

    source = exact_keys(
        top_level["source"],
        {"corpus", "publisher_doi", "license", "archive", "members", "observers"},
        "source",
    )
    archive = exact_keys(
        source["archive"],
        {"key", "filename", "bytes", "md5", "sha256"},
        "source.archive",
    )
    if archive != {
        "key": "sorbonne-campus-rssi",
        "filename": "220211012-SU-Outdoors-Campus.zip",
        "bytes": 3_144_312,
        "md5": "3ce2868b97eb1a8750233e67fb3cfbe3",
        "sha256": EXPECTED_ARCHIVE_SHA256,
    }:
        raise EvaluationError("campaign archive identity differs from registration")
    members = exact_keys(
        source["members"],
        {
            "root",
            "name_pattern",
            "name_regex",
            "format",
            "delimiter",
            "header",
            "expected_member_count",
            "require_complete_members",
            "reject_unmatched_members",
        },
        "source.members",
    )
    if (
        members["header"] != list(EXPECTED_COLUMNS)
        or members["delimiter"] != "\t"
        or members["format"] != "sorbonne-rssi-tsv-v1"
        or members["expected_member_count"] != len(EXPECTED_OBSERVERS)
        or members["require_complete_members"] is not True
        or members["reject_unmatched_members"] is not True
        or source["observers"] != list(EXPECTED_OBSERVERS)
    ):
        raise EvaluationError("campaign TSV inventory differs from registration")

    if top_level["expected_structure"] != EXPECTED_STRUCTURE:
        raise EvaluationError(
            "campaign expected structural counts differ from registration"
        )
    blocking = exact_keys(
        top_level["synchronized_time_diagnostic"],
        {
            "field",
            "window_milliseconds",
            "window_seconds",
            "comparison",
            "boundary",
            "cross_observer_only",
            "undirected_pairs",
            "emit_each_pair_once",
            "expected_same_event_pairs",
            "expected_different_event_pairs",
            "predictive_use",
            "reason",
        },
        "synchronized_time_diagnostic",
    )
    if (
        blocking["field"] != "Frame_time_epoch"
        or blocking["window_milliseconds"] != 1
        or blocking["window_seconds"] != 0.001
        or blocking["comparison"] != "absolute_timestamp_delta_less_than_or_equal"
        or blocking["boundary"] != "inclusive"
        or blocking["cross_observer_only"] is not True
        or blocking["undirected_pairs"] is not True
        or blocking["emit_each_pair_once"] is not True
        or blocking["expected_same_event_pairs"] != 64_149
        or blocking["expected_different_event_pairs"] != 0
        or blocking["predictive_use"] != "forbidden"
    ):
        raise EvaluationError(
            "campaign synchronized-time audit differs from registration"
        )

    field_policy = top_level["field_policy"]
    if (
        not isinstance(field_policy, dict)
        or field_policy.get("oracle_fields")
        != ["Source_MAC_address", "Sequence_number"]
        or field_policy.get("oracle_event_key")
        != ["Source_MAC_address", "Sequence_number"]
        or field_policy.get("derived_diagnostic_fields") != ["Frame_time_epoch"]
    ):
        raise EvaluationError("campaign oracle field policy differs from registration")

    return top_level, campaign_sha256


def select_members(
    archive: zipfile.ZipFile,
) -> Tuple[Dict[str, zipfile.ZipInfo], Dict[str, int]]:
    infos = archive.infolist()
    if len(infos) > MAX_ARCHIVE_MEMBERS:
        raise EvaluationError("archive exceeds the member-count limit")

    selected: Dict[str, zipfile.ZipInfo] = {}
    seen_names = set()
    total_uncompressed = 0
    selected_uncompressed = 0
    for info in infos:
        if info.filename in seen_names:
            raise EvaluationError(f"archive contains duplicate member: {info.filename}")
        seen_names.add(info.filename)
        if info.filename.startswith("/") or ".." in info.filename.split("/"):
            raise EvaluationError(
                f"archive contains unsafe member path: {info.filename}"
            )
        if info.flag_bits & 1:
            raise EvaluationError(f"archive contains encrypted member: {info.filename}")
        if info.file_size < 0 or info.file_size > MAX_MEMBER_UNCOMPRESSED_BYTES:
            raise EvaluationError(
                f"archive member exceeds its byte limit: {info.filename}"
            )
        total_uncompressed += info.file_size
        if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise EvaluationError(
                "archive exceeds the aggregate uncompressed-byte limit"
            )

        match = MEMBER_PATTERN.search(info.filename)
        if (
            "/1m/csvTracesSynchronized/" in info.filename
            and not info.is_dir()
            and match is None
        ):
            raise EvaluationError(
                f"unregistered member in synchronized 1 m run: {info.filename}"
            )
        if match is None:
            continue
        if info.is_dir():
            raise EvaluationError(
                f"selected TSV member is a directory: {info.filename}"
            )
        observer = match.group(1)
        if observer in selected:
            raise EvaluationError(f"archive contains duplicate observer: {observer}")
        selected[observer] = info
        selected_uncompressed += info.file_size
        if selected_uncompressed > MAX_SELECTED_UNCOMPRESSED_BYTES:
            raise EvaluationError(
                "selected TSV members exceed their aggregate byte limit"
            )

    if len(selected) > MAX_OBSERVERS:
        raise EvaluationError("selected run exceeds the observer-count limit")
    if tuple(sorted(selected)) != EXPECTED_OBSERVERS:
        raise EvaluationError(
            "1 m synchronized run must contain exactly sniffers S01 through S10"
        )
    return selected, {
        "archive_members": len(infos),
        "archive_uncompressed_bytes": total_uncompressed,
        "selected_uncompressed_bytes": selected_uncompressed,
    }


def parse_member(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, observer: str
) -> List[Observation]:
    try:
        with archive.open(info, "r") as source:
            data = source.read(MAX_MEMBER_UNCOMPRESSED_BYTES + 1)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise EvaluationError(
            f"failed to read selected member: {info.filename}"
        ) from error
    if len(data) != info.file_size or len(data) > MAX_MEMBER_UNCOMPRESSED_BYTES:
        raise EvaluationError(
            f"selected member violates its byte contract: {info.filename}"
        )
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvaluationError(
            f"selected member is not strict UTF-8: {info.filename}"
        ) from error

    reader = csv.reader(io.StringIO(text, newline=""), delimiter="\t", strict=True)
    try:
        header = next(reader)
    except StopIteration as error:
        raise EvaluationError(f"selected member is empty: {info.filename}") from error
    if tuple(header) != EXPECTED_COLUMNS:
        raise EvaluationError(
            f"selected member has the wrong 9-column schema: {info.filename}"
        )

    observations: List[Observation] = []
    try:
        for row_number, row in enumerate(reader, start=2):
            if len(row) != len(EXPECTED_COLUMNS):
                raise EvaluationError(
                    f"{observer} row {row_number}: expected exactly 9 TSV columns"
                )
            if len(observations) >= MAX_ROWS_PER_OBSERVER:
                raise EvaluationError(f"{observer} exceeds the row-count limit")
            if MAC_PATTERN.fullmatch(row[7]) is None:
                raise EvaluationError(
                    f"{observer} row {row_number}: Source_MAC_address is invalid"
                )
            observations.append(
                Observation(
                    observer=observer,
                    frame_number=bounded_int(
                        row[0], "Frame_number", observer, row_number, 1, 10_000_000
                    ),
                    time_ns=timestamp_ns(row[1], observer, row_number),
                    rssi_dbm=bounded_int(
                        row[2], "RSSI_dBm", observer, row_number, -128, 127
                    ),
                    channel=bounded_int(
                        row[3], "Channel", observer, row_number, 0, 255
                    ),
                    frame_type=bounded_int(
                        row[4], "Frame_type", observer, row_number, 0, 3
                    ),
                    frame_subtype=bounded_int(
                        row[5], "Frame_subtype", observer, row_number, 0, 15
                    ),
                    retransmission=bounded_int(
                        row[6], "Retransmission", observer, row_number, 0, 1
                    ),
                    source_mac=row[7].lower(),
                    sequence_number=bounded_int(
                        row[8], "Sequence_number", observer, row_number, 0, 4095
                    ),
                )
            )
    except csv.Error as error:
        raise EvaluationError(
            f"malformed TSV in selected member: {info.filename}"
        ) from error
    if not observations:
        raise EvaluationError(f"selected member has no observations: {info.filename}")
    return observations


def collision_excess(counts: Counter[Any]) -> int:
    return sum(count - 1 for count in counts.values() if count > 1)


def observer_audit(
    members: Dict[str, zipfile.ZipInfo], by_observer: Dict[str, List[Observation]]
) -> List[Dict[str, Any]]:
    result = []
    for observer in EXPECTED_OBSERVERS:
        rows = by_observer[observer]
        sequences = Counter(item.sequence_number for item in rows)
        oracle_keys = Counter(item.oracle_key() for item in rows)
        result.append(
            {
                "observer_id": observer,
                "member": members[observer].filename,
                "observations": len(rows),
                "unique_sequences": len(sequences),
                "sequence_numbers_are_unique": len(sequences) == len(rows),
                "sequence_collision_groups": sum(
                    count > 1 for count in sequences.values()
                ),
                "sequence_collision_excess_observations": collision_excess(sequences),
                "oracle_key_collision_groups": sum(
                    count > 1 for count in oracle_keys.values()
                ),
                "oracle_key_collision_excess_observations": collision_excess(
                    oracle_keys
                ),
            }
        )
    return result


def cross_observer_pairs(group: Sequence[Observation]) -> int:
    per_observer = list(Counter(item.observer for item in group).values())
    return sum(
        left * right
        for index, left in enumerate(per_observer)
        for right in per_observer[index + 1 :]
    )


def oracle_audit(
    observations: Sequence[Observation],
) -> Tuple[Dict[str, Any], Dict[str, int], int]:
    events: Dict[Tuple[str, int], List[Observation]] = defaultdict(list)
    sequence_sources: Dict[int, set[str]] = defaultdict(set)
    for item in observations:
        events[item.oracle_key()].append(item)
        sequence_sources[item.sequence_number].add(item.source_mac)

    contradictory_events = 0
    contradictory_observations = 0
    same_observer_collision_events = 0
    duplicate_event_keys_within_observer = 0
    coverage = Counter()
    positive_pairs = 0
    for group in events.values():
        observer_counts = Counter(item.observer for item in group)
        coverage[len(observer_counts)] += 1
        positive_pairs += cross_observer_pairs(group)
        if any(count > 1 for count in observer_counts.values()):
            same_observer_collision_events += 1
        duplicate_event_keys_within_observer += collision_excess(observer_counts)
        if len({item.invariant_metadata() for item in group}) > 1:
            contradictory_events += 1
            contradictory_observations += len(group)

    observed_structure = {
        "observations": len(observations),
        "events": len(events),
        "multi_observer_events": sum(
            event_count for observers, event_count in coverage.items() if observers >= 2
        ),
        "all_observer_events": coverage[len(EXPECTED_OBSERVERS)],
        "positive_cross_observer_pairs": positive_pairs,
        "duplicate_event_keys_within_observer": duplicate_event_keys_within_observer,
        "events_with_contradictory_invariant_metadata": contradictory_events,
    }
    return (
        {
            "event_key_fields": ["Source_MAC_address", "Sequence_number"],
            "observations": len(observations),
            "events": len(events),
            "cross_observer_positive_pairs": positive_pairs,
            "event_observer_coverage": [
                {"observers": count, "events": coverage[count]}
                for count in sorted(coverage)
            ],
            "collision_audit": {
                "same_observer_oracle_key_collision_events": same_observer_collision_events,
                "sequence_numbers_with_multiple_source_macs": sum(
                    len(sources) > 1 for sources in sequence_sources.values()
                ),
                "invariant_metadata_fields": [
                    "Channel",
                    "Frame_type",
                    "Frame_subtype",
                    "Retransmission",
                ],
                "contradictory_invariant_metadata_events": contradictory_events,
                "observations_in_contradictory_events": contradictory_observations,
            },
        },
        observed_structure,
        positive_pairs,
    )


def synchronized_time_audit(
    observations: Sequence[Observation], oracle_positive_pairs: int
) -> Dict[str, Any]:
    ordered = sorted(
        observations,
        key=lambda item: (item.time_ns, item.observer, item.frame_number),
    )
    active: Deque[Observation] = deque()
    positives = 0
    negatives = 0
    for item in ordered:
        while active and item.time_ns - active[0].time_ns > SYNCHRONIZED_TIME_WINDOW_NS:
            active.popleft()
        for previous in active:
            if previous.observer == item.observer:
                continue
            if previous.oracle_key() == item.oracle_key():
                positives += 1
            else:
                negatives += 1
        active.append(item)

    result = {
        "derived_with_oracle_related_correspondence": True,
        "pairs_within_1ms": positives + negatives,
        "same_event_pairs_within_1ms": positives,
        "different_event_pairs_within_1ms": negatives,
        "usable_as_predictive_evidence": False,
    }
    expected = {
        "derived_with_oracle_related_correspondence": True,
        "pairs_within_1ms": 64_149,
        "same_event_pairs_within_1ms": 64_149,
        "different_event_pairs_within_1ms": 0,
        "usable_as_predictive_evidence": False,
    }
    if result != expected or positives != oracle_positive_pairs:
        raise EvaluationError(
            "observed synchronized-time all-positive fact differs from registration"
        )
    return result


def evaluate(path: Path, campaign_path: Path) -> Dict[str, Any]:
    campaign, campaign_sha256 = load_campaign(campaign_path)
    archive_data, archive_md5, archive_sha256 = read_archive(path)
    archive_bytes = len(archive_data)
    registered_archive = campaign["source"]["archive"]
    if (
        archive_bytes != registered_archive["bytes"]
        or archive_md5 != registered_archive["md5"]
        or archive_sha256 != EXPECTED_ARCHIVE_SHA256
    ):
        raise EvaluationError("archive identity differs from preregistration")
    try:
        with zipfile.ZipFile(io.BytesIO(archive_data), "r") as archive:
            members, inventory = select_members(archive)
            by_observer = {
                observer: parse_member(archive, members[observer], observer)
                for observer in EXPECTED_OBSERVERS
            }
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise EvaluationError(f"archive is not a readable ZIP file: {path}") from error

    observations = [
        item for observer in EXPECTED_OBSERVERS for item in by_observer[observer]
    ]
    if len(observations) > MAX_TOTAL_OBSERVATIONS:
        raise EvaluationError("selected run exceeds the total-observation limit")
    oracle, observed_structure, positive_pairs = oracle_audit(observations)
    registered_structure = {
        key: value for key, value in EXPECTED_STRUCTURE.items() if key != "comparison"
    }
    if observed_structure != registered_structure:
        raise EvaluationError("observed structural counts differ from preregistration")
    return {
        "schema": SCHEMA_VERSION,
        "report_kind": "preregistered_oracle_audit",
        "campaign": {
            "path": str(campaign_path),
            "schema": campaign["schema"],
            "campaign_id": campaign["campaign_id"],
            "sha256": campaign_sha256,
            "preregistration": campaign["preregistration"],
            "registered_structure": campaign["expected_structure"],
        },
        "input": {
            "archive": str(path),
            "archive_bytes": archive_bytes,
            "archive_md5": archive_md5,
            "archive_sha256": archive_sha256,
            "distance_m": 1,
            "synchronized_tsv": True,
            "observers": list(EXPECTED_OBSERVERS),
            **inventory,
        },
        "bounds": {
            "max_archive_bytes": MAX_ARCHIVE_BYTES,
            "max_archive_members": MAX_ARCHIVE_MEMBERS,
            "max_archive_uncompressed_bytes": MAX_ARCHIVE_UNCOMPRESSED_BYTES,
            "max_member_uncompressed_bytes": MAX_MEMBER_UNCOMPRESSED_BYTES,
            "max_selected_uncompressed_bytes": MAX_SELECTED_UNCOMPRESSED_BYTES,
            "max_observers": MAX_OBSERVERS,
            "max_rows_per_observer": MAX_ROWS_PER_OBSERVER,
            "max_total_observations": MAX_TOTAL_OBSERVATIONS,
        },
        "tsv_schema": {
            "columns": list(EXPECTED_COLUMNS),
            "column_count": len(EXPECTED_COLUMNS),
            "strict_header_order_and_row_width": True,
            "encoding": "UTF-8",
        },
        "observer_audit": observer_audit(members, by_observer),
        "observed_structure": observed_structure,
        "oracle_audit": oracle,
        "synchronized_time_audit": synchronized_time_audit(
            observations, positive_pairs
        ),
        "leakage_limitations": {
            "predictive_classification_performed": False,
            "oracle_only_fields": ["Source_MAC_address", "Sequence_number"],
            "predictive_evidence_available": False,
            "statements": [
                "Source MAC and sequence number label pairs only; a predictor must not consume them.",
                "PyPal synchronization used same-frame composite correspondences that included source MAC and sequence number.",
                "Every cross-observer pair inside 1 ms is oracle-positive, so this is not a viable three-way candidate set.",
                "This version is an oracle audit and reports no candidate, classifier, calibration, or predictive metric.",
                "Publisher-synchronized timestamps are oracle-related derived data and do not test deployment clock synchronization.",
                "The single 1 m capture is not an independent generalization or identity benchmark.",
                "Oracle-key reuse or contradictory invariant metadata would make labels ambiguous and is reported as an audit condition.",
            ],
        },
    }


def write_report(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            newline="\n",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
    finally:
        if temporary_name is not None and os.path.exists(temporary_name):
            os.unlink(temporary_name)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        report = evaluate(args.archive, args.campaign)
        write_report(args.report, report)
    except (EvaluationError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"wrote {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
