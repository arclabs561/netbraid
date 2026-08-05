#!/usr/bin/env python3
"""Profile bounded RoboLoc-G structure without opening locked-test payloads."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import zipfile
from contextlib import ExitStack
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, BinaryIO, Mapping, Sequence

import robolocg_policy as policy


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.robolocg_structural_alignment_profile.v0"
RECORD_ID = 15_989_282
RECORD_SHA256 = "29d18cbb38c1061401fec0454ca1b4e5cb962b69986aecb6fd2f7f243f3d40d4"
DEFAULT_MANIFEST = ROOT / "data/catalog/curated-eval-artifacts-v1.json"
DEFAULT_RAW_RECORD_DIR = ROOT / f"data/raw/curated-eval/{RECORD_ID}"
DEFAULT_RECEIPT_RECORD_DIR = ROOT / f"data/receipts/curated-eval/{RECORD_ID}"
DEFAULT_REPORT = ROOT / "data/derived/eval/robolocg-structural-alignment-v0/report.json"

MIB = 1024 * 1024
MAX_MANIFEST_BYTES = MIB
MAX_RECEIPT_BYTES = 16 * 1024
MAX_ARCHIVE_MEMBERS = 128
MAX_MEMBER_NAME_BYTES = 192
MAX_TOTAL_CENTRAL_METADATA_BYTES = 128 * 1024
MAX_MEMBER_BYTES = 32 * MIB
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 512 * MIB
MAX_COMPRESSION_RATIO = 200
MAX_CSV_ROW_BYTES = 8 * 1024
MAX_CSV_COLUMNS = 64
MAX_FIELD_BYTES = 128
MAX_ROWS_PER_MEMBER = 2_000_000
MAX_TOTAL_ROWS = 5_000_000
MAX_REPORT_BYTES = 256 * 1024
DIGEST_CHUNK_BYTES = MIB
ALLOWED_COMPRESSION = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}

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
        "record_url",
        "api_updated",
        "title",
        "version",
        "doi",
        "license",
        "license_id",
        "task_rationale",
        "difficulty_rationale",
        "grouping_warning",
        "expected_artifact_count",
        "expected_total_bytes",
        "artifacts",
    }
)
ARTIFACT_KEYS = frozenset({"filename", "bytes", "md5", "content_url"})
SOURCE_KEYS = frozenset(
    {
        "record_id",
        "api_url",
        "record_url",
        "api_updated",
        "title",
        "version",
        "doi",
        "license",
        "license_id",
        "filename",
        "bytes",
        "md5",
        "content_url",
    }
)
RECEIPT_KEYS = frozenset({"schema", "source", "integrity"})
INTEGRITY_KEYS = frozenset({"bytes", "md5", "sha256"})
MD5 = re.compile(r"[0-9a-f]{32}\Z")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
TOKEN = re.compile(r"[A-Za-z0-9_./:-]+\Z")
UNSIGNED = re.compile(r"(?:0|[1-9][0-9]*)\Z")
SIGNED_INTEGER = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
UNSIGNED_COLUMNS = frozenset(
    {
        "anchor_id",
        "array_index",
        "frames.rtt",
        "frames.t1",
        "frames.t2",
        "frames.t3",
        "frames.t4",
        "height",
        "num_frames",
        "point_step",
        "range",
        "row_step",
        "rtt_est",
        "rtt_raw",
        "seq",
        "tag_id",
        "width",
    }
)


class RoboLocGProfileError(RuntimeError):
    """Stable fail-closed reason at a profiling boundary."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ArchiveSpec:
    kind: str
    filename: str
    entry_count: int
    file_count: int


@dataclass(frozen=True)
class ProfileContract:
    record_id: int
    record_sha256: str
    archives: tuple[ArchiveSpec, ...]


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


@dataclass(frozen=True)
class MemberPlan:
    take: policy.Take | None
    modality: str | None
    header: policy.CsvHeaderContract | None
    directory: bool


@dataclass
class IntegerStats:
    count: int = 0
    minimum: int | None = None
    maximum: int | None = None
    total: int = 0
    zero_count: int = 0

    def add(self, value: int) -> None:
        self.count += 1
        self.minimum = value if self.minimum is None else min(self.minimum, value)
        self.maximum = value if self.maximum is None else max(self.maximum, value)
        self.total += value
        self.zero_count += value == 0

    def merge(self, other: IntegerStats) -> None:
        if other.count == 0:
            return
        self.count += other.count
        self.minimum = (
            other.minimum
            if self.minimum is None
            else min(self.minimum, _required(other.minimum))
        )
        self.maximum = (
            other.maximum
            if self.maximum is None
            else max(self.maximum, _required(other.maximum))
        )
        self.total += other.total
        self.zero_count += other.zero_count

    def report(self) -> dict[str, int]:
        if self.count == 0:
            raise RoboLocGProfileError("empty_integer_summary")
        return {
            "count": self.count,
            "maximum_ns": _required(self.maximum),
            "minimum_ns": _required(self.minimum),
            "sum_ns": self.total,
            "zero_count": self.zero_count,
        }


@dataclass
class DecimalMagnitude:
    count: int = 0
    minimum: Decimal | None = None
    maximum: Decimal | None = None
    total: Decimal = Decimal(0)
    buckets: dict[str, int] = field(
        default_factory=lambda: {
            "below_10": 0,
            "from_10_below_100": 0,
            "from_100_below_1000": 0,
            "at_least_1000": 0,
        }
    )

    def add(self, value: Decimal) -> None:
        if value < 0:
            raise RoboLocGProfileError("negative_uwb_range")
        self.count += 1
        self.minimum = value if self.minimum is None else min(self.minimum, value)
        self.maximum = value if self.maximum is None else max(self.maximum, value)
        self.total += value
        if value < 10:
            self.buckets["below_10"] += 1
        elif value < 100:
            self.buckets["from_10_below_100"] += 1
        elif value < 1000:
            self.buckets["from_100_below_1000"] += 1
        else:
            self.buckets["at_least_1000"] += 1

    def merge(self, other: DecimalMagnitude) -> None:
        if other.count == 0:
            return
        self.count += other.count
        self.minimum = (
            other.minimum
            if self.minimum is None
            else min(self.minimum, _required(other.minimum))
        )
        self.maximum = (
            other.maximum
            if self.maximum is None
            else max(self.maximum, _required(other.maximum))
        )
        self.total += other.total
        for name, count in other.buckets.items():
            self.buckets[name] += count

    def report(self) -> dict[str, Any]:
        if self.count == 0:
            raise RoboLocGProfileError("empty_uwb_summary")
        return {
            "bucket_counts": dict(sorted(self.buckets.items())),
            "count": self.count,
            "maximum": canonical_decimal(_required(self.maximum)),
            "minimum": canonical_decimal(_required(self.minimum)),
            "sum": canonical_decimal(self.total),
            "unit_interpretation": "unresolved",
        }


@dataclass
class MemberSummary:
    take: policy.Take
    modality: str
    role: policy.Role
    rows: int
    first_clock_ns: int
    last_clock_ns: int
    deltas: IntegerStats
    uwb: DecimalMagnitude
    ftm_anchors: set[str]


PRODUCTION_CONTRACT = ProfileContract(
    record_id=RECORD_ID,
    record_sha256=RECORD_SHA256,
    archives=(
        ArchiveSpec("sensor_measurements_csv", "SENSORS_MEASUREMENTS_CSV.zip", 101, 64),
        ArchiveSpec("ground_truth", "GROUND_TRUTH.zip", 17, 16),
        ArchiveSpec("gantry_measurements", "GANTRY_MEASUREMENTS.zip", 9, 8),
    ),
)


def _required(value: Any) -> Any:
    if value is None:
        raise RoboLocGProfileError("missing_summary_value")
    return value


def canonical_decimal(value: Decimal) -> str:
    """Serialize one finite decimal without exponent notation or negative zero."""

    if not value.is_finite():
        raise RoboLocGProfileError("non_finite_decimal")
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return "0" if rendered in {"", "-0"} else rendered


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RoboLocGProfileError("duplicate_json_key")
        result[key] = value
    return result


def _identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def _require_directory(path: Path, code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RoboLocGProfileError(code) from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise RoboLocGProfileError(code)


def _open_regular(path: Path, maximum_bytes: int, code: str) -> BinaryIO:
    try:
        before = path.lstat()
    except OSError as error:
        raise RoboLocGProfileError(code) from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_size > maximum_bytes
    ):
        raise RoboLocGProfileError(code)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RoboLocGProfileError(code) from error
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or _identity(after) != _identity(before):
            raise RoboLocGProfileError(code)
        return os.fdopen(descriptor, "rb")
    except BaseException:
        os.close(descriptor)
        raise


def _read_json(path: Path, maximum_bytes: int, code: str) -> Mapping[str, Any]:
    with _open_regular(path, maximum_bytes, code) as source:
        payload = source.read(maximum_bytes + 1)
        if len(payload) > maximum_bytes:
            raise RoboLocGProfileError(code)
        try:
            value = json.loads(payload, object_pairs_hook=_strict_object)
        except RoboLocGProfileError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RoboLocGProfileError(code) from error
    if not isinstance(value, Mapping):
        raise RoboLocGProfileError(code)
    return value


def _positive_integer(value: Any, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RoboLocGProfileError(code)
    return value


def _safe_filename(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.startswith(".")
        or "/" in value
        or "\\" in value
        or len(value.encode("utf-8", errors="surrogatepass")) > MAX_MEMBER_NAME_BYTES
    ):
        raise RoboLocGProfileError("unsafe_artifact_filename")
    return value


def _canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def load_record(manifest_path: Path, contract: ProfileContract) -> Mapping[str, Any]:
    manifest = _read_json(manifest_path, MAX_MANIFEST_BYTES, "invalid_manifest")
    if (
        set(manifest) != TOP_LEVEL_KEYS
        or manifest.get("schema") != "netbraid.curated_eval_artifacts.v1"
    ):
        raise RoboLocGProfileError("manifest_schema_mismatch")
    records = manifest.get("records")
    if not isinstance(records, list) or not records:
        raise RoboLocGProfileError("manifest_records_invalid")

    artifact_count = 0
    total_bytes = 0
    targets: list[Mapping[str, Any]] = []
    seen_records: set[int] = set()
    seen_artifacts: set[tuple[int, str]] = set()
    for record in records:
        if not isinstance(record, Mapping) or set(record) != RECORD_KEYS:
            raise RoboLocGProfileError("manifest_record_schema_mismatch")
        record_id = _positive_integer(record.get("record_id"), "invalid_record_id")
        if record_id in seen_records:
            raise RoboLocGProfileError("duplicate_record_id")
        seen_records.add(record_id)
        artifacts = record.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise RoboLocGProfileError("manifest_artifacts_invalid")
        record_bytes = 0
        for artifact in artifacts:
            if not isinstance(artifact, Mapping) or set(artifact) != ARTIFACT_KEYS:
                raise RoboLocGProfileError("manifest_artifact_schema_mismatch")
            filename = _safe_filename(artifact.get("filename"))
            key = (record_id, filename.casefold())
            if key in seen_artifacts:
                raise RoboLocGProfileError("duplicate_artifact")
            seen_artifacts.add(key)
            size = _positive_integer(artifact.get("bytes"), "invalid_artifact_bytes")
            if (
                not isinstance(artifact.get("md5"), str)
                or MD5.fullmatch(artifact["md5"]) is None
            ):
                raise RoboLocGProfileError("invalid_artifact_md5")
            record_bytes += size
        if (
            record.get("expected_artifact_count") != len(artifacts)
            or record.get("expected_total_bytes") != record_bytes
        ):
            raise RoboLocGProfileError("manifest_record_totals_mismatch")
        artifact_count += len(artifacts)
        total_bytes += record_bytes
        if record_id == contract.record_id:
            targets.append(record)

    if (
        manifest.get("expected_record_count") != len(records)
        or manifest.get("expected_artifact_count") != artifact_count
        or manifest.get("expected_total_bytes") != total_bytes
    ):
        raise RoboLocGProfileError("manifest_totals_mismatch")
    if len(targets) != 1:
        raise RoboLocGProfileError("record_selection_mismatch")
    record = targets[0]
    if hashlib.sha256(_canonical_bytes(record)).hexdigest() != contract.record_sha256:
        raise RoboLocGProfileError("record_manifest_digest_mismatch")
    return record


def _source_for(
    record: Mapping[str, Any], artifact: Mapping[str, Any]
) -> dict[str, Any]:
    source = {
        key: record[key]
        for key in SOURCE_KEYS
        if key not in {"filename", "bytes", "md5", "content_url"}
    }
    source.update({key: artifact[key] for key in ARTIFACT_KEYS})
    return source


def _artifact_by_name(record: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    matches = [item for item in record["artifacts"] if item["filename"] == name]
    if len(matches) != 1:
        raise RoboLocGProfileError("required_artifact_mismatch")
    return matches[0]


def authenticate_archive(
    raw_record_dir: Path,
    receipt_record_dir: Path,
    record: Mapping[str, Any],
    spec: ArchiveSpec,
) -> tuple[BinaryIO, FileIdentity]:
    artifact = _artifact_by_name(record, spec.filename)
    receipt_path = receipt_record_dir / f"{spec.filename}.json"
    receipt = _read_json(receipt_path, MAX_RECEIPT_BYTES, "invalid_receipt")
    try:
        receipt_mode = stat.S_IMODE(receipt_path.lstat().st_mode)
    except OSError as error:
        raise RoboLocGProfileError("invalid_receipt") from error
    if receipt_mode != 0o600:
        raise RoboLocGProfileError("receipt_mode_mismatch")
    if (
        set(receipt) != RECEIPT_KEYS
        or receipt.get("schema") != "local.netbraid_curated_eval_artifact.v1"
    ):
        raise RoboLocGProfileError("receipt_schema_mismatch")
    source = receipt.get("source")
    integrity = receipt.get("integrity")
    if (
        not isinstance(source, Mapping)
        or set(source) != SOURCE_KEYS
        or source != _source_for(record, artifact)
    ):
        raise RoboLocGProfileError("receipt_source_mismatch")
    if not isinstance(integrity, Mapping) or set(integrity) != INTEGRITY_KEYS:
        raise RoboLocGProfileError("receipt_integrity_mismatch")
    if (
        integrity.get("bytes") != artifact["bytes"]
        or integrity.get("md5") != artifact["md5"]
        or not isinstance(integrity.get("sha256"), str)
        or SHA256.fullmatch(integrity["sha256"]) is None
    ):
        raise RoboLocGProfileError("receipt_integrity_mismatch")

    raw_path = raw_record_dir / spec.filename
    source_file = _open_regular(raw_path, artifact["bytes"], "unsafe_raw_archive")
    identity = _identity(os.fstat(source_file.fileno()))
    if identity.size != artifact["bytes"]:
        source_file.close()
        raise RoboLocGProfileError("raw_archive_byte_mismatch")
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    remaining = identity.size
    while remaining:
        chunk = source_file.read(min(remaining, DIGEST_CHUNK_BYTES))
        if not chunk:
            source_file.close()
            raise RoboLocGProfileError("raw_archive_changed")
        md5.update(chunk)
        sha256.update(chunk)
        remaining -= len(chunk)
    if source_file.read(1) or _identity(os.fstat(source_file.fileno())) != identity:
        source_file.close()
        raise RoboLocGProfileError("raw_archive_changed")
    if md5.hexdigest() != artifact["md5"] or sha256.hexdigest() != integrity["sha256"]:
        source_file.close()
        raise RoboLocGProfileError("raw_archive_digest_mismatch")
    source_file.seek(0)
    return source_file, identity


def expected_members(spec: ArchiveSpec) -> dict[str, MemberPlan]:
    takes = tuple(item.take for item in policy.TAKE_ASSIGNMENTS)
    plans: dict[str, MemberPlan] = {}

    def add(name: str, plan: MemberPlan) -> None:
        if name in plans:
            raise RoboLocGProfileError("duplicate_member_plan")
        plans[name] = plan

    if spec.kind == "sensor_measurements_csv":
        root = "SENSORS_MEASUREMENTS_CSV"
        add(f"{root}/", MemberPlan(None, None, None, True))
        groups = (
            ("AOP", (("radar_scan.csv", "radar_scan", policy.RADAR_HEADER),)),
            (
                "ISK0",
                (
                    ("cloud.csv", "radar_point_cloud", policy.POINT_CLOUD_HEADER),
                    ("radar_scan.csv", "radar_scan", policy.RADAR_HEADER),
                ),
            ),
            (
                "ISK1",
                (
                    ("cloud.csv", "radar_point_cloud", policy.POINT_CLOUD_HEADER),
                    ("radar_scan.csv", "radar_scan", policy.RADAR_HEADER),
                ),
            ),
            (
                "UWB_FTM_IMU",
                (
                    ("gtec-ftm.csv", "ftm", policy.FTM_HEADER),
                    ("gtec-uwb-imu-pozyx_0.csv", "imu", policy.IMU_HEADER),
                    ("gtec-uwb-ranging-pozyx.csv", "uwb", policy.UWB_HEADER),
                ),
            ),
        )
        for group, files in groups:
            add(f"{root}/{group}/", MemberPlan(None, None, None, True))
            for take in takes:
                prefix = f"{root}/{group}/{take.value}"
                add(f"{prefix}/", MemberPlan(None, None, None, True))
                for filename, modality, header in files:
                    add(
                        f"{prefix}/{filename}",
                        MemberPlan(take, modality, header, False),
                    )
    elif spec.kind == "ground_truth":
        root = "GROUND_TRUTH"
        add(f"{root}/", MemberPlan(None, None, None, True))
        for take in takes:
            add(
                f"{root}/{take.value}_ground_truth_gantry.csv",
                MemberPlan(
                    take, "ground_truth_gantry", policy.GROUND_TRUTH_HEADER, False
                ),
            )
            add(
                f"{root}/{take.value}_ground_truth_optitrack.csv",
                MemberPlan(
                    take, "ground_truth_optitrack", policy.GROUND_TRUTH_HEADER, False
                ),
            )
    elif spec.kind == "gantry_measurements":
        root = "GANTRY_MEASUREMENTS"
        add(f"{root}/", MemberPlan(None, None, None, True))
        for take in takes:
            add(
                f"{root}/{take.value}_gantry.csv",
                MemberPlan(
                    take, "gantry_measurement", policy.GANTRY_MEASUREMENT_HEADER, False
                ),
            )
    else:
        raise RoboLocGProfileError("unknown_archive_kind")
    return plans


def _safe_member_name(info: zipfile.ZipInfo) -> str:
    if info.orig_filename != info.filename:
        raise RoboLocGProfileError("truncated_zip_member_name")
    name = info.filename
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError as error:
        raise RoboLocGProfileError("unsafe_zip_member_path") from error
    canonical = name[:-1] if name.endswith("/") else name
    parts = canonical.split("/")
    if (
        not canonical
        or name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in parts)
        or parts[0].endswith(":")
        or len(encoded) > MAX_MEMBER_NAME_BYTES
    ):
        raise RoboLocGProfileError("unsafe_zip_member_path")
    return name


def inspect_archive(
    archive: zipfile.ZipFile, spec: ArchiveSpec
) -> tuple[dict[str, zipfile.ZipInfo], dict[str, int]]:
    infos = archive.infolist()
    if len(infos) != spec.entry_count or len(infos) > MAX_ARCHIVE_MEMBERS:
        raise RoboLocGProfileError("zip_entry_count_mismatch")
    expected = expected_members(spec)
    members: dict[str, zipfile.ZipInfo] = {}
    folded: set[str] = set()
    central_bytes = len(archive.comment)
    compressed_bytes = 0
    uncompressed_bytes = 0
    file_count = 0
    for info in infos:
        name = _safe_member_name(info)
        central_bytes += len(name.encode("ascii")) + len(info.extra) + len(info.comment)
        folded_name = name.casefold()
        if folded_name in folded:
            raise RoboLocGProfileError("duplicate_zip_member")
        folded.add(folded_name)
        plan = expected.get(name)
        if plan is None or info.is_dir() != plan.directory:
            raise RoboLocGProfileError("zip_member_grammar_mismatch")
        unix_mode = info.external_attr >> 16
        if stat.S_ISLNK(unix_mode):
            raise RoboLocGProfileError("zip_symlink_member")
        if info.flag_bits & 1 or info.compress_type not in ALLOWED_COMPRESSION:
            raise RoboLocGProfileError("unsupported_zip_member")
        if info.file_size > MAX_MEMBER_BYTES or info.compress_size > MAX_MEMBER_BYTES:
            raise RoboLocGProfileError("zip_member_size_limit")
        if (
            info.file_size
            and info.file_size > max(1, info.compress_size) * MAX_COMPRESSION_RATIO
        ):
            raise RoboLocGProfileError("zip_compression_ratio_limit")
        if not plan.directory:
            file_count += 1
        compressed_bytes += info.compress_size
        uncompressed_bytes += info.file_size
        members[name] = info
    if (
        set(members) != set(expected)
        or file_count != spec.file_count
        or central_bytes > MAX_TOTAL_CENTRAL_METADATA_BYTES
        or uncompressed_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES
    ):
        raise RoboLocGProfileError("zip_inventory_mismatch")
    return members, {
        "compressed_bytes": compressed_bytes,
        "directories": len(infos) - file_count,
        "entries": len(infos),
        "files": file_count,
        "uncompressed_bytes": uncompressed_bytes,
    }


def _parse_row(
    source: BinaryIO, columns: int, *, header: bool = False
) -> tuple[str, ...] | None:
    payload = source.readline(MAX_CSV_ROW_BYTES + 1)
    if not payload:
        return None
    if len(payload) > MAX_CSV_ROW_BYTES or b"\x00" in payload:
        raise RoboLocGProfileError("csv_row_size_limit")
    try:
        text = payload.decode("utf-8")
        parsed = list(csv.reader([text], strict=True))
    except (UnicodeDecodeError, csv.Error) as error:
        raise RoboLocGProfileError("invalid_csv_row") from error
    if len(parsed) != 1 or len(parsed[0]) != columns:
        raise RoboLocGProfileError("csv_field_count_mismatch")
    row = tuple(parsed[0])
    if any(len(value.encode("utf-8")) > MAX_FIELD_BYTES for value in row):
        raise RoboLocGProfileError("csv_field_size_limit")
    if header and len(set(row)) != len(row):
        raise RoboLocGProfileError("duplicate_csv_header")
    return row


def _unsigned(value: str, code: str) -> int:
    if UNSIGNED.fullmatch(value) is None:
        raise RoboLocGProfileError(code)
    return int(value)


def _decimal(value: str) -> Decimal:
    if NUMBER.fullmatch(value) is None:
        raise RoboLocGProfileError("invalid_decimal_field")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise RoboLocGProfileError("invalid_decimal_field") from error
    if not parsed.is_finite():
        raise RoboLocGProfileError("invalid_decimal_field")
    return parsed


def _role_for(take: policy.Take) -> policy.Role:
    assignment = next(item for item in policy.TAKE_ASSIGNMENTS if item.take is take)
    return assignment.role


def _validate_fields(
    modality: str,
    header: policy.CsvHeaderContract,
    row: Sequence[str],
) -> tuple[int, int | None, Decimal | None, str | None]:
    values = dict(zip(header.columns, row))
    clock_text = values[header.outer_clock_column]
    try:
        if header.outer_clock_column == "timestamp":
            clock_ns = policy.parse_integer_nanoseconds(clock_text)
        else:
            clock_ns = policy.parse_decimal_seconds_nanoseconds(clock_text)
    except policy.RoboLocGPolicyError as error:
        raise RoboLocGProfileError(error.code) from error

    embedded_ns: int | None = None
    if header.embedded_clock_columns:
        seconds = _unsigned(values["header.stamp.sec"], "invalid_header_seconds")
        nanoseconds = _unsigned(
            values["header.stamp.nanosec"], "invalid_header_nanoseconds"
        )
        if nanoseconds >= policy.NANOSECONDS_PER_SECOND:
            raise RoboLocGProfileError("header_nanoseconds_out_of_range")
        embedded_ns = seconds * policy.NANOSECONDS_PER_SECOND + nanoseconds

    uwb_range: Decimal | None = None
    ftm_anchor: str | None = None
    for column, value in values.items():
        if (
            column == header.outer_clock_column
            or column in header.embedded_clock_columns
        ):
            continue
        if column == "header.frame_id":
            if TOKEN.fullmatch(value) is None:
                raise RoboLocGProfileError("invalid_frame_token")
        elif modality == "ftm" and column == "anchor_id":
            if TOKEN.fullmatch(value) is None:
                raise RoboLocGProfileError("invalid_ftm_anchor_token")
            ftm_anchor = value
        elif modality == "radar_point_cloud" and column == "header.seq":
            if value:
                raise RoboLocGProfileError("unexpected_point_cloud_sequence")
        elif column in {"is_bigendian", "is_dense"}:
            if value not in {"True", "False"}:
                raise RoboLocGProfileError("invalid_boolean_field")
        elif column == "frames.rssi":
            if SIGNED_INTEGER.fullmatch(value) is None:
                raise RoboLocGProfileError("invalid_signed_integer_field")
        elif column in UNSIGNED_COLUMNS:
            numeric = Decimal(_unsigned(value, "invalid_unsigned_integer_field"))
            if modality == "uwb" and column == "range":
                uwb_range = numeric
        else:
            _decimal(value)
    return clock_ns, embedded_ns, uwb_range, ftm_anchor


def profile_member(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    plan: MemberPlan,
    *,
    row_limit: int = MAX_ROWS_PER_MEMBER,
    row_limit_code: str = "csv_member_row_limit",
) -> MemberSummary:
    take = _required(plan.take)
    modality = _required(plan.modality)
    header = _required(plan.header)
    role = _role_for(take)
    if role is policy.Role.LOCKED_TEST:
        raise RoboLocGProfileError("locked_test_payload_read_forbidden")
    if len(header.columns) > MAX_CSV_COLUMNS:
        raise RoboLocGProfileError("csv_column_limit")
    if row_limit <= 0 or row_limit > MAX_ROWS_PER_MEMBER:
        raise RoboLocGProfileError("invalid_csv_row_limit")

    rows = 0
    first_clock: int | None = None
    last_clock: int | None = None
    deltas = IntegerStats()
    uwb = DecimalMagnitude()
    anchors: set[str] = set()
    with archive.open(info, "r") as source:
        observed_header = _parse_row(source, len(header.columns), header=True)
        if observed_header != header.columns:
            raise RoboLocGProfileError("csv_header_mismatch")
        while True:
            row = _parse_row(source, len(header.columns))
            if row is None:
                break
            rows += 1
            if rows > row_limit:
                raise RoboLocGProfileError(row_limit_code)
            clock_ns, embedded_ns, uwb_range, anchor = _validate_fields(
                modality, header, row
            )
            if last_clock is not None and clock_ns < last_clock:
                raise RoboLocGProfileError("non_monotonic_member_clock")
            first_clock = clock_ns if first_clock is None else first_clock
            last_clock = clock_ns
            if embedded_ns is not None:
                deltas.add(clock_ns - embedded_ns)
            if uwb_range is not None:
                uwb.add(uwb_range)
            if anchor is not None:
                anchors.add(anchor)
    if rows == 0:
        raise RoboLocGProfileError("empty_csv_member")
    return MemberSummary(
        take,
        modality,
        role,
        rows,
        _required(first_clock),
        _required(last_clock),
        deltas,
        uwb,
        anchors,
    )


def _modality_report(summaries: Sequence[MemberSummary]) -> dict[str, Any]:
    by_take: dict[policy.Take, tuple[int, int]] = {}
    for item in summaries:
        previous = by_take.get(item.take)
        if previous is None:
            by_take[item.take] = (item.first_clock_ns, item.last_clock_ns)
        else:
            by_take[item.take] = (
                min(previous[0], item.first_clock_ns),
                max(previous[1], item.last_clock_ns),
            )
    durations = [maximum - minimum for minimum, maximum in by_take.values()]
    return {
        "member_count": len(summaries),
        "row_count": sum(item.rows for item in summaries),
        "take_count": len(by_take),
        "take_duration_ns": {
            "maximum": max(durations),
            "minimum": min(durations),
            "sum": sum(durations),
        },
    }


def _anchor_diagnostics(summaries: Sequence[MemberSummary]) -> dict[str, Any]:
    anchor_sets = {item.take: frozenset(item.ftm_anchors) for item in summaries}
    train_sets = [
        anchors
        for take, anchors in anchor_sets.items()
        if _role_for(take) is policy.Role.TRAIN
    ]
    reference = train_sets[0] if train_sets and len(set(train_sets)) == 1 else None
    roles: list[dict[str, Any]] = []
    for role in (policy.Role.TRAIN, policy.Role.CALIBRATION, policy.Role.VALIDATION):
        selected = [
            anchors for take, anchors in anchor_sets.items() if _role_for(take) is role
        ]
        differences = (
            [len(anchors.symmetric_difference(reference)) for anchors in selected]
            if reference is not None
            else []
        )
        roles.append(
            {
                "anchor_count_maximum": max(map(len, selected)),
                "anchor_count_minimum": min(map(len, selected)),
                "all_sets_equal_within_role": len(set(selected)) == 1,
                "distinct_anchor_set_count": len(set(selected)),
                "mismatch_take_count_vs_train_reference": sum(
                    difference > 0 for difference in differences
                ),
                "role": role.value,
                "symmetric_difference_maximum_vs_train_reference": (
                    max(differences) if differences else None
                ),
                "take_count": len(selected),
            }
        )
    return {
        "raw_anchor_ids_retained": False,
        "roles": roles,
        "train_reference_available": reference is not None,
    }


def build_report(
    inventories: Mapping[str, Mapping[str, int]],
    summaries: Sequence[MemberSummary],
    contract: ProfileContract,
) -> dict[str, Any]:
    if sum(item.rows for item in summaries) > MAX_TOTAL_ROWS:
        raise RoboLocGProfileError("csv_total_row_limit")
    expected_role_counts = {
        policy.Role.TRAIN: 4,
        policy.Role.CALIBRATION: 1,
        policy.Role.VALIDATION: 1,
    }
    roles: list[dict[str, Any]] = []
    modality_order = (
        "radar_scan",
        "radar_point_cloud",
        "ftm",
        "imu",
        "uwb",
        "ground_truth_gantry",
        "ground_truth_optitrack",
        "gantry_measurement",
    )
    for role, expected_takes in expected_role_counts.items():
        role_items = [item for item in summaries if item.role is role]
        takes = {item.take for item in role_items}
        if len(takes) != expected_takes:
            raise RoboLocGProfileError("profiled_take_count_mismatch")
        modalities = []
        for modality in modality_order:
            selected = [item for item in role_items if item.modality == modality]
            if selected:
                modalities.append({"modality": modality, **_modality_report(selected)})
        roles.append(
            {"modalities": modalities, "role": role.value, "take_count": len(takes)}
        )

    clock_diagnostics: list[dict[str, Any]] = []
    for role in expected_role_counts:
        for modality in ("radar_scan", "radar_point_cloud", "imu"):
            selected = [
                item
                for item in summaries
                if item.role is role and item.modality == modality
            ]
            merged = IntegerStats()
            for item in selected:
                merged.merge(item.deltas)
            clock_diagnostics.append(
                {"modality": modality, "role": role.value, **merged.report()}
            )

    uwb_diagnostics: list[dict[str, Any]] = []
    for role in expected_role_counts:
        merged = DecimalMagnitude()
        for item in summaries:
            if item.role is role and item.modality == "uwb":
                merged.merge(item.uwb)
        uwb_diagnostics.append({"role": role.value, **merged.report()})

    closed = (policy.Blocker.OUTER_VS_HEADER_DELTAS_DIAGNOSTIC,)
    gate = policy.evaluate_gate(closed)
    blocker_evidence = {
        policy.Blocker.UWB_UNIT_CONFLICT: "magnitude_profile_complete_unit_unresolved",
        policy.Blocker.FTM_ANCHOR_ID_MISMATCH: "set_profile_complete_external_mapping_unresolved",
        policy.Blocker.OUTER_VS_HEADER_DELTAS_DIAGNOSTIC: "complete",
        policy.Blocker.RADAR_ASSOCIATION_EXTRINSICS_ABSENT: "not_claimed_by_this_profile",
        policy.Blocker.INTERPOLATION_NO_EXTRAPOLATION_TOLERANCE_UNFIXED: "not_fixed_by_this_profile",
    }
    blockers = [
        {
            "blocker": blocker.value,
            "evidence": blocker_evidence[blocker],
            "state": "closed" if blocker in gate.closed_blockers else "open",
        }
        for blocker in policy.BLOCKER_ORDER
    ]
    return {
        "archive_inventory": [
            {"archive_kind": spec.kind, **inventories[spec.kind]}
            for spec in contract.archives
        ],
        "authentication": {
            "manifest_record_authenticated": True,
            "raw_archive_count": len(contract.archives),
            "raw_archives_authenticated": True,
            "receipt_count": len(contract.archives),
            "receipts_authenticated": True,
        },
        "blockers": blockers,
        "claims": {
            "gantry_evidence_role": "dependent_consistency_only",
            "ground_truth_role": "sole_oracle",
            "localization_scores_computed": False,
            "radar_associations_or_extrinsics_claimed": False,
        },
        "diagnostics": {
            "ftm_anchor_sets": _anchor_diagnostics(
                [item for item in summaries if item.modality == "ftm"]
            ),
            "outer_vs_header_clock_delta_ns": clock_diagnostics,
            "uwb_range_magnitude": uwb_diagnostics,
        },
        "gate": {
            "fusion_capable": gate.fusion_capable,
            "scoring_allowed": gate.scoring_allowed,
        },
        "limits": {
            "csv_columns": MAX_CSV_COLUMNS,
            "csv_field_bytes": MAX_FIELD_BYTES,
            "csv_row_bytes": MAX_CSV_ROW_BYTES,
            "rows_per_member": MAX_ROWS_PER_MEMBER,
            "total_rows": MAX_TOTAL_ROWS,
            "zip_member_bytes": MAX_MEMBER_BYTES,
            "zip_members": MAX_ARCHIVE_MEMBERS,
        },
        "locked_test": {
            "gate_enforced": True,
            "payload_members_opened": 0,
            "take_count": 2,
        },
        "metadata_only": True,
        "roles": roles,
        "schema": SCHEMA,
        "status": "blocked",
    }


def profile_record(
    manifest_path: Path = DEFAULT_MANIFEST,
    raw_record_dir: Path = DEFAULT_RAW_RECORD_DIR,
    receipt_record_dir: Path = DEFAULT_RECEIPT_RECORD_DIR,
    contract: ProfileContract = PRODUCTION_CONTRACT,
) -> dict[str, Any]:
    if (
        contract.record_id <= 0
        or SHA256.fullmatch(contract.record_sha256) is None
        or len(contract.archives) != 3
        or len({item.kind for item in contract.archives}) != 3
        or len({item.filename for item in contract.archives}) != 3
    ):
        raise RoboLocGProfileError("invalid_profile_contract")
    _require_directory(raw_record_dir, "unsafe_raw_record_directory")
    _require_directory(receipt_record_dir, "unsafe_receipt_record_directory")
    record = load_record(manifest_path, contract)
    summaries: list[MemberSummary] = []
    inventories: dict[str, dict[str, int]] = {}
    with ExitStack() as stack:
        authenticated: list[tuple[ArchiveSpec, BinaryIO, FileIdentity]] = []
        total_rows = 0
        for spec in contract.archives:
            source, identity = authenticate_archive(
                raw_record_dir, receipt_record_dir, record, spec
            )
            stack.callback(source.close)
            authenticated.append((spec, source, identity))
        for spec, source, identity in authenticated:
            try:
                with zipfile.ZipFile(source, "r") as archive:
                    members, inventory = inspect_archive(archive, spec)
                    plans = expected_members(spec)
                    for name, plan in plans.items():
                        if (
                            plan.directory
                            or _role_for(_required(plan.take))
                            is policy.Role.LOCKED_TEST
                        ):
                            continue
                        remaining_rows = MAX_TOTAL_ROWS - total_rows
                        if remaining_rows <= 0:
                            raise RoboLocGProfileError("csv_total_row_limit")
                        row_limit = min(MAX_ROWS_PER_MEMBER, remaining_rows)
                        summary = profile_member(
                            archive,
                            members[name],
                            plan,
                            row_limit=row_limit,
                            row_limit_code=(
                                "csv_total_row_limit"
                                if row_limit < MAX_ROWS_PER_MEMBER
                                else "csv_member_row_limit"
                            ),
                        )
                        total_rows += summary.rows
                        summaries.append(summary)
            except zipfile.BadZipFile as error:
                raise RoboLocGProfileError("invalid_zip_archive") from error
            if _identity(os.fstat(source.fileno())) != identity:
                raise RoboLocGProfileError("raw_archive_changed")
            inventories[spec.kind] = inventory
    return build_report(inventories, summaries, contract)


def render_report(report: Mapping[str, Any]) -> bytes:
    rendered = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(rendered) > MAX_REPORT_BYTES:
        raise RoboLocGProfileError("report_size_limit")
    return rendered


def write_report(path: Path, rendered: bytes) -> None:
    if len(rendered) > MAX_REPORT_BYTES:
        raise RoboLocGProfileError("report_size_limit")
    parent = path.parent
    if parent.exists():
        _require_directory(parent, "unsafe_report_directory")
    else:
        ancestor = parent.parent
        _require_directory(ancestor, "unsafe_report_directory")
        try:
            parent.mkdir(mode=0o700)
        except OSError as error:
            raise RoboLocGProfileError("report_directory_create_failed") from error
    try:
        destination = path.lstat()
    except FileNotFoundError:
        destination = None
    except OSError as error:
        raise RoboLocGProfileError("unsafe_report_path") from error
    if destination is not None and (
        not stat.S_ISREG(destination.st_mode) or stat.S_ISLNK(destination.st_mode)
    ):
        raise RoboLocGProfileError("unsafe_report_path")

    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, 0o600, follow_symlinks=False)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--raw-record-dir", type=Path, default=DEFAULT_RAW_RECORD_DIR)
    parser.add_argument(
        "--receipt-record-dir", type=Path, default=DEFAULT_RECEIPT_RECORD_DIR
    )
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_args(argv)
    try:
        report = profile_record(
            arguments.manifest.absolute(),
            arguments.raw_record_dir.absolute(),
            arguments.receipt_record_dir.absolute(),
        )
        rendered = render_report(report)
        write_report(arguments.report.absolute(), rendered)
    except RoboLocGProfileError as error:
        print(error.code, file=sys.stderr)
        return 2
    sys.stdout.buffer.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
