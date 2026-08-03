#!/usr/bin/env python3
"""Profile bounded CAEZ frame/position-axis alignment without extracting files."""

from __future__ import annotations

import argparse
import csv
import importlib.util
import io
import json
import re
import sys
import tarfile
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Sequence

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCHEMA = "netbraid.caez_alignment_profile.v0"
HASH_PATTERN = re.compile(r"[0-9a-f]{64}")


def load_base_module() -> Any:
    specification = importlib.util.spec_from_file_location(
        "profile_caez_csi_slices", HERE / "profile-caez-csi-slices.py"
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("could not load the CAEZ structural profiler")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    specification.loader.exec_module(module)
    return module


BASE = load_base_module()


@dataclass(frozen=True)
class FrameSample:
    sample: str
    timestamp: Decimal
    psdu_hash: str


def decimal_value(value: Any, label: str) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise RuntimeError(f"{label} is not numeric")
    try:
        parsed = Decimal(str(value))
    except InvalidOperation as error:
        raise RuntimeError(f"{label} is not numeric") from error
    if not parsed.is_finite():
        raise RuntimeError(f"{label} is not finite")
    return parsed


def rendered_decimal(value: Decimal) -> str:
    return format(value, "f")


def selected_metadata_names(stems: Sequence[str]) -> dict[str, str]:
    return {f"{BASE.ROOT_MEMBER}/{stem}_metadata.json": stem for stem in stems}


def parse_frame_samples(
    selected: dict[str, bytes], stems: Sequence[str]
) -> list[FrameSample]:
    names = selected_metadata_names(stems)
    if set(selected) != set(names):
        raise RuntimeError("CAEZ alignment metadata sample is incomplete")
    samples = []
    for name, stem in names.items():
        metadata = BASE.strict_json(selected[name])
        timestamp = decimal_value(metadata.get("timestamp"), f"{stem} timestamp")
        psdu_hash = metadata.get("psdu_hash")
        psdu_length = metadata.get("psdu_length")
        if (
            not isinstance(psdu_hash, str)
            or not HASH_PATTERN.fullmatch(psdu_hash)
            or isinstance(psdu_length, bool)
            or not isinstance(psdu_length, int)
            or psdu_length <= 0
        ):
            raise RuntimeError(f"CAEZ frame metadata identity changed: {stem}")
        samples.append(FrameSample(stem, timestamp, psdu_hash))
    return samples


def profile_position_axis(
    stream: io.BufferedReader, samples: Sequence[FrameSample]
) -> dict[str, Any]:
    nearest: list[tuple[Decimal, int] | None] = [None] * len(samples)
    minima: list[Decimal | None] = [None] * 4
    maxima: list[Decimal | None] = [None] * 4
    rows = 0
    wrapper = io.TextIOWrapper(stream, encoding="utf-8", newline="")
    try:
        for row_number, row in enumerate(csv.reader(wrapper), start=1):
            if len(row) != 4:
                raise RuntimeError("CAEZ position row does not have four columns")
            values = [decimal_value(value, "CAEZ position value") for value in row]
            rows += 1
            for index, value in enumerate(values):
                minima[index] = (
                    value if minima[index] is None else min(minima[index], value)
                )
                maxima[index] = (
                    value if maxima[index] is None else max(maxima[index], value)
                )
            candidate_axis = values[0]
            for index, sample in enumerate(samples):
                delta = abs(candidate_axis - sample.timestamp)
                current = nearest[index]
                if current is None or delta < current[0]:
                    nearest[index] = (delta, row_number)
    except UnicodeDecodeError as error:
        raise RuntimeError("CAEZ position member is not UTF-8") from error
    finally:
        wrapper.detach()
    if rows == 0 or any(value is None for value in [*minima, *maxima, *nearest]):
        raise RuntimeError("CAEZ position member is empty")
    resolved = [item for item in nearest if item is not None]
    return {
        "rows": rows,
        "columns": 4,
        "column_ranges": [
            {
                "minimum": rendered_decimal(minimum),
                "maximum": rendered_decimal(maximum),
            }
            for minimum, maximum in zip(minima, maxima)
            if minimum is not None and maximum is not None
        ],
        "sample_nearest_candidate_axis": [
            {
                "sample": sample.sample,
                "absolute_delta": rendered_decimal(item[0]),
                "row": item[1],
            }
            for sample, item in zip(samples, resolved)
        ],
        "exact_candidate_axis_matches": sum(item[0] == 0 for item in resolved),
    }


def profile_alignment(
    path: Path,
    *,
    stems: Sequence[str] = BASE.SELECTED_STEMS,
    expected_ground_truth_bytes: int = BASE.EXPECTED_GT_BYTES,
) -> dict[str, Any]:
    wanted = selected_metadata_names(stems)
    selected: dict[str, bytes] = {}
    ground_truth = None
    try:
        with tarfile.open(path, "r:") as source:
            for member in source:
                if member.name.startswith("/") or ".." in member.name.split("/"):
                    raise RuntimeError(f"unsafe CAEZ member path: {member.name}")
                if member.name == f"{BASE.ROOT_MEMBER}/gt-positions.csv":
                    if (
                        ground_truth is not None
                        or not member.isfile()
                        or member.size != expected_ground_truth_bytes
                    ):
                        raise RuntimeError("CAEZ position member changed")
                    ground_truth = member
                elif member.name in wanted:
                    if member.name in selected:
                        raise RuntimeError(
                            f"duplicate CAEZ metadata sample: {member.name}"
                        )
                    selected[member.name] = BASE.read_selected_member(source, member)
            samples = parse_frame_samples(selected, stems)
            if ground_truth is None:
                raise RuntimeError("CAEZ position member is absent")
            stream = source.extractfile(ground_truth)
            if stream is None:
                raise RuntimeError("CAEZ position member is unreadable")
            position_axis = profile_position_axis(stream, samples)
    except tarfile.TarError as error:
        raise RuntimeError(
            "CAEZ artifact is not the declared uncompressed tar"
        ) from error

    hashes = [sample.psdu_hash for sample in samples]
    timestamps = [sample.timestamp for sample in samples]
    return {
        "schema": SCHEMA,
        "status": "pass",
        "archive_sha256": BASE.ARCHIVE_SHA256,
        "frame_metadata_sample": {
            "samples": len(samples),
            "distinct_psdu_hashes": len(set(hashes)),
            "timestamp_range": {
                "minimum": rendered_decimal(min(timestamps)),
                "maximum": rendered_decimal(max(timestamps)),
            },
        },
        "position_candidate_axis": position_axis,
        "claims": [
            "four_numeric_position_columns",
            "bounded_frame_metadata_shape",
            "candidate_axis_nearest_sample_deltas",
        ],
        "not_established": [
            "position_column_semantics",
            "timestamp_unit_or_clock_domain",
            "physical_coordinate_axes",
            "radio_identity",
            "same_event_relation",
            "ranging_or_model_quality",
        ],
        "limits": {
            "selected_frame_metadata_members": len(stems),
            "max_selected_member_bytes": BASE.MAX_SELECTED_MEMBER_BYTES,
            "position_rows_retained": 0,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive", type=Path, default=ROOT / "data" / "raw" / BASE.ARCHIVE_NAME
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "data" / "derived" / "eval" / "caez-alignment-profile.json",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    archive = args.archive.expanduser().absolute()
    md5, sha256 = BASE.digest_archive(archive)
    if md5 != BASE.ARCHIVE_MD5 or sha256 != BASE.ARCHIVE_SHA256:
        raise RuntimeError("CAEZ archive digest failed validation")
    BASE.validate_receipt(archive)
    report = profile_alignment(archive)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    BASE.write_report(args.report.expanduser().absolute(), rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
