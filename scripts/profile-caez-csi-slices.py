#!/usr/bin/env python3
"""Profile bounded CAEZ CSI structure without extracting or deserializing payloads."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import math
import os
import re
import tarfile
import tempfile
from pathlib import Path
from typing import Any

MIB = 1024 * 1024
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.caez_csi_profile.v0"
ARCHIVE_NAME = "caez-wifi-indoor-Lshape.tar.gz"
ARCHIVE_BYTES = 1_933_783_040
ARCHIVE_MD5 = "a6127a35dd7397fe592da9e6b942eb25"
ARCHIVE_SHA256 = "3ee1fd4f2746b1ac6ac8e7c5172c35b4abe5d507353981359218b0e7fd868bdf"
ROOT_MEMBER = "caez-wifi-indoor-1"
EXPECTED_FILES = 322_370
EXPECTED_DIRECTORIES = 13
EXPECTED_PAIRS = 161_182
EXPECTED_PAIRS_BY_AP = {1: 33_411, 2: 43_518, 3: 40_339, 4: 43_914}
EXPECTED_GT_BYTES = 169_874_402
EXPECTED_POSITION_BYTES = 330
MAX_SELECTED_MEMBER_BYTES = 16 * 1024
EXPECTED_CSI_ROWS = 5
EXPECTED_CSI_COLUMNS = 52
FRAME_METADATA_KEYS = {
    "CFO",
    "MCS",
    "SNR",
    "USRP",
    "avg_RX_pwr",
    "psdu_hash",
    "psdu_length",
    "timestamp",
}
AP_METADATA_KEYS = {"OS_samp_rate", "measurement_start", "samp_rate"}
MEASUREMENT_START_PATTERN = re.compile(
    r"[0-9]{4}(?:-[0-9]{2}){2}_(?:[0-9]{2}-){2}[0-9]{2}"
)
PAIR_PATTERN = re.compile(
    rf"^{ROOT_MEMBER}/ap([1-4])/take([12])/frame([0-9]+)_(csi\.csv|metadata\.json)$"
)
SELECTED_STEMS = (
    "ap1/take1/frame0",
    "ap1/take2/frame1",
    "ap2/take1/frame0",
    "ap2/take2/frame0",
    "ap3/take1/frame0",
    "ap3/take2/frame0",
    "ap4/take1/frame0",
    "ap4/take2/frame0",
)


class DuplicateKeyError(ValueError):
    pass


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(key)
        value[key] = item
    return value


def strict_json(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data, object_pairs_hook=strict_object)
    except (DuplicateKeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("selected metadata is not strict JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("selected metadata is not an object")
    return value


def digest_archive(path: Path) -> tuple[str, str]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size != ARCHIVE_BYTES:
        raise RuntimeError("CAEZ archive path or byte count failed validation")
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    read_bytes = 0
    with path.open("rb") as source:
        while chunk := source.read(MIB):
            read_bytes += len(chunk)
            if read_bytes > ARCHIVE_BYTES:
                raise RuntimeError("CAEZ archive exceeded its byte contract")
            md5.update(chunk)
            sha256.update(chunk)
    if read_bytes != ARCHIVE_BYTES:
        raise RuntimeError("CAEZ archive changed while hashing")
    return md5.hexdigest(), sha256.hexdigest()


def validate_receipt(path: Path) -> None:
    receipt_path = path.with_suffix(path.suffix + ".json")
    if receipt_path.is_symlink() or not receipt_path.is_file():
        raise RuntimeError("CAEZ fetch receipt is absent or unsafe")
    receipt = strict_json(receipt_path.read_bytes())
    source = receipt.get("source")
    if (
        receipt.get("schema") != "local.public_wireless_archive.v1"
        or receipt.get("archive") != ARCHIVE_NAME
        or receipt.get("bytes") != ARCHIVE_BYTES
        or receipt.get("md5") != ARCHIVE_MD5
        or receipt.get("sha256") != ARCHIVE_SHA256
        or not isinstance(source, dict)
        or source.get("filename") != ARCHIVE_NAME
        or source.get("format") != "tar"
        or source.get("bytes") != ARCHIVE_BYTES
        or source.get("md5") != ARCHIVE_MD5
        or source.get("sha256") != ARCHIVE_SHA256
    ):
        raise RuntimeError("CAEZ fetch receipt does not match the profile contract")


def wanted_members() -> set[str]:
    selected = {
        f"{ROOT_MEMBER}/{stem}_{suffix}"
        for stem in SELECTED_STEMS
        for suffix in ("csi.csv", "metadata.json")
    }
    selected.update(
        f"{ROOT_MEMBER}/ap{ap}/measurement_metadata.json" for ap in range(1, 5)
    )
    return selected


def read_selected_member(source: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if not member.isfile() or not 0 < member.size <= MAX_SELECTED_MEMBER_BYTES:
        raise RuntimeError(f"selected member violates its size contract: {member.name}")
    stream = source.extractfile(member)
    if stream is None:
        raise RuntimeError(f"selected member is unreadable: {member.name}")
    data = stream.read(MAX_SELECTED_MEMBER_BYTES + 1)
    if len(data) != member.size:
        raise RuntimeError(f"selected member changed while reading: {member.name}")
    return data


def profile_archive(path: Path) -> dict[str, Any]:
    expected_selected = wanted_members()
    selected: dict[str, bytes] = {}
    pair_parts: dict[tuple[int, int, int], int] = {}
    frame_ids: dict[tuple[int, int], set[int]] = {}
    files = 0
    directories = 0
    gt_bytes = None
    position_bytes = None

    try:
        with tarfile.open(path, "r:") as source:
            for member in source:
                parts = Path(member.name).parts
                if member.name.startswith("/") or ".." in parts:
                    raise RuntimeError(f"unsafe CAEZ member path: {member.name}")
                if member.isdir():
                    directories += 1
                    continue
                if not member.isfile():
                    raise RuntimeError(f"unsupported CAEZ member type: {member.name}")
                files += 1
                if member.name == f"{ROOT_MEMBER}/gt-positions.csv":
                    gt_bytes = member.size
                elif member.name == f"{ROOT_MEMBER}/ap_pos.npz":
                    position_bytes = member.size

                match = PAIR_PATTERN.fullmatch(member.name)
                if match:
                    ap, take, frame = (int(match.group(index)) for index in range(1, 4))
                    key = (ap, take, frame)
                    bit = 1 if match.group(4) == "csi.csv" else 2
                    if pair_parts.get(key, 0) & bit:
                        raise RuntimeError(f"duplicate CAEZ pair member: {member.name}")
                    pair_parts[key] = pair_parts.get(key, 0) | bit
                    frame_ids.setdefault((ap, take), set()).add(frame)

                if member.name in expected_selected:
                    if member.name in selected:
                        raise RuntimeError(f"duplicate selected member: {member.name}")
                    selected[member.name] = read_selected_member(source, member)
    except tarfile.TarError as error:
        raise RuntimeError(
            "CAEZ artifact is not the declared uncompressed tar"
        ) from error

    if files != EXPECTED_FILES or directories != EXPECTED_DIRECTORIES:
        raise RuntimeError("CAEZ container inventory changed")
    if gt_bytes != EXPECTED_GT_BYTES or position_bytes != EXPECTED_POSITION_BYTES:
        raise RuntimeError("CAEZ ground-truth sidecar inventory changed")
    if len(pair_parts) != EXPECTED_PAIRS or any(
        parts != 3 for parts in pair_parts.values()
    ):
        raise RuntimeError("CAEZ CSI/frame-metadata pairing changed")
    pairs_by_ap = {
        ap: sum(key[0] == ap for key in pair_parts) for ap in EXPECTED_PAIRS_BY_AP
    }
    if pairs_by_ap != EXPECTED_PAIRS_BY_AP:
        raise RuntimeError("CAEZ per-AP pair counts changed")
    if set(selected) != expected_selected:
        raise RuntimeError("CAEZ selected profile members are incomplete")

    gap_groups = 0
    for ids in frame_ids.values():
        if len(ids) != max(ids) - min(ids) + 1:
            gap_groups += 1
    if gap_groups == 0:
        raise RuntimeError("CAEZ frame IDs unexpectedly became contiguous")

    selected_pair_bytes = 0
    for stem in SELECTED_STEMS:
        csi_name = f"{ROOT_MEMBER}/{stem}_csi.csv"
        metadata_name = f"{ROOT_MEMBER}/{stem}_metadata.json"
        selected_pair_bytes += len(selected[csi_name]) + len(selected[metadata_name])
        try:
            rows = list(csv.reader(io.StringIO(selected[csi_name].decode("utf-8"))))
        except UnicodeDecodeError as error:
            raise RuntimeError(f"CSI sample is not UTF-8: {csi_name}") from error
        if len(rows) != EXPECTED_CSI_ROWS or any(
            len(row) != EXPECTED_CSI_COLUMNS or any(not cell for cell in row)
            for row in rows
        ):
            raise RuntimeError(f"CSI sample shape changed: {csi_name}")
        if set(strict_json(selected[metadata_name])) != FRAME_METADATA_KEYS:
            raise RuntimeError(f"frame metadata keys changed: {metadata_name}")

    ap_metadata_bytes = 0
    for ap in range(1, 5):
        name = f"{ROOT_MEMBER}/ap{ap}/measurement_metadata.json"
        ap_metadata_bytes += len(selected[name])
        metadata = strict_json(selected[name])
        sample_rates = (metadata.get("samp_rate"), metadata.get("OS_samp_rate"))
        if (
            set(metadata) != AP_METADATA_KEYS
            or not isinstance(metadata["measurement_start"], str)
            or not MEASUREMENT_START_PATTERN.fullmatch(metadata["measurement_start"])
            or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                or value <= 0
                for value in sample_rates
            )
        ):
            raise RuntimeError(f"AP metadata changed: {name}")

    return {
        "schema": SCHEMA,
        "status": "pass",
        "archive": {
            "bytes": ARCHIVE_BYTES,
            "md5": ARCHIVE_MD5,
            "sha256": ARCHIVE_SHA256,
            "format": "tar",
        },
        "container": {
            "files": files,
            "directories": directories,
            "paired_csi_frames": len(pair_parts),
            "paired_csi_frames_by_ap": {
                f"ap{ap}": count for ap, count in pairs_by_ap.items()
            },
            "ap_take_groups_with_frame_id_gaps": gap_groups,
        },
        "selected_profile": {
            "samples": len(SELECTED_STEMS),
            "pair_bytes": selected_pair_bytes,
            "ap_metadata_bytes": ap_metadata_bytes,
            "total_bytes_read": selected_pair_bytes + ap_metadata_bytes,
            "csi_rows": EXPECTED_CSI_ROWS,
            "csi_columns": EXPECTED_CSI_COLUMNS,
            "frame_metadata_keys": sorted(FRAME_METADATA_KEYS),
            "ap_metadata_keys": sorted(AP_METADATA_KEYS),
        },
        "unread_payloads": {
            "ground_truth_csv_bytes": gt_bytes,
            "position_npz_bytes": position_bytes,
        },
        "limits": {"max_selected_member_bytes": MAX_SELECTED_MEMBER_BYTES},
        "claims": [
            "container_inventory",
            "csi_metadata_pairing",
            "selected_csi_shape",
            "selected_metadata_shape",
        ],
        "not_established": [
            "position_alignment",
            "radio_identity",
            "ranging_accuracy",
            "model_quality",
        ],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive", type=Path, default=ROOT / "eval-data" / ARCHIVE_NAME
    )
    parser.add_argument(
        "--report", type=Path, default=ROOT / "eval-data" / "caez-csi-profile.json"
    )
    return parser.parse_args()


def write_report(path: Path, rendered: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    args = parse_args()
    archive = args.archive.expanduser().absolute()
    md5, sha256 = digest_archive(archive)
    if md5 != ARCHIVE_MD5 or sha256 != ARCHIVE_SHA256:
        raise RuntimeError("CAEZ archive digest failed validation")
    validate_receipt(archive)
    report = profile_archive(archive)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    write_report(args.report.expanduser().absolute(), rendered)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
