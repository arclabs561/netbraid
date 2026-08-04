#!/usr/bin/env python3
"""Profile bounded BLE/Zigbee acquisition structure in the SDR4IoT archive.

Only the archive bytes and ZIP central directory are read. Capture, CSV, and
publisher-named SigMF payloads are never opened, and publisher token values are
reduced to aggregate counts.
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
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.sdr4iot_layout_profile.v0"
ARCHIVE_NAME = "sdr4iot-ble-zigbee-dataset.zip"
ARCHIVE_BYTES = 78_658_727
ARCHIVE_MD5 = "c966c5cbf1243b5a16f59675451de84e"
DOI = "10.5281/zenodo.4639390"
MIB = 1024 * 1024
MAX_ARCHIVE_BYTES = 96 * MIB
MAX_MEMBERS = 1_000
MAX_MEMBER_BYTES = 16 * MIB
MAX_TOTAL_MEMBER_BYTES = 256 * MIB
MAX_NAME_BYTES = 512
MAX_COMPRESSION_RATIO = 100
READ_CHUNK_BYTES = MIB
MODALITIES = ("ble", "zigbee")
LAYERS = {
    "cap": "packet_capture",
    "csv": "tabular_extract",
    "sigmf": "publisher_sigmf",
}

STANDARD_NAME = re.compile(
    r"(?P<extract>extract_)?S(?P<scenario>[0-9]+)(?P<variant>b?)_"
    r"s(?P<scene>[0-9]+)_"
    r"(?P<year>[0-9]{4})-(?P<month>[0-9]{2,3})-(?P<day>[0-9]{2})_"
    r"(?P<hour>[0-9]{2})-(?P<minute>[0-9]{2})_"
    r"server(?P<receiver>[0-9]+)(?:_mobile(?P<mobile>[0-9]+))?\."
    r"(?P<extension>cap|csv|sigmf)\Z"
)
ALTERNATE_NAME = re.compile(
    r"S(?P<scenario>[0-9]+)_s(?P<scene>[0-9]+)_"
    r"server(?P<receiver>[0-9]+)-mobile(?P<mobile>[0-9]+)-"
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}_[0-9]{2}-[0-9]{2}-[0-9]{2}"
    r"(?P<tag>-tag)?\.(?P<extension>cap|csv|sigmf)\Z"
)
RUN_TOKEN = re.compile(r"(?:[0-9]{6}|[0-9]{8})_[0-9]{4}\Z")


class LayoutProfileError(RuntimeError):
    """Stable fail-closed reason for an unsafe or unsupported archive."""


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, order=True)
class ObservationKey:
    modality: str
    scenario: str
    scene: str
    run: str
    receiver: str
    mobile: str | None


@dataclass(frozen=True)
class ParsedArtifact:
    observation: ObservationKey
    layer: str
    irregular_date_token: bool
    supplemental_extract: bool


def _identity(metadata: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        modified_ns=metadata.st_mtime_ns,
        changed_ns=metadata.st_ctime_ns,
    )


def _open_regular(path: Path) -> tuple[BinaryIO, FileIdentity]:
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise LayoutProfileError("archive_not_regular")
    if not 0 < before.st_size <= MAX_ARCHIVE_BYTES:
        raise LayoutProfileError("archive_size_limit")
    source = path.open("rb")
    after = os.fstat(source.fileno())
    if _identity(before) != _identity(after):
        source.close()
        raise LayoutProfileError("archive_identity_changed")
    return source, _identity(after)


def _require_unchanged(source: BinaryIO, expected: FileIdentity) -> None:
    if _identity(os.fstat(source.fileno())) != expected:
        raise LayoutProfileError("archive_changed_during_profile")


def _digests(source: BinaryIO) -> tuple[str, str]:
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    source.seek(0)
    while chunk := source.read(READ_CHUNK_BYTES):
        md5.update(chunk)
        sha256.update(chunk)
    source.seek(0)
    return md5.hexdigest(), sha256.hexdigest()


def _safe_member_name(name: str) -> tuple[str, ...]:
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as error:
        raise LayoutProfileError("unsafe_member_name") from error
    path = Path(name)
    parts = path.parts
    if (
        not encoded
        or len(encoded) > MAX_NAME_BYTES
        or name.startswith("/")
        or "\\" in name
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise LayoutProfileError("unsafe_member_name")
    return parts


def _parse_artifact(parts: tuple[str, ...]) -> ParsedArtifact | None:
    if len(parts) != 5:
        return None
    modality, scenario_dir, scene_dir, run, filename = parts
    if modality not in MODALITIES or not RUN_TOKEN.fullmatch(run):
        return None
    if not scenario_dir.startswith("scenario") or not scene_dir.startswith("scene"):
        return None

    match = STANDARD_NAME.fullmatch(filename)
    if match is None:
        match = ALTERNATE_NAME.fullmatch(filename)
    if match is None:
        return None

    scenario = match.group("scenario")
    scene = match.group("scene")
    if scenario_dir != f"scenario{scenario}" or scene_dir != f"scene{scene}":
        raise LayoutProfileError("path_filename_group_mismatch")
    extension = match.group("extension")
    extract = match.groupdict().get("extract") is not None
    if extract and extension != "csv":
        raise LayoutProfileError("unsupported_supplemental_extract")
    month = match.groupdict().get("month")
    return ParsedArtifact(
        observation=ObservationKey(
            modality=modality,
            scenario=scenario,
            scene=scene,
            run=run,
            receiver=match.group("receiver"),
            mobile=match.group("mobile"),
        ),
        layer=LAYERS[extension],
        irregular_date_token=month is not None and len(month) != 2,
        supplemental_extract=extract,
    )


def _supplemental_kind(parts: tuple[str, ...]) -> str | None:
    name = parts[-1]
    if parts[0] == "__MACOSX" or name == ".DS_Store" or name.startswith("._"):
        return "archive_metadata"
    if name == "robot6-centerpath2020-06-29 18-10-37.png":
        return "route_plot"
    if name == "essai_alexis.csv":
        return "unstructured_csv"
    if name.endswith(".log"):
        return "capture_log"
    return None


def _layer_set_counts(groups: dict[ObservationKey, set[str]]) -> list[dict[str, Any]]:
    counts = Counter(tuple(sorted(layers)) for layers in groups.values())
    return [
        {"layers": list(layers), "observation_groups": count}
        for layers, count in sorted(counts.items())
    ]


def _modality_report(
    modality: str,
    groups: dict[ObservationKey, set[str]],
    artifact_counts: Counter[str],
) -> dict[str, Any]:
    selected = {
        key: layers for key, layers in groups.items() if key.modality == modality
    }
    runs = {(key.scenario, key.scene, key.run) for key in selected}
    scenarios = {key.scenario for key in selected}
    scenes = {(key.scenario, key.scene) for key in selected}
    receivers = {key.receiver for key in selected}
    mobiles = {key.mobile for key in selected if key.mobile is not None}
    complete = sum(1 for layers in selected.values() if set(LAYERS.values()) <= layers)
    return {
        "modality": modality,
        "artifact_counts": {
            layer: artifact_counts[f"{modality}:{layer}"]
            for layer in sorted(LAYERS.values())
        },
        "observation_groups": len(selected),
        "complete_three_layer_groups": complete,
        "layer_set_counts": _layer_set_counts(selected),
        "collection_runs": len(runs),
        "scenario_tokens": len(scenarios),
        "scene_tokens": len(scenes),
        "receiver_tokens": len(receivers),
        "mobile_tokens": len(mobiles),
    }


def profile_archive(
    path: Path, *, verify_publisher_digest: bool = True
) -> dict[str, Any]:
    source, identity = _open_regular(path)
    try:
        observed_md5, observed_sha256 = _digests(source)
        if verify_publisher_digest and (
            identity.size != ARCHIVE_BYTES or observed_md5 != ARCHIVE_MD5
        ):
            raise LayoutProfileError("archive_digest_mismatch")

        names: set[str] = set()
        groups: dict[ObservationKey, set[str]] = defaultdict(set)
        artifact_counts: Counter[str] = Counter()
        supplemental: Counter[str] = Counter()
        irregular_dates = 0
        member_bytes = 0
        compressed_bytes = 0
        file_members = 0

        try:
            archive = zipfile.ZipFile(source)
        except (OSError, zipfile.BadZipFile) as error:
            raise LayoutProfileError("invalid_zip_archive") from error
        with archive:
            members = archive.infolist()
            if not 1 <= len(members) <= MAX_MEMBERS:
                raise LayoutProfileError("archive_member_count_limit")
            for member in members:
                parts = _safe_member_name(member.filename.rstrip("/"))
                if member.filename in names:
                    raise LayoutProfileError("duplicate_member_name")
                names.add(member.filename)
                if member.is_dir():
                    if member.file_size != 0:
                        raise LayoutProfileError("invalid_directory_member")
                    continue
                file_members += 1
                if member.flag_bits & 0x1:
                    raise LayoutProfileError("encrypted_member")
                if member.compress_type not in {
                    zipfile.ZIP_STORED,
                    zipfile.ZIP_DEFLATED,
                }:
                    raise LayoutProfileError("unsupported_compression")
                if not 0 < member.file_size <= MAX_MEMBER_BYTES:
                    raise LayoutProfileError("member_size_limit")
                if not 0 < member.compress_size <= MAX_MEMBER_BYTES:
                    raise LayoutProfileError("invalid_compressed_size")
                if member.file_size > member.compress_size * MAX_COMPRESSION_RATIO:
                    raise LayoutProfileError("compression_ratio_limit")
                member_bytes += member.file_size
                compressed_bytes += member.compress_size
                if member_bytes > MAX_TOTAL_MEMBER_BYTES:
                    raise LayoutProfileError("total_member_size_limit")

                parsed = _parse_artifact(parts)
                if parsed is not None:
                    if parsed.supplemental_extract:
                        supplemental["additional_tabular_extract"] += 1
                        continue
                    layers = groups[parsed.observation]
                    if parsed.layer in layers:
                        raise LayoutProfileError("duplicate_observation_layer")
                    layers.add(parsed.layer)
                    artifact_counts[
                        f"{parsed.observation.modality}:{parsed.layer}"
                    ] += 1
                    irregular_dates += int(parsed.irregular_date_token)
                    continue

                kind = _supplemental_kind(parts)
                if kind is None:
                    raise LayoutProfileError("unsupported_member_layout")
                supplemental[kind] += 1

        if set(key.modality for key in groups) != set(MODALITIES):
            raise LayoutProfileError("modality_coverage_mismatch")
        _require_unchanged(source, identity)
        receiver_sets = {
            modality: {key.receiver for key in groups if key.modality == modality}
            for modality in MODALITIES
        }
        mobile_sets = {
            modality: {
                key.mobile
                for key in groups
                if key.modality == modality and key.mobile is not None
            }
            for modality in MODALITIES
        }
        shared_receivers = len(receiver_sets["ble"] & receiver_sets["zigbee"])
        established = [
            "ble_and_zigbee_archive_roots",
            "protocol_specific_collection_groups",
            "candidate_packet_table_signal_artifact_pairing",
        ]
        if shared_receivers:
            established.append("publisher_receiver_token_reuse_across_modalities")
        return {
            "schema": SCHEMA,
            "status": "pass",
            "source": {
                "archive": path.name,
                "bytes": identity.size,
                "md5": observed_md5,
                "sha256": observed_sha256,
                "doi": DOI,
            },
            "bounds": {
                "max_archive_bytes": MAX_ARCHIVE_BYTES,
                "max_members": MAX_MEMBERS,
                "max_member_bytes": MAX_MEMBER_BYTES,
                "max_total_member_bytes": MAX_TOTAL_MEMBER_BYTES,
                "max_name_bytes": MAX_NAME_BYTES,
                "max_compression_ratio": MAX_COMPRESSION_RATIO,
            },
            "archive": {
                "members": len(names),
                "file_members": file_members,
                "member_bytes": member_bytes,
                "compressed_member_bytes": compressed_bytes,
                "irregular_filename_date_tokens": irregular_dates,
            },
            "modalities": [
                _modality_report(modality, groups, artifact_counts)
                for modality in MODALITIES
            ],
            "cross_modality": {
                "shared_receiver_tokens": shared_receivers,
                "shared_mobile_tokens": len(mobile_sets["ble"] & mobile_sets["zigbee"]),
                "cross_protocol_event_alignment": "not_established",
            },
            "supplemental_member_counts": dict(sorted(supplemental.items())),
            "privacy": {
                "payload_bytes_read": 0,
                "member_names_retained": 0,
                "publisher_token_values_retained": 0,
            },
            "interpretation": {
                "established": established,
                "not_established": [
                    "payload_alignment",
                    "sigmf_format_conformance",
                    "event_identity",
                    "cross_protocol_event_identity",
                    "physical_device_identity",
                    "physical_source_identity",
                    "location_truth",
                    "malicious_intent",
                    "tamper",
                ],
            },
        }
    finally:
        source.close()


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise LayoutProfileError("report_path_is_symlink")
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive", type=Path, default=ROOT / "data" / "raw" / ARCHIVE_NAME
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "data" / "derived" / "eval" / "sdr4iot-layout-profile.json",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        report = profile_archive(arguments.archive)
        _write_report(arguments.report, report)
    except (OSError, LayoutProfileError, zipfile.BadZipFile) as error:
        print(error, file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
