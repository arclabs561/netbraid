#!/usr/bin/env python3
"""Profile pinned OPERAnet ZIP layouts without reading member payloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Dict, List, Optional, Pattern, Set, Tuple

MIB = 1024 * 1024
GIB = 1024 * MIB
ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "netbraid.operanet_layout_profile.v0"
RECEIPT_SCHEMA = "local.public_wireless_archive.v1"
MAX_ARCHIVES = 7
MAX_ARCHIVE_MEMBERS = 128
MAX_MEMBER_NAME_BYTES = 255
MAX_TOTAL_MEMBER_NAME_BYTES = 32 * 1024
MAX_MEMBER_EXTRA_BYTES = 4 * 1024
MAX_MEMBER_COMMENT_BYTES = 1024
MAX_TOTAL_CENTRAL_METADATA_BYTES = 256 * 1024
MAX_MEMBER_BYTES = 4 * GIB
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 64 * GIB
MAX_RECEIPT_BYTES = 64 * 1024
MAX_REPORT_BYTES = 256 * 1024
DIGEST_CHUNK_BYTES = 4 * MIB
ALLOWED_COMPRESSION_METHODS = {zipfile.ZIP_DEFLATED}

CODE_MEMBERS = (
    "get_end_point_data_Func.m",
    "get_mid_points_FUNC.m",
    "get_targetReturns_FUNC.m",
    "keep_translatation_on_pts.m",
    "plot_kinect_data.m",
    "plot_PWR_demonstration.m",
    "plot_pwr_spectrogram.py",
    "plot_uwb.m",
    "plot_uwb_fppow_crowdcount.m",
    "plot_wificsi.m",
    "qmult.m",
    "rotate_tr.m",
    "show_stick_figure_Func.m",
    "translate_obj.m",
)


@dataclass(frozen=True)
class ArchiveSpec:
    key: str
    filename: str
    modality: str
    archive_bytes: int
    md5: str
    sha256: str
    doi: str
    url: str
    expected_members: int
    expected_uncompressed_bytes: int
    member_prefix: Optional[str] = None
    member_extension: Optional[str] = None
    member_pattern: Optional[Pattern[str]] = None


@dataclass(frozen=True)
class FileIdentity:
    device: int
    inode: int
    size: int
    modified_ns: int


@dataclass(frozen=True)
class ArchiveObservation:
    report: Dict[str, Any]
    experiment_ids: Set[int]
    normalized_member_keys: Set[str]
    extensions: Set[str]
    variant_ids: Dict[int, List[str]]
    unmatched_names: List[str]


def experiment_pattern(prefix: str, extension: str, variant: str = "") -> Pattern[str]:
    return re.compile(
        rf"^{re.escape(prefix)}(?P<experiment>[0-9]{{3}})"
        rf"(?P<variant>{variant}){re.escape(extension)}$"
    )


# This lock mirrors data/fetch/fetch-public-eval-corpus.py:SOURCES. SHA-256 values
# absent from older source entries are explicitly locked from verified receipts.
SPECS = (
    ArchiveSpec(
        key="codes",
        filename="OPERAnet-codes.zip",
        modality="analysis_code",
        archive_bytes=13_983,
        md5="6b9d2068629bc3f0f139301447b69898",
        sha256="8a06d4f71ba4e6fcdf135ab1d562e315535858f0012835874a38775b9abf77e1",
        doi="10.6084/m9.figshare.16578299.v1",
        url="https://ndownloader.figshare.com/files/30686756",
        expected_members=14,
        expected_uncompressed_bytes=36_248,
    ),
    ArchiveSpec(
        key="kinect",
        filename="OPERAnet-kinect.zip",
        modality="kinect",
        archive_bytes=190_903_745,
        md5="5a333a86da131f2ebae5730f1bf22ffc",
        sha256="0f0de1682d92176b5a21b3008847f5d59e8121a0858b6b61438a8dd948dfa290",
        doi="10.6084/m9.figshare.16578191.v1",
        url="https://ndownloader.figshare.com/files/30686327",
        expected_members=36,
        expected_uncompressed_bytes=195_285_192,
        member_prefix="Kinect_exp_",
        member_extension=".mat",
        member_pattern=experiment_pattern("Kinect_exp_", ".mat"),
    ),
    ArchiveSpec(
        key="pwr",
        filename="OPERAnet-pwr.zip",
        modality="pwr",
        archive_bytes=1_048_378_050,
        md5="ac1301876899ff51b3826afaff6634a7",
        sha256="bb1a1478ab624f76c40677101fb36ae8102dd7e7b85512c0bb8213cf0ceb5bf5",
        doi="10.6084/m9.figshare.16578203.v1",
        url="https://ndownloader.figshare.com/files/30686384",
        expected_members=38,
        expected_uncompressed_bytes=1_052_072_599,
        member_prefix="PWR_exp_",
        member_extension=".mat",
        member_pattern=experiment_pattern("PWR_exp_", ".mat"),
    ),
    ArchiveSpec(
        key="uwb1",
        filename="OPERAnet-uwb1.zip",
        modality="uwb1",
        archive_bytes=2_908_466_535,
        md5="41cb357326a9b2911dcb5801aa6c483f",
        sha256="f5681f2996507d77fb823d7eb0d36b620322dd1fa4273ebdecbf195c81bed17b",
        doi="10.6084/m9.figshare.16578245.v1",
        url="https://ndownloader.figshare.com/files/30686474",
        expected_members=40,
        expected_uncompressed_bytes=10_991_674_403,
        member_prefix="uwb1_exp",
        member_extension=".csv",
        member_pattern=experiment_pattern("uwb1_exp", ".csv"),
    ),
    ArchiveSpec(
        key="uwb2",
        filename="OPERAnet-uwb2.zip",
        modality="uwb2",
        archive_bytes=2_091_091_120,
        md5="cf794dbaf7fb31629c9f9888571177f2",
        sha256="44b2a16079a17b5eb6167c920cadf6f32397ca8601cb4e0219db155a03573faf",
        doi="10.6084/m9.figshare.16578251.v1",
        url="https://ndownloader.figshare.com/files/30686552",
        expected_members=40,
        expected_uncompressed_bytes=7_279_088_046,
        member_prefix="uwb2_exp",
        member_extension=".csv",
        member_pattern=experiment_pattern("uwb2_exp", ".csv"),
    ),
    ArchiveSpec(
        key="wificsi1",
        filename="OPERAnet-wificsi1.zip",
        modality="wifi_csi1",
        archive_bytes=36_490_626_012,
        md5="0bd15bc2577c6479a6fa6aaaea89087b",
        sha256="5a85119bc25041af904b0c92bfc1cb87c4c31106efc25496968bf4891c5222ed",
        doi="10.6084/m9.figshare.16578428.v1",
        url="https://ndownloader.figshare.com/files/30689729",
        expected_members=40,
        expected_uncompressed_bytes=39_136_751_894,
        member_prefix="wificsi1_exp",
        member_extension=".mat",
        member_pattern=experiment_pattern("wificsi1_exp", ".mat"),
    ),
    ArchiveSpec(
        key="wificsi2",
        filename="OPERAnet-wificsi2.zip",
        modality="wifi_csi2",
        archive_bytes=34_352_781_492,
        md5="1eee5528687b42f5e866c232a68bb411",
        sha256="9a7e9d313706cab34e7fce60e2dfca3c2342959e386def49e4c2b54002e7c7f3",
        doi="10.6084/m9.figshare.16578431.v1",
        url="https://ndownloader.figshare.com/files/30694595",
        expected_members=63,
        expected_uncompressed_bytes=43_812_423_114,
        member_prefix="wificsi2_exp",
        member_extension=".mat",
        member_pattern=experiment_pattern("wificsi2_exp", ".mat", "b?"),
    ),
)


class DuplicateKeyError(ValueError):
    pass


def strict_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(key)
        value[key] = item
    return value


def reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def strict_json(data: bytes, label: str) -> Dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=strict_object,
            parse_constant=reject_json_constant,
        )
    except (DuplicateKeyError, UnicodeDecodeError, ValueError) as error:
        raise RuntimeError(f"{label} is not strict JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} is not a JSON object")
    return value


def identity(value: os.stat_result) -> FileIdentity:
    return FileIdentity(
        device=value.st_dev,
        inode=value.st_ino,
        size=value.st_size,
        modified_ns=value.st_mtime_ns,
    )


def open_regular(
    path: Path, minimum_bytes: int, maximum_bytes: int
) -> Tuple[BinaryIO, FileIdentity]:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise RuntimeError(f"cannot inspect required file: {path}") from error
    if not stat.S_ISREG(before.st_mode):
        raise RuntimeError(f"required file is not regular and non-symlink: {path}")
    if not minimum_bytes <= before.st_size <= maximum_bytes:
        raise RuntimeError(
            f"file byte count is outside [{minimum_bytes}, {maximum_bytes}]: {path}"
        )

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RuntimeError(f"cannot open required file safely: {path}") from error
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISREG(after.st_mode) or identity(after) != identity(before):
            raise RuntimeError(f"file changed between inspection and open: {path}")
        return os.fdopen(descriptor, "rb"), identity(after)
    except BaseException:
        os.close(descriptor)
        raise


def require_unchanged(source: BinaryIO, expected: FileIdentity, label: str) -> None:
    if identity(os.fstat(source.fileno())) != expected:
        raise RuntimeError(f"{label} changed while being inspected")


def read_receipt(path: Path, spec: ArchiveSpec) -> None:
    source, expected = open_regular(path, 1, MAX_RECEIPT_BYTES)
    with source:
        data = source.read(MAX_RECEIPT_BYTES + 1)
        require_unchanged(source, expected, f"receipt for {spec.filename}")
    if len(data) != expected.size or len(data) > MAX_RECEIPT_BYTES:
        raise RuntimeError(f"receipt exceeded its read bound: {path}")

    receipt = strict_json(data, f"receipt for {spec.filename}")
    source_metadata = receipt.get("source")
    if not isinstance(source_metadata, dict):
        raise RuntimeError(f"receipt source metadata is absent: {path}")
    expected_source = {
        "bytes": spec.archive_bytes,
        "doi": spec.doi,
        "filename": spec.filename,
        "group": "motivating",
        "license": "CC0",
        "md5": spec.md5,
        "url": spec.url,
    }
    if (
        receipt.get("schema") != RECEIPT_SCHEMA
        or receipt.get("archive") != spec.filename
        or receipt.get("bytes") != spec.archive_bytes
        or receipt.get("md5") != spec.md5
        or receipt.get("sha256") != spec.sha256
        or any(
            source_metadata.get(key) != value for key, value in expected_source.items()
        )
        or source_metadata.get("sha256", spec.sha256) != spec.sha256
    ):
        raise RuntimeError(f"receipt does not match the locked source: {path}")


def safe_member_name(name: str) -> int:
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError as error:
        raise RuntimeError(f"ZIP member name is not bounded ASCII: {name!r}") from error
    parts = name.split("/")
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in parts)
        or len(parts) != 1
        or len(encoded) > MAX_MEMBER_NAME_BYTES
    ):
        raise RuntimeError(f"unsafe or overlong ZIP member name: {name!r}")
    return len(encoded)


def compression_name(method: int) -> str:
    if method == zipfile.ZIP_DEFLATED:
        return "deflate"
    return f"method_{method}"


def inspect_central_directory(
    archive: zipfile.ZipFile, spec: ArchiveSpec
) -> ArchiveObservation:
    infos = archive.infolist()
    if not 0 < len(infos) <= MAX_ARCHIVE_MEMBERS:
        raise RuntimeError(f"{spec.filename} exceeds its member-count bound")
    if len(infos) != spec.expected_members:
        raise RuntimeError(f"{spec.filename} member count changed")
    if len(archive.comment) > MAX_RECEIPT_BYTES:
        raise RuntimeError(f"{spec.filename} archive comment is overlong")

    names: Set[str] = set()
    extensions: Counter[str] = Counter()
    compression_methods: Counter[str] = Counter()
    experiment_members: Dict[int, List[Tuple[str, str]]] = defaultdict(list)
    normalized_member_keys: Set[str] = set()
    unmatched_names: List[str] = []
    total_name_bytes = 0
    total_central_metadata_bytes = 0
    total_compressed = 0
    total_uncompressed = 0

    for info in infos:
        if info.orig_filename != info.filename:
            raise RuntimeError(f"ZIP member name was truncated: {info.orig_filename!r}")
        total_name_bytes += safe_member_name(info.filename)
        if total_name_bytes > MAX_TOTAL_MEMBER_NAME_BYTES:
            raise RuntimeError(
                f"{spec.filename} member names exceed their aggregate bound"
            )
        if (
            len(info.extra) > MAX_MEMBER_EXTRA_BYTES
            or len(info.comment) > MAX_MEMBER_COMMENT_BYTES
        ):
            raise RuntimeError(f"ZIP member metadata is overlong: {info.filename}")
        total_central_metadata_bytes += (
            len(info.filename.encode("ascii")) + len(info.extra) + len(info.comment)
        )
        if total_central_metadata_bytes > MAX_TOTAL_CENTRAL_METADATA_BYTES:
            raise RuntimeError(
                f"{spec.filename} central metadata exceeds its aggregate bound"
            )
        if info.filename in names:
            raise RuntimeError(f"duplicate ZIP member: {info.filename}")
        names.add(info.filename)
        if info.is_dir():
            raise RuntimeError(f"unexpected directory member: {info.filename}")
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
            raise RuntimeError(f"non-regular ZIP member: {info.filename}")
        if info.flag_bits & 0x1:
            raise RuntimeError(f"encrypted ZIP member: {info.filename}")
        if info.compress_type not in ALLOWED_COMPRESSION_METHODS:
            raise RuntimeError(f"unsupported ZIP compression: {info.filename}")
        if not 0 <= info.file_size <= MAX_MEMBER_BYTES:
            raise RuntimeError(
                f"ZIP member exceeds its declared byte bound: {info.filename}"
            )
        if not 0 <= info.compress_size <= spec.archive_bytes:
            raise RuntimeError(f"ZIP compressed size is invalid: {info.filename}")
        if not 0 <= info.header_offset < spec.archive_bytes:
            raise RuntimeError(f"ZIP member header offset is invalid: {info.filename}")

        total_compressed += info.compress_size
        total_uncompressed += info.file_size
        if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise RuntimeError(f"{spec.filename} exceeds its declared expansion bound")
        extension = PurePosixPath(info.filename).suffix.lower() or "<none>"
        extensions[extension] += 1
        compression_methods[compression_name(info.compress_type)] += 1

        if spec.member_pattern is not None:
            match = spec.member_pattern.fullmatch(info.filename)
            if match is None:
                unmatched_names.append(info.filename)
                continue
            experiment_id = int(match.group("experiment"))
            variant = match.groupdict().get("variant") or ""
            experiment_members[experiment_id].append((variant, info.filename))
            normalized_member_keys.add(f"{experiment_id:03d}{variant}")

    if total_uncompressed != spec.expected_uncompressed_bytes:
        raise RuntimeError(f"{spec.filename} declared uncompressed bytes changed")
    if spec.key == "codes" and names != set(CODE_MEMBERS):
        raise RuntimeError("OPERAnet code member inventory changed")

    variant_ids = {
        experiment_id: sorted(variant for variant, _ in members)
        for experiment_id, members in experiment_members.items()
        if len(members) > 1 or any(variant for variant, _ in members)
    }
    duplicate_canonical_ids = {
        f"{experiment_id:03d}": sorted(name for _, name in members)
        for experiment_id, members in experiment_members.items()
        if len(members) > 1
    }
    report = {
        "archive": {
            "bytes": spec.archive_bytes,
            "filename": spec.filename,
            "format": "zip",
            "md5": spec.md5,
            "sha256": spec.sha256,
        },
        "central_directory": {
            "archive_comment_bytes": len(archive.comment),
            "compressed_member_bytes": total_compressed,
            "compression_methods": dict(sorted(compression_methods.items())),
            "crc_payloads_verified": False,
            "declared_uncompressed_bytes": total_uncompressed,
            "directories": 0,
            "files": len(infos),
            "member_name_bytes": total_name_bytes,
            "payload_members_opened": 0,
            "variable_metadata_bytes": total_central_metadata_bytes,
        },
        "experiment_naming": {
            "duplicate_canonical_ids": duplicate_canonical_ids,
            "experiment_ids": sorted(experiment_members),
            "filename_pattern": spec.member_pattern.pattern
            if spec.member_pattern is not None
            else None,
            "member_prefix": spec.member_prefix,
            "member_extension": spec.member_extension,
            "normalized_member_keys": sorted(normalized_member_keys),
            "unmatched_member_names": sorted(unmatched_names),
            "variant_suffixes_by_experiment": {
                f"{experiment_id:03d}": variants
                for experiment_id, variants in sorted(variant_ids.items())
            },
        },
        "member_extensions": dict(sorted(extensions.items())),
        "member_names": sorted(names),
        "modality": spec.modality,
        "receipt": {"schema": RECEIPT_SCHEMA, "validated": True},
    }
    return ArchiveObservation(
        report=report,
        experiment_ids=set(experiment_members),
        normalized_member_keys=normalized_member_keys,
        extensions=set(extensions),
        variant_ids=variant_ids,
        unmatched_names=unmatched_names,
    )


def inspect_archive(path: Path, spec: ArchiveSpec) -> ArchiveObservation:
    source, expected = open_regular(path, spec.archive_bytes, spec.archive_bytes)
    with source:
        md5 = hashlib.md5(usedforsecurity=False)
        sha256 = hashlib.sha256()
        read_bytes = 0
        while read_bytes < spec.archive_bytes:
            chunk = source.read(
                min(DIGEST_CHUNK_BYTES, spec.archive_bytes - read_bytes)
            )
            if not chunk:
                raise RuntimeError(f"{spec.filename} changed while hashing")
            read_bytes += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
        if source.read(1):
            raise RuntimeError(f"{spec.filename} exceeded its byte contract")
        if md5.hexdigest() != spec.md5 or sha256.hexdigest() != spec.sha256:
            raise RuntimeError(f"{spec.filename} digest failed validation")

        source.seek(0)
        try:
            with zipfile.ZipFile(source, mode="r", allowZip64=True) as archive:
                observation = inspect_central_directory(archive, spec)
        except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
            raise RuntimeError(f"{spec.filename} is not a readable ZIP") from error
        require_unchanged(source, expected, spec.filename)
    return observation


def overlap_report(observations: Dict[str, ArchiveObservation]) -> Dict[str, Any]:
    sensing_keys = sorted(
        key for key, spec in ((item.key, item) for item in SPECS) if spec.member_pattern
    )
    experiment_sets = {key: observations[key].experiment_ids for key in sensing_keys}
    normalized_sets = {
        key: observations[key].normalized_member_keys for key in sensing_keys
    }
    all_experiment_ids = set.union(*experiment_sets.values())
    common_experiment_ids = set.intersection(*experiment_sets.values())
    presence = {
        f"{experiment_id:03d}": [
            key for key in sensing_keys if experiment_id in experiment_sets[key]
        ]
        for experiment_id in sorted(all_experiment_ids)
    }

    pairwise = []
    for left, right in combinations(sensing_keys, 2):
        left_ids = experiment_sets[left]
        right_ids = experiment_sets[right]
        pairwise.append(
            {
                "experiment_id_intersection": sorted(left_ids & right_ids),
                "left": left,
                "left_only_experiment_ids": sorted(left_ids - right_ids),
                "prefix_stripped_key_intersection": sorted(
                    normalized_sets[left] & normalized_sets[right]
                ),
                "right": right,
                "right_only_experiment_ids": sorted(right_ids - left_ids),
            }
        )

    identical_groups: Dict[Tuple[int, ...], List[str]] = defaultdict(list)
    for key in sensing_keys:
        identical_groups[tuple(sorted(experiment_sets[key]))].append(key)

    extension_modalities: Dict[str, List[str]] = defaultdict(list)
    for spec in SPECS:
        for extension in sorted(observations[spec.key].extensions):
            extension_modalities[extension].append(spec.key)

    raw_prefixes = {
        spec.key: spec.member_prefix for spec in SPECS if spec.member_prefix is not None
    }
    repeated_prefixes = {
        prefix: sorted(key for key, value in raw_prefixes.items() if value == prefix)
        for prefix in sorted(set(raw_prefixes.values()))
        if sum(value == prefix for value in raw_prefixes.values()) > 1
    }

    blockers = []
    if any(observations[key].unmatched_names for key in sensing_keys):
        blockers.append(
            {
                "code": "unparsed_sensing_member_names",
                "detail": "At least one sensing member does not match its locked experiment filename family.",
            }
        )
    variant_members = {
        key: {
            f"{experiment_id:03d}": variants
            for experiment_id, variants in sorted(observations[key].variant_ids.items())
        }
        for key in sensing_keys
        if observations[key].variant_ids
    }
    if variant_members:
        blockers.append(
            {
                "code": "variant_suffix_semantics_unknown",
                "detail": (
                    "Filename suffixes identify extra members but do not say whether they are "
                    "continuations, repetitions, or separate captures."
                ),
                "members": variant_members,
            }
        )
    if any(experiment_sets[key] != all_experiment_ids for key in sensing_keys):
        blockers.append(
            {
                "code": "incomplete_cross_modality_coverage",
                "detail": (
                    f"Only {len(common_experiment_ids)} of {len(all_experiment_ids)} observed "
                    "experiment IDs occur in all six sensing archives."
                ),
            }
        )
    blockers.extend(
        [
            {
                "code": "filename_tokens_are_not_capture_metadata",
                "detail": (
                    "Equal experiment-number tokens do not establish shared participant, activity, "
                    "room, clock, start time, duration, or observation window."
                ),
            },
            {
                "code": "code_archive_has_no_experiment_ids",
                "detail": (
                    "The analysis-code archive is inventoried but cannot participate in "
                    "experiment-ID alignment from filenames."
                ),
            },
        ]
    )

    return {
        "all_sensing_modalities_same_experiment_id_set": all(
            experiment_sets[key] == all_experiment_ids for key in sensing_keys
        ),
        "claim": "OPERAnet modality archives align on experiment IDs",
        "claim_status": "blocked_as_universal_or_semantic_alignment",
        "common_experiment_ids": sorted(common_experiment_ids),
        "experiment_id_presence": presence,
        "identical_experiment_id_groups": [
            {"experiment_ids": list(ids), "modalities": sorted(keys)}
            for ids, keys in sorted(identical_groups.items(), key=lambda item: item[1])
        ],
        "member_extension_modalities": {
            extension: sorted(keys)
            for extension, keys in sorted(extension_modalities.items())
        },
        "pairwise_overlap": pairwise,
        "prefix_normalization": {
            "method": "locked full-match pattern; strip modality prefix and extension",
            "raw_prefixes": raw_prefixes,
            "repeated_raw_prefixes": repeated_prefixes,
        },
        "sensing_modalities": sensing_keys,
        "supported_filename_claims": [
            (
                f"{len(common_experiment_ids)} experiment-number tokens occur in every sensing "
                "archive."
            ),
            "uwb1, uwb2, and wificsi1 have identical experiment-ID sets.",
        ],
        "union_experiment_ids": sorted(all_experiment_ids),
        "blockers": blockers,
    }


def profile(archive_dir: Path) -> Dict[str, Any]:
    if len(SPECS) != MAX_ARCHIVES or len({spec.key for spec in SPECS}) != len(SPECS):
        raise RuntimeError("internal OPERAnet archive lock is inconsistent")
    if archive_dir.is_symlink() or not archive_dir.is_dir():
        raise RuntimeError(f"archive directory is absent or unsafe: {archive_dir}")

    observations: Dict[str, ArchiveObservation] = {}
    for spec in SPECS:
        archive_path = archive_dir / spec.filename
        receipt_path = archive_path.with_suffix(archive_path.suffix + ".json")
        read_receipt(receipt_path, spec)
        observations[spec.key] = inspect_archive(archive_path, spec)

    return {
        "archives": {key: observations[key].report for key in sorted(observations)},
        "claims": overlap_report(observations),
        "limits": {
            "archives": MAX_ARCHIVES,
            "digest_chunk_bytes": DIGEST_CHUNK_BYTES,
            "max_archive_members": MAX_ARCHIVE_MEMBERS,
            "max_archive_uncompressed_bytes": MAX_ARCHIVE_UNCOMPRESSED_BYTES,
            "max_member_bytes": MAX_MEMBER_BYTES,
            "max_member_comment_bytes": MAX_MEMBER_COMMENT_BYTES,
            "max_member_extra_bytes": MAX_MEMBER_EXTRA_BYTES,
            "max_member_name_bytes": MAX_MEMBER_NAME_BYTES,
            "max_receipt_bytes": MAX_RECEIPT_BYTES,
            "max_report_bytes": MAX_REPORT_BYTES,
            "max_total_member_name_bytes_per_archive": MAX_TOTAL_MEMBER_NAME_BYTES,
            "max_total_variable_central_metadata_bytes_per_archive": (
                MAX_TOTAL_CENTRAL_METADATA_BYTES
            ),
            "total_pinned_archive_bytes": sum(spec.archive_bytes for spec in SPECS),
        },
        "method": {
            "archive_verification": "full MD5 and SHA-256 over exact pinned bytes",
            "container_inspection": "ZIP end records and central directories only",
            "determinism": "sorted inputs and output; no timestamps or runtime fields",
            "member_payloads_extracted_or_deserialized": 0,
            "member_streams_opened": 0,
            "receipt_source": (
                "locked constants mirrored from data/fetch/fetch-public-eval-corpus.py:SOURCES "
                "and verified local receipts"
            ),
        },
        "schema": SCHEMA,
        "status": "pass",
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive-dir",
        type=Path,
        default=ROOT / "data" / "raw",
        help="directory containing the seven pinned OPERAnet ZIPs and receipts",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=ROOT / "data" / "derived" / "eval" / "operanet-layout-profile.json",
        help="local JSON report path",
    )
    return parser.parse_args()


def write_report(path: Path, rendered: bytes) -> None:
    if len(rendered) > MAX_REPORT_BYTES:
        raise RuntimeError("rendered report exceeds its byte bound")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError(f"refusing symlink report path: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
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
    archive_dir = args.archive_dir.expanduser().absolute()
    report_path = args.report.expanduser().absolute()
    if report_path in {
        archive_dir / spec.filename for spec in SPECS
    } or report_path in {
        (archive_dir / spec.filename).with_suffix(".zip.json") for spec in SPECS
    }:
        raise RuntimeError("report path collides with a locked OPERAnet input")
    report = profile(archive_dir)
    rendered = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    write_report(report_path, rendered)
    print(
        json.dumps(
            {
                "archives": len(SPECS),
                "claim_status": report["claims"]["claim_status"],
                "report": str(report_path),
                "report_bytes": len(rendered),
                "status": report["status"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
