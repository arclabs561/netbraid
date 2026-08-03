#!/usr/bin/env python3
"""Evaluate bounded public-corpus slices without admitting their bytes to Git."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import stat
import subprocess
import tempfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MIB = 1024 * 1024
MANIFEST_SCHEMA = "netbraid.public_corpus_slices.v0"
REPORT_SCHEMA = "netbraid.public_corpus_eval.v1"
IEEE802154_PROJECTION_SCHEMA = "netmon.saved_pcap_ieee802154_projection.v0"
CAPTURE_MANIFEST_SCHEMA = "netmon.capture_manifest.v0"
PACKET_ENVELOPE_SCHEMA = "netmon.packet_envelope.v0"
PACKET_QUARANTINE_SCHEMA = "netmon.packet_quarantine.v0"
PUBLIC_ARCHIVE_RECEIPT_SCHEMA = "local.public_wireless_archive.v1"
IEEE802154_BASE_ORACLE_KEYS = {
    "completeness",
    "counts",
    "frame_type_version_mix",
    "address_forms",
    "commands",
    "fcs",
}
IEEE802154_RECORD_ORACLE_KEY = "preserved_6lowpan_decoded_ipv6"
IEEE802154_LIMITATIONS = [
    "aggregate over validated PacketEnvelopeV0.ieee802154 evidence; no raw DLT decoding",
    "complete_capture applies to normalization completeness, not continuous RF observation",
    "normalized_packet_subset cannot support capture-wide negative claims",
    "address values, PAN identifiers, sequence numbers, and observer identifiers are excluded",
    "command values are frame fields, not device, role, or behavior identity",
    "FCS availability depends on the saved capture and upstream dissector evidence",
    "no payload retention, cross-observer join, or device, person, place, or intent inference",
]
IEEE802154_FORBIDDEN_KEYS = {
    "capture_id",
    "destination_pan_id",
    "observer_id",
    "raw_row",
    "record_id",
    "sequence_number",
    "source_pan_id",
}
MAX_MANIFEST_BYTES = MIB
MAX_RECEIPT_BYTES = 64 * 1024
MAX_CASES = 64
MAX_MEMBER_BYTES = 16 * MIB
MAX_TOTAL_MEMBER_BYTES = 64 * MIB
MAX_TOOL_OUTPUT_BYTES = 4 * MIB
MAX_BINARY_BYTES = 256 * MIB
TOOL_TIMEOUT_S = 75
SHA256 = 64
MD5 = 32
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = Path(__file__).parent / "fixtures/public-corpus-slices-v0.json"


class DuplicateKeyError(ValueError):
    pass


class EvaluationError(Exception):
    def __init__(self, stage: str, case: str | None = None) -> None:
        super().__init__(stage, case)
        self.stage = stage
        self.case = case


@dataclass(frozen=True)
class ExtractedCase:
    case: dict[str, Any]
    capture_path: Path
    capture_bytes: bytes
    reference_bytes: bytes | None


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKeyError(key)
        value[key] = item
    return value


def strict_json(data: bytes, stage: str, case: str | None = None) -> Any:
    try:
        return json.loads(data, object_pairs_hook=strict_object)
    except (
        DuplicateKeyError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
    ):
        raise EvaluationError(stage, case) from None


def is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def is_sha256_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and is_hex(value.removeprefix("sha256:"), SHA256)
    )


def validate_ieee802154_oracle(
    expectation: Any, packet_limit: Any, case_id: str
) -> None:
    if not isinstance(expectation, dict) or frozenset(expectation) not in {
        frozenset(IEEE802154_BASE_ORACLE_KEYS),
        frozenset(IEEE802154_BASE_ORACLE_KEYS | {IEEE802154_RECORD_ORACLE_KEY}),
    }:
        raise EvaluationError("expectation", case_id)
    completeness = expectation["completeness"]
    counts = expectation["counts"]
    address_forms = expectation["address_forms"]
    commands = expectation["commands"]
    fcs = expectation["fcs"]
    if (
        not isinstance(completeness, dict)
        or set(completeness)
        != {"state", "scope", "packet_limit", "packet_limit_reached"}
        or completeness["state"] not in {"complete", "partial"}
        or completeness["scope"] not in {"complete_capture", "normalized_packet_subset"}
        or type(completeness["packet_limit"]) is not int
        or completeness["packet_limit"] != packet_limit
        or type(completeness["packet_limit_reached"]) is not bool
        or completeness["state"] == "complete"
        and (
            completeness["scope"] != "complete_capture"
            or completeness["packet_limit_reached"]
        )
        or completeness["state"] == "partial"
        and completeness["scope"] != "normalized_packet_subset"
    ):
        raise EvaluationError("expectation", case_id)

    count_keys = {
        "packet_envelopes",
        "packet_quarantines",
        "packet_rows_inspected",
        "ieee802154_frames",
        "other_packet_envelopes",
    }
    if (
        not isinstance(counts, dict)
        or set(counts) != count_keys
        or any(type(counts[key]) is not int or counts[key] < 0 for key in count_keys)
        or counts["packet_rows_inspected"]
        != counts["packet_envelopes"] + counts["packet_quarantines"]
        or counts["packet_envelopes"]
        != counts["ieee802154_frames"] + counts["other_packet_envelopes"]
        or completeness["state"] == "complete"
        and counts["packet_quarantines"] != 0
    ):
        raise EvaluationError("expectation", case_id)

    frame_mix = expectation["frame_type_version_mix"]
    if not isinstance(frame_mix, list):
        raise EvaluationError("expectation", case_id)
    frame_keys: list[tuple[int, int]] = []
    frame_total = 0
    for item in frame_mix:
        if (
            not isinstance(item, dict)
            or set(item) != {"frame_type", "frame_version", "frames"}
            or any(type(item[key]) is not int for key in item)
            or not 0 <= item["frame_type"] <= 7
            or not 0 <= item["frame_version"] <= 3
            or item["frames"] <= 0
        ):
            raise EvaluationError("expectation", case_id)
        frame_keys.append((item["frame_type"], item["frame_version"]))
        frame_total += item["frames"]
    if (
        frame_keys != sorted(set(frame_keys))
        or frame_total != counts["ieee802154_frames"]
    ):
        raise EvaluationError("expectation", case_id)

    if not isinstance(address_forms, dict) or set(address_forms) != {
        "destination",
        "source",
    }:
        raise EvaluationError("expectation", case_id)
    address_keys = {"absent_frames", "short_frames", "extended_frames"}
    for role in ("destination", "source"):
        coverage = address_forms[role]
        if (
            not isinstance(coverage, dict)
            or set(coverage) != address_keys
            or any(
                type(coverage[key]) is not int or coverage[key] < 0
                for key in address_keys
            )
            or sum(coverage.values()) != counts["ieee802154_frames"]
        ):
            raise EvaluationError("expectation", case_id)

    if (
        not isinstance(commands, dict)
        or set(commands) != {"present_frames", "unavailable_frames", "command_mix"}
        or type(commands["present_frames"]) is not int
        or type(commands["unavailable_frames"]) is not int
        or commands["present_frames"] < 0
        or commands["unavailable_frames"] < 0
        or commands["present_frames"] + commands["unavailable_frames"]
        != counts["ieee802154_frames"]
        or not isinstance(commands["command_mix"], list)
    ):
        raise EvaluationError("expectation", case_id)
    command_values = []
    command_total = 0
    for item in commands["command_mix"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"command", "frames"}
            or type(item["command"]) is not int
            or type(item["frames"]) is not int
            or not 0 <= item["command"] <= 255
            or item["frames"] <= 0
        ):
            raise EvaluationError("expectation", case_id)
        command_values.append(item["command"])
        command_total += item["frames"]
    if (
        command_values != sorted(set(command_values))
        or command_total != commands["present_frames"]
    ):
        raise EvaluationError("expectation", case_id)

    fcs_keys = {"valid_frames", "invalid_frames", "unavailable_frames"}
    if (
        not isinstance(fcs, dict)
        or set(fcs) != fcs_keys
        or any(type(fcs[key]) is not int or fcs[key] < 0 for key in fcs_keys)
        or sum(fcs.values()) != counts["ieee802154_frames"]
    ):
        raise EvaluationError("expectation", case_id)

    record_expectation = expectation.get(IEEE802154_RECORD_ORACLE_KEY)
    if record_expectation is not None and (
        not isinstance(record_expectation, dict)
        or set(record_expectation) != {"total_length_exceeds_frame"}
        or type(record_expectation["total_length_exceeds_frame"]) is not int
        or not 0
        <= record_expectation["total_length_exceeds_frame"]
        <= counts["packet_envelopes"]
    ):
        raise EvaluationError("expectation", case_id)


def contains_forbidden_ieee802154_key(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(IEEE802154_FORBIDDEN_KEYS & value.keys()) or any(
            contains_forbidden_ieee802154_key(item) for item in value.values()
        )
    if isinstance(value, list):
        return any(contains_forbidden_ieee802154_key(item) for item in value)
    return False


def read_bounded(path: Path, limit: int, stage: str) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            raise EvaluationError(stage)
        with path.open("rb") as source:
            data = source.read(limit + 1)
    except OSError:
        raise EvaluationError(stage) from None
    if len(data) > limit:
        raise EvaluationError(stage)
    return data


def digest_binary(path: Path) -> str:
    try:
        if path.is_symlink() or not path.is_file() or not os.access(path, os.X_OK):
            raise EvaluationError("binary")
        size = path.stat().st_size
        if not 0 < size <= MAX_BINARY_BYTES:
            raise EvaluationError("binary")
        digest = hashlib.sha256()
        read_bytes = 0
        with path.open("rb") as source:
            while chunk := source.read(MIB):
                read_bytes += len(chunk)
                if read_bytes > MAX_BINARY_BYTES:
                    raise EvaluationError("binary")
                digest.update(chunk)
    except OSError:
        raise EvaluationError("binary") from None
    if read_bytes != size:
        raise EvaluationError("binary_mutation")
    return digest.hexdigest()


def validate_manifest(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], str]:
    manifest_bytes = read_bounded(path, MAX_MANIFEST_BYTES, "manifest_read")
    manifest = strict_json(manifest_bytes, "manifest_json")
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "archives", "cases"}
        or manifest["schema"] != MANIFEST_SCHEMA
        or not isinstance(manifest["archives"], dict)
        or not isinstance(manifest["cases"], list)
        or not 1 <= len(manifest["cases"]) <= MAX_CASES
    ):
        raise EvaluationError("manifest_shape")
    archives = manifest["archives"]
    for key, archive in archives.items():
        archive_format = archive.get("format") if isinstance(archive, dict) else None
        expected_keys = {"filename", "bytes", "md5"}
        if archive_format == "file":
            expected_keys |= {"format", "sha256", "receipt"}
        if (
            not isinstance(key, str)
            or not isinstance(archive, dict)
            or set(archive) != expected_keys
            or not isinstance(archive["filename"], str)
            or Path(archive["filename"]).name != archive["filename"]
            or not isinstance(archive["bytes"], int)
            or archive["bytes"] <= 0
            or not is_hex(archive["md5"], MD5)
        ):
            raise EvaluationError("archive_manifest")
        if archive_format == "file":
            receipt = archive["receipt"]
            if (
                not is_hex(archive["sha256"], SHA256)
                or not isinstance(receipt, dict)
                or set(receipt) != {"filename", "bytes", "sha256"}
                or not isinstance(receipt["filename"], str)
                or Path(receipt["filename"]).name != receipt["filename"]
                or receipt["filename"] != f"{archive['filename']}.json"
                or type(receipt["bytes"]) is not int
                or not 0 < receipt["bytes"] <= MAX_RECEIPT_BYTES
                or not is_hex(receipt["sha256"], SHA256)
            ):
                raise EvaluationError("archive_manifest")
    total_bytes = 0
    case_ids: set[str] = set()
    for case in manifest["cases"]:
        if not isinstance(case, dict):
            raise EvaluationError("case_shape")
        case_id = case.get("id")
        mode = case.get("mode")
        expected_keys = {"archive", "expect", "id", "member", "mode"}
        if mode in {"netbraid-wlan", "netbraid-ieee802154"}:
            expected_keys.add("packet_limit")
            if mode == "netbraid-wlan" and "reference" in case:
                expected_keys.add("reference")
        if (
            set(case) != expected_keys
            or not isinstance(case_id, str)
            or not case_id
            or case_id in case_ids
            or case.get("archive") not in archives
            or mode not in {"netbraid-wlan", "netbraid-ieee802154", "structured-json"}
        ):
            raise EvaluationError("case_shape", case_id)
        case_ids.add(case_id)
        member = case["member"]
        if (
            not isinstance(member, dict)
            or set(member) != {"name", "bytes", "sha256"}
            or not isinstance(member["name"], str)
            or member["name"].startswith("/")
            or ".." in Path(member["name"]).parts
            or not isinstance(member["bytes"], int)
            or not 0 < member["bytes"] <= MAX_MEMBER_BYTES
            or not is_hex(member["sha256"], SHA256)
            or not isinstance(case["expect"], dict)
        ):
            raise EvaluationError("member_manifest", case_id)
        archive = archives[case["archive"]]
        if archive.get("format") == "file" and member != {
            "name": archive["filename"],
            "bytes": archive["bytes"],
            "sha256": archive["sha256"],
        }:
            raise EvaluationError("member_manifest", case_id)
        total_bytes += member["bytes"]
        reference = case.get("reference")
        if reference is not None:
            if (
                not isinstance(reference, dict)
                or set(reference) != {"format", "member"}
                or reference["format"]
                not in {"wifi-management-csv-v1", "sorbonne-rssi-tsv-v1"}
            ):
                raise EvaluationError("reference_manifest", case_id)
            reference_member = reference["member"]
            if (
                not isinstance(reference_member, dict)
                or set(reference_member) != {"name", "bytes", "sha256"}
                or not isinstance(reference_member["name"], str)
                or reference_member["name"].startswith("/")
                or ".." in Path(reference_member["name"]).parts
                or not isinstance(reference_member["bytes"], int)
                or not 0 < reference_member["bytes"] <= MAX_MEMBER_BYTES
                or not is_hex(reference_member["sha256"], SHA256)
            ):
                raise EvaluationError("reference_manifest", case_id)
            total_bytes += reference_member["bytes"]
        if total_bytes > MAX_TOTAL_MEMBER_BYTES:
            raise EvaluationError("total_member_bytes")
        if mode in {"netbraid-wlan", "netbraid-ieee802154"} and (
            not isinstance(case["packet_limit"], int)
            or not 1 <= case["packet_limit"] <= 100_000
        ):
            raise EvaluationError("expectation", case_id)
        if mode == "netbraid-wlan":
            expectation = case["expect"]
            if (
                set(expectation) != {"reason", "scope", "status"}
                or expectation["status"]
                not in {"observed", "unsupported", "insufficient"}
                or not isinstance(expectation["scope"], str)
                or expectation["reason"] is not None
                and not isinstance(expectation["reason"], str)
            ):
                raise EvaluationError("expectation", case_id)
        elif mode == "netbraid-ieee802154":
            validate_ieee802154_oracle(case["expect"], case["packet_limit"], case_id)
        elif set(case["expect"]) != {"top_level_keys"} or not all(
            isinstance(key, str) for key in case["expect"]["top_level_keys"]
        ):
            raise EvaluationError("expectation", case_id)
    return archives, manifest["cases"], hashlib.sha256(manifest_bytes).hexdigest()


def validate_external_file_receipt(path: Path, expected: dict[str, Any]) -> None:
    receipt_spec = expected["receipt"]
    receipt_path = path.parent / receipt_spec["filename"]
    receipt_bytes = read_bounded(
        receipt_path, MAX_RECEIPT_BYTES, "archive_receipt_verification"
    )
    if (
        len(receipt_bytes) != receipt_spec["bytes"]
        or hashlib.sha256(receipt_bytes).hexdigest() != receipt_spec["sha256"]
    ):
        raise EvaluationError("archive_receipt_verification")
    receipt = strict_json(receipt_bytes, "archive_receipt_verification")
    if (
        not isinstance(receipt, dict)
        or set(receipt) != {"archive", "bytes", "md5", "schema", "sha256", "source"}
        or receipt["schema"] != PUBLIC_ARCHIVE_RECEIPT_SCHEMA
        or receipt["archive"] != expected["filename"]
        or receipt["bytes"] != expected["bytes"]
        or receipt["md5"] != expected["md5"]
        or receipt["sha256"] != expected["sha256"]
        or not isinstance(receipt["source"], dict)
        or receipt["source"].get("filename") != expected["filename"]
        or receipt["source"].get("format") != "file"
        or receipt["source"].get("bytes") != expected["bytes"]
        or receipt["source"].get("md5") != expected["md5"]
    ):
        raise EvaluationError("archive_receipt_verification")


def digest_archive(path: Path, expected: dict[str, Any]) -> None:
    try:
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size != expected["bytes"]
        ):
            raise EvaluationError("archive_verification")
        digest = hashlib.md5(usedforsecurity=False)
        size = 0
        with path.open("rb") as source:
            while chunk := source.read(MIB):
                size += len(chunk)
                digest.update(chunk)
    except OSError:
        raise EvaluationError("archive_verification") from None
    if size != expected["bytes"] or digest.hexdigest() != expected["md5"]:
        raise EvaluationError("archive_verification")
    if expected.get("format") == "file":
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(MIB):
                digest.update(chunk)
        if digest.hexdigest() != expected["sha256"]:
            raise EvaluationError("archive_verification")
        validate_external_file_receipt(path, expected)


def extract_member(
    archive_path: Path, member_spec: dict[str, Any], destination: Path, case_id: str
) -> bytes:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            member = archive.getinfo(member_spec["name"])
            mode = member.external_attr >> 16
            if (
                member.is_dir()
                or stat.S_ISLNK(mode)
                or member.file_size != member_spec["bytes"]
                or member.file_size > MAX_MEMBER_BYTES
            ):
                raise EvaluationError("member_verification", case_id)
            digest = hashlib.sha256()
            size = 0
            with archive.open(member) as source, destination.open("xb") as output:
                while chunk := source.read(MIB):
                    size += len(chunk)
                    if size > member_spec["bytes"]:
                        raise EvaluationError("member_verification", case_id)
                    digest.update(chunk)
                    output.write(chunk)
    except EvaluationError:
        raise
    except (KeyError, OSError, zipfile.BadZipFile):
        raise EvaluationError("member_verification", case_id) from None
    if size != member_spec["bytes"] or digest.hexdigest() != member_spec["sha256"]:
        raise EvaluationError("member_verification", case_id)
    return destination.read_bytes()


def extract_external_file(
    source: Path, member_spec: dict[str, Any], destination: Path, case_id: str
) -> bytes:
    data = read_bounded(source, MAX_MEMBER_BYTES, "member_verification")
    if (
        len(data) != member_spec["bytes"]
        or hashlib.sha256(data).hexdigest() != member_spec["sha256"]
    ):
        raise EvaluationError("member_verification", case_id)
    try:
        with destination.open("xb") as output:
            output.write(data)
    except OSError:
        raise EvaluationError("member_verification", case_id) from None
    return data


def batch_requests_jsonl(
    cases: list[ExtractedCase], request_case_ids: list[str] | None = None
) -> bytes:
    if request_case_ids is None:
        request_case_ids = [extracted.case["id"] for extracted in cases]
    if len(request_case_ids) != len(cases):
        raise EvaluationError("batch_request_identity")
    output = bytearray()
    for extracted, request_case_id in zip(cases, request_case_ids):
        request = {
            "case_id": request_case_id,
            "path": os.fspath(extracted.capture_path),
            "packet_limit": extracted.case["packet_limit"],
        }
        output.extend(
            json.dumps(request, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )
        output.extend(b"\n")
    return bytes(output)


def run_batch_driver(binary: Path, requests: bytes) -> bytes:
    argv = [os.fspath(binary), "pcap-batch-wlan-fingerprint-jsonl"]
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            input=requests,
            timeout=TOOL_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise EvaluationError("batch_driver_execution") from None
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout) > MAX_TOOL_OUTPUT_BYTES
    ):
        raise EvaluationError("batch_driver_execution")
    return completed.stdout


def parse_batch_output(
    data: bytes, expected_case_ids: list[str]
) -> list[dict[str, Any]]:
    if not data.endswith(b"\n"):
        raise EvaluationError("batch_output_shape")
    lines = data.splitlines()
    if len(lines) != len(expected_case_ids):
        raise EvaluationError("batch_output_identity")
    fingerprints = []
    for line, expected_case_id in zip(lines, expected_case_ids):
        output = strict_json(line, "batch_output_json", expected_case_id)
        if (
            not isinstance(output, dict)
            or set(output) != {"case_id", "fingerprint"}
            or output["case_id"] != expected_case_id
            or not isinstance(output["fingerprint"], dict)
        ):
            raise EvaluationError("batch_output_identity", expected_case_id)
        fingerprints.append(output["fingerprint"])
    return fingerprints


def run_ieee802154_driver(binary: Path, extracted: ExtractedCase) -> bytes:
    case = extracted.case
    case_id = case["id"]
    argv = [
        os.fspath(binary),
        "pcap",
        os.fspath(extracted.capture_path),
        "--packet-limit",
        str(case["packet_limit"]),
        "--ieee802154-json",
    ]
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            timeout=TOOL_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise EvaluationError("ieee802154_driver_execution", case_id) from None
    if (
        completed.returncode != 0
        or completed.stderr
        or not completed.stdout
        or len(completed.stdout) > MAX_TOOL_OUTPUT_BYTES
    ):
        raise EvaluationError("ieee802154_driver_execution", case_id)
    return completed.stdout


def run_ieee802154_records_driver(binary: Path, extracted: ExtractedCase) -> bytes:
    case = extracted.case
    case_id = case["id"]
    argv = [
        os.fspath(binary),
        "pcap",
        os.fspath(extracted.capture_path),
        "--packet-limit",
        str(case["packet_limit"]),
        "--records-jsonl",
    ]
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            timeout=TOOL_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise EvaluationError("ieee802154_records_execution", case_id) from None
    if (
        completed.returncode != 0
        or completed.stderr
        or not completed.stdout
        or len(completed.stdout) > MAX_TOOL_OUTPUT_BYTES
    ):
        raise EvaluationError("ieee802154_records_execution", case_id)
    return completed.stdout


def parse_ieee802154_output(data: bytes, extracted: ExtractedCase) -> dict[str, Any]:
    case = extracted.case
    case_id = case["id"]
    if not data.endswith(b"\n") or len(data.splitlines()) != 1:
        raise EvaluationError("ieee802154_output_shape", case_id)
    document = strict_json(data, "ieee802154_output_json", case_id)
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "schema",
            "source",
            "completeness",
            "counts",
            "frame_type_version_mix",
            "address_forms",
            "commands",
            "fcs",
            "limitations",
        }
        or document["schema"] != IEEE802154_PROJECTION_SCHEMA
        or document["limitations"] != IEEE802154_LIMITATIONS
        or contains_forbidden_ieee802154_key(document)
    ):
        raise EvaluationError("ieee802154_output_shape", case_id)
    source = document["source"]
    if not isinstance(source, dict) or set(source) != {
        "artifact",
        "extractor",
        "normalized_records_sha256",
    }:
        raise EvaluationError("ieee802154_source", case_id)
    artifact = source["artifact"]
    extractor = source["extractor"]
    if (
        not isinstance(artifact, dict)
        or set(artifact) != {"content_sha256", "size_bytes"}
        or artifact["content_sha256"] != f"sha256:{case['member']['sha256']}"
        or artifact["size_bytes"] != case["member"]["bytes"]
        or not isinstance(extractor, dict)
        or set(extractor)
        != {
            "adapter",
            "adapter_version",
            "tool",
            "tool_version",
            "configuration_sha256",
            "field_registry",
        }
        or any(not isinstance(value, str) or not value for value in extractor.values())
        or not is_sha256_digest(extractor["configuration_sha256"])
        or not is_sha256_digest(source["normalized_records_sha256"])
    ):
        raise EvaluationError("ieee802154_source", case_id)
    canonical = (
        json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    if data != canonical:
        raise EvaluationError("ieee802154_output_canonical", case_id)
    return document


def parse_ieee802154_records_output(
    data: bytes, extracted: ExtractedCase
) -> dict[str, Any]:
    case = extracted.case
    case_id = case["id"]
    if not data.endswith(b"\n"):
        raise EvaluationError("ieee802154_records_shape", case_id)
    lines = data.splitlines()
    if len(lines) < 2:
        raise EvaluationError("ieee802154_records_shape", case_id)
    documents = [
        strict_json(line, "ieee802154_records_json", case_id) for line in lines
    ]
    canonical = b"".join(
        json.dumps(document, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
        for document in documents
    )
    if data != canonical:
        raise EvaluationError("ieee802154_records_canonical", case_id)

    manifest = documents[0]
    expected_capture_id = f"sha256:{case['member']['sha256']}"
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != CAPTURE_MANIFEST_SCHEMA
        or manifest.get("capture_id") != expected_capture_id
        or manifest.get("artifact")
        != {
            "content_sha256": expected_capture_id,
            "size_bytes": case["member"]["bytes"],
        }
    ):
        raise EvaluationError("ieee802154_records_source", case_id)

    packet_envelopes = 0
    packet_quarantines = 0
    length_exceeds_frame = 0
    for document in documents[1:]:
        if not isinstance(document, dict):
            raise EvaluationError("ieee802154_records_shape", case_id)
        schema = document.get("schema")
        if schema == PACKET_QUARANTINE_SCHEMA:
            if document.get("capture_id") != expected_capture_id:
                raise EvaluationError("ieee802154_records_source", case_id)
            packet_quarantines += 1
            continue
        if schema != PACKET_ENVELOPE_SCHEMA:
            raise EvaluationError("ieee802154_records_shape", case_id)
        if document.get("capture_id") != expected_capture_id:
            raise EvaluationError("ieee802154_records_source", case_id)
        packet_envelopes += 1
        frame = document.get("frame")
        if not isinstance(frame, dict):
            raise EvaluationError("ieee802154_records_shape", case_id)
        protocols = frame.get("protocols", [])
        original_length = frame.get("original_len")
        if (
            not isinstance(protocols, list)
            or any(not isinstance(protocol, str) for protocol in protocols)
            or type(original_length) is not int
            or original_length < 0
        ):
            raise EvaluationError("ieee802154_records_shape", case_id)
        sixlowpan_decoded_ipv6 = any(
            left == "6lowpan" and right == "ipv6"
            for left, right in zip(protocols, protocols[1:])
        )
        ipv6 = document.get("ipv6")
        if sixlowpan_decoded_ipv6 and isinstance(ipv6, dict):
            total_length = ipv6.get("total_length_octets")
            if type(total_length) is int and total_length > original_length:
                length_exceeds_frame += 1

    return {
        "packet_envelopes": packet_envelopes,
        "packet_quarantines": packet_quarantines,
        IEEE802154_RECORD_ORACLE_KEY: {
            "total_length_exceeds_frame": length_exceeds_frame
        },
    }


def require_preserved_inputs(cases: list[ExtractedCase]) -> None:
    for extracted in cases:
        try:
            observed = extracted.capture_path.read_bytes()
        except OSError:
            raise EvaluationError("input_preservation", extracted.case["id"]) from None
        if observed != extracted.capture_bytes:
            raise EvaluationError("input_preservation", extracted.case["id"])


def netbraid_git_revision() -> str:
    try:
        revision_result = subprocess.run(
            ["git", "-C", os.fspath(ROOT), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        status_result = subprocess.run(
            [
                "git",
                "-C",
                os.fspath(ROOT),
                "status",
                "--porcelain=v1",
                "--untracked-files=no",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise EvaluationError("git_revision") from None
    revision = revision_result.stdout.strip()
    if (
        revision_result.returncode != 0
        or revision_result.stderr
        or status_result.returncode != 0
        or status_result.stderr
        or status_result.stdout
        or len(revision) != 40
        or any(character not in "0123456789abcdef" for character in revision)
    ):
        raise EvaluationError("git_revision")
    return revision


def reconcile_wifi_management_csv(
    reference_bytes: bytes, basis: Any, case_id: str
) -> tuple[bool, dict[str, Any]]:
    if not isinstance(basis, dict):
        raise EvaluationError("netbraid_reference_shape", case_id)
    expected_fields = [
        "Timestamp",
        "type",
        "MAC_timestamp",
        "rssi",
        "addr1",
        "addr2",
        "addr3",
        "SSID",
    ]
    type_map = {
        "Dot11ProbeReq": (0, 4),
        "Dot11ProbeResp": (0, 5),
        "Dot11Beacon": (0, 8),
    }
    try:
        text = reference_bytes.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text, newline=""))
        if reader.fieldnames != expected_fields:
            raise EvaluationError("reference_shape", case_id)
        reference_mix: dict[tuple[int, int], int] = {}
        rows = 0
        for row in reader:
            if set(row) != set(expected_fields) or any(
                value is None for value in row.values()
            ):
                raise EvaluationError("reference_shape", case_id)
            frame = type_map.get(row["type"])
            if frame is None:
                raise EvaluationError("reference_frame_type", case_id)
            rows += 1
            if rows > 100_000:
                raise EvaluationError("reference_rows", case_id)
            reference_mix[frame] = reference_mix.get(frame, 0) + 1
    except UnicodeDecodeError:
        raise EvaluationError("reference_encoding", case_id) from None

    observed_mix: dict[tuple[int, int], int] = {}
    frame_mix = basis.get("frame_mix")
    if not isinstance(frame_mix, list):
        raise EvaluationError("netbraid_reference_shape", case_id)
    for item in frame_mix:
        if (
            not isinstance(item, dict)
            or set(item) != {"frame_type", "frame_subtype", "frames"}
            or not all(isinstance(item[key], int) for key in item)
        ):
            raise EvaluationError("netbraid_reference_shape", case_id)
        key = (item["frame_type"], item["frame_subtype"])
        if key in observed_mix:
            raise EvaluationError("netbraid_reference_shape", case_id)
        observed_mix[key] = item["frames"]
    wlan_frames = basis.get("wlan_frames")
    if not isinstance(wlan_frames, int):
        raise EvaluationError("netbraid_reference_shape", case_id)

    frame_keys = sorted(reference_mix.keys() | observed_mix.keys())
    deltas = [
        {
            "frame_type": frame_type,
            "frame_subtype": frame_subtype,
            "reference_frames": reference_mix.get((frame_type, frame_subtype), 0),
            "normalized_frames": observed_mix.get((frame_type, frame_subtype), 0),
            "absolute_delta": abs(
                reference_mix.get((frame_type, frame_subtype), 0)
                - observed_mix.get((frame_type, frame_subtype), 0)
            ),
        }
        for frame_type, frame_subtype in frame_keys
    ]
    total_delta = abs(rows - wlan_frames)
    passed = total_delta == 0 and all(item["absolute_delta"] == 0 for item in deltas)
    return passed, {
        "format": "wifi-management-csv-v1",
        "reference_rows": rows,
        "normalized_frames": wlan_frames,
        "absolute_count_delta": total_delta,
        "frame_mix": deltas,
    }


def reconcile_sorbonne_rssi_tsv(
    reference_bytes: bytes, basis: Any, case_id: str
) -> tuple[bool, dict[str, Any]]:
    if not isinstance(basis, dict):
        raise EvaluationError("netbraid_reference_shape", case_id)
    expected_fields = [
        "Frame_number",
        "Frame_time_epoch",
        "RSSI_dBm",
        "Channel",
        "Frame_type",
        "Frame_subtype",
        "Retransmission",
        "Source_MAC_address",
        "Sequence_number",
    ]
    try:
        text = reference_bytes.decode("utf-8")
        reader = csv.DictReader(io.StringIO(text, newline=""), delimiter="\t")
        if reader.fieldnames != expected_fields:
            raise EvaluationError("reference_shape", case_id)
        reference_mix: dict[tuple[int, int], int] = {}
        reference_channels: dict[int, int] = {}
        signal_values: list[int] = []
        rows = 0
        for row in reader:
            if set(row) != set(expected_fields) or any(
                value is None for value in row.values()
            ):
                raise EvaluationError("reference_shape", case_id)
            frame = (int(row["Frame_type"]), int(row["Frame_subtype"]))
            channel = int(row["Channel"])
            signal = int(row["RSSI_dBm"])
            rows += 1
            if rows > 100_000:
                raise EvaluationError("reference_rows", case_id)
            reference_mix[frame] = reference_mix.get(frame, 0) + 1
            reference_channels[channel] = reference_channels.get(channel, 0) + 1
            signal_values.append(signal)
    except UnicodeDecodeError:
        raise EvaluationError("reference_encoding", case_id) from None
    except ValueError:
        raise EvaluationError("reference_value", case_id) from None
    if not signal_values:
        raise EvaluationError("reference_rows", case_id)

    frame_mix = basis.get("frame_mix")
    channels = basis.get("channels")
    signal_dbm = basis.get("signal_dbm")
    wlan_frames = basis.get("wlan_frames")
    if (
        not isinstance(frame_mix, list)
        or not isinstance(channels, list)
        or not isinstance(signal_dbm, dict)
        or not isinstance(wlan_frames, int)
    ):
        raise EvaluationError("netbraid_reference_shape", case_id)
    observed_mix: dict[tuple[int, int], int] = {}
    for item in frame_mix:
        if (
            not isinstance(item, dict)
            or set(item) != {"frame_type", "frame_subtype", "frames"}
            or any(type(item[key]) is not int for key in item)
            or item["frames"] <= 0
        ):
            raise EvaluationError("netbraid_reference_shape", case_id)
        key = (item["frame_type"], item["frame_subtype"])
        if key in observed_mix:
            raise EvaluationError("netbraid_reference_shape", case_id)
        observed_mix[key] = item["frames"]
    observed_channels: dict[int, int] = {}
    for item in channels:
        if (
            not isinstance(item, dict)
            or set(item) != {"value", "frames"}
            or any(type(item[key]) is not int for key in item)
            or item["frames"] <= 0
            or item["value"] in observed_channels
        ):
            raise EvaluationError("netbraid_reference_shape", case_id)
        observed_channels[item["value"]] = item["frames"]
    signal_keys = {"samples", "sum_dbm", "minimum_dbm", "maximum_dbm"}
    if set(signal_dbm) != signal_keys or any(
        type(signal_dbm[key]) is not int for key in signal_keys
    ):
        raise EvaluationError("netbraid_reference_shape", case_id)
    observed_signal = {key: signal_dbm[key] for key in signal_keys}
    reference_signal = {
        "samples": rows,
        "sum_dbm": sum(signal_values),
        "minimum_dbm": min(signal_values),
        "maximum_dbm": max(signal_values),
    }
    passed = (
        rows == wlan_frames
        and reference_mix == observed_mix
        and reference_channels == observed_channels
        and reference_signal == observed_signal
    )
    return passed, {
        "format": "sorbonne-rssi-tsv-v1",
        "reference_rows": rows,
        "normalized_frames": wlan_frames,
        "absolute_count_delta": abs(rows - wlan_frames),
        "frame_mix_match": reference_mix == observed_mix,
        "channel_mix_match": reference_channels == observed_channels,
        "signal_summary_match": reference_signal == observed_signal,
        "reference_signal_dbm": reference_signal,
    }


def extract_case(
    case: dict[str, Any],
    archive: dict[str, Any],
    archive_path: Path,
    temporary: Path,
) -> ExtractedCase:
    case_id = case["id"]
    capture_path = temporary / "capture"
    if archive.get("format") == "file":
        capture_bytes = extract_external_file(
            archive_path, case["member"], capture_path, case_id
        )
    else:
        capture_bytes = extract_member(
            archive_path, case["member"], capture_path, case_id
        )
    reference_bytes = None
    if "reference" in case:
        reference_bytes = extract_member(
            archive_path,
            case["reference"]["member"],
            temporary / "reference",
            case_id,
        )
    return ExtractedCase(case, capture_path, capture_bytes, reference_bytes)


def evaluate_structured_case(
    extracted: ExtractedCase,
) -> tuple[bool, dict[str, Any]]:
    case = extracted.case
    case_id = case["id"]
    document = strict_json(extracted.capture_bytes, "structured_json", case_id)
    observed_keys = sorted(document) if isinstance(document, dict) else []
    expected_keys = sorted(case["expect"]["top_level_keys"])
    passed = observed_keys == expected_keys
    return passed, {
        "case": case_id,
        "input_bytes": len(extracted.capture_bytes),
        "mode": case["mode"],
        "result": "pass" if passed else "expectation_failure",
        "status": "structured_only",
        "top_level_key_count": len(observed_keys),
    }


def evaluate_packet_case(
    extracted: ExtractedCase, document: dict[str, Any]
) -> tuple[bool, dict[str, Any]]:
    case = extracted.case
    case_id = case["id"]
    result: dict[str, Any] = {
        "case": case_id,
        "input_bytes": len(extracted.capture_bytes),
        "mode": case["mode"],
    }
    try:
        status = document["status"]
        observed = {
            "reason": status.get("reason"),
            "scope": document["scope"],
            "status": status["status"],
        }
        capture_id = document["source"]["capture_id"]
    except (KeyError, TypeError, AttributeError):
        raise EvaluationError("netbraid_shape", case_id) from None
    if capture_id != f"sha256:{case['member']['sha256']}":
        raise EvaluationError("capture_identity", case_id)
    passed = observed == case["expect"]
    result.update(observed)
    result["result"] = "pass" if passed else "expectation_failure"
    if isinstance(status.get("normalized_packets"), int):
        result["normalized_packets"] = status["normalized_packets"]
    basis = status.get("basis")
    if isinstance(basis, dict) and isinstance(basis.get("wlan_frames"), int):
        result["wlan_frames"] = basis["wlan_frames"]
    reference = case.get("reference")
    if reference is not None:
        if extracted.reference_bytes is None:
            raise EvaluationError("reference_missing", case_id)
        if reference["format"] == "wifi-management-csv-v1":
            reference_passed, reconciliation = reconcile_wifi_management_csv(
                extracted.reference_bytes, basis, case_id
            )
        else:
            reference_passed, reconciliation = reconcile_sorbonne_rssi_tsv(
                extracted.reference_bytes, basis, case_id
            )
        passed = passed and reference_passed
        result["reference_reconciliation"] = reconciliation
        result["result"] = "pass" if passed else "expectation_failure"
    return passed, result


def evaluate_ieee802154_case(
    extracted: ExtractedCase,
    document: dict[str, Any],
    records: dict[str, Any] | None,
) -> tuple[bool, dict[str, Any]]:
    case = extracted.case
    case_id = case["id"]
    observed = {key: document[key] for key in IEEE802154_BASE_ORACLE_KEYS}
    if IEEE802154_RECORD_ORACLE_KEY in case["expect"]:
        if records is None:
            raise EvaluationError("ieee802154_records_missing", case_id)
        counts = document["counts"]
        if (
            records["packet_envelopes"] != counts["packet_envelopes"]
            or records["packet_quarantines"] != counts["packet_quarantines"]
        ):
            raise EvaluationError("ieee802154_records_consistency", case_id)
        observed[IEEE802154_RECORD_ORACLE_KEY] = records[IEEE802154_RECORD_ORACLE_KEY]
    passed = observed == case["expect"]
    counts = document["counts"]
    result = {
        "case": case_id,
        "input_bytes": len(extracted.capture_bytes),
        "mode": case["mode"],
        "result": "pass" if passed else "expectation_failure",
        "status": "projected",
        "scope": document["completeness"]["scope"],
        "normalized_packets": counts["packet_envelopes"],
        "packet_quarantines": counts["packet_quarantines"],
        "ieee802154_frames": counts["ieee802154_frames"],
        "identity_inference": "not_performed",
    }
    if records is not None:
        result[IEEE802154_RECORD_ORACLE_KEY] = records[IEEE802154_RECORD_ORACLE_KEY]
    return passed, result


def evaluate(
    manifest: Path,
    archive_dir: Path,
    binary: Path,
    case_workers: int,
) -> tuple[int, dict[str, Any]]:
    if case_workers <= 0:
        raise EvaluationError("case_workers")
    revision = netbraid_git_revision()
    archives, cases, manifest_sha256 = validate_manifest(manifest)
    binary_sha256 = digest_binary(binary)
    used_archives = {case["archive"] for case in cases}
    archive_paths = {}
    for key in sorted(used_archives):
        path = archive_dir / archives[key]["filename"]
        digest_archive(path, archives[key])
        archive_paths[key] = path
    results = []
    failures = 0
    with tempfile.TemporaryDirectory(prefix="netbraid-public-corpus-") as directory:
        temporary = Path(directory)
        case_directories = []
        for index in range(len(cases)):
            case_directory = temporary / f"case-{index}"
            case_directory.mkdir()
            case_directories.append(case_directory)
        with ThreadPoolExecutor(max_workers=min(case_workers, len(cases))) as executor:
            futures = [
                executor.submit(
                    extract_case,
                    case,
                    archives[case["archive"]],
                    archive_paths[case["archive"]],
                    case_directory,
                )
                for case, case_directory in zip(cases, case_directories)
            ]
        extracted_cases = [future.result() for future in futures]
        packet_cases = [
            extracted
            for extracted in extracted_cases
            if extracted.case["mode"] == "netbraid-wlan"
        ]
        fingerprints_by_case = {}
        if packet_cases:
            packet_case_ids = [extracted.case["id"] for extracted in packet_cases]
            request_case_ids = []
            combined_cases = []
            for index, packet_case in enumerate(packet_cases):
                request_case_ids.extend((f"first-{index}", f"second-{index}"))
                combined_cases.extend((packet_case, packet_case))
            combined_bytes = run_batch_driver(
                binary, batch_requests_jsonl(combined_cases, request_case_ids)
            )
            combined = parse_batch_output(combined_bytes, request_case_ids)
            first = combined[::2]
            second = combined[1::2]
            if first != second:
                raise EvaluationError("batch_output_determinism")
            fingerprints_by_case = dict(zip(packet_case_ids, first))
        ieee802154_cases = [
            extracted
            for extracted in extracted_cases
            if extracted.case["mode"] == "netbraid-ieee802154"
        ]
        ieee802154_by_case = {}
        ieee802154_records_by_case = {}
        if ieee802154_cases:
            with ThreadPoolExecutor(
                max_workers=min(case_workers, len(ieee802154_cases) * 2)
            ) as executor:
                executions = [
                    (
                        extracted,
                        executor.submit(run_ieee802154_driver, binary, extracted),
                        executor.submit(run_ieee802154_driver, binary, extracted),
                    )
                    for extracted in ieee802154_cases
                ]
                for extracted, first_execution, second_execution in executions:
                    first = first_execution.result()
                    second = second_execution.result()
                    if first != second:
                        raise EvaluationError(
                            "ieee802154_output_determinism", extracted.case["id"]
                        )
                    ieee802154_by_case[extracted.case["id"]] = parse_ieee802154_output(
                        first, extracted
                    )
            record_cases = [
                extracted
                for extracted in ieee802154_cases
                if IEEE802154_RECORD_ORACLE_KEY in extracted.case["expect"]
            ]
            with ThreadPoolExecutor(
                max_workers=min(case_workers, max(1, len(record_cases) * 2))
            ) as executor:
                record_executions = [
                    (
                        extracted,
                        executor.submit(
                            run_ieee802154_records_driver, binary, extracted
                        ),
                        executor.submit(
                            run_ieee802154_records_driver, binary, extracted
                        ),
                    )
                    for extracted in record_cases
                ]
                for extracted, first_execution, second_execution in record_executions:
                    first = first_execution.result()
                    second = second_execution.result()
                    if first != second:
                        raise EvaluationError(
                            "ieee802154_records_determinism", extracted.case["id"]
                        )
                    ieee802154_records_by_case[extracted.case["id"]] = (
                        parse_ieee802154_records_output(first, extracted)
                    )
        require_preserved_inputs(extracted_cases)

        for extracted in extracted_cases:
            if extracted.case["mode"] == "structured-json":
                passed, result = evaluate_structured_case(extracted)
            elif extracted.case["mode"] == "netbraid-wlan":
                passed, result = evaluate_packet_case(
                    extracted, fingerprints_by_case[extracted.case["id"]]
                )
            else:
                passed, result = evaluate_ieee802154_case(
                    extracted,
                    ieee802154_by_case[extracted.case["id"]],
                    ieee802154_records_by_case.get(extracted.case["id"]),
                )
            failures += not passed
            results.append(result)
    if digest_binary(binary) != binary_sha256:
        raise EvaluationError("binary_mutation")
    report = {
        "schema": REPORT_SCHEMA,
        "manifest_sha256": manifest_sha256,
        "netbraid_binary_sha256": binary_sha256,
        "netbraid_git_sha": revision,
        "status": "pass" if failures == 0 else "expectation_failure",
        "archives": len(used_archives),
        "cases": len(cases),
        "expectation_failures": failures,
        "limits": {
            "max_cases": MAX_CASES,
            "max_member_bytes": MAX_MEMBER_BYTES,
            "max_total_member_bytes": MAX_TOTAL_MEMBER_BYTES,
            "tool_timeout_s": TOOL_TIMEOUT_S,
        },
        "results": results,
    }
    return (0 if failures == 0 else 1), report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--archive-dir", type=Path, default=ROOT / "data" / "raw")
    parser.add_argument(
        "--netbraid", type=Path, default=ROOT / "rust/target/debug/netbraid"
    )
    parser.add_argument(
        "--case-workers",
        type=int,
        default=min(4, os.cpu_count() or 1),
        help="parallel evaluation cases (default: up to 4)",
    )
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        code, report = evaluate(
            args.manifest.resolve(),
            args.archive_dir.resolve(),
            args.netbraid.resolve(),
            args.case_workers,
        )
    except EvaluationError as error:
        detail: dict[str, Any] = {"stage": error.stage}
        if error.case is not None:
            detail["case"] = error.case
        code = 2
        report = {"schema": REPORT_SCHEMA, "status": "error", "error": detail}
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        args.report.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
