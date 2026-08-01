#!/usr/bin/env python3
"""Evaluate bounded public-corpus slices without admitting their bytes to Git."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

MIB = 1024 * 1024
MANIFEST_SCHEMA = "netbraid.public_corpus_slices.v0"
REPORT_SCHEMA = "netbraid.public_corpus_eval.v0"
MAX_MANIFEST_BYTES = MIB
MAX_CASES = 64
MAX_MEMBER_BYTES = 16 * MIB
MAX_TOTAL_MEMBER_BYTES = 64 * MIB
MAX_TOOL_OUTPUT_BYTES = 4 * MIB
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


def validate_manifest(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    manifest = strict_json(
        read_bounded(path, MAX_MANIFEST_BYTES, "manifest_read"), "manifest_json"
    )
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
        if (
            not isinstance(key, str)
            or not isinstance(archive, dict)
            or set(archive) != {"filename", "bytes", "md5"}
            or not isinstance(archive["filename"], str)
            or Path(archive["filename"]).name != archive["filename"]
            or not isinstance(archive["bytes"], int)
            or archive["bytes"] <= 0
            or not is_hex(archive["md5"], MD5)
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
        if mode == "netbraid-wlan":
            expected_keys.add("packet_limit")
        if (
            set(case) != expected_keys
            or not isinstance(case_id, str)
            or not case_id
            or case_id in case_ids
            or case.get("archive") not in archives
            or mode not in {"netbraid-wlan", "structured-json"}
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
        total_bytes += member["bytes"]
        if total_bytes > MAX_TOTAL_MEMBER_BYTES:
            raise EvaluationError("total_member_bytes")
        if mode == "netbraid-wlan":
            expectation = case["expect"]
            if (
                set(expectation) != {"reason", "scope", "status"}
                or expectation["status"]
                not in {"observed", "unsupported", "insufficient"}
                or not isinstance(expectation["scope"], str)
                or expectation["reason"] is not None
                and not isinstance(expectation["reason"], str)
                or not isinstance(case["packet_limit"], int)
                or not 1 <= case["packet_limit"] <= 100_000
            ):
                raise EvaluationError("expectation", case_id)
        elif set(case["expect"]) != {"top_level_keys"} or not all(
            isinstance(key, str) for key in case["expect"]["top_level_keys"]
        ):
            raise EvaluationError("expectation", case_id)
    return archives, manifest["cases"]


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


def run_netbraid(binary: Path, capture: Path, packet_limit: int, case_id: str) -> bytes:
    argv = [
        os.fspath(binary),
        "pcap",
        os.fspath(capture),
        "--wlan-fingerprint-json",
        "--packet-limit",
        str(packet_limit),
        "--max-input-mib",
        "16",
        "--max-output-mib",
        "128",
        "--timeout-seconds",
        "60",
    ]
    try:
        completed = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            timeout=TOOL_TIMEOUT_S,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise EvaluationError("netbraid_execution", case_id) from None
    if (
        completed.returncode != 0
        or completed.stderr
        or len(completed.stdout) > MAX_TOOL_OUTPUT_BYTES
    ):
        raise EvaluationError("netbraid_execution", case_id)
    return completed.stdout


def evaluate_case(
    case: dict[str, Any], archive_path: Path, binary: Path, temporary: Path
) -> tuple[bool, dict[str, Any]]:
    case_id = case["id"]
    member_path = temporary / f"case-{len(list(temporary.iterdir()))}"
    source_bytes = extract_member(archive_path, case["member"], member_path, case_id)
    result: dict[str, Any] = {
        "case": case_id,
        "input_bytes": len(source_bytes),
        "mode": case["mode"],
    }
    if case["mode"] == "structured-json":
        document = strict_json(source_bytes, "structured_json", case_id)
        observed_keys = sorted(document) if isinstance(document, dict) else []
        expected_keys = sorted(case["expect"]["top_level_keys"])
        passed = observed_keys == expected_keys
        result.update(
            {
                "result": "pass" if passed else "expectation_failure",
                "status": "structured_only",
                "top_level_key_count": len(observed_keys),
            }
        )
        return passed, result

    first = run_netbraid(binary, member_path, case["packet_limit"], case_id)
    second = run_netbraid(binary, member_path, case["packet_limit"], case_id)
    if first != second or member_path.read_bytes() != source_bytes:
        raise EvaluationError("determinism_or_input_mutation", case_id)
    document = strict_json(first, "netbraid_json", case_id)
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
    return passed, result


def evaluate(
    manifest: Path, archive_dir: Path, binary: Path
) -> tuple[int, dict[str, Any]]:
    archives, cases = validate_manifest(manifest)
    if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise EvaluationError("binary")
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
        for case in cases:
            passed, result = evaluate_case(
                case, archive_paths[case["archive"]], binary, temporary
            )
            failures += not passed
            results.append(result)
    report = {
        "schema": REPORT_SCHEMA,
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
    parser.add_argument("--archive-dir", type=Path, default=ROOT / "eval-data")
    parser.add_argument(
        "--netbraid", type=Path, default=ROOT / "rust/target/debug/netbraid"
    )
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        code, report = evaluate(
            args.manifest.resolve(), args.archive_dir.resolve(), args.netbraid.resolve()
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
