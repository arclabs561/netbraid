#!/usr/bin/env python3
"""Run and verify the complete IoT-23 packet-flow lineage campaign.

Raw corpus bytes and generated outputs remain outside Git.  The durable receipt
contains only bounded artifact metadata, producer identities, and policy values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence


SCHEMA_VERSION = "netbraid.iot23_flow_lineage_campaign_receipt.v1"
ZEEK_PROFILE_SCHEMA = "netbraid.zeek_conn_adapter_profile.v0"
MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_OUTPUT_BYTES = 512 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 300
OUTPUT_NAMES = (
    "packet-flows.tsv",
    "packet-flows-repeat.tsv",
    "report.json",
    "report-repeat.json",
    "zeek-adapter-profile.json",
    "zeek-adapter-profile-repeat.json",
    "campaign-receipt.json",
)


class CampaignError(RuntimeError):
    """Raised when campaign execution or provenance checks fail."""


def checked_regular_file(path: Path, label: str, maximum: int) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise CampaignError(f"cannot inspect {label}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise CampaignError(f"{label} is not a regular non-symlink file")
    if not 0 < metadata.st_size <= maximum:
        raise CampaignError(f"{label} byte count is outside (0, {maximum}]")
    return metadata


def digest_file(path: Path, label: str, maximum: int) -> dict[str, int | str]:
    initial = checked_regular_file(path, label, maximum)
    digest = hashlib.sha256()
    total = 0
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CampaignError(f"cannot open {label} without following links") from error
    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
            raise CampaignError(f"{label} changed between inspection and open")
        while chunk := source.read(1024 * 1024):
            total += len(chunk)
            if total > maximum:
                raise CampaignError(f"{label} exceeds {maximum} bytes")
            digest.update(chunk)
        final = os.fstat(source.fileno())
    stable = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(opened, field) != getattr(final, field) for field in stable):
        raise CampaignError(f"{label} changed while reading")
    return {"bytes": total, "sha256": digest.hexdigest()}


def prepare_output_directory(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
        metadata = path.lstat()
    except OSError as error:
        raise CampaignError("cannot prepare output directory") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise CampaignError("output path is not a non-symlink directory")
    for name in OUTPUT_NAMES:
        candidate = path / name
        if candidate.exists() or candidate.is_symlink():
            metadata = candidate.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                raise CampaignError(f"existing output {name} is not a regular file")


def run_to_file(
    argv: list[str], output: Path, label: str, timeout_seconds: int
) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stdout:
            try:
                result = subprocess.run(
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=timeout_seconds,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise CampaignError(f"{label} could not complete") from error
            stdout.flush()
            os.fsync(stdout.fileno())
        if result.returncode != 0:
            raise CampaignError(f"{label} failed with exit code {result.returncode}")
        checked_regular_file(temporary, f"{label} output", MAX_OUTPUT_BYTES)
        os.replace(temporary, output)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def run_evaluator(
    python: Path,
    evaluator: Path,
    zeek_log: Path,
    packet_flows: Path,
    report: Path,
    label: str,
    timeout_seconds: int,
) -> None:
    try:
        result = subprocess.run(
            [
                str(python),
                str(evaluator),
                "--zeek-log",
                str(zeek_log),
                "--packet-flows",
                str(packet_flows),
                "--report",
                str(report),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CampaignError(f"{label} could not complete") from error
    if result.returncode != 0:
        raise CampaignError(f"{label} failed with exit code {result.returncode}")
    checked_regular_file(report, f"{label} output", MAX_OUTPUT_BYTES)


def require_identical(left: Path, right: Path, label: str) -> dict[str, int | str]:
    left_receipt = digest_file(left, f"first {label}", MAX_OUTPUT_BYTES)
    right_receipt = digest_file(right, f"repeated {label}", MAX_OUTPUT_BYTES)
    if left_receipt != right_receipt:
        raise CampaignError(f"{label} was not byte-for-byte deterministic")
    return left_receipt


def read_json_object(path: Path, label: str) -> dict[str, object]:
    checked_regular_file(path, label, MAX_OUTPUT_BYTES)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CampaignError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise CampaignError(f"{label} is not a JSON object")
    return value


def checked_zeek_profile(path: Path) -> dict[str, object]:
    profile = read_json_object(path, "Zeek adapter profile")
    expected_keys = {
        "schema",
        "connection_count",
        "protocol_counts",
        "missing_duration_count",
        "missing_counter_counts",
        "projection_sha256",
    }
    if set(profile) != expected_keys or profile.get("schema") != ZEEK_PROFILE_SCHEMA:
        raise CampaignError(
            "Zeek adapter profile schema differs from the locked contract"
        )
    connection_count = profile.get("connection_count")
    missing_duration_count = profile.get("missing_duration_count")
    if (
        not isinstance(connection_count, int)
        or isinstance(connection_count, bool)
        or connection_count <= 0
        or not isinstance(missing_duration_count, int)
        or isinstance(missing_duration_count, bool)
        or not 0 <= missing_duration_count <= connection_count
    ):
        raise CampaignError("Zeek adapter profile counts are invalid")
    for key, expected in (
        ("protocol_counts", {"icmp", "tcp", "udp", "unknown_transport"}),
        (
            "missing_counter_counts",
            {"orig_ip_bytes", "orig_packets", "resp_ip_bytes", "resp_packets"},
        ),
    ):
        counts = profile.get(key)
        if not isinstance(counts, dict) or set(counts) != expected:
            raise CampaignError(f"Zeek adapter profile {key} differs from the contract")
        if any(
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= connection_count
            for value in counts.values()
        ):
            raise CampaignError(f"Zeek adapter profile {key} contains invalid counts")
    protocol_counts = profile["protocol_counts"]
    if (
        not isinstance(protocol_counts, dict)
        or sum(protocol_counts.values()) != connection_count
    ):
        raise CampaignError(
            "Zeek adapter protocol counts do not cover every connection"
        )
    projection_sha256 = profile.get("projection_sha256")
    if (
        not isinstance(projection_sha256, str)
        or len(projection_sha256) != 64
        or any(character not in "0123456789abcdef" for character in projection_sha256)
    ):
        raise CampaignError("Zeek adapter projection digest is invalid")
    return profile


def require_profile_matches_evaluator(profile: dict[str, object], report: Path) -> None:
    evaluation = read_json_object(report, "IoT-23 lineage report")
    inputs = evaluation.get("inputs")
    if not isinstance(inputs, dict):
        raise CampaignError("IoT-23 lineage report has no input summary")
    if inputs.get("publisher_flows") != profile["connection_count"]:
        raise CampaignError("Zeek adapter and evaluator connection counts differ")
    if (
        inputs.get("publisher_flows_without_duration")
        != profile["missing_duration_count"]
    ):
        raise CampaignError("Zeek adapter and evaluator duration coverage differs")


def write_json_atomic(path: Path, value: dict[str, object]) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def run_campaign(args: argparse.Namespace) -> dict[str, object]:
    if not 1 <= args.timeout_seconds <= 3600:
        raise CampaignError("timeout seconds is outside [1, 3600]")
    for name, value in (
        ("TCP inactivity seconds", args.tcp_inactivity_seconds),
        ("UDP inactivity seconds", args.udp_inactivity_seconds),
    ):
        if not value.isascii() or not value.isdecimal() or int(value) > 86_400:
            raise CampaignError(f"{name} must be an integer in [0, 86400]")

    prepare_output_directory(args.output_dir)
    capture = digest_file(args.capture, "capture", MAX_INPUT_BYTES)
    zeek_log = digest_file(args.zeek_log, "publisher flow log", MAX_INPUT_BYTES)
    netbraid = digest_file(args.netbraid_bin, "Netbraid executable", MAX_INPUT_BYTES)
    zeek_profiler = digest_file(
        args.zeek_profile_bin, "Zeek adapter profiler", MAX_INPUT_BYTES
    )
    evaluator = digest_file(args.evaluator, "evaluator", MAX_INPUT_BYTES)
    try:
        python_path = args.python.resolve(strict=True)
    except OSError as error:
        raise CampaignError("cannot resolve Python executable") from error
    python = digest_file(python_path, "Python executable", MAX_INPUT_BYTES)

    flow_paths = [
        args.output_dir / "packet-flows.tsv",
        args.output_dir / "packet-flows-repeat.tsv",
    ]
    report_paths = [
        args.output_dir / "report.json",
        args.output_dir / "report-repeat.json",
    ]
    profile_paths = [
        args.output_dir / "zeek-adapter-profile.json",
        args.output_dir / "zeek-adapter-profile-repeat.json",
    ]
    producer_argv = [
        str(args.netbraid_bin),
        "pcap",
        str(args.capture),
        "--flows-tsv",
        "--tcp-inactivity-seconds",
        args.tcp_inactivity_seconds,
        "--udp-inactivity-seconds",
        args.udp_inactivity_seconds,
    ]
    for index, (flow_path, report_path, profile_path) in enumerate(
        zip(flow_paths, report_paths, profile_paths), start=1
    ):
        run_to_file(
            producer_argv,
            flow_path,
            f"packet-flow production run {index}",
            args.timeout_seconds,
        )
        run_evaluator(
            python_path,
            args.evaluator,
            args.zeek_log,
            flow_path,
            report_path,
            f"lineage evaluation run {index}",
            args.timeout_seconds,
        )
        run_to_file(
            [str(args.zeek_profile_bin), str(args.zeek_log)],
            profile_path,
            f"Zeek adapter profile run {index}",
            args.timeout_seconds,
        )
        profile = checked_zeek_profile(profile_path)
        require_profile_matches_evaluator(profile, report_path)

    flow_receipt = require_identical(flow_paths[0], flow_paths[1], "packet-flow TSV")
    report_receipt = require_identical(
        report_paths[0], report_paths[1], "evaluation report"
    )
    profile_receipt = require_identical(
        profile_paths[0], profile_paths[1], "Zeek adapter profile"
    )
    receipt: dict[str, object] = {
        "schema": SCHEMA_VERSION,
        "status": "complete_deterministic",
        "inputs": {"capture": capture, "publisher_flow_log": zeek_log},
        "producer": {
            "artifact": netbraid,
            "mode": "pcap_flows_tsv",
            "tcp_inactivity_seconds": int(args.tcp_inactivity_seconds),
            "udp_inactivity_seconds": int(args.udp_inactivity_seconds),
        },
        "zeek_adapter": {
            "artifact": zeek_profiler,
            "mode": "canonical_full_metadata_conn_profile",
            "schema": ZEEK_PROFILE_SCHEMA,
        },
        "evaluator": {"script": evaluator, "python": python},
        "outputs": {
            "packet_flows": {"file": flow_paths[0].name, **flow_receipt},
            "report": {"file": report_paths[0].name, **report_receipt},
            "zeek_adapter_profile": {
                "file": profile_paths[0].name,
                **profile_receipt,
            },
        },
        "repetitions": 2,
        "retained": {
            "endpoint_values": 0,
            "raw_rows": 0,
            "absolute_paths": 0,
        },
    }
    write_json_atomic(args.output_dir / "campaign-receipt.json", receipt)
    return receipt


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", required=True, type=Path)
    parser.add_argument("--zeek-log", required=True, type=Path)
    parser.add_argument("--netbraid-bin", required=True, type=Path)
    parser.add_argument("--zeek-profile-bin", required=True, type=Path)
    parser.add_argument(
        "--evaluator",
        type=Path,
        default=Path(__file__).with_name("evaluate-iot23-flow-lineage.py"),
    )
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--tcp-inactivity-seconds", default="300")
    parser.add_argument("--udp-inactivity-seconds", default="60")
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        run_campaign(parse_args(argv))
    except CampaignError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
