#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# ///

"""Run a local, metadata-only evaluation over Netbraid's admitted PCAP corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCRIPT_SCHEMA = "local.netbraid_capture_corpus_eval.v0"
REPO = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = (
    REPO / "rust/crates/netbraid-adapter-tshark/tests/fixtures/upstream/corpus-v0.json"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        type=Path,
        default=REPO,
        help="Netbraid checkout containing the corpus and binary",
    )
    parser.add_argument(
        "--binary",
        type=Path,
        help="Netbraid binary; defaults to <repo>/rust/target/debug/netbraid",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
        help="Corpus manifest; defaults to the adapter's corpus-v0.json",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=REPO / "data/derived/eval/corpus-report.json",
        help="Metadata-only JSON report path",
    )
    parser.add_argument(
        "--packet-limit",
        type=int,
        default=1000,
        help="Bound passed to Netbraid for each fixture",
    )
    return parser.parse_args()


def run_git_sha(repo: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected an object in {path}")
    return value


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_hex(path: Path) -> bytes:
    text = "".join(
        line.split("#", 1)[0] for line in path.read_text(encoding="utf-8").splitlines()
    )
    try:
        return bytes.fromhex(text)
    except ValueError as error:
        raise ValueError(f"invalid hexadecimal fixture {path}: {error}") from error


def run_candidate(binary: Path, fixture: Path, packet_limit: int) -> dict[str, Any]:
    result = subprocess.run(
        [
            str(binary),
            "pcap",
            str(fixture),
            "--packet-limit",
            str(packet_limit),
            "--wlan-fingerprint-json",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(
            f"{binary.name} failed for {fixture.name} with exit {result.returncode}: "
            f"{stderr[-2000:]}"
        )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"{binary.name} emitted invalid JSON for {fixture.name}: {error}"
        ) from error
    if not isinstance(value, dict):
        raise RuntimeError(f"candidate for {fixture.name} was not a JSON object")
    return value


def expected_wlan_checks(
    expected: dict[str, Any], candidate: dict[str, Any]
) -> list[str]:
    failures: list[str] = []
    wlan = expected.get("ieee80211")
    status = candidate.get("status", {})
    if not isinstance(status, dict):
        return ["status is not an object"]

    if wlan is None:
        if status.get("status") != "unsupported":
            failures.append("non-WLAN fixture did not produce unsupported status")
        return failures

    if status.get("status") != "observed":
        failures.append("WLAN fixture did not produce observed status")
        return failures
    basis = status.get("basis", {})
    if not isinstance(basis, dict):
        return ["observed status has no basis object"]

    expected_counts = {
        "wlan_frames": wlan.get("frames"),
        "radiotap_frames": wlan.get("frames")
        if "radiotap" in expected.get("required_protocols", [])
        else 0,
        "radio_metadata_frames": wlan.get("radio_frames"),
        "ssid_element_frames": wlan.get("nonempty_ssid_frames"),
    }
    for field, expected_value in expected_counts.items():
        if basis.get(field) != expected_value:
            failures.append(
                f"{field}={basis.get(field)!r}, expected {expected_value!r}"
            )

    if [entry.get("value") for entry in basis.get("channels", [])] != wlan.get(
        "channels", []
    ):
        failures.append("channel values differ from corpus expectation")
    expected_signal = wlan.get("signal_dbm")
    actual_signal = basis.get("signal_dbm", {})
    if expected_signal is not None:
        for field, expected_field in [
            ("samples", "samples"),
            ("minimum_dbm", "minimum"),
            ("maximum_dbm", "maximum"),
        ]:
            if actual_signal.get(field) != expected_signal.get(expected_field):
                failures.append(
                    f"signal {field}={actual_signal.get(field)!r}, "
                    f"expected {expected_signal.get(expected_field)!r}"
                )
    return failures


def identifier_leak_checks(
    expected: dict[str, Any], candidate: dict[str, Any]
) -> list[str]:
    encoded = json.dumps(candidate, sort_keys=True)
    wlan = expected.get("ieee80211") or {}
    leaks: list[str] = []
    for field in ("bssids", "transmitters", "ssid_hex"):
        for value in wlan.get(field, []):
            if value and value in encoded:
                leaks.append(f"{field} value appeared in candidate output")
    return leaks


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    repo = args.repo.resolve()
    binary = (args.binary or repo / "rust/target/debug/netbraid").resolve()
    corpus = args.corpus.resolve()
    if not binary.is_file():
        raise FileNotFoundError(f"Netbraid binary not found: {binary}")
    manifest = read_json(corpus)
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or not fixtures:
        raise ValueError(f"corpus has no fixtures: {corpus}")

    seen_hashes: set[str] = set()
    duplicate_hashes: list[str] = []
    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="netbraid-corpus-") as staged:
        staged_dir = Path(staged)
        for fixture in fixtures:
            if not isinstance(fixture, dict):
                raise ValueError("corpus fixture entry is not an object")
            fixture_id = fixture["id"]
            source_path = corpus.parent.parent / fixture["path"]
            raw = decode_hex(source_path)
            digest = sha256_bytes(raw)
            declared_digest = fixture["content_sha256"]
            if digest != declared_digest:
                raise ValueError(
                    f"{fixture_id}: content digest {digest} != declared {declared_digest}"
                )
            if digest in seen_hashes:
                duplicate_hashes.append(fixture_id)
            seen_hashes.add(digest)
            staged_input = staged_dir / Path(fixture["origin"]["source_path"]).name
            staged_input.write_bytes(raw)
            first = run_candidate(binary, staged_input, args.packet_limit)
            second = run_candidate(binary, staged_input, args.packet_limit)
            failures = expected_wlan_checks(fixture["expected"], first)
            failures.extend(identifier_leak_checks(fixture["expected"], first))
            if first != second:
                failures.append(
                    "repeated candidate output was not byte-equivalent JSON"
                )
            source = first.get("source", {})
            if source.get("capture_id") != f"sha256:{declared_digest}":
                failures.append("candidate source capture_id is not content-bound")
            results.append(
                {
                    "id": fixture_id,
                    "origin": {
                        "repository": fixture["origin"]["repository"],
                        "revision": fixture["origin"]["revision"],
                        "source_path": fixture["origin"]["source_path"],
                        "license": fixture["origin"]["license"],
                    },
                    "content_sha256": declared_digest,
                    "size_bytes": len(raw),
                    "declared_file_type": fixture["expected"]["file_type"],
                    "declared_wlan": fixture["expected"].get("ieee80211") is not None,
                    "candidate_status": first.get("status", {}).get("status"),
                    "candidate_digest_present": "digest" in first.get("status", {}),
                    "failures": failures,
                }
            )

    failed = [item["id"] for item in results if item["failures"]]
    return {
        "schema": SCRIPT_SCHEMA,
        "script": "evaluate-admitted-corpus.py",
        "hypothesis": "declared WLAN evidence is deterministic, provenance-bound, and identifier-free; non-WLAN input abstains",
        "repo": str(repo),
        "netbraid_git_sha": run_git_sha(repo),
        "corpus": str(corpus),
        "corpus_schema": manifest.get("schema"),
        "packet_limit": args.packet_limit,
        "fixture_count": len(results),
        "unique_content_count": len(seen_hashes),
        "duplicate_content_fixture_ids": duplicate_hashes,
        "passed_fixture_count": len(results) - len(failed),
        "failed_fixture_ids": failed,
        "fixtures": results,
    }


def main() -> int:
    args = parse_args()
    report = evaluate(args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "schema",
                    "netbraid_git_sha",
                    "fixture_count",
                    "unique_content_count",
                    "passed_fixture_count",
                    "failed_fixture_ids",
                )
            },
            indent=2,
            sort_keys=True,
        )
    )
    if report["failed_fixture_ids"]:
        print(f"full metadata report: {args.out}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
