#!/usr/bin/env python3
"""Hermetic tests for the controlled-scenario Zenodo fetcher."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import ssl
import sys
import tempfile
import threading
import types
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from copy import deepcopy
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
FETCHER = ROOT / "data" / "fetch" / "fetch-controlled-jamming.py"
MANIFEST = ROOT / "data" / "catalog" / "controlled-jamming-artifacts-v1.json"
TRUSTSTORE = types.ModuleType("truststore")
TRUSTSTORE.SSLContext = ssl.SSLContext
sys.modules.setdefault("truststore", TRUSTSTORE)
SPEC = importlib.util.spec_from_file_location("fetch_controlled_jamming", FETCHER)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load controlled-jamming fetcher")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

RECORD_ID = 9990001


@dataclass
class ServerState:
    payloads: dict[str, bytes]
    ignore_range: set[str] = field(default_factory=set)
    content_range_overrides: dict[str, str] = field(default_factory=dict)
    requests: list[tuple[str, str | None]] = field(default_factory=list)


def _artifact_path(filename: str) -> str:
    return f"/api/records/{RECORD_ID}/files/{quote(filename, safe='')}/content"


@contextmanager
def local_server(state: ServerState):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            range_header = self.headers.get("Range")
            state.requests.append((self.path, range_header))
            payload = state.payloads.get(self.path)
            if payload is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return

            body = payload
            status = 200
            content_range = None
            if range_header is not None and self.path not in state.ignore_range:
                prefix = "bytes="
                if not range_header.startswith(prefix) or not range_header.endswith(
                    "-"
                ):
                    self.send_response(416)
                    self.send_header("Content-Length", "0")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    return
                offset = int(range_header[len(prefix) : -1])
                body = payload[offset:]
                status = 206
                content_range = f"bytes {offset}-{len(payload) - 1}/{len(payload)}"
                content_range = state.content_range_overrides.get(
                    self.path, content_range
                )
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            if content_range is not None:
                self.send_header("Content-Range", content_range)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def synthetic_manifest(
    base_url: str,
    payloads: dict[str, bytes],
    *,
    declared: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    artifacts = []
    for filename in sorted(payloads):
        payload = payloads[filename]
        overrides = (declared or {}).get(filename, {})
        artifacts.append(
            {
                "filename": filename,
                "content_url": f"{base_url}{_artifact_path(filename)}",
                "bytes": overrides.get("bytes", len(payload)),
                "md5": overrides.get(
                    "md5",
                    hashlib.md5(payload, usedforsecurity=False).hexdigest(),
                ),
            }
        )
    total_bytes = sum(artifact["bytes"] for artifact in artifacts)
    return {
        "schema": MODULE.MANIFEST_SCHEMA,
        "publisher": "Zenodo",
        "expected_record_count": 1,
        "expected_artifact_count": len(artifacts),
        "expected_total_bytes": total_bytes,
        "records": [
            {
                "record_id": RECORD_ID,
                "api_url": f"https://zenodo.org/api/records/{RECORD_ID}",
                "doi": f"10.5281/zenodo.{RECORD_ID}",
                "license": "CC BY 4.0",
                "license_id": "cc-by-4.0",
                "expected_artifact_count": len(artifacts),
                "expected_total_bytes": total_bytes,
                "artifacts": artifacts,
            }
        ],
    }


def write_manifest(directory: Path, value: dict[str, Any]) -> Path:
    path = directory / "manifest.json"
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def run_main(arguments: list[str]) -> tuple[int, dict[str, Any], str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        exit_code = MODULE.main(arguments)
    output = json.loads(stdout.getvalue())
    return exit_code, output, stderr.getvalue()


def cli_arguments(
    manifest: Path,
    raw_dir: Path,
    receipt_dir: Path,
    command: str,
    *,
    workers: int = 1,
) -> list[str]:
    arguments = [
        "--manifest",
        str(manifest),
        "--raw-dir",
        str(raw_dir),
        "--receipt-dir",
        str(receipt_dir),
        "--allow-loopback-http",
        command,
        str(RECORD_ID),
    ]
    if command == "fetch":
        arguments.extend(
            [
                "--workers",
                str(workers),
                "--max-total-bytes",
                "4096",
                "--max-file-bytes",
                "4096",
            ]
        )
    return arguments


class TrackedManifestTests(unittest.TestCase):
    def test_exact_zenodo_record_and_artifact_pins(self) -> None:
        catalog = MODULE.load_catalog(MANIFEST)
        self.assertEqual(
            (
                catalog.expected_record_count,
                catalog.expected_artifact_count,
                catalog.expected_total_bytes,
            ),
            (2, 112, 119_191_308_440),
        )
        expected = {
            6516954: (80, 738_542_988),
            7119040: (32, 118_452_765_452),
        }
        self.assertEqual(
            {record.record_id for record in catalog.records}, set(expected)
        )
        for record in catalog.records:
            self.assertEqual(
                (record.expected_artifact_count, record.expected_total_bytes),
                expected[record.record_id],
            )
            self.assertEqual(record.doi, f"10.5281/zenodo.{record.record_id}")
            self.assertEqual(record.license, "CC BY 4.0")
            self.assertEqual(record.license_id, "cc-by-4.0")
            self.assertEqual(
                sum(artifact.bytes for artifact in record.artifacts),
                record.expected_total_bytes,
            )
            for artifact in record.artifacts:
                self.assertEqual(len(artifact.md5), 32)
                self.assertEqual(
                    artifact.content_url,
                    "https://zenodo.org/api/records/"
                    f"{record.record_id}/files/"
                    f"{quote(artifact.filename, safe='')}/content",
                )


class HermeticFetchTests(unittest.TestCase):
    def test_resume_and_deterministic_status_receipt(self) -> None:
        filename = "sample.mat"
        payload = b"controlled-scenario-payload"
        path = _artifact_path(filename)
        state = ServerState({path: payload})
        with tempfile.TemporaryDirectory() as directory, local_server(state) as base:
            root = Path(directory)
            manifest = write_manifest(
                root, synthetic_manifest(base, {filename: payload})
            )
            raw_dir = root / "raw"
            receipt_dir = root / "receipts"
            record_dir = raw_dir / str(RECORD_ID)
            record_dir.mkdir(parents=True)
            partial = record_dir / f".{filename}.part"
            offset = 7
            partial.write_bytes(payload[:offset])

            exit_code, output, stderr = run_main(
                cli_arguments(manifest, raw_dir, receipt_dir, "fetch")
            )
            self.assertEqual(exit_code, 0, stderr)
            self.assertEqual(output["summary"]["downloaded"], 1)
            self.assertEqual(output["summary"]["verified"], 1)
            self.assertEqual(state.requests, [(path, f"bytes={offset}-")])
            target = record_dir / filename
            self.assertEqual(target.read_bytes(), payload)
            self.assertFalse(partial.exists())

            receipt_path = receipt_dir / str(RECORD_ID) / f"{filename}.json"
            receipt_before = receipt_path.read_bytes()
            receipt = json.loads(receipt_before)
            self.assertEqual(
                receipt["integrity"]["sha256"],
                hashlib.sha256(payload).hexdigest(),
            )
            status_arguments = cli_arguments(manifest, raw_dir, receipt_dir, "status")
            first_code, first_status, first_stderr = run_main(status_arguments)
            second_code, second_status, second_stderr = run_main(status_arguments)
            self.assertEqual((first_code, second_code), (0, 0))
            self.assertEqual((first_stderr, second_stderr), ("", ""))
            self.assertEqual(first_status, second_status)
            self.assertEqual(first_status["summary"]["verified"], 1)

            reuse_code, reuse, reuse_stderr = run_main(
                cli_arguments(manifest, raw_dir, receipt_dir, "fetch")
            )
            self.assertEqual(reuse_code, 0, reuse_stderr)
            self.assertEqual(reuse["summary"]["downloaded"], 0)
            self.assertEqual(reuse["summary"]["verified"], 1)
            self.assertEqual(receipt_path.read_bytes(), receipt_before)
            self.assertEqual(state.requests, [(path, f"bytes={offset}-")])

    def test_server_ignoring_range_preserves_partial(self) -> None:
        filename = "ignored-range.mat"
        payload = b"0123456789abcdef"
        path = _artifact_path(filename)
        state = ServerState({path: payload}, ignore_range={path})
        with tempfile.TemporaryDirectory() as directory, local_server(state) as base:
            root = Path(directory)
            manifest = write_manifest(
                root, synthetic_manifest(base, {filename: payload})
            )
            raw_dir = root / "raw"
            receipt_dir = root / "receipts"
            record_dir = raw_dir / str(RECORD_ID)
            record_dir.mkdir(parents=True)
            partial = record_dir / f".{filename}.part"
            prefix = payload[:5]
            partial.write_bytes(prefix)

            exit_code, output, stderr = run_main(
                cli_arguments(manifest, raw_dir, receipt_dir, "fetch")
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("1 artifact(s) failed", stderr)
            self.assertEqual(output["summary"]["failed"], 1)
            self.assertEqual(output["results"][0]["error"], "resume_requires_http_206")
            self.assertEqual(partial.read_bytes(), prefix)
            self.assertFalse((record_dir / filename).exists())
            self.assertFalse(
                (receipt_dir / str(RECORD_ID) / f"{filename}.json").exists()
            )

    def test_invalid_content_range_is_rejected(self) -> None:
        filename = "bad-range.mat"
        payload = b"range-validation"
        path = _artifact_path(filename)
        state = ServerState(
            {path: payload},
            content_range_overrides={path: f"bytes 0-3/{len(payload)}"},
        )
        with tempfile.TemporaryDirectory() as directory, local_server(state) as base:
            root = Path(directory)
            manifest = write_manifest(
                root, synthetic_manifest(base, {filename: payload})
            )
            raw_dir = root / "raw"
            receipt_dir = root / "receipts"
            record_dir = raw_dir / str(RECORD_ID)
            record_dir.mkdir(parents=True)
            partial = record_dir / f".{filename}.part"
            partial.write_bytes(payload[:4])

            exit_code, output, _ = run_main(
                cli_arguments(manifest, raw_dir, receipt_dir, "fetch")
            )
            self.assertEqual(exit_code, 1)
            self.assertEqual(output["results"][0]["error"], "invalid_content_range")
            self.assertEqual(partial.read_bytes(), payload[:4])

    def test_digest_and_size_mismatch_are_rejected(self) -> None:
        filename = "mismatch.mat"
        payload = b"publisher-bytes"
        path = _artifact_path(filename)
        cases = {
            "digest": (
                {"md5": "0" * 32},
                "artifact_md5_mismatch",
                payload,
            ),
            "size": (
                {"bytes": len(payload) + 1},
                "download_content_length_mismatch",
                None,
            ),
        }
        for name, (overrides, expected_error, expected_partial) in cases.items():
            with self.subTest(name=name):
                state = ServerState({path: payload})
                with (
                    tempfile.TemporaryDirectory() as directory,
                    local_server(state) as base,
                ):
                    root = Path(directory)
                    manifest = write_manifest(
                        root,
                        synthetic_manifest(
                            base,
                            {filename: payload},
                            declared={filename: overrides},
                        ),
                    )
                    raw_dir = root / "raw"
                    receipt_dir = root / "receipts"
                    exit_code, output, _ = run_main(
                        cli_arguments(manifest, raw_dir, receipt_dir, "fetch")
                    )
                    self.assertEqual(exit_code, 1)
                    self.assertEqual(output["results"][0]["error"], expected_error)
                    target = raw_dir / str(RECORD_ID) / filename
                    partial = target.with_name(f".{filename}.part")
                    self.assertFalse(target.exists())
                    if expected_partial is None:
                        self.assertFalse(partial.exists())
                    else:
                        self.assertEqual(partial.read_bytes(), expected_partial)

    def test_aggregate_failure_reports_every_artifact(self) -> None:
        payloads = {
            "available.mat": b"available",
            "missing.mat": b"declared-but-not-served",
        }
        available_path = _artifact_path("available.mat")
        state = ServerState({available_path: payloads["available.mat"]})
        with tempfile.TemporaryDirectory() as directory, local_server(state) as base:
            root = Path(directory)
            manifest = write_manifest(root, synthetic_manifest(base, payloads))
            raw_dir = root / "raw"
            receipt_dir = root / "receipts"
            exit_code, output, stderr = run_main(
                cli_arguments(manifest, raw_dir, receipt_dir, "fetch", workers=2)
            )
            self.assertEqual(exit_code, 1)
            self.assertIn("1 artifact(s) failed", stderr)
            self.assertEqual(len(output["results"]), 2)
            self.assertEqual(
                output["summary"],
                {
                    "artifacts": 2,
                    "downloaded": 1,
                    "failed": 1,
                    "missing": 0,
                    "partial": 0,
                    "present": 1,
                    "verified": 1,
                },
            )
            results = {result["filename"]: result for result in output["results"]}
            self.assertTrue(results["available.mat"]["downloaded"])
            self.assertEqual(results["missing.mat"]["error"], "download_request_failed")

    def test_status_rejects_symlink_as_regular_file(self) -> None:
        filename = "unsafe.mat"
        payload = b"not-read-through-a-link"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_manifest(
                root,
                synthetic_manifest("http://127.0.0.1:9", {filename: payload}),
            )
            raw_dir = root / "raw"
            receipt_dir = root / "receipts"
            record_dir = raw_dir / str(RECORD_ID)
            record_dir.mkdir(parents=True)
            outside = root / "outside.mat"
            outside.write_bytes(payload)
            (record_dir / filename).symlink_to(outside)

            exit_code, output, _ = run_main(
                cli_arguments(manifest, raw_dir, receipt_dir, "status")
            )
            self.assertEqual(exit_code, 1)
            self.assertTrue(output["results"][0]["present"])
            self.assertFalse(output["results"][0]["verified"])
            self.assertEqual(output["results"][0]["error"], "unsafe_local_file")


class ManifestBoundaryTests(unittest.TestCase):
    def test_traversal_duplicate_and_schema_drift_are_rejected(self) -> None:
        payload = b"manifest-boundary"
        base = "http://127.0.0.1:9"
        valid = synthetic_manifest(base, {"sample.mat": payload})
        cases: list[tuple[str, dict[str, Any], str]] = []

        traversal = deepcopy(valid)
        traversal["records"][0]["artifacts"][0]["filename"] = "../escape.mat"
        cases.append(("traversal", traversal, "invalid_artifact_filename"))

        duplicate = deepcopy(valid)
        artifact = deepcopy(duplicate["records"][0]["artifacts"][0])
        duplicate["records"][0]["artifacts"].append(artifact)
        duplicate["records"][0]["expected_artifact_count"] = 2
        duplicate["records"][0]["expected_total_bytes"] *= 2
        duplicate["expected_artifact_count"] = 2
        duplicate["expected_total_bytes"] *= 2
        cases.append(("duplicate", duplicate, "duplicate_artifact_filename"))

        drift = deepcopy(valid)
        drift["records"][0]["artifacts"][0]["unexpected"] = True
        cases.append(("schema", drift, "manifest_schema_drift"))

        for name, value, expected_error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = write_manifest(Path(directory), value)
                with self.assertRaisesRegex(MODULE.FetchError, expected_error):
                    MODULE.load_catalog(path, allow_loopback_http=True)

    def test_duplicate_json_object_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(
                '{"schema":"first","schema":"second"}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.FetchError, "duplicate_json_key"):
                MODULE.load_catalog(path)

    def test_list_and_status_never_open_network(self) -> None:
        payload = b"offline-commands"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = write_manifest(
                root,
                synthetic_manifest("http://127.0.0.1:9", {"offline.mat": payload}),
            )
            raw_dir = root / "raw"
            receipt_dir = root / "receipts"
            with mock.patch.object(
                MODULE,
                "_open",
                side_effect=AssertionError("network must remain unused"),
            ) as opener:
                list_code, listing, list_stderr = run_main(
                    cli_arguments(manifest, raw_dir, receipt_dir, "list")
                )
                status_code, status, status_stderr = run_main(
                    cli_arguments(manifest, raw_dir, receipt_dir, "status")
                )
            opener.assert_not_called()
            self.assertEqual(list_code, 0, list_stderr)
            self.assertEqual(listing["summary"]["artifacts"], 1)
            self.assertEqual(status_code, 1, status_stderr)
            self.assertEqual(
                status["summary"],
                {
                    "artifacts": 1,
                    "downloaded": 0,
                    "failed": 0,
                    "missing": 1,
                    "partial": 0,
                    "present": 0,
                    "verified": 0,
                },
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
