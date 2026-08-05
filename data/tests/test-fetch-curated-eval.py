#!/usr/bin/env python3
"""Hermetic tests for the curated-evaluation Zenodo fetcher."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import ssl
import stat
import subprocess
import sys
import tempfile
import types
import unittest
import urllib.error
from contextlib import redirect_stdout
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
FETCHER = ROOT / "data" / "fetch" / "fetch-curated-eval.py"
MANIFEST = ROOT / "data" / "catalog" / "curated-eval-artifacts-v1.json"

TRUSTSTORE = types.ModuleType("truststore")
TRUSTSTORE.SSLContext = ssl.SSLContext
sys.modules.setdefault("truststore", TRUSTSTORE)

SPEC = importlib.util.spec_from_file_location("fetch_curated_eval", FETCHER)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class Response(io.BytesIO):
    """Minimal context-managed urllib response for deterministic tests."""

    def __init__(
        self,
        payload: bytes,
        url: str,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(payload)
        self.status = status
        self.headers = headers or {"Content-Length": str(len(payload))}
        self._url = url

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class PartialFailureResponse(Response):
    """Return one persisted prefix, then simulate a dropped connection."""

    def __init__(self, payload: bytes, url: str, prefix_bytes: int) -> None:
        super().__init__(
            b"",
            url,
            headers={"Content-Length": str(len(payload))},
        )
        self._prefix = payload[:prefix_bytes]
        self._read_count = 0

    def read(self, _size: int = -1) -> bytes:
        self._read_count += 1
        if self._read_count == 1:
            return self._prefix
        raise ConnectionResetError("sensitive upstream socket detail")


def synthetic_artifact(payload: bytes, *, filename: str = "synthetic.bin"):
    base = MODULE.load_catalog().records[0].artifacts[0]
    return replace(
        base,
        filename=filename,
        bytes=len(payload),
        md5=hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        content_url=(
            f"https://zenodo.org/api/records/{base.record_id}/files/{filename}/content"
        ),
    )


def response_for(
    artifact,
    payload: bytes,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    return Response(
        payload,
        artifact.content_url,
        status=status,
        headers=headers,
    )


def http_error(artifact, status: int, *, retry_after: str | None = None):
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    return urllib.error.HTTPError(
        artifact.content_url,
        status,
        "sensitive upstream HTTP detail",
        headers,
        None,
    )


class CuratedEvalFetcherTests(unittest.TestCase):
    def test_manifest_totals_uniqueness_and_selection(self):
        catalog = MODULE.load_catalog()
        self.assertEqual(
            tuple(record.record_id for record in catalog.records),
            (1193563, 7108614, 7396485, 15005190, 15989282, 17347695),
        )
        self.assertEqual(catalog.expected_artifact_count, 50)
        self.assertEqual(catalog.expected_total_bytes, 4_862_542_072)
        self.assertEqual(len(catalog.artifacts), 50)
        self.assertEqual(
            sum(artifact.bytes for artifact in catalog.artifacts), 4_862_542_072
        )

        targets = [
            (artifact.record_id, artifact.filename.casefold())
            for artifact in catalog.artifacts
        ]
        urls = [artifact.content_url for artifact in catalog.artifacts]
        self.assertEqual(len(targets), len(set(targets)))
        self.assertEqual(len(urls), len(set(urls)))
        self.assertTrue(all(artifact.doi for artifact in catalog.artifacts))
        self.assertTrue(all(artifact.license_id for artifact in catalog.artifacts))
        self.assertTrue(all(record.task_rationale for record in catalog.records))
        self.assertTrue(all(record.difficulty_rationale for record in catalog.records))
        self.assertTrue(all(record.grouping_warning for record in catalog.records))

        self.assertEqual(len(MODULE.select_artifacts(catalog, "all")), 50)
        self.assertEqual(len(MODULE.select_artifacts(catalog, "7108614")), 14)
        selected = MODULE.select_artifacts(catalog, "17347695/sample_1_meter.csv")
        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].bytes, 80396)
        with self.assertRaisesRegex(MODULE.FetchError, "unknown_selection"):
            MODULE.select_artifacts(catalog, "17347695/missing.csv")

    def test_list_output_is_deterministic_and_network_free(self):
        outputs = []
        with mock.patch.object(
            MODULE, "_open", side_effect=AssertionError("network access")
        ):
            for _ in range(2):
                output = io.StringIO()
                with redirect_stdout(output):
                    exit_code = MODULE.main(["list", "15005190"])
                self.assertEqual(exit_code, 0)
                outputs.append(output.getvalue())
        self.assertEqual(outputs[0], outputs[1])
        listing = json.loads(outputs[0])
        self.assertEqual(
            listing["summary"],
            {
                "artifacts": 2,
                "expected_bytes": 69726725,
                "records": 1,
            },
        )
        self.assertEqual(listing["records"][0]["doi"], "10.5281/zenodo.15005190")
        self.assertEqual(listing["records"][0]["license_id"], "cc-by-nc-4.0")

    def test_download_receipt_and_idempotent_reuse(self):
        payload = b"curated synthetic payload"
        artifact = synthetic_artifact(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            raw_dir = base / "raw"
            receipt_dir = base / "receipts"
            with mock.patch.object(
                MODULE,
                "_open",
                return_value=response_for(artifact, payload),
            ) as opener:
                first = MODULE.acquire_artifact(
                    artifact, raw_dir=raw_dir, receipt_dir=receipt_dir
                )
                second = MODULE.acquire_artifact(
                    artifact, raw_dir=raw_dir, receipt_dir=receipt_dir
                )

            target, partial, receipt_path, lock_path = MODULE._paths(
                artifact, raw_dir, receipt_dir
            )
            self.assertEqual(target.read_bytes(), payload)
            self.assertFalse(partial.exists())
            self.assertFalse(lock_path.exists())
            self.assertEqual(opener.call_count, 1)
            self.assertTrue(first["downloaded"])
            self.assertFalse(second["downloaded"])
            self.assertEqual(first["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(stat.S_IMODE(receipt_path.stat().st_mode), 0o600)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema"], MODULE.RECEIPT_SCHEMA)
            self.assertEqual(receipt["source"]["doi"], artifact.doi)
            self.assertEqual(receipt["source"]["license_id"], artifact.license_id)
            self.assertEqual(
                receipt["integrity"]["sha256"], hashlib.sha256(payload).hexdigest()
            )

    def test_request_uses_publisher_compatible_content_negotiation(self):
        artifact = synthetic_artifact(b"payload")
        request = MODULE._request(artifact, 0)

        self.assertEqual(request.get_header("Accept"), "*/*")
        self.assertEqual(request.get_header("Accept-encoding"), "identity")
        self.assertIsNone(request.get_header("User-agent"))

    def test_zero_byte_partial_restarts_without_a_range_request(self):
        payload = b"restart an empty partial"
        artifact = synthetic_artifact(payload)
        captured = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            raw_dir = base / "raw"
            receipt_dir = base / "receipts"
            partial = raw_dir / str(artifact.record_id) / f".{artifact.filename}.part"
            partial.parent.mkdir(parents=True)
            partial.write_bytes(b"")
            partial.chmod(0o600)

            def open_restart(request, *, timeout):
                captured.append((request.get_header("Range"), timeout))
                return response_for(artifact, payload)

            with mock.patch.object(MODULE, "_open", side_effect=open_restart):
                result = MODULE.acquire_artifact(
                    artifact, raw_dir=raw_dir, receipt_dir=receipt_dir
                )

            target, _, _, _ = MODULE._paths(artifact, raw_dir, receipt_dir)
            self.assertEqual(target.read_bytes(), payload)
            self.assertFalse(partial.exists())
            self.assertTrue(result["verified"])
        self.assertEqual(captured, [(None, MODULE.DOWNLOAD_TIMEOUT_SECONDS)])

    def test_resume_requires_exact_content_range(self):
        payload = b"0123456789abcdef"
        artifact = synthetic_artifact(payload)
        offset = 5
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            raw_dir = base / "raw"
            receipt_dir = base / "receipts"
            partial = raw_dir / str(artifact.record_id) / f".{artifact.filename}.part"
            partial.parent.mkdir(parents=True)
            partial.write_bytes(payload[:offset])
            partial.chmod(0o600)
            captured = []

            def open_resume(request, *, timeout):
                captured.append((request.get_header("Range"), timeout))
                return response_for(
                    artifact,
                    payload[offset:],
                    status=206,
                    headers={
                        "Content-Length": str(len(payload) - offset),
                        "Content-Range": f"bytes {offset}-{len(payload) - 1}/{len(payload)}",
                    },
                )

            with mock.patch.object(MODULE, "_open", side_effect=open_resume):
                result = MODULE.acquire_artifact(
                    artifact, raw_dir=raw_dir, receipt_dir=receipt_dir
                )
            target, _, _, _ = MODULE._paths(artifact, raw_dir, receipt_dir)
            self.assertEqual(captured, [(f"bytes={offset}-", 120)])
            self.assertEqual(target.read_bytes(), payload)
            self.assertTrue(result["verified"])

        for status_code, content_range, expected_error in (
            (200, None, "resume_requires_http_206"),
            (
                206,
                f"bytes {offset + 1}-{len(payload) - 1}/{len(payload)}",
                "invalid_content_range",
            ),
        ):
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                raw_dir = base / "raw"
                receipt_dir = base / "receipts"
                partial = (
                    raw_dir / str(artifact.record_id) / f".{artifact.filename}.part"
                )
                partial.parent.mkdir(parents=True)
                partial.write_bytes(payload[:offset])
                partial.chmod(0o600)
                headers = {"Content-Length": str(len(payload) - offset)}
                if content_range is not None:
                    headers["Content-Range"] = content_range
                with (
                    mock.patch.object(
                        MODULE,
                        "_open",
                        return_value=response_for(
                            artifact,
                            payload[offset:],
                            status=status_code,
                            headers=headers,
                        ),
                    ),
                    self.assertRaisesRegex(MODULE.FetchError, expected_error),
                ):
                    MODULE.acquire_artifact(
                        artifact, raw_dir=raw_dir, receipt_dir=receipt_dir
                    )
                self.assertEqual(partial.read_bytes(), payload[:offset])

    def test_transient_failure_retries_to_eventual_success(self):
        payload = b"eventual success payload"
        artifact = synthetic_artifact(payload)
        sleeps = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            raw_dir = base / "raw"
            receipt_dir = base / "receipts"
            with mock.patch.object(
                MODULE,
                "_open",
                side_effect=[
                    urllib.error.URLError(
                        TimeoutError("sensitive upstream timeout detail")
                    ),
                    response_for(artifact, payload),
                ],
            ) as opener:
                result = MODULE.acquire_artifact(
                    artifact,
                    raw_dir=raw_dir,
                    receipt_dir=receipt_dir,
                    sleeper=sleeps.append,
                )

            target, partial, _, _ = MODULE._paths(artifact, raw_dir, receipt_dir)
            self.assertEqual(target.read_bytes(), payload)
            self.assertFalse(partial.exists())
            self.assertTrue(result["verified"])
            self.assertEqual(opener.call_count, 2)
            self.assertEqual(sleeps, [MODULE.DOWNLOAD_RETRY_DELAYS_SECONDS[0]])

    def test_transient_failures_exhaust_bounded_retries_without_leaking_details(self):
        payload = b"retry exhaustion payload"
        artifact = synthetic_artifact(payload)
        sleeps = []
        attempts = len(MODULE.DOWNLOAD_RETRY_DELAYS_SECONDS) + 1
        failures = [
            ConnectionResetError("token=do-not-expose") for _ in range(attempts)
        ]
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            with (
                mock.patch.object(MODULE, "_open", side_effect=failures) as opener,
                self.assertRaises(MODULE.FetchError) as caught,
            ):
                MODULE.acquire_artifact(
                    artifact,
                    raw_dir=base / "raw",
                    receipt_dir=base / "receipts",
                    sleeper=sleeps.append,
                )

        self.assertEqual(str(caught.exception), "download_request_failed")
        self.assertIsNone(caught.exception.__cause__)
        self.assertEqual(opener.call_count, attempts)
        self.assertEqual(sleeps, list(MODULE.DOWNLOAD_RETRY_DELAYS_SECONDS))
        self.assertNotIn("token=do-not-expose", str(caught.exception))

    def test_retry_after_and_backoff_are_bounded(self):
        payload = b"bounded retry delay payload"
        artifact = synthetic_artifact(payload)
        sleeps = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            with mock.patch.object(
                MODULE,
                "_open",
                side_effect=[
                    http_error(artifact, 503, retry_after="999999"),
                    http_error(artifact, 429, retry_after="not-a-delay"),
                    response_for(artifact, payload),
                ],
            ):
                MODULE.acquire_artifact(
                    artifact,
                    raw_dir=base / "raw",
                    receipt_dir=base / "receipts",
                    sleeper=sleeps.append,
                )

        self.assertEqual(
            sleeps,
            [
                MODULE.MAX_RETRY_AFTER_SECONDS,
                MODULE.DOWNLOAD_RETRY_DELAYS_SECONDS[1],
            ],
        )
        self.assertTrue(
            all(0 <= delay <= MODULE.MAX_RETRY_AFTER_SECONDS for delay in sleeps)
        )

    def test_retry_resumes_from_bytes_persisted_before_disconnect(self):
        payload = b"0123456789abcdef"
        artifact = synthetic_artifact(payload)
        prefix_bytes = 6
        ranges = []
        sleeps = []

        def open_with_disconnect(request, *, timeout):
            self.assertEqual(timeout, MODULE.DOWNLOAD_TIMEOUT_SECONDS)
            ranges.append(request.get_header("Range"))
            if len(ranges) == 1:
                return PartialFailureResponse(
                    payload,
                    artifact.content_url,
                    prefix_bytes,
                )
            return response_for(
                artifact,
                payload[prefix_bytes:],
                status=206,
                headers={
                    "Content-Length": str(len(payload) - prefix_bytes),
                    "Content-Range": (
                        f"bytes {prefix_bytes}-{len(payload) - 1}/{len(payload)}"
                    ),
                },
            )

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            raw_dir = base / "raw"
            receipt_dir = base / "receipts"
            with mock.patch.object(MODULE, "_open", side_effect=open_with_disconnect):
                MODULE.acquire_artifact(
                    artifact,
                    raw_dir=raw_dir,
                    receipt_dir=receipt_dir,
                    sleeper=sleeps.append,
                )
            target, partial, _, _ = MODULE._paths(artifact, raw_dir, receipt_dir)
            self.assertEqual(target.read_bytes(), payload)
            self.assertFalse(partial.exists())

        self.assertEqual(ranges, [None, f"bytes={prefix_bytes}-"])
        self.assertEqual(sleeps, [MODULE.DOWNLOAD_RETRY_DELAYS_SECONDS[0]])

    def test_permanent_http_error_is_not_retried(self):
        artifact = synthetic_artifact(b"permanent failure payload")
        sleeps = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            with (
                mock.patch.object(
                    MODULE,
                    "_open",
                    side_effect=http_error(artifact, 404),
                ) as opener,
                self.assertRaisesRegex(MODULE.FetchError, "download_request_failed"),
            ):
                MODULE.acquire_artifact(
                    artifact,
                    raw_dir=base / "raw",
                    receipt_dir=base / "receipts",
                    sleeper=sleeps.append,
                )

        self.assertEqual(opener.call_count, 1)
        self.assertEqual(sleeps, [])

    def test_corruption_and_remote_drift_fail_without_promotion(self):
        payload = b"expected payload bytes"
        corrupt = b"corrupt! payload bytes"
        self.assertEqual(len(payload), len(corrupt))
        artifact = synthetic_artifact(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            raw_dir = base / "raw"
            receipt_dir = base / "receipts"
            with (
                mock.patch.object(
                    MODULE,
                    "_open",
                    return_value=response_for(artifact, corrupt),
                ),
                self.assertRaisesRegex(MODULE.FetchError, "artifact_md5_mismatch"),
            ):
                MODULE.acquire_artifact(
                    artifact, raw_dir=raw_dir, receipt_dir=receipt_dir
                )
            target, partial, receipt_path, lock_path = MODULE._paths(
                artifact, raw_dir, receipt_dir
            )
            self.assertFalse(target.exists())
            self.assertTrue(partial.is_file())
            self.assertFalse(receipt_path.exists())
            self.assertFalse(lock_path.exists())

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            raw_dir = base / "raw"
            receipt_dir = base / "receipts"
            drift = response_for(
                artifact,
                payload,
                headers={"Content-Length": str(len(payload) + 1)},
            )
            with (
                mock.patch.object(MODULE, "_open", return_value=drift),
                self.assertRaisesRegex(MODULE.FetchError, "remote_size_drift"),
            ):
                MODULE.acquire_artifact(
                    artifact, raw_dir=raw_dir, receipt_dir=receipt_dir
                )
            target, partial, receipt_path, _ = MODULE._paths(
                artifact, raw_dir, receipt_dir
            )
            self.assertFalse(target.exists())
            self.assertFalse(partial.exists())
            self.assertFalse(receipt_path.exists())

    def test_bounds_fail_before_network_or_local_writes(self):
        payload = b"bounded payload"
        artifact = synthetic_artifact(payload)
        for total_limit, file_limit, expected_error in (
            (len(payload) - 1, len(payload), "max_total_bytes_exceeded"),
            (len(payload), len(payload) - 1, "max_file_bytes_exceeded"),
            (0, len(payload), "byte_limits_must_be_positive"),
        ):
            with tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                raw_dir = base / "raw"
                receipt_dir = base / "receipts"
                with (
                    mock.patch.object(
                        MODULE, "_open", side_effect=AssertionError("network access")
                    ),
                    self.assertRaisesRegex(MODULE.FetchError, expected_error),
                ):
                    MODULE.fetch_artifacts(
                        [artifact],
                        raw_dir=raw_dir,
                        receipt_dir=receipt_dir,
                        max_total_bytes=total_limit,
                        max_file_bytes=file_limit,
                    )
                self.assertFalse(raw_dir.exists())
                self.assertFalse(receipt_dir.exists())

    def test_unsafe_symlinks_and_redirects_fail_closed(self):
        payload = b"safe bytes"
        artifact = synthetic_artifact(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            outside = base / "outside"
            outside.mkdir()
            raw_dir = base / "raw"
            raw_dir.symlink_to(outside, target_is_directory=True)
            with (
                mock.patch.object(
                    MODULE, "_open", side_effect=AssertionError("network access")
                ),
                self.assertRaisesRegex(MODULE.FetchError, "unsafe_local_directory"),
            ):
                MODULE.acquire_artifact(
                    artifact, raw_dir=raw_dir, receipt_dir=base / "receipts"
                )

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            outside = base / "outside"
            outside.mkdir()
            linked_parent = base / "linked-parent"
            linked_parent.symlink_to(outside, target_is_directory=True)
            raw_dir = linked_parent / "raw"
            with (
                mock.patch.object(
                    MODULE, "_open", side_effect=AssertionError("network access")
                ),
                self.assertRaisesRegex(MODULE.FetchError, "unsafe_local_directory"),
            ):
                MODULE.acquire_artifact(
                    artifact, raw_dir=raw_dir, receipt_dir=base / "receipts"
                )
            self.assertFalse((outside / "raw").exists())

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            outside = base / "outside"
            existing = outside / "existing"
            existing.mkdir(parents=True)
            linked_parent = base / "linked-parent"
            linked_parent.symlink_to(outside, target_is_directory=True)
            raw_dir = linked_parent / "existing" / "raw"
            with (
                mock.patch.object(
                    MODULE, "_open", side_effect=AssertionError("network access")
                ),
                self.assertRaisesRegex(MODULE.FetchError, "unsafe_local_directory"),
            ):
                MODULE.acquire_artifact(
                    artifact, raw_dir=raw_dir, receipt_dir=base / "receipts"
                )
            self.assertFalse((existing / "raw").exists())

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            raw_dir = base / "raw"
            receipt_dir = base / "receipts"
            raw_record = raw_dir / str(artifact.record_id)
            raw_record.mkdir(parents=True)
            receipt_dir.mkdir()
            outside = base / "outside.bin"
            outside.write_bytes(payload)
            target, _, _, _ = MODULE._paths(artifact, raw_dir, receipt_dir)
            target.symlink_to(outside)
            with (
                mock.patch.object(
                    MODULE, "_open", side_effect=AssertionError("network access")
                ),
                self.assertRaisesRegex(MODULE.FetchError, "unsafe_local_file"),
            ):
                MODULE.acquire_artifact(
                    artifact, raw_dir=raw_dir, receipt_dir=receipt_dir
                )

        with self.assertRaisesRegex(MODULE.FetchError, "redirect_rejected"):
            MODULE._RejectRedirects().redirect_request()
        wrong_url = Response(
            payload,
            "https://zenodo.org/api/records/1193563/files/other/content",
        )
        with self.assertRaisesRegex(MODULE.FetchError, "response_url_mismatch"):
            MODULE._validate_response(wrong_url, artifact, 0)

    def test_manifest_drift_unsafe_names_and_duplicate_targets_are_rejected(self):
        original = json.loads(MANIFEST.read_text(encoding="utf-8"))
        mutations = []

        extra_key = deepcopy(original)
        extra_key["unexpected"] = True
        mutations.append((extra_key, "manifest_schema_drift"))

        wrong_size = deepcopy(original)
        wrong_size["expected_total_bytes"] += 1
        mutations.append((wrong_size, "invalid_manifest_aggregates"))

        unsafe_name = deepcopy(original)
        unsafe_name["records"][0]["artifacts"][0]["filename"] = "../escape.csv"
        mutations.append((unsafe_name, "invalid_artifact_filename"))

        duplicate = deepcopy(original)
        duplicate["records"][0]["artifacts"][1] = deepcopy(
            duplicate["records"][0]["artifacts"][0]
        )
        mutations.append((duplicate, "duplicate_artifact_target"))

        for value, expected_error in mutations:
            with tempfile.TemporaryDirectory() as directory:
                manifest = Path(directory) / "manifest.json"
                manifest.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaisesRegex(MODULE.FetchError, expected_error):
                    MODULE.load_catalog(manifest)

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "manifest.json"
            target.write_text(json.dumps(original), encoding="utf-8")
            link = Path(directory) / "manifest-link.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(MODULE.FetchError, "invalid_manifest"):
                MODULE.load_catalog(link)

    def test_status_is_network_free_and_reports_verified_partial_and_corrupt(self):
        payload = b"status payload"
        artifact = synthetic_artifact(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            raw_dir = base / "raw"
            receipt_dir = base / "receipts"
            with mock.patch.object(
                MODULE, "_open", side_effect=AssertionError("network access")
            ):
                missing = MODULE.status_artifacts(
                    [artifact], raw_dir=raw_dir, receipt_dir=receipt_dir
                )[0]
            self.assertFalse(missing["present"])
            self.assertFalse(raw_dir.exists())

            with mock.patch.object(
                MODULE,
                "_open",
                return_value=response_for(artifact, payload),
            ):
                MODULE.acquire_artifact(
                    artifact, raw_dir=raw_dir, receipt_dir=receipt_dir
                )
            verified = MODULE.status_artifacts(
                [artifact], raw_dir=raw_dir, receipt_dir=receipt_dir
            )[0]
            self.assertTrue(verified["verified"])

            target, _, _, _ = MODULE._paths(artifact, raw_dir, receipt_dir)
            target.write_bytes(b"x" * len(payload))
            corrupt = MODULE.status_artifacts(
                [artifact], raw_dir=raw_dir, receipt_dir=receipt_dir
            )[0]
            self.assertEqual(corrupt["error"], "artifact_md5_mismatch")

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            raw_dir = base / "raw"
            receipt_dir = base / "receipts"
            _, partial, _, _ = MODULE._paths(artifact, raw_dir, receipt_dir)
            partial.parent.mkdir(parents=True)
            partial.write_bytes(payload[:4])
            partial.chmod(0o600)
            observed = MODULE.status_artifacts(
                [artifact], raw_dir=raw_dir, receipt_dir=receipt_dir
            )[0]
            self.assertEqual(observed["partial_bytes"], 4)
            self.assertIsNone(observed["error"])

    def test_default_storage_is_ignored_and_contains_no_tracked_data(self):
        self.assertEqual(
            MODULE.DEFAULT_RAW_DIR,
            ROOT / "data" / "raw" / "curated-eval",
        )
        self.assertEqual(
            MODULE.DEFAULT_RECEIPT_DIR,
            ROOT / "data" / "receipts" / "curated-eval",
        )
        tracked = subprocess.run(  # noqa: S603
            ["git", "ls-files", "--", "data/raw", "data/receipts"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(tracked.stdout, "")
        for probe in (
            "data/raw/curated-eval/probe",
            "data/receipts/curated-eval/probe",
        ):
            ignored = subprocess.run(  # noqa: S603
                ["git", "check-ignore", "-q", probe],
                cwd=ROOT,
                check=False,
            )
            self.assertEqual(ignored.returncode, 0, probe)


if __name__ == "__main__":
    unittest.main(verbosity=2)
