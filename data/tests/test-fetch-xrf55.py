#!/usr/bin/env python3
"""Hermetic tests for the resumable XRF55 fetcher."""

from __future__ import annotations

import importlib.util
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "fetch_xrf55", HERE.parent / "fetch" / "fetch-xrf55.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class Response(io.BytesIO):
    def __init__(self, payload, *, status=200, headers=None):
        super().__init__(payload)
        self.status = status
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def synthetic_spec(payload):
    return {
        "kaggle_ref": "synthetic/example",
        "version": 2,
        "metadata_bytes": len(payload) + 7,
        "archive_bytes": len(payload),
        "archive_md5": hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        "filename": "synthetic-v2.zip",
    }


def metadata(spec):
    return json.dumps(
        {
            "ref": spec["kaggle_ref"],
            "currentVersionNumber": spec["version"],
            "totalBytes": spec["metadata_bytes"],
            "isPrivate": False,
        }
    ).encode()


class FetchXrf55Tests(unittest.TestCase):
    def test_catalog_pins_all_official_bundles(self):
        catalog = MODULE._catalog()
        self.assertEqual(set(catalog), {"part1", "part2", "raw"})
        self.assertEqual(
            sum(item["metadata_bytes"] for item in catalog.values()),
            235_496_571_505,
        )
        self.assertEqual(
            sum(item["archive_bytes"] for item in catalog.values()),
            195_896_168_944,
        )
        self.assertTrue(
            all(item["license"] == "CC BY-NC 4.0" for item in catalog.values())
        )
        self.assertTrue(
            all(
                "datasetVersionNumber=" in MODULE.download_url(item)
                for item in catalog.values()
            )
        )

    def test_first_download_writes_receipt_and_reuse_verifies_digest(self):
        payload = b"synthetic archive bytes"
        spec = synthetic_spec(payload)
        responses = [Response(metadata(spec)), Response(payload)]
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(
                MODULE.urllib.request, "urlopen", side_effect=responses
            ) as urlopen,
        ):
            base = Path(directory)
            output_dir = base / "raw"
            receipt_dir = base / "receipts"
            archive = MODULE.download(spec, output_dir, receipt_dir)
            self.assertEqual(archive.read_bytes(), payload)
            receipt = json.loads(
                MODULE.receipt_path(archive, receipt_dir).read_text(encoding="utf-8")
            )
            self.assertEqual(
                receipt, MODULE.source_receipt(spec, len(payload), receipt["sha256"])
            )
            MODULE.download(spec, output_dir, receipt_dir)
            self.assertEqual(urlopen.call_count, 2)

    def test_default_custom_and_legacy_receipt_placement(self):
        payload = b"legacy-pinned archive"
        spec = synthetic_spec(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            default_receipts = base / "default"
            with mock.patch.object(MODULE, "DEFAULT_RECEIPT_DIR", default_receipts):
                arguments = MODULE._arguments(["part1"])
            self.assertEqual(arguments.receipt_dir, default_receipts)
            self.assertIn(
                "data/receipts/xrf55",
                MODULE._arguments(["part1"]).receipt_dir.as_posix(),
            )

            output_dir = base / "raw"
            output_dir.mkdir()
            archive = output_dir / spec["filename"]
            archive.write_bytes(payload)
            sha256 = hashlib.sha256(payload).hexdigest()
            legacy = MODULE.legacy_receipt_path(archive)
            legacy.write_text(
                json.dumps(MODULE.source_receipt(spec, len(payload), sha256)),
                encoding="utf-8",
            )
            custom_receipts = base / "custom-receipts"

            with (
                mock.patch.object(MODULE, "DEFAULT_RECEIPT_DIR", default_receipts),
                mock.patch.object(MODULE, "SOURCES", {"synthetic": spec}),
                mock.patch.object(MODULE.urllib.request, "urlopen") as urlopen,
                mock.patch("builtins.print"),
            ):
                default_exit = MODULE.main(
                    ["synthetic", "--output-dir", str(output_dir)]
                )
                custom_exit = MODULE.main(
                    [
                        "synthetic",
                        "--output-dir",
                        str(output_dir),
                        "--receipt-dir",
                        str(custom_receipts),
                    ]
                )

            self.assertEqual((default_exit, custom_exit), (0, 0))
            urlopen.assert_not_called()
            self.assertTrue(MODULE.receipt_path(archive, default_receipts).is_file())
            central = MODULE.receipt_path(archive, custom_receipts)
            self.assertTrue(central.is_file())
            receipt = json.loads(central.read_text(encoding="utf-8"))
            self.assertEqual(
                receipt["source"],
                MODULE.source_receipt(spec, len(payload), sha256)["source"],
            )
            self.assertNotIn(str(output_dir), json.dumps(receipt, sort_keys=True))

    def test_metadata_status_reports_legacy_migration_without_hashing_payload(self):
        payload = b"legacy-pinned archive"
        spec = synthetic_spec(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output_dir = base / "raw"
            output_dir.mkdir()
            receipt_dir = base / "receipts"
            archive = output_dir / spec["filename"]
            archive.write_bytes(payload)
            legacy = MODULE.legacy_receipt_path(archive)
            legacy.write_text(
                json.dumps(
                    MODULE.source_receipt(
                        spec, len(payload), hashlib.sha256(payload).hexdigest()
                    )
                ),
                encoding="utf-8",
            )

            with mock.patch.object(
                MODULE, "digest_file", side_effect=AssertionError("payload read")
            ):
                status = MODULE.local_status(
                    {"synthetic": spec}, output_dir, receipt_dir
                )

            self.assertEqual(status["inspection"], "metadata_only")
            observed = status["datasets"]["synthetic"]
            self.assertEqual(observed["archive_state"], "present")
            self.assertEqual(observed["central_receipt_state"], "absent")
            self.assertEqual(observed["legacy_receipt_state"], "valid")
            self.assertEqual(
                observed["next_action"],
                "run_full_verification_to_migrate_receipt",
            )
            self.assertFalse(observed["payload_integrity_verified"])
            self.assertNotIn(str(base), json.dumps(status, sort_keys=True))

    def test_metadata_status_distinguishes_absent_partial_and_mismatched_files(self):
        payload = b"expected"
        spec = synthetic_spec(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output_dir = base / "raw"
            output_dir.mkdir()
            receipt_dir = base / "receipts"

            missing = MODULE.local_status({"synthetic": spec}, output_dir, receipt_dir)[
                "datasets"
            ]["synthetic"]
            self.assertEqual(missing["next_action"], "download")

            partial = output_dir / f".{spec['filename']}.part"
            partial.write_bytes(payload[:3])
            resumable = MODULE.local_status(
                {"synthetic": spec}, output_dir, receipt_dir
            )["datasets"]["synthetic"]
            self.assertEqual(resumable["next_action"], "resume_download")
            self.assertEqual(resumable["partial_bytes"], 3)

            archive = output_dir / spec["filename"]
            archive.write_bytes(payload + b"drift")
            mismatch = MODULE.local_status(
                {"synthetic": spec}, output_dir, receipt_dir
            )["datasets"]["synthetic"]
            self.assertEqual(mismatch["archive_state"], "size_mismatch")
            self.assertEqual(mismatch["next_action"], "inspect_local_state")

    def test_complete_partial_is_verified_and_finalized_without_redownload(self):
        payload = b"already complete compressed archive"
        spec = synthetic_spec(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output_dir = base / "raw"
            output_dir.mkdir()
            receipt_dir = base / "receipts"
            partial = output_dir / f".{spec['filename']}.part"
            partial.write_bytes(payload)
            with mock.patch.object(
                MODULE.urllib.request,
                "urlopen",
                return_value=Response(metadata(spec)),
            ) as urlopen:
                archive = MODULE.download(spec, output_dir, receipt_dir)
            self.assertEqual(archive.read_bytes(), payload)
            self.assertFalse(partial.exists())
            self.assertEqual(urlopen.call_count, 1)

            archive.unlink()
            MODULE.receipt_path(archive, receipt_dir).unlink()
            partial.write_bytes(payload)
            wrong = {**spec, "archive_md5": "0" * 32}
            with (
                mock.patch.object(
                    MODULE.urllib.request,
                    "urlopen",
                    return_value=Response(metadata(wrong)),
                ),
                self.assertRaisesRegex(MODULE.FetchError, "archive_md5_mismatch"),
            ):
                MODULE.download(wrong, output_dir, receipt_dir)

    def test_partial_download_resumes_only_with_matching_content_range(self):
        payload = b"0123456789"
        spec = synthetic_spec(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output_dir = base / "raw"
            output_dir.mkdir()
            receipt_dir = base / "receipts"
            partial = output_dir / f".{spec['filename']}.part"
            partial.write_bytes(payload[:4])
            responses = [
                Response(metadata(spec)),
                Response(
                    payload[4:],
                    status=206,
                    headers={"Content-Range": f"bytes 4-9/{len(payload)}"},
                ),
            ]
            with mock.patch.object(
                MODULE.urllib.request, "urlopen", side_effect=responses
            ):
                archive = MODULE.download(spec, output_dir, receipt_dir)
            self.assertEqual(archive.read_bytes(), payload)

            archive.unlink()
            MODULE.receipt_path(archive, receipt_dir).unlink()
            partial.write_bytes(payload[:4])
            bad_responses = [
                Response(metadata(spec)),
                Response(payload[4:], status=200),
            ]
            with (
                mock.patch.object(
                    MODULE.urllib.request, "urlopen", side_effect=bad_responses
                ),
                self.assertRaisesRegex(MODULE.FetchError, "resume_requires_http_206"),
            ):
                MODULE.download(spec, output_dir, receipt_dir)

    def test_remote_drift_and_unsafe_paths_fail_closed(self):
        payload = b"bounded"
        spec = synthetic_spec(payload)
        drift = json.loads(metadata(spec))
        drift["totalBytes"] += 1
        with (
            mock.patch.object(
                MODULE.urllib.request,
                "urlopen",
                return_value=Response(json.dumps(drift).encode()),
            ),
            self.assertRaisesRegex(MODULE.FetchError, "remote_metadata_drift"),
        ):
            MODULE.validate_remote_metadata(spec)

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            output_dir = base / "raw"
            output_dir.mkdir()
            archive = output_dir / spec["filename"]
            target = base / "target"
            target.write_bytes(payload)
            archive.symlink_to(target)
            with self.assertRaisesRegex(MODULE.FetchError, "unsafe_archive_path"):
                MODULE.download(spec, output_dir, base / "receipts")

            archive.unlink()
            archive.write_bytes(payload)
            receipt_dir = base / "receipts"
            receipt_dir.mkdir(exist_ok=True)
            receipt = MODULE.receipt_path(archive, receipt_dir)
            receipt.symlink_to(target)
            with self.assertRaisesRegex(MODULE.FetchError, "receipt_missing_or_unsafe"):
                MODULE.download(spec, output_dir, receipt_dir)

            receipt.unlink()
            receipt_dir.rmdir()
            receipt_dir.write_text("not a directory", encoding="utf-8")
            with self.assertRaisesRegex(MODULE.FetchError, "unsafe_receipt_directory"):
                MODULE.download(spec, output_dir, receipt_dir)


if __name__ == "__main__":
    unittest.main(verbosity=2)
