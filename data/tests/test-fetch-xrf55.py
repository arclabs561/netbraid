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
            archive = MODULE.download(spec, Path(directory))
            self.assertEqual(archive.read_bytes(), payload)
            receipt = json.loads(MODULE.receipt_path(archive).read_text())
            self.assertEqual(
                receipt, MODULE.source_receipt(spec, len(payload), receipt["sha256"])
            )
            MODULE.download(spec, Path(directory))
            self.assertEqual(urlopen.call_count, 2)

    def test_complete_partial_is_verified_and_finalized_without_redownload(self):
        payload = b"already complete compressed archive"
        spec = synthetic_spec(payload)
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
            partial = output_dir / f".{spec['filename']}.part"
            partial.write_bytes(payload)
            with mock.patch.object(
                MODULE.urllib.request,
                "urlopen",
                return_value=Response(metadata(spec)),
            ) as urlopen:
                archive = MODULE.download(spec, output_dir)
            self.assertEqual(archive.read_bytes(), payload)
            self.assertFalse(partial.exists())
            self.assertEqual(urlopen.call_count, 1)

            archive.unlink()
            MODULE.receipt_path(archive).unlink()
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
                MODULE.download(wrong, output_dir)

    def test_partial_download_resumes_only_with_matching_content_range(self):
        payload = b"0123456789"
        spec = synthetic_spec(payload)
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory)
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
                archive = MODULE.download(spec, output_dir)
            self.assertEqual(archive.read_bytes(), payload)

            archive.unlink()
            MODULE.receipt_path(archive).unlink()
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
                MODULE.download(spec, output_dir)

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
            archive = Path(directory) / spec["filename"]
            target = Path(directory) / "target"
            target.write_bytes(payload)
            archive.symlink_to(target)
            with self.assertRaisesRegex(MODULE.FetchError, "unsafe_archive_path"):
                MODULE.download(spec, Path(directory))


if __name__ == "__main__":
    unittest.main(verbosity=2)
