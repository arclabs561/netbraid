#!/usr/bin/env python3
"""Hermetic tests for the bounded Oregon State LoRa RFFI fetcher."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "fetch_osu_lora", ROOT / "data" / "fetch" / "fetch-osu-lora.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class Response(io.BytesIO):
    def __init__(self, payload=b"", *, url, status=200, headers=None):
        super().__init__(payload)
        self._url = url
        self.status = status
        self.headers = headers or {}

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def remote_file(payload, *, etag='"v1"'):
    root = MODULE.SETUPS["distances"]["root"]
    return MODULE.RemoteFile(
        setup="distances",
        path="5m/IQ_1.dat",
        url=f"{root}5m/IQ_1.dat",
        bytes=len(payload),
        etag=etag,
        last_modified="Wed, 21 Oct 2015 07:28:00 GMT",
    )


def download_response(remote, payload, *, status=200, content_range=None):
    headers = {
        "Content-Length": str(len(payload)),
        "ETag": remote.etag,
        "Last-Modified": remote.last_modified,
    }
    if content_range is not None:
        headers["Content-Range"] = content_range
    return Response(payload, url=remote.url, status=status, headers=headers)


class FetchOsuLoraTests(unittest.TestCase):
    def test_catalog_uses_all_seven_official_release_note_roots(self):
        catalog = MODULE._catalog()
        self.assertEqual(catalog["release_note"], MODULE.RELEASE_NOTE)
        self.assertEqual(len(catalog["setups"]), 7)
        self.assertEqual(
            [item["setup"] for item in catalog["setups"]], list(MODULE.SETUPS)
        )
        self.assertTrue(
            all(
                item["root"].startswith(MODULE.PUBLISHER_ROOT)
                and item["root"].endswith("/")
                for item in catalog["setups"]
            )
        )

    def test_traversal_escape_and_redirect_are_rejected(self):
        root = MODULE.SETUPS["distances"]["root"]
        escaped = b'<html><a href="../escape/">escape</a></html>'
        with (
            mock.patch.object(
                MODULE,
                "_open",
                return_value=Response(
                    escaped,
                    url=root,
                    headers={"Content-Type": "text/html"},
                ),
            ),
            self.assertRaisesRegex(MODULE.FetchError, "traversal_escape"),
        ):
            MODULE._discover_structure("distances", max_depth=4, max_entries=10)

        redirected = Response(
            b"<html></html>",
            url=f"{root}elsewhere/",
            headers={"Content-Type": "text/html"},
        )
        with (
            mock.patch.object(MODULE, "_open", return_value=redirected),
            self.assertRaisesRegex(MODULE.FetchError, "response_url_mismatch"),
        ):
            MODULE._read_index(root, root)

    def test_index_and_head_retry_only_transient_request_failures(self):
        root = MODULE.SETUPS["distances"]["root"]
        index_response = Response(
            b"<html></html>",
            url=root,
            headers={"Content-Type": "text/html"},
        )
        head_url = f"{root}sample.dat"
        head_response = Response(
            url=head_url,
            headers={"Content-Length": "7", "ETag": '"v1"'},
        )
        with (
            mock.patch.object(
                MODULE,
                "_open",
                side_effect=[urllib.error.URLError("transient"), index_response],
            ) as index_open,
            mock.patch.object(MODULE.time, "sleep") as index_sleep,
        ):
            self.assertEqual(MODULE._read_index(root, root), [])
        self.assertEqual(index_open.call_count, 2)
        index_sleep.assert_called_once_with(MODULE.REQUEST_RETRY_DELAYS_SECONDS[0])

        with (
            mock.patch.object(
                MODULE,
                "_open",
                side_effect=[urllib.error.URLError("transient"), head_response],
            ) as head_open,
            mock.patch.object(MODULE.time, "sleep") as head_sleep,
        ):
            remote = MODULE.head_remote("distances", "sample.dat", head_url)
        self.assertEqual(remote.bytes, 7)
        self.assertEqual(head_open.call_count, 2)
        head_sleep.assert_called_once_with(MODULE.REQUEST_RETRY_DELAYS_SECONDS[0])

        wrong_url = Response(
            url=f"{root}elsewhere.dat", headers={"Content-Length": "7"}
        )
        with (
            mock.patch.object(MODULE, "_open", return_value=wrong_url) as opener,
            mock.patch.object(MODULE.time, "sleep") as sleeper,
            self.assertRaisesRegex(MODULE.FetchError, "response_url_mismatch"),
        ):
            MODULE.head_remote("distances", "sample.dat", head_url)
        opener.assert_called_once()
        sleeper.assert_not_called()

    def test_resume_requires_exact_206_content_range(self):
        payload = b"0123456789"
        remote = remote_file(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = MODULE._local_path(base / "raw", remote)
            partial = target.with_name(f".{target.name}.part")
            partial.write_bytes(payload[:4])
            mismatch = download_response(
                remote,
                payload[4:],
                status=206,
                content_range=f"bytes 3-9/{len(payload)}",
            )
            with (
                mock.patch.object(MODULE, "head_remote", return_value=remote),
                mock.patch.object(MODULE, "_open", return_value=mismatch),
                self.assertRaisesRegex(MODULE.FetchError, "invalid_content_range"),
            ):
                MODULE.download_one(remote, base / "raw", base / "receipts")
            self.assertEqual(partial.read_bytes(), payload[:4])

    def test_receipt_reuse_verifies_sha256_without_second_get(self):
        payload = b"publisher bytes"
        remote = remote_file(payload)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            response = download_response(remote, payload)
            with (
                mock.patch.object(MODULE, "head_remote", return_value=remote),
                mock.patch.object(MODULE, "_open", return_value=response) as opener,
            ):
                disposition, target = MODULE.download_one(
                    remote, base / "raw", base / "receipts"
                )
                self.assertEqual(disposition, "downloaded")
                disposition, reused = MODULE.download_one(
                    remote, base / "raw", base / "receipts"
                )
            self.assertEqual(disposition, "reused")
            self.assertEqual(reused, target)
            self.assertEqual(target.read_bytes(), payload)
            receipt_path = MODULE._receipt_path(base / "receipts", remote)
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["source"], remote.as_dict())
            self.assertEqual(len(receipt["sha256"]), 64)
            self.assertEqual(opener.call_count, 1)

    def test_remote_drift_fails_before_get_or_local_write(self):
        payload = b"publisher bytes"
        expected = remote_file(payload)
        drifted = remote_file(payload, etag='"v2"')
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with (
                mock.patch.object(MODULE, "head_remote", return_value=drifted),
                mock.patch.object(MODULE, "_open") as opener,
                self.assertRaisesRegex(MODULE.FetchError, "remote_drift"),
            ):
                MODULE.download_one(expected, base / "raw", base / "receipts")
            opener.assert_not_called()
            self.assertFalse((base / "raw").exists())

    def test_inventory_is_deterministic_and_sorted(self):
        root = MODULE.SETUPS["distances"]["root"]
        child = f"{root}5m/"
        listings = {
            root: b"""
                <html><a href=\"?C=N;O=D\">Name</a>
                <a href=\"5m/\">5m/</a>
                <a href=\"z.dat\">z.dat</a></html>
            """,
            child: b"""
                <html><a href=\"../\">Parent Directory</a>
                <a href=\"b.dat\">b.dat</a>
                <a href=\"a.dat\">a.dat</a></html>
            """,
        }

        def open_fixture(request, *, timeout):
            del timeout
            url = request.full_url
            if request.get_method() == "GET":
                return Response(
                    listings[url],
                    url=url,
                    headers={"Content-Type": "text/html; charset=UTF-8"},
                )
            size = {"z.dat": 3, "5m/a.dat": 1, "5m/b.dat": 2}[url.removeprefix(root)]
            return Response(
                url=url,
                headers={
                    "Content-Length": str(size),
                    "ETag": f'"{size}"',
                    "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT",
                },
            )

        with mock.patch.object(MODULE, "_open", side_effect=open_fixture):
            first = MODULE.discover(
                ["distances"], max_depth=2, max_entries=10, workers=2
            )
            second = MODULE.discover(
                ["distances"], max_depth=2, max_entries=10, workers=2
            )
        self.assertEqual(first, second)
        self.assertEqual(
            [item["path"] for item in first["files"]],
            ["5m/a.dat", "5m/b.dat", "z.dat"],
        )
        self.assertEqual(
            first["summary"], {"files": 3, "known_bytes": 6, "unknown_size_files": 0}
        )

    def test_entry_budget_is_global_across_selected_setups(self):
        with (
            mock.patch.object(
                MODULE, "_read_index", return_value=[("one.dat", "one.dat")]
            ),
            self.assertRaisesRegex(MODULE.FetchError, "max_entries_exceeded"),
        ):
            MODULE.discover(
                ["distances", "locations"],
                max_depth=1,
                max_entries=1,
                workers=1,
            )

    def test_aggregate_byte_cap_fails_before_local_writes(self):
        remote = remote_file(b"eleven bytes")
        inventory = {"files": [remote.as_dict()]}
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            with (
                mock.patch.object(MODULE, "download_one") as download,
                self.assertRaisesRegex(MODULE.FetchError, "max_total_bytes_exceeded"),
            ):
                MODULE.fetch_inventory(
                    inventory,
                    raw_dir=base / "raw",
                    receipt_dir=base / "receipts",
                    workers=1,
                    max_total_bytes=remote.bytes - 1,
                    max_file_bytes=remote.bytes,
                )
            download.assert_not_called()
            self.assertFalse((base / "raw").exists())
            self.assertFalse((base / "receipts").exists())

    def test_symlink_destinations_are_rejected(self):
        remote = remote_file(b"bytes")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            raw = base / "raw"
            raw.mkdir()
            target = base / "outside"
            target.mkdir()
            (raw / remote.setup).symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(MODULE.FetchError, "unsafe_local_directory"):
                MODULE._local_path(raw, remote)

    def test_default_data_paths_are_gitignored(self):
        arguments = MODULE._arguments(["fetch", "distances"])
        self.assertEqual(arguments.raw_dir, ROOT / "data" / "raw" / "osu-lora")
        self.assertEqual(arguments.receipt_dir, ROOT / "data" / "receipts" / "osu-lora")
        ignores = set((ROOT / ".gitignore").read_text(encoding="utf-8").splitlines())
        self.assertIn("/data/raw/", ignores)
        self.assertIn("/data/receipts/", ignores)


if __name__ == "__main__":
    unittest.main(verbosity=2)
