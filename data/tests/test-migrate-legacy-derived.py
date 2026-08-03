#!/usr/bin/env python3
"""Hermetic tests for the one-time legacy derived-output migration."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "migrate_legacy_derived",
    HERE.parent / "migrate" / "migrate-legacy-derived.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def fixture(directory: str) -> tuple[Path, Path, dict[str, bytes]]:
    base = Path(directory)
    raw_dir = base / "raw"
    archive_dir = base / "derived" / "archive" / "legacy-unscripted"
    raw_dir.mkdir()
    payloads = {
        basename: f"fixture-{index}-{basename}\n".encode()
        for index, basename in enumerate(MODULE.ALLOWLIST)
    }
    for basename, payload in payloads.items():
        (raw_dir / basename).write_bytes(payload)
    return raw_dir, archive_dir, payloads


def run_main(raw_dir: Path, archive_dir: Path) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        exit_code = MODULE.main(
            ["--raw-dir", str(raw_dir), "--archive-dir", str(archive_dir)]
        )
    return exit_code, stdout.getvalue(), stderr.getvalue()


class LegacyDerivedMigrationTests(unittest.TestCase):
    def test_exact_allowlist_migrates_with_path_free_receipt_and_reruns(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, archive_dir, payloads = fixture(directory)
            unrelated = raw_dir / "public-corpus-members.json"
            unrelated.write_bytes(b"not allowlisted")

            exit_code, stdout, stderr = run_main(raw_dir, archive_dir)

            self.assertEqual(exit_code, 0, stderr)
            self.assertEqual(
                json.loads(stdout),
                {"files": len(MODULE.ALLOWLIST), "status": "migrated"},
            )
            self.assertEqual(stderr, "")
            self.assertEqual(unrelated.read_bytes(), b"not allowlisted")
            self.assertTrue(all(not (raw_dir / name).exists() for name in payloads))
            receipt_path = archive_dir / MODULE.RECEIPT_BASENAME
            self.assertEqual(
                {path.name for path in archive_dir.iterdir()},
                {*MODULE.ALLOWLIST, MODULE.RECEIPT_BASENAME},
            )
            for basename, payload in payloads.items():
                self.assertEqual((archive_dir / basename).read_bytes(), payload)

            receipt_before = receipt_path.read_bytes()
            receipt = json.loads(receipt_before)
            self.assertEqual(
                receipt,
                {
                    "files": [
                        {
                            "basename": basename,
                            "bytes": len(payloads[basename]),
                            "sha256": hashlib.sha256(payloads[basename]).hexdigest(),
                            "status": "legacy/unknown",
                        }
                        for basename in MODULE.ALLOWLIST
                    ],
                    "schema": MODULE.RECEIPT_SCHEMA,
                },
            )
            self.assertNotIn(directory, receipt_before.decode())
            self.assertFalse(
                any(
                    path.name.startswith(f".{MODULE.RECEIPT_BASENAME}.")
                    for path in archive_dir.iterdir()
                )
            )

            exit_code, stdout, stderr = run_main(raw_dir, archive_dir)

            self.assertEqual(exit_code, 0, stderr)
            self.assertEqual(
                json.loads(stdout),
                {"files": len(MODULE.ALLOWLIST), "status": "verified"},
            )
            self.assertEqual(stderr, "")
            self.assertEqual(receipt_path.read_bytes(), receipt_before)

    def test_source_symlink_nonregular_and_destination_conflict_fail_closed(self):
        cases = ["symlink", "conflict"]
        if hasattr(os, "mkfifo"):
            cases.append("nonregular")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                raw_dir, archive_dir, payloads = fixture(directory)
                selected = MODULE.ALLOWLIST[0]
                original = payloads[selected]
                if case == "symlink":
                    outside = Path(directory) / "outside"
                    outside.write_bytes(original)
                    (raw_dir / selected).unlink()
                    (raw_dir / selected).symlink_to(outside)
                elif case == "nonregular":
                    (raw_dir / selected).unlink()
                    os.mkfifo(raw_dir / selected)
                else:
                    archive_dir.mkdir(parents=True)
                    (archive_dir / selected).write_bytes(b"conflict")

                exit_code, stdout, stderr = run_main(raw_dir, archive_dir)

                self.assertEqual(exit_code, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(json.loads(stderr)["status"], "error")
                if case == "conflict":
                    self.assertEqual((archive_dir / selected).read_bytes(), b"conflict")
                else:
                    self.assertFalse(archive_dir.exists())
                for basename, payload in payloads.items():
                    source = raw_dir / basename
                    if basename != selected or case == "conflict":
                        self.assertEqual(source.read_bytes(), payload)

    def test_rerun_rejects_changed_archive_without_overwriting_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, archive_dir, _payloads = fixture(directory)
            exit_code, _stdout, stderr = run_main(raw_dir, archive_dir)
            self.assertEqual(exit_code, 0, stderr)
            receipt_path = archive_dir / MODULE.RECEIPT_BASENAME
            receipt_before = receipt_path.read_bytes()
            selected = archive_dir / MODULE.ALLOWLIST[0]
            selected.write_bytes(b"changed archive")

            exit_code, stdout, stderr = run_main(raw_dir, archive_dir)

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout, "")
            self.assertEqual(
                json.loads(stderr),
                {"error": "archive_receipt_mismatch", "status": "error"},
            )
            self.assertEqual(selected.read_bytes(), b"changed archive")
            self.assertEqual(receipt_path.read_bytes(), receipt_before)


if __name__ == "__main__":
    unittest.main()
