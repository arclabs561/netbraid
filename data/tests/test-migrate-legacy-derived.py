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
from unittest import mock

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


def fixture(
    directory: str, *, populate_raw: bool = True
) -> tuple[Path, Path, Path, dict[str, bytes]]:
    base = Path(directory)
    raw_dir = base / "raw"
    archive_dir = base / "archive" / "legacy-derived-unknown"
    legacy_archive_dir = base / "derived" / "archive" / "legacy-unscripted"
    raw_dir.mkdir()
    payloads = {
        basename: f"fixture-{index}-{basename}\n".encode()
        for index, basename in enumerate(MODULE.ALLOWLIST)
    }
    if populate_raw:
        for basename, payload in payloads.items():
            (raw_dir / basename).write_bytes(payload)
    return raw_dir, archive_dir, legacy_archive_dir, payloads


def expected_receipt(payloads: dict[str, bytes]) -> dict[str, object]:
    return {
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
    }


def write_verified_archive(archive_dir: Path, payloads: dict[str, bytes]) -> None:
    archive_dir.mkdir(parents=True)
    for basename, payload in payloads.items():
        (archive_dir / basename).write_bytes(payload)
    (archive_dir / MODULE.RECEIPT_BASENAME).write_text(
        json.dumps(expected_receipt(payloads), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def archive_snapshot(archive_dir: Path) -> dict[str, bytes]:
    return {path.name: path.read_bytes() for path in archive_dir.iterdir()}


def run_main(
    raw_dir: Path, archive_dir: Path, legacy_archive_dir: Path
) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        exit_code = MODULE.main(
            [
                "--raw-dir",
                str(raw_dir),
                "--archive-dir",
                str(archive_dir),
                "--legacy-archive-dir",
                str(legacy_archive_dir),
            ]
        )
    return exit_code, stdout.getvalue(), stderr.getvalue()


class LegacyDerivedMigrationTests(unittest.TestCase):
    def test_fresh_raw_migration_uses_new_path_and_path_free_receipt(self):
        self.assertEqual(
            MODULE.DEFAULT_ARCHIVE_DIR,
            MODULE.REPOSITORY / "data" / "archive" / "legacy-derived-unknown",
        )
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, archive_dir, legacy_archive_dir, payloads = fixture(directory)
            unrelated = raw_dir / "public-corpus-members.json"
            unrelated.write_bytes(b"not allowlisted")

            exit_code, stdout, stderr = run_main(
                raw_dir, archive_dir, legacy_archive_dir
            )

            self.assertEqual(exit_code, 0, stderr)
            self.assertEqual(
                json.loads(stdout),
                {"files": len(MODULE.ALLOWLIST), "status": "migrated"},
            )
            self.assertEqual(stderr, "")
            self.assertFalse(legacy_archive_dir.exists())
            self.assertEqual(unrelated.read_bytes(), b"not allowlisted")
            self.assertTrue(all(not (raw_dir / name).exists() for name in payloads))
            self.assertEqual(
                {path.name for path in archive_dir.iterdir()},
                {*MODULE.ALLOWLIST, MODULE.RECEIPT_BASENAME},
            )
            for basename, payload in payloads.items():
                self.assertEqual((archive_dir / basename).read_bytes(), payload)

            receipt_path = archive_dir / MODULE.RECEIPT_BASENAME
            receipt_bytes = receipt_path.read_bytes()
            self.assertEqual(json.loads(receipt_bytes), expected_receipt(payloads))
            self.assertNotIn(directory, receipt_bytes.decode())
            self.assertFalse(
                any(
                    path.name.startswith(f".{MODULE.RECEIPT_BASENAME}.")
                    for path in archive_dir.iterdir()
                )
            )

    def test_already_new_archive_is_verified_idempotently(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, archive_dir, legacy_archive_dir, _payloads = fixture(directory)
            exit_code, _stdout, stderr = run_main(
                raw_dir, archive_dir, legacy_archive_dir
            )
            self.assertEqual(exit_code, 0, stderr)
            before = archive_snapshot(archive_dir)

            exit_code, stdout, stderr = run_main(
                raw_dir, archive_dir, legacy_archive_dir
            )

            self.assertEqual(exit_code, 0, stderr)
            self.assertEqual(
                json.loads(stdout),
                {"files": len(MODULE.ALLOWLIST), "status": "verified"},
            )
            self.assertEqual(stderr, "")
            self.assertEqual(archive_snapshot(archive_dir), before)
            self.assertFalse(legacy_archive_dir.exists())

    def test_verified_legacy_archive_relocates_without_changing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, archive_dir, legacy_archive_dir, payloads = fixture(
                directory, populate_raw=False
            )
            write_verified_archive(legacy_archive_dir, payloads)
            before = archive_snapshot(legacy_archive_dir)

            exit_code, stdout, stderr = run_main(
                raw_dir, archive_dir, legacy_archive_dir
            )

            self.assertEqual(exit_code, 0, stderr)
            self.assertEqual(
                json.loads(stdout),
                {"files": len(MODULE.ALLOWLIST), "status": "relocated"},
            )
            self.assertEqual(stderr, "")
            self.assertFalse(os.path.lexists(legacy_archive_dir))
            self.assertEqual(archive_snapshot(archive_dir), before)
            self.assertNotIn(
                directory,
                (archive_dir / MODULE.RECEIPT_BASENAME).read_text(encoding="utf-8"),
            )

    def test_partial_and_conflicting_states_fail_without_changes(self):
        cases = (
            "partial_raw",
            "partial_legacy",
            "target_conflict",
            "receipt_conflict",
            "both_complete",
        )
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                raw_dir, archive_dir, legacy_archive_dir, payloads = fixture(
                    directory, populate_raw=case == "partial_raw"
                )
                selected = MODULE.ALLOWLIST[0]
                if case == "partial_raw":
                    (raw_dir / selected).unlink()
                else:
                    write_verified_archive(legacy_archive_dir, payloads)
                    if case == "partial_legacy":
                        (legacy_archive_dir / selected).unlink()
                    elif case == "target_conflict":
                        archive_dir.mkdir(parents=True)
                        (archive_dir / selected).write_bytes(b"do not overwrite")
                    elif case == "receipt_conflict":
                        archive_dir.mkdir(parents=True)
                        (archive_dir / MODULE.RECEIPT_BASENAME).write_bytes(
                            b"do not overwrite"
                        )
                    else:
                        write_verified_archive(archive_dir, payloads)
                raw_before = {
                    path.name: path.read_bytes() for path in raw_dir.iterdir()
                }
                archive_before = (
                    archive_snapshot(archive_dir) if archive_dir.exists() else None
                )
                legacy_before = (
                    archive_snapshot(legacy_archive_dir)
                    if legacy_archive_dir.exists()
                    else None
                )

                exit_code, stdout, stderr = run_main(
                    raw_dir, archive_dir, legacy_archive_dir
                )

                self.assertEqual(exit_code, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(
                    json.loads(stderr),
                    {"error": "incomplete_or_conflicting_state", "status": "error"},
                )
                self.assertEqual(
                    {path.name: path.read_bytes() for path in raw_dir.iterdir()},
                    raw_before,
                )
                self.assertEqual(
                    archive_snapshot(archive_dir) if archive_dir.exists() else None,
                    archive_before,
                )
                self.assertEqual(
                    archive_snapshot(legacy_archive_dir)
                    if legacy_archive_dir.exists()
                    else None,
                    legacy_before,
                )

    def test_symlink_sources_entries_and_archive_paths_fail_closed(self):
        for case in ("raw_entry", "legacy_entry", "legacy_path", "target_path"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                raw_dir, archive_dir, legacy_archive_dir, payloads = fixture(
                    directory, populate_raw=case == "raw_entry"
                )
                selected = MODULE.ALLOWLIST[0]
                outside = Path(directory) / "outside"
                if case == "raw_entry":
                    outside.write_bytes(payloads[selected])
                    (raw_dir / selected).unlink()
                    (raw_dir / selected).symlink_to(outside)
                elif case == "legacy_entry":
                    write_verified_archive(legacy_archive_dir, payloads)
                    outside.write_bytes(payloads[selected])
                    (legacy_archive_dir / selected).unlink()
                    (legacy_archive_dir / selected).symlink_to(outside)
                elif case == "legacy_path":
                    write_verified_archive(outside, payloads)
                    legacy_archive_dir.parent.mkdir(parents=True)
                    legacy_archive_dir.symlink_to(outside, target_is_directory=True)
                else:
                    outside.mkdir()
                    archive_dir.parent.mkdir(parents=True)
                    archive_dir.symlink_to(outside, target_is_directory=True)

                exit_code, stdout, stderr = run_main(
                    raw_dir, archive_dir, legacy_archive_dir
                )

                self.assertEqual(exit_code, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(json.loads(stderr)["status"], "error")
                self.assertTrue(os.path.lexists(outside))
                if case != "target_path":
                    self.assertFalse(os.path.lexists(archive_dir))

    def test_interrupted_relocation_preserves_every_file_and_reruns(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, archive_dir, legacy_archive_dir, payloads = fixture(
                directory, populate_raw=False
            )
            write_verified_archive(legacy_archive_dir, payloads)
            before = archive_snapshot(legacy_archive_dir)
            move_new = MODULE._move_new
            calls = 0

            def interrupt_after_two_moves(source, target, expected):
                nonlocal calls
                if calls == 2:
                    raise MODULE.MigrationError("injected_move_failure")
                calls += 1
                move_new(source, target, expected)

            with mock.patch.object(MODULE, "_move_new", interrupt_after_two_moves):
                exit_code, stdout, stderr = run_main(
                    raw_dir, archive_dir, legacy_archive_dir
                )

            self.assertEqual(exit_code, 1)
            self.assertEqual(stdout, "")
            self.assertEqual(
                json.loads(stderr),
                {"error": "injected_move_failure", "status": "error"},
            )
            for basename, original in before.items():
                copies = [
                    path.read_bytes()
                    for path in (
                        legacy_archive_dir / basename,
                        archive_dir / basename,
                    )
                    if os.path.lexists(path)
                ]
                self.assertEqual(copies, [original])

            exit_code, stdout, stderr = run_main(
                raw_dir, archive_dir, legacy_archive_dir
            )
            self.assertEqual(exit_code, 0, stderr)
            self.assertEqual(
                json.loads(stdout),
                {"files": len(MODULE.ALLOWLIST), "status": "relocated"},
            )
            self.assertEqual(stderr, "")
            self.assertFalse(os.path.lexists(legacy_archive_dir))
            self.assertEqual(archive_snapshot(archive_dir), before)

    def test_rerun_retires_same_inode_duplicates_without_changing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, archive_dir, legacy_archive_dir, payloads = fixture(
                directory, populate_raw=False
            )
            write_verified_archive(legacy_archive_dir, payloads)
            before = archive_snapshot(legacy_archive_dir)
            archive_dir.mkdir(parents=True)
            for basename in (MODULE.ALLOWLIST[0], MODULE.RECEIPT_BASENAME):
                os.link(legacy_archive_dir / basename, archive_dir / basename)

            exit_code, stdout, stderr = run_main(
                raw_dir, archive_dir, legacy_archive_dir
            )

            self.assertEqual(exit_code, 0, stderr)
            self.assertEqual(
                json.loads(stdout),
                {"files": len(MODULE.ALLOWLIST), "status": "relocated"},
            )
            self.assertEqual(stderr, "")
            self.assertFalse(os.path.lexists(legacy_archive_dir))
            self.assertEqual(archive_snapshot(archive_dir), before)

    def test_each_entry_can_resume_when_already_at_new_path(self):
        entries = (*MODULE.ALLOWLIST, MODULE.RECEIPT_BASENAME)
        for selected in entries:
            with (
                self.subTest(selected=selected),
                tempfile.TemporaryDirectory() as directory,
            ):
                raw_dir, archive_dir, legacy_archive_dir, payloads = fixture(
                    directory, populate_raw=False
                )
                write_verified_archive(legacy_archive_dir, payloads)
                before = archive_snapshot(legacy_archive_dir)
                archive_dir.mkdir(parents=True)
                (legacy_archive_dir / selected).rename(archive_dir / selected)

                exit_code, stdout, stderr = run_main(
                    raw_dir, archive_dir, legacy_archive_dir
                )

                self.assertEqual(exit_code, 0, stderr)
                self.assertEqual(
                    json.loads(stdout),
                    {"files": len(MODULE.ALLOWLIST), "status": "relocated"},
                )
                self.assertEqual(stderr, "")
                self.assertFalse(os.path.lexists(legacy_archive_dir))
                self.assertEqual(archive_snapshot(archive_dir), before)

    def test_unrelated_archive_entries_fail_without_changes(self):
        for location in ("legacy", "archive"):
            with (
                self.subTest(location=location),
                tempfile.TemporaryDirectory() as directory,
            ):
                raw_dir, archive_dir, legacy_archive_dir, payloads = fixture(
                    directory, populate_raw=False
                )
                write_verified_archive(legacy_archive_dir, payloads)
                conflict_dir = (
                    legacy_archive_dir if location == "legacy" else archive_dir
                )
                conflict_dir.mkdir(parents=True, exist_ok=True)
                (conflict_dir / "unrelated.json").write_bytes(b"do not move")
                archive_before = (
                    archive_snapshot(archive_dir) if archive_dir.exists() else None
                )
                legacy_before = archive_snapshot(legacy_archive_dir)

                exit_code, stdout, stderr = run_main(
                    raw_dir, archive_dir, legacy_archive_dir
                )

                self.assertEqual(exit_code, 1)
                self.assertEqual(stdout, "")
                self.assertEqual(
                    json.loads(stderr),
                    {"error": "archive_conflict", "status": "error"},
                )
                self.assertEqual(
                    archive_snapshot(archive_dir) if archive_dir.exists() else None,
                    archive_before,
                )
                self.assertEqual(archive_snapshot(legacy_archive_dir), legacy_before)

    def test_verified_archive_rejects_changed_payload_without_overwriting_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_dir, archive_dir, legacy_archive_dir, _payloads = fixture(directory)
            exit_code, _stdout, stderr = run_main(
                raw_dir, archive_dir, legacy_archive_dir
            )
            self.assertEqual(exit_code, 0, stderr)
            receipt_path = archive_dir / MODULE.RECEIPT_BASENAME
            receipt_before = receipt_path.read_bytes()
            selected = archive_dir / MODULE.ALLOWLIST[0]
            selected.write_bytes(b"changed archive")

            exit_code, stdout, stderr = run_main(
                raw_dir, archive_dir, legacy_archive_dir
            )

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
