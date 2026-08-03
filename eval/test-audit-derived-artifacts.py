#!/usr/bin/env python3
"""Hermetic tests for the ignored derived-artifact audit."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest import mock

SCRIPT = Path(__file__).with_name("audit-derived-artifacts.py")
SPEC = importlib.util.spec_from_file_location("audit_derived_artifacts", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("failed to load audit module")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class DerivedArtifactAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "eval").mkdir()
        (self.root / "data/derived/eval/campaign").mkdir(parents=True)
        (self.root / "eval/produce.py").write_text(
            "OUTPUTS = ('result.json', 'campaign/archive.tsv', 'future.json')\n",
            encoding="utf-8",
        )
        (self.root / "justfile").write_text(
            "derive:\n    python3 eval/produce.py\n",
            encoding="utf-8",
        )
        (self.root / "data/derived/eval/result.json").write_bytes(
            b"opaque corpus output"
        )
        (self.root / "data/derived/eval/campaign/archive.tsv").write_bytes(
            b"opaque\tcorpus\n"
        )
        self.contract = {
            "schema": MODULE.SCHEMA,
            "derived_root": "data/derived",
            "artifacts": [
                {
                    "path": "data/derived/eval/result.json",
                    "format": "json",
                    "retention": "reproducibility_output",
                    "producer": "eval/produce.py",
                    "recipe": "derive",
                },
                {
                    "path": "data/derived/eval/campaign/archive.tsv",
                    "format": "tsv",
                    "retention": "legacy/unknown",
                    "producer": "eval/produce.py",
                    "recipe": "derive",
                },
                {
                    "path": "data/derived/eval/future.json",
                    "format": "json",
                    "retention": "reproducibility_output",
                    "producer": "eval/produce.py",
                    "recipe": "derive",
                },
            ],
        }
        self.contract_path = self.root / "eval/contract.json"
        self.tracked = {"eval/contract.json", "eval/produce.py", "justfile"}
        self._write_contract()

    def _write_contract(self) -> None:
        self.contract_path.write_text(
            json.dumps(self.contract, sort_keys=True), encoding="utf-8"
        )

    def _audit(self) -> dict[str, object]:
        return MODULE.audit_repository(
            self.root,
            PurePosixPath("eval/contract.json"),
            tracked_paths=self.tracked,
        )

    def test_success_is_path_free_aggregate_and_never_opens_artifacts(self) -> None:
        real_open = MODULE.os.open
        derived_root = os.fspath(self.root / "data/derived")

        def guarded_open(path, *args, **kwargs):
            if os.fspath(path).startswith(derived_root):
                raise AssertionError("audit opened a derived artifact")
            return real_open(path, *args, **kwargs)

        with mock.patch.object(MODULE.os, "open", side_effect=guarded_open):
            report = self._audit()

        self.assertTrue(report["ok"])
        self.assertEqual(report["artifact_count"], 2)
        self.assertEqual(report["contract_entry_count"], 3)
        self.assertEqual(
            report["retention_counts"],
            {"legacy/unknown": 1, "reproducibility_output": 1},
        )
        self.assertEqual(report["format_counts"], {"json": 1, "tsv": 1})
        encoded = json.dumps(report, sort_keys=True)
        for forbidden in (
            os.fspath(self.root),
            "result.json",
            "archive.tsv",
            "eval/produce.py",
            "data/derived",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertLess(len(encoded.encode("utf-8")), MODULE.MAX_REPORT_BYTES)

    def test_rejects_unclassified_and_duplicate_artifacts(self) -> None:
        (self.root / "data/derived/eval/unclassified.json").write_bytes(b"unknown")
        duplicate = copy.deepcopy(self.contract["artifacts"][0])
        self.contract["artifacts"].append(duplicate)
        self._write_contract()

        errors = self._audit()["error_counts"]

        self.assertEqual(errors["unclassified_artifact"], 1)
        self.assertEqual(errors["duplicate_contract_entry"], 1)

    def test_rejects_symlinks_and_special_files_without_following_them(self) -> None:
        target = self.root / "outside.json"
        target.write_text("private corpus payload", encoding="utf-8")
        link = self.root / "data/derived/eval/link.json"
        link.symlink_to(target)
        fifo = self.root / "data/derived/eval/special.tsv"
        os.mkfifo(fifo)

        report = self._audit()

        self.assertFalse(report["ok"])
        self.assertEqual(report["error_counts"]["unsafe_artifact_type"], 2)

    def test_rejects_missing_untracked_and_unwired_producers(self) -> None:
        cases = (
            ("missing", "eval/missing.py", {"justfile"}, "missing_or_unsafe_producer"),
            ("untracked", "eval/produce.py", {"justfile"}, "untracked_producer"),
        )
        for label, producer, tracked, expected in cases:
            with self.subTest(label=label):
                self.contract["artifacts"][0]["producer"] = producer
                self._write_contract()
                report = MODULE.audit_repository(
                    self.root,
                    PurePosixPath("eval/contract.json"),
                    tracked_paths={"eval/contract.json", *tracked},
                )
                self.assertIn(expected, report["error_counts"])
                self.contract["artifacts"][0]["producer"] = "eval/produce.py"

        (self.root / "justfile").write_text(
            "derive:\n    python3 eval/produce.py.backup result.json\n",
            encoding="utf-8",
        )
        self.assertIn("producer_not_invoked_by_recipe", self._audit()["error_counts"])

    def test_rejects_untracked_contract(self) -> None:
        tracked = self.tracked - {"eval/contract.json"}

        report = MODULE.audit_repository(
            self.root,
            PurePosixPath("eval/contract.json"),
            tracked_paths=tracked,
        )

        self.assertEqual(report["error_counts"]["untracked_contract"], 1)

    def test_rejects_missing_recipe_definition_and_undeclared_output(self) -> None:
        self.contract["artifacts"][0]["recipe"] = "absent"
        self._write_contract()
        self.assertIn("missing_recipe", self._audit()["error_counts"])

        self.contract["artifacts"][0]["recipe"] = "derive"
        self.contract["artifacts"][0]["path"] = "data/derived/eval/unnamed.json"
        (self.root / "data/derived/eval/result.json").rename(
            self.root / "data/derived/eval/unnamed.json"
        )
        self._write_contract()
        self.assertIn(
            "artifact_not_declared_by_producer_or_recipe",
            self._audit()["error_counts"],
        )

    def test_rejects_absolute_private_and_out_of_scope_contract_paths(self) -> None:
        cases = (
            (
                "absolute",
                "/Users/private/eval/produce.py",
                "private_or_absolute_contract_path",
            ),
            ("home", "~/eval/produce.py", "private_or_absolute_contract_path"),
            ("escape", "../eval/produce.py", "invalid_producer_path"),
        )
        for label, producer, expected in cases:
            with self.subTest(label=label):
                self.contract["artifacts"][0]["producer"] = producer
                self._write_contract()
                report = self._audit()
                self.assertFalse(report["ok"])
                self.assertIn(expected, report["error_counts"])
        self.contract["artifacts"][0]["producer"] = "eval/produce.py"
        self.contract["artifacts"][0]["path"] = "data/raw/result.json"
        self._write_contract()
        self.assertIn("artifact_outside_derived_root", self._audit()["error_counts"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
