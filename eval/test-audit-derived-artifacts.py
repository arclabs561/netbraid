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
        (self.root / "data/derived/eval").mkdir(parents=True)
        (self.root / "eval/produce.py").write_text(
            "from pathlib import Path\n"
            "OUTPUTS = ('result.json', 'future.json')\n"
            "def main():\n"
            "    for output in OUTPUTS:\n"
            "        (Path('data/derived/eval') / output).write_text('{}')\n"
            "    return 0\n"
            "if __name__ == '__main__':\n"
            "    raise SystemExit(main())\n",
            encoding="utf-8",
        )
        (self.root / "justfile").write_text(
            "derive:\n    python3 eval/produce.py\n",
            encoding="utf-8",
        )
        (self.root / "data/derived/eval/result.json").write_bytes(
            b"opaque corpus output"
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
        self.assertEqual(report["artifact_count"], 1)
        self.assertEqual(report["contract_entry_count"], 2)
        self.assertEqual(report["scripted_output_count"], 2)
        self.assertEqual(report["exception_count"], 0)
        self.assertEqual(report["producer_count"], 1)
        self.assertEqual(report["custodian_count"], 0)
        self.assertNotIn("missing_declared_artifact", report["error_counts"])
        self.assertEqual(
            report["retention_counts"],
            {"legacy/unknown": 0, "reproducibility_output": 1},
        )
        self.assertEqual(
            report["format_counts"], {"cap": 0, "json": 1, "npy": 0, "tsv": 0}
        )
        encoded = json.dumps(report, sort_keys=True)
        for forbidden in (
            os.fspath(self.root),
            "result.json",
            "eval/produce.py",
            "data/derived",
        ):
            self.assertNotIn(forbidden, encoded)
        self.assertLess(len(encoded.encode("utf-8")), MODULE.MAX_REPORT_BYTES)

    def test_rejects_legacy_custodian_entry_with_zero_compatibility_counts(
        self,
    ) -> None:
        legacy_path = self.root / "data/derived/archive/legacy-unscripted/archive.tsv"
        legacy_path.parent.mkdir(parents=True)
        legacy_path.write_bytes(b"opaque\tcorpus\n")
        self.contract["artifacts"].append(
            {
                "path": "data/derived/archive/legacy-unscripted/archive.tsv",
                "format": "tsv",
                "retention": "legacy/unknown",
                "custodian": "eval/produce.py",
            }
        )
        self._write_contract()

        report = self._audit()

        self.assertFalse(report["ok"])
        self.assertEqual(report["error_counts"]["invalid_retention"], 1)
        self.assertEqual(report["error_counts"]["unclassified_artifact"], 1)
        self.assertEqual(report["exception_count"], 0)
        self.assertEqual(report["custodian_count"], 0)
        self.assertEqual(report["retention_counts"]["legacy/unknown"], 0)

    def test_rejects_custodian_key_on_reproducibility_output(self) -> None:
        self.contract["artifacts"].append(
            {
                "path": "data/derived/eval/custodian.json",
                "format": "json",
                "retention": "reproducibility_output",
                "custodian": "eval/produce.py",
            }
        )
        self._write_contract()

        report = self._audit()

        self.assertFalse(report["ok"])
        self.assertEqual(report["error_counts"]["invalid_contract_entry"], 1)
        self.assertEqual(report["exception_count"], 0)
        self.assertEqual(report["custodian_count"], 0)

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

    def test_requires_actual_python_or_uv_producer_invocation(self) -> None:
        invalid_recipes = {
            "echo": "derive:\n    echo python3 eval/produce.py result.json\n",
            "comment": "derive:\n    # python3 eval/produce.py result.json\n",
        }
        for label, recipe in invalid_recipes.items():
            with self.subTest(label=label):
                (self.root / "justfile").write_text(recipe, encoding="utf-8")
                errors = self._audit()["error_counts"]
                self.assertEqual(errors["producer_not_invoked_by_recipe"], 2)

        (self.root / "justfile").write_text(
            "derive:\n"
            "    uv run --script eval/produce.py --out "
            "data/derived/eval/result.json\n",
            encoding="utf-8",
        )
        errors = self._audit()["error_counts"]
        self.assertNotIn("producer_not_invoked_by_recipe", errors)

    def test_rejects_comment_only_producer(self) -> None:
        (self.root / "eval/produce.py").write_text(
            "# result.json\n# executable producer entrypoint\n",
            encoding="utf-8",
        )

        errors = self._audit()["error_counts"]

        self.assertEqual(errors["producer_missing_entrypoint"], 1)
        self.assertEqual(errors["artifact_not_declared_by_producer_or_recipe"], 2)

    def test_ignores_producer_docstrings_as_output_evidence(self) -> None:
        (self.root / "eval/produce.py").write_text(
            '"""result.json"""\n'
            "def main():\n"
            "    return 0\n"
            "if __name__ == '__main__':\n"
            "    raise SystemExit(main())\n",
            encoding="utf-8",
        )

        errors = self._audit()["error_counts"]

        self.assertEqual(errors["artifact_not_declared_by_producer_or_recipe"], 2)

    def test_rejects_noop_producer_that_only_names_outputs(self) -> None:
        (self.root / "eval/produce.py").write_text(
            "OUTPUTS = ('result.json', 'future.json')\n"
            "def main():\n"
            "    return 0\n"
            "if __name__ == '__main__':\n"
            "    raise SystemExit(main())\n",
            encoding="utf-8",
        )

        errors = self._audit()["error_counts"]

        self.assertNotIn("producer_missing_entrypoint", errors)
        self.assertEqual(errors["artifact_not_declared_by_producer_or_recipe"], 2)

    def test_allows_an_absent_derived_root_for_a_fresh_clone(self) -> None:
        self.contract["derived_root"] = "fresh/derived"
        self.contract["artifacts"] = [
            {
                "path": "fresh/derived/future.json",
                "format": "json",
                "retention": "reproducibility_output",
                "producer": "eval/produce.py",
                "recipe": "derive",
            }
        ]
        self._write_contract()

        report = self._audit()

        self.assertTrue(report["ok"])
        self.assertEqual(report["artifact_count"], 0)

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
