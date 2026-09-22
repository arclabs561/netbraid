#!/usr/bin/env python3
"""Hermetic tests for the safe dataset-fetch orchestration boundary."""

from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("dataset_fetch", ROOT / "data/fetch/dataset-fetch.py")
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


class DatasetFetchTests(unittest.TestCase):
    def test_parser_requires_action_and_selection(self) -> None:
        with self.assertRaises(SystemExit):
            module._parser().parse_args(["fetch"])

    def test_sources_are_explicit_and_no_all_default_exists(self) -> None:
        self.assertNotIn("all", module.FETCHERS)
        self.assertEqual(module._selection_args("osu-lora", "days-indoor", "fetch"), ("fetch", "days-indoor"))

    def test_plan_reports_pinned_bytes_and_terms(self) -> None:
        catalog = {
            "demo": {"bytes": 123, "license": "CC0", "group": "baseline"},
            "other": {"bytes": 7, "license": "MIT", "group": "other"},
        }
        completed = module.subprocess.CompletedProcess([], 0, json.dumps(catalog), "")
        with patch.object(module, "_run", return_value=completed):
            plan = module._plan("public-eval", "demo")
        self.assertEqual(plan["estimated_bytes"], 123)
        self.assertEqual(plan["terms"], ["CC0"])

    def test_fetch_without_confirmation_never_invokes_fetcher(self) -> None:
        with patch.object(module, "_plan", return_value={"estimated_bytes": 10, "terms": ["MIT"]}), patch.object(module, "_run") as run:
            result = module.main(["fetch", "smorffi", "smorffi",])
        self.assertEqual(result, 3)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
