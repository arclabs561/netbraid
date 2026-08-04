#!/usr/bin/env python3
"""Hermetic tests for the SMoRFFI relation-split capability report."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "evaluate_smorffi_relation_split_capability",
    HERE / "evaluate-smorffi-relation-split-capability.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def opaque(kind: str, index: int) -> str:
    return f"{kind}-{index:024x}"


def valid_adapter() -> dict[str, object]:
    row_count = 122_511
    spans = []
    cursor = 0
    for index in range(123):
        end = row_count if index == 122 else cursor + 1
        spans.append(
            {
                "source_file": opaque("artifact", index),
                "physical_source": opaque("source", index),
                "row_start": cursor,
                "row_end": end,
            }
        )
        cursor = end
    return {
        "schema": MODULE.ADAPTER_SCHEMA,
        "provenance": {
            "dataset_version": 3,
            "receipt_schema": "local.netbraid.smorffi.v1",
            "receipt_sha256": "1" * 64,
            "local_inventory_sha256": "2" * 64,
            "integrity_basis": "local_sha256_after_version_pinned_download",
            "publisher_checksum_available": False,
            "header_errata_applied": 1,
        },
        "artifacts": {
            "iq": {
                "format": "npy",
                "dtype": "<c16",
                "shape": [38_561_309],
                "sha256": "3" * 64,
            },
            "row_offsets": {
                "format": "npy",
                "dtype": "<u8",
                "shape": [row_count + 1],
                "sha256": "4" * 64,
            },
        },
        "axes": {
            "physical_source": {"state": "publisher_claimed", "groups": 123},
            "acquisition_session": {
                "state": "unknown",
                "reason": "not_exposed_by_publisher_metadata",
            },
            "receiver": {
                "state": "unknown",
                "reason": "not_exposed_by_publisher_metadata",
            },
            "location": {
                "state": "unknown",
                "reason": "not_exposed_by_publisher_metadata",
            },
        },
        "counts": {
            "files": 123,
            "rows": row_count,
            "samples": 38_561_309,
            "spans": 123,
            "minimum_samples_per_row": 288,
            "maximum_samples_per_row": 579,
            "rows_with_288_samples": 37_288,
        },
        "source_spans": spans,
        "privacy": {
            "absolute_paths_retained": False,
            "relative_paths_retained": False,
            "publisher_device_values_retained": False,
            "publisher_address_values_retained": False,
            "iq_values_retained_in_adapter": False,
        },
        "limitations": [
            "publisher device labels are claims, not independently verified physical identity",
            "file boundaries and row order are not acquisition-session evidence",
        ],
    }


class Fixture:
    def __init__(self, case: unittest.TestCase):
        temporary = tempfile.TemporaryDirectory()
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.adapter = self.root / "PRIVATE_ADAPTER.json"
        self.report = self.root / "derived" / "PRIVATE_REPORT.json"
        self.value = valid_adapter()
        self.write()

    def write(self) -> None:
        self.adapter.write_text(json.dumps(self.value), encoding="utf-8")
        os.chmod(self.adapter, 0o600)


class SmorffiRelationSplitCapabilityTests(unittest.TestCase):
    def test_complete_audit_blocks_only_the_unbounded_session_axis(self):
        fixture = Fixture(self)

        report = MODULE.evaluate(fixture.adapter)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(
            report["relation_split"],
            {
                "status": "blocked",
                "blocker": "unbounded_session_axis",
                "partitions_assigned": 0,
                "manifest_published": False,
            },
        )
        self.assertEqual(
            report["axes"]["physical_source"],
            {"state": "publisher_claimed", "groups": 123},
        )
        self.assertEqual(
            report["privacy"],
            {
                "iq_payload_bytes_read": 0,
                "row_offset_payload_bytes_read": 0,
                "source_identifiers_retained": 0,
                "input_paths_retained": 0,
            },
        )

    def test_report_is_path_free_and_contains_no_source_assignments(self):
        fixture = Fixture(self)
        report = MODULE.evaluate(fixture.adapter)
        MODULE.write_report(fixture.report, report)

        encoded = fixture.report.read_text(encoding="ascii")

        self.assertEqual(oct(fixture.report.stat().st_mode & 0o777), "0o600")
        for forbidden in (
            os.fspath(fixture.root),
            "PRIVATE_ADAPTER",
            opaque("source", 0),
            opaque("artifact", 0),
            "MAC_address",
            "Device Number",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_known_session_claim_is_rejected_instead_of_enabling_a_split(self):
        fixture = Fixture(self)
        fixture.value["axes"]["acquisition_session"] = {
            "state": "known",
            "groups": 123,
        }
        fixture.write()

        with self.assertRaisesRegex(MODULE.CapabilityError, "invalid_unknown_axis"):
            MODULE.evaluate(fixture.adapter)

    def test_privacy_regression_is_rejected(self):
        fixture = Fixture(self)
        fixture.value["privacy"]["relative_paths_retained"] = True
        fixture.write()

        with self.assertRaisesRegex(
            MODULE.CapabilityError, "privacy_contract_not_satisfied"
        ):
            MODULE.evaluate(fixture.adapter)

    def test_span_gap_duplicate_source_and_bad_terminal_row_are_rejected(self):
        mutations = (
            lambda value: value["source_spans"][1].update(row_start=2),
            lambda value: value["source_spans"][1].update(
                physical_source=value["source_spans"][0]["physical_source"]
            ),
            lambda value: value["source_spans"][-1].update(row_end=122_510),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                fixture = Fixture(self)
                mutate(fixture.value)
                fixture.write()
                with self.assertRaisesRegex(
                    MODULE.CapabilityError, "invalid_source_span"
                ):
                    MODULE.evaluate(fixture.adapter)

    def test_extra_field_and_duplicate_json_key_fail_closed(self):
        fixture = Fixture(self)
        fixture.value["private_path"] = "/PRIVATE/PATH"
        fixture.write()
        with self.assertRaisesRegex(MODULE.CapabilityError, "invalid_adapter_schema"):
            MODULE.evaluate(fixture.adapter)

        fixture.adapter.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
        with self.assertRaisesRegex(MODULE.CapabilityError, "invalid_adapter_json"):
            MODULE.evaluate(fixture.adapter)

    def test_invalid_input_does_not_replace_existing_report(self):
        fixture = Fixture(self)
        fixture.report.parent.mkdir()
        fixture.report.write_bytes(b"sentinel")
        broken = copy.deepcopy(fixture.value)
        broken["counts"]["rows"] = 1
        fixture.value = broken
        fixture.write()

        with self.assertRaises(MODULE.CapabilityError):
            report = MODULE.evaluate(fixture.adapter)
            MODULE.write_report(fixture.report, report)

        self.assertEqual(fixture.report.read_bytes(), b"sentinel")


if __name__ == "__main__":
    unittest.main(verbosity=2)
