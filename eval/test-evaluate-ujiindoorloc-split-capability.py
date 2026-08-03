#!/usr/bin/env python3
"""Hermetic tests for the UJIIndoorLoc split-capability evaluator."""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import io
import json
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "evaluate_ujiindoorloc_split_capability",
    HERE / "evaluate-ujiindoorloc-split-capability.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FIXED_TIME = (2020, 1, 2, 3, 4, 6)


def row(
    *,
    user: int,
    phone: int,
    building: int,
    floor: int,
    space: int,
    relative: int = 1,
    rssi: int = -50,
) -> list[str]:
    values = ["100"] * 520
    values[0] = str(rssi)
    return [
        *values,
        "-7500.25",
        "4864900.75",
        str(floor),
        str(building),
        str(space),
        str(relative),
        str(user),
        str(phone),
        "1370000000",
    ]


def csv_bytes(rows: list[list[str]]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(MODULE.EXPECTED_HEADER)
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def zip_info(name: str, *, directory: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    if directory:
        info.external_attr = (stat.S_IFDIR | 0o755) << 16
    else:
        info.external_attr = (stat.S_IFREG | 0o644) << 16
    return info


def fixture(
    root: Path,
    *,
    train_rows: list[list[str]] | None = None,
    validation_rows: list[list[str]] | None = None,
    extra_member: bool = False,
) -> tuple[Path, Path, object]:
    if train_rows is None:
        train_rows = [
            row(user=1, phone=1, building=0, floor=0, space=1),
            row(user=2, phone=2, building=1, floor=1, space=2),
            row(user=2, phone=2, building=1, floor=1, space=3),
        ]
    if validation_rows is None:
        validation_rows = [
            row(user=0, phone=2, building=0, floor=0, space=1),
            row(user=0, phone=3, building=1, floor=1, space=4),
        ]
    train_payload = csv_bytes(train_rows)
    validation_payload = csv_bytes(validation_rows)
    archive_path = root / "fixture.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(zip_info(MODULE.DIRECTORY_MEMBER, directory=True), b"")
        archive.writestr(zip_info(MODULE.TRAIN_MEMBER), train_payload)
        archive.writestr(zip_info(MODULE.VALIDATION_MEMBER), validation_payload)
        if extra_member:
            archive.writestr(zip_info("UJIndoorLoc/extra.txt"), b"unexpected")

    payload = archive_path.read_bytes()
    source = {
        "bytes": len(payload),
        "doi": "10.24432/C5MS59",
        "filename": archive_path.name,
        "group": "indoor-positioning",
        "license": "CC BY 4.0",
        "md5": hashlib.md5(payload, usedforsecurity=False).hexdigest(),
        "record": "synthetic-ujiindoorloc",
        "record_bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "sha256_provenance": "hermetic_fixture",
        "url": "https://example.test/ujiindoorloc.zip",
    }
    contract = MODULE.ArtifactContract(
        source=source,
        member_sizes={
            MODULE.TRAIN_MEMBER: len(train_payload),
            MODULE.VALIDATION_MEMBER: len(validation_payload),
        },
        row_counts={"train": len(train_rows), "validation": len(validation_rows)},
    )
    receipt_path = root / "receipt.json"
    receipt_path.write_text(
        json.dumps(MODULE._expected_receipt(contract)), encoding="utf-8"
    )
    return archive_path, receipt_path, contract


def axis(report: dict[str, object], name: str) -> dict[str, object]:
    axes = report["axes"]
    assert isinstance(axes, list)
    return next(item for item in axes if item["axis"] == name)


class UjiIndoorLocSplitCapabilityTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_reports_identity_holdouts_separately_from_target_coverage(self):
        archive, receipt, contract = fixture(self.temporary_directory())

        report = MODULE.evaluate_archive(archive, receipt, contract)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["rows"]["total"], 5)
        self.assertEqual(axis(report, "user")["intersection_group_count"], 0)
        self.assertEqual(axis(report, "phone")["intersection_group_count"], 1)
        self.assertEqual(axis(report, "building_floor")["intersection_group_count"], 2)
        self.assertEqual(axis(report, "location_cell")["intersection_group_count"], 1)
        self.assertTrue(report["capabilities"]["user_disjoint"])
        self.assertFalse(report["capabilities"]["phone_disjoint"])
        self.assertTrue(report["capabilities"]["shared_building_floor_coverage"])

    def test_report_is_aggregate_path_free_and_value_free(self):
        root = self.temporary_directory()
        archive, receipt, contract = fixture(root)

        report = MODULE.evaluate_archive(archive, receipt, contract)
        rendered = MODULE.render_report(report)

        self.assertNotIn(str(root).encode(), rendered)
        self.assertNotIn(str(contract.source["url"]).encode(), rendered)
        self.assertNotIn(b"4864900.75", rendered)
        self.assertNotIn(b"1370000000", rendered)
        self.assertEqual(
            set(report["privacy"].values()),
            {0},
        )

    def test_unexpected_member_and_invalid_rssi_fail_closed(self):
        extra_root = self.temporary_directory()
        archive, receipt, contract = fixture(extra_root, extra_member=True)
        with self.assertRaises(MODULE.SplitCapabilityError) as raised:
            MODULE.evaluate_archive(archive, receipt, contract)
        self.assertEqual(raised.exception.code, "unexpected_archive_inventory")

        rssi_root = self.temporary_directory()
        archive, receipt, contract = fixture(
            rssi_root,
            train_rows=[row(user=1, phone=1, building=0, floor=0, space=1, rssi=99)],
        )
        with self.assertRaises(MODULE.SplitCapabilityError) as raised:
            MODULE.evaluate_archive(archive, receipt, contract)
        self.assertEqual(raised.exception.code, "invalid_rssi_value")

    def test_withheld_validation_location_is_unknown_not_disjoint(self):
        root = self.temporary_directory()
        archive, receipt, contract = fixture(
            root,
            validation_rows=[
                row(
                    user=0,
                    phone=2,
                    building=0,
                    floor=0,
                    space=0,
                    relative=0,
                )
            ],
        )

        report = MODULE.evaluate_archive(archive, receipt, contract)

        location = axis(report, "location_cell")
        self.assertEqual(location["validation_observed_row_count"], 0)
        self.assertEqual(location["intersection_group_count"], 0)
        self.assertIsNone(report["capabilities"]["shared_location_cell_coverage"])

    def test_receipt_is_required_and_report_write_is_private(self):
        root = self.temporary_directory()
        archive, receipt, contract = fixture(root)
        receipt.write_text("{}", encoding="utf-8")
        with self.assertRaises(MODULE.SplitCapabilityError) as raised:
            MODULE.evaluate_archive(archive, receipt, contract)
        self.assertEqual(raised.exception.code, "receipt_contract_mismatch")

        receipt.write_text(
            json.dumps(MODULE._expected_receipt(contract)), encoding="utf-8"
        )
        report_path = root / "derived" / "report.json"
        MODULE.write_report(
            report_path,
            MODULE.render_report(MODULE.evaluate_archive(archive, receipt, contract)),
        )
        self.assertEqual(stat.S_IMODE(report_path.stat().st_mode), 0o600)

    def test_archive_mutation_fence_fails_closed(self):
        root = self.temporary_directory()
        archive, receipt, contract = fixture(root)
        integrity = MODULE._digest_regular_file(archive)
        changed = (integrity[0], integrity[1], "0" * 64)

        with mock.patch.object(
            MODULE, "_digest_regular_file", side_effect=(integrity, changed)
        ):
            with self.assertRaises(MODULE.SplitCapabilityError) as raised:
                MODULE.evaluate_archive(archive, receipt, contract)

        self.assertEqual(raised.exception.code, "archive_changed_during_evaluation")

    def test_default_publisher_split_v0_matches_requirement_oracle(self):
        archive, receipt, contract = fixture(self.temporary_directory())

        report = MODULE.evaluate_archive(archive, receipt, contract)

        expected = {
            "schema": "netbraid.ujiindoorloc_split_capability.v0",
            "status": "pass",
            "integrity": {
                "bytes": contract.source["bytes"],
                "md5": contract.source["md5"],
                "sha256": contract.source["sha256"],
            },
            "schema_summary": {
                "columns": 529,
                "rssi_columns": 520,
                "metadata_columns": 9,
                "csv_members": 2,
            },
            "rows": {
                "train": 3,
                "validation": 2,
                "total": 5,
                "observed_rssi_cells": 5,
            },
            "axes": [
                {
                    "axis": "user",
                    "policy": "identity_holdout",
                    "train_group_count": 2,
                    "validation_group_count": 1,
                    "intersection_group_count": 0,
                    "train_only_group_count": 2,
                    "validation_only_group_count": 1,
                    "train_observed_row_count": 3,
                    "validation_observed_row_count": 2,
                },
                {
                    "axis": "phone",
                    "policy": "acquisition_domain_holdout",
                    "train_group_count": 2,
                    "validation_group_count": 2,
                    "intersection_group_count": 1,
                    "train_only_group_count": 1,
                    "validation_only_group_count": 1,
                    "train_observed_row_count": 3,
                    "validation_observed_row_count": 2,
                },
                {
                    "axis": "user_phone",
                    "policy": "joint_identity_domain_holdout",
                    "train_group_count": 2,
                    "validation_group_count": 2,
                    "intersection_group_count": 0,
                    "train_only_group_count": 2,
                    "validation_only_group_count": 2,
                    "train_observed_row_count": 3,
                    "validation_observed_row_count": 2,
                },
                {
                    "axis": "building",
                    "policy": "target_coverage",
                    "train_group_count": 2,
                    "validation_group_count": 2,
                    "intersection_group_count": 2,
                    "train_only_group_count": 0,
                    "validation_only_group_count": 0,
                    "train_observed_row_count": 3,
                    "validation_observed_row_count": 2,
                },
                {
                    "axis": "floor",
                    "policy": "target_coverage",
                    "train_group_count": 2,
                    "validation_group_count": 2,
                    "intersection_group_count": 2,
                    "train_only_group_count": 0,
                    "validation_only_group_count": 0,
                    "train_observed_row_count": 3,
                    "validation_observed_row_count": 2,
                },
                {
                    "axis": "building_floor",
                    "policy": "target_coverage",
                    "train_group_count": 2,
                    "validation_group_count": 2,
                    "intersection_group_count": 2,
                    "train_only_group_count": 0,
                    "validation_only_group_count": 0,
                    "train_observed_row_count": 3,
                    "validation_observed_row_count": 2,
                },
                {
                    "axis": "location_cell",
                    "policy": "target_coverage",
                    "train_group_count": 3,
                    "validation_group_count": 2,
                    "intersection_group_count": 1,
                    "train_only_group_count": 2,
                    "validation_only_group_count": 1,
                    "train_observed_row_count": 3,
                    "validation_observed_row_count": 2,
                },
            ],
            "capabilities": {
                "user_disjoint": True,
                "phone_disjoint": False,
                "joint_user_phone_disjoint": True,
                "shared_building_floor_coverage": True,
                "shared_location_cell_coverage": True,
            },
            "privacy": {
                "rows_retained": 0,
                "rssi_vectors_retained": 0,
                "coordinate_values_retained": 0,
                "timestamp_values_retained": 0,
                "identifier_values_retained": 0,
                "member_paths_retained": 0,
                "source_urls_retained": 0,
                "local_paths_retained": 0,
            },
        }
        expected_payload = (
            json.dumps(
                expected,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")

        self.assertEqual(report, expected)
        self.assertEqual(MODULE.render_report(report), expected_payload)

    def test_phone_holdout_finds_four_disjoint_full_coverage_roles(self):
        root = self.temporary_directory()
        rows = [
            row(user=phone, phone=phone, building=building, floor=building, space=1)
            for phone in range(1, 5)
            for building in range(2)
        ]
        archive, receipt, contract = fixture(
            root,
            train_rows=rows[:4],
            validation_rows=rows[4:],
        )

        report = MODULE.evaluate_phone_holdout_feasibility(archive, receipt, contract)

        phone = report["phone_holdout"]
        self.assertEqual(report["schema"], MODULE.PHONE_HOLDOUT_SCHEMA)
        self.assertEqual(phone["status"], "candidate_found")
        self.assertIsNone(phone["blocker"])
        self.assertEqual(phone["unit_count"], 4)
        self.assertEqual(phone["minimum_target_group_unit_support"], 4)
        self.assertTrue(phone["candidate"]["all_rows_assigned_once"])
        self.assertTrue(phone["candidate"]["all_units_assigned_once"])
        self.assertEqual(phone["candidate"]["disjoint_unit_overlap_count"], 0)
        self.assertFalse(phone["candidate"]["is_benchmark_recommendation"])
        self.assertEqual(
            phone["candidate"]["row_balance_method"],
            "coverage_preserving_single_unit_local_search",
        )
        self.assertEqual(
            [
                item["missing_target_group_count"]
                for item in phone["candidate"]["roles"]
            ],
            [0, 0, 0, 0],
        )

    def test_phone_holdout_is_input_order_invariant(self):
        rows = [
            row(user=phone, phone=phone, building=building, floor=building, space=1)
            for phone in range(1, 5)
            for building in range(2)
        ]
        left = self.temporary_directory()
        left_archive, left_receipt, left_contract = fixture(
            left, train_rows=rows[:4], validation_rows=rows[4:]
        )
        right = self.temporary_directory()
        right_archive, right_receipt, right_contract = fixture(
            right,
            train_rows=list(reversed(rows[:4])),
            validation_rows=list(reversed(rows[4:])),
        )

        left_report = MODULE.evaluate_phone_holdout_feasibility(
            left_archive, left_receipt, left_contract
        )
        right_report = MODULE.evaluate_phone_holdout_feasibility(
            right_archive, right_receipt, right_contract
        )
        left_report.pop("integrity")
        right_report.pop("integrity")

        self.assertEqual(left_report, right_report)

    def test_phone_holdout_balances_only_redundant_coverage_units(self):
        units = [
            MODULE.HoldoutUnit(key=(index,), rows=rows, target_mask=1)
            for index, rows in enumerate((100, 90, 80, 70, 60, 50, 40, 30))
        ]

        assignment = MODULE._find_role_assignment(units, full_mask=1, role_count=4)

        self.assertIsNotNone(assignment)
        row_counts = [sum(unit.rows for unit in role) for role in assignment]
        keys = [unit.key for role in assignment for unit in role]
        self.assertLess(max(row_counts), 250)
        self.assertEqual(len(keys), len(set(keys)))
        self.assertEqual(set(keys), {unit.key for unit in units})
        self.assertEqual([MODULE._union_mask(role) for role in assignment], [1] * 4)

    def test_phone_holdout_composes_partial_coverage_units(self):
        units = [
            MODULE.HoldoutUnit(key=(index,), rows=1, target_mask=target_mask)
            for index, target_mask in enumerate((1, 1, 1, 1, 2, 2, 2, 2))
        ]

        assignment = MODULE._find_role_assignment(units, full_mask=3, role_count=4)

        self.assertIsNotNone(assignment)
        self.assertEqual([len(role) for role in assignment], [2, 2, 2, 2])
        self.assertEqual([MODULE._union_mask(role) for role in assignment], [3] * 4)
        self.assertTrue(
            all(unit.target_mask != 3 for role in assignment for unit in role)
        )

    def test_phone_holdout_reports_post_support_gate_infeasibility(self):
        units = [
            MODULE.HoldoutUnit(key=(index,), rows=1, target_mask=target_mask)
            for index, target_mask in enumerate((3, 5, 6, 7, 7))
        ]

        report = MODULE._feasibility_report(units, full_mask=7, target_count=3)

        self.assertEqual(MODULE._minimum_target_support(units, 7), 4)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["blocker"], "no_complete_role_assignment")
        self.assertIsNone(report["candidate"])

    def test_phone_holdout_reports_a_necessary_coverage_blocker(self):
        root = self.temporary_directory()
        train_rows = [
            row(user=phone, phone=phone, building=0, floor=0, space=1)
            for phone in range(1, 5)
        ]
        validation_rows = [
            row(user=phone, phone=phone, building=1, floor=1, space=1)
            for phone in range(1, 4)
        ]
        archive, receipt, contract = fixture(
            root,
            train_rows=train_rows,
            validation_rows=validation_rows,
        )

        report = MODULE.evaluate_phone_holdout_feasibility(archive, receipt, contract)

        phone = report["phone_holdout"]
        self.assertEqual(phone["status"], "blocked")
        self.assertEqual(phone["minimum_target_group_unit_support"], 3)
        self.assertEqual(phone["blocker"], "target_group_support_below_role_count")
        self.assertIsNone(phone["candidate"])

    def test_joint_user_phone_holdout_preserves_connected_components(self):
        root = self.temporary_directory()
        rows = [
            row(user=1, phone=phone, building=building, floor=building, space=1)
            for phone in range(1, 5)
            for building in range(2)
        ]
        archive, receipt, contract = fixture(
            root,
            train_rows=rows[:4],
            validation_rows=rows[4:],
        )

        report = MODULE.evaluate_phone_holdout_feasibility(archive, receipt, contract)

        self.assertEqual(report["phone_holdout"]["status"], "candidate_found")
        joint = report["joint_user_phone_holdout"]
        self.assertEqual(joint["status"], "blocked")
        self.assertEqual(joint["unit_count"], 1)
        self.assertEqual(joint["blocker"], "insufficient_disjoint_units")

    def test_joint_user_phone_holdout_preserves_disconnected_components(self):
        root = self.temporary_directory()
        rows = [
            row(user=phone, phone=phone, building=building, floor=building, space=1)
            for phone in range(1, 5)
            for building in range(2)
        ]
        archive, receipt, contract = fixture(
            root,
            train_rows=rows[:4],
            validation_rows=rows[4:],
        )

        report = MODULE.evaluate_phone_holdout_feasibility(archive, receipt, contract)

        joint = report["joint_user_phone_holdout"]
        self.assertEqual(joint["status"], "candidate_found")
        self.assertEqual(joint["unit_count"], 4)
        self.assertEqual(joint["minimum_target_group_unit_support"], 4)
        self.assertTrue(joint["candidate"]["all_units_assigned_once"])
        self.assertEqual(joint["candidate"]["disjoint_unit_overlap_count"], 0)

    def test_phone_holdout_report_is_aggregate_and_cli_default_is_unchanged(self):
        root = self.temporary_directory()
        rows = [
            row(user=1, phone=phone, building=building, floor=building, space=1)
            for phone in range(1, 5)
            for building in range(2)
        ]
        archive, receipt, contract = fixture(
            root,
            train_rows=rows[:4],
            validation_rows=rows[4:],
        )

        report = MODULE.evaluate_phone_holdout_feasibility(archive, receipt, contract)
        rendered = MODULE.render_report(report)
        arguments = MODULE.parse_args([])

        self.assertNotIn(str(root).encode(), rendered)
        self.assertNotIn(str(contract.source["url"]).encode(), rendered)
        self.assertNotIn(b"4864900.75", rendered)
        self.assertNotIn(b"1370000000", rendered)
        self.assertEqual(set(report["privacy"].values()), {0})
        self.assertEqual(arguments.report, MODULE.DEFAULT_REPORT)
        self.assertIsNone(arguments.phone_holdout_report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
