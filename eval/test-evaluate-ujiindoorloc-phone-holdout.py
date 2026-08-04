#!/usr/bin/env python3
"""Hermetic tests for the UJIIndoorLoc phone-holdout baseline."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from collections import defaultdict
from contextlib import redirect_stderr
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "evaluate_ujiindoorloc_phone_holdout",
    HERE / "evaluate-ujiindoorloc-phone-holdout.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
UJI = MODULE.uji

FIXTURE_SPEC = importlib.util.spec_from_file_location(
    "ujiindoorloc_capability_fixture_helpers",
    HERE / "test-evaluate-ujiindoorloc-split-capability.py",
)
assert FIXTURE_SPEC is not None and FIXTURE_SPEC.loader is not None
FIXTURES = importlib.util.module_from_spec(FIXTURE_SPEC)
sys.modules[FIXTURE_SPEC.name] = FIXTURES
FIXTURE_SPEC.loader.exec_module(FIXTURES)


def synthetic_rows(*, reverse: bool = False) -> tuple[UJI.ModelRow, ...]:
    rows = []
    for phone in range(8):
        for class_index, (building, floor) in enumerate(MODULE.TARGET_CLASSES):
            rssi: list[int | None] = [None] * len(UJI.WAP_FIELDS)
            rssi[class_index] = -30 - (phone % 2)
            rssi[len(MODULE.TARGET_CLASSES)] = -80 + class_index
            rows.append(UJI.ModelRow(tuple(rssi), building, floor, phone))
    if reverse:
        rows.reverse()
    return tuple(rows)


def scan_for(rows: tuple[UJI.ModelRow, ...]) -> UJI.CorpusScan:
    phones: dict[int, UJI.PhoneAggregate] = {}
    for row in rows:
        aggregate = phones.setdefault(row.phone, UJI.PhoneAggregate())
        aggregate.rows += 1
        aggregate.targets.add(row.target)
    return UJI.CorpusScan(
        (1234, "a" * 32, "b" * 64),
        {"train": len(rows) - 7, "validation": 7},
        phones,
    )


def partition(
    rows: tuple[UJI.ModelRow, ...], plan: UJI.PhoneRolePlan
) -> dict[str, tuple[UJI.ModelRow, ...]]:
    grouped: dict[str, list[UJI.ModelRow]] = defaultdict(list)
    for row in rows:
        grouped[plan.phone_roles[row.phone]].append(row)
    return {role: tuple(grouped[role]) for role in UJI.ROLES}


def run_protocol(
    rows: tuple[UJI.ModelRow, ...],
    *,
    override: dict[str, tuple[UJI.ModelRow, ...]] | None = None,
) -> tuple[dict[str, object], list[str], UJI.PhoneRolePlan]:
    scan = scan_for(rows)
    plan = UJI.build_phone_role_plan(scan)
    roles = partition(rows, plan)
    if override:
        roles.update(override)
    reads = []

    def reader(role: str):
        reads.append(role)
        return roles[role]

    report = MODULE.evaluate_protocol(
        reader,
        integrity=scan.integrity,
        publisher_rows=scan.publisher_rows,
        role_rows=plan.row_counts,
        role_phones=plan.phone_counts,
        role_targets=plan.target_counts,
    )
    return report, reads, plan


class UjiIndoorLocPhoneHoldoutTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_verified_archive_reader_drives_the_complete_protocol(self):
        csv_rows = []
        for phone in range(8):
            for class_index, (building, floor) in enumerate(MODULE.TARGET_CLASSES):
                values = FIXTURES.row(
                    user=phone,
                    phone=phone,
                    building=building,
                    floor=floor,
                    space=1,
                )
                values[0] = "100"
                values[class_index] = str(-30 - (phone % 2))
                values[len(MODULE.TARGET_CLASSES)] = str(-80 + class_index)
                csv_rows.append(values)
        archive, receipt, contract = FIXTURES.fixture(
            self.temporary_directory(),
            train_rows=csv_rows[:52],
            validation_rows=csv_rows[52:],
        )

        report = MODULE.evaluate_archive(archive, receipt, contract)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["reconciliation"]["raw_row_total"], 104)
        self.assertEqual(
            report["reconciliation"]["model_row_read_counts"],
            report["split"]["role_row_counts"],
        )
        self.assertTrue(report["test"]["read"])
        self.assertTrue(report["test"]["evaluated"])

    def test_split_is_disjoint_complete_and_order_invariant(self):
        rows = synthetic_rows()
        first = UJI.build_phone_role_plan(scan_for(rows))
        second = UJI.build_phone_role_plan(scan_for(tuple(reversed(rows))))

        self.assertEqual(first, second)
        self.assertEqual(sum(first.row_counts.values()), len(rows))
        self.assertEqual(set(first.phone_roles), set(range(8)))
        self.assertEqual(set(first.target_counts.values()), {13})
        role_phones = [
            {phone for phone, assigned in first.phone_roles.items() if assigned == role}
            for role in UJI.ROLES
        ]
        self.assertTrue(all(role_phones))
        for index, left in enumerate(role_phones):
            for right in role_phones[index + 1 :]:
                self.assertFalse(left & right)

    def test_missing_sentinel_is_encoded_as_weak_signal_from_train_only(self):
        rows = synthetic_rows()
        plan = UJI.build_phone_role_plan(scan_for(rows))
        fit = MODULE.fit_centroids(partition(rows, plan)["train"])

        self.assertEqual(MODULE.MISSING_RSSI_DBM, -105.0)
        missing = UJI.ModelRow(
            (None,) * len(UJI.WAP_FIELDS),
            MODULE.TARGET_CLASSES[0][0],
            MODULE.TARGET_CLASSES[0][1],
            0,
        )
        self.assertEqual(MODULE._encoded(missing, (0,)), (-105.0,))
        self.assertTrue(all(mean < 0 for mean in fit.means))
        self.assertNotIn(100.0, fit.means)
        self.assertEqual(set(fit.centroids), set(MODULE.TARGET_CLASSES))

    def test_report_is_deterministic_reconciled_and_private(self):
        first, first_reads, _ = run_protocol(synthetic_rows())
        second, second_reads, _ = run_protocol(synthetic_rows(reverse=True))

        self.assertEqual(MODULE.render_report(first), MODULE.render_report(second))
        self.assertEqual(first_reads, list(UJI.ROLES))
        self.assertEqual(second_reads, list(UJI.ROLES))
        self.assertTrue(first["reconciliation"]["all_raw_rows_assigned_once"])
        self.assertEqual(
            first["reconciliation"]["raw_row_total"],
            first["reconciliation"]["assigned_row_total"],
        )
        for role in ("calibration", "validation", "test"):
            metrics = (
                first[role]["metrics"]
                if role != "calibration"
                else first[role]["metrics"]
            )
            self.assertEqual(metrics["rows"], metrics["outcomes"]["reconciled_total"])
            self.assertEqual(len(metrics["per_class"]), 13)
            self.assertEqual(
                sum(item["support"] for item in metrics["per_class"]),
                metrics["rows"],
            )
            self.assertEqual(
                sum(item["predicted"] for item in metrics["per_class"]),
                metrics["coverage"]["numerator"],
            )
            for item in metrics["per_class"]:
                self.assertEqual(
                    item["support"],
                    item["correct"] + item["incorrect"] + item["abstained"],
                )
                self.assertEqual(
                    item["predicted"], item["correct"] + item["false_positive"]
                )
            self.assertTrue(metrics["per_phone"])
            self.assertEqual(
                sum(item["rows"] for item in metrics["per_phone"]), metrics["rows"]
            )
            for outcome in ("correct", "incorrect", "abstained"):
                self.assertEqual(
                    sum(item["outcomes"][outcome] for item in metrics["per_phone"]),
                    metrics["outcomes"][outcome],
                )
            self.assertTrue(
                all(
                    "phone" not in key and "id" not in key
                    for item in metrics["per_phone"]
                    for key in item
                )
            )
        encoded = MODULE.render_report(first).decode("ascii")
        for forbidden in ("USERID", "PHONEID", "LONGITUDE", "LATITUDE", "/tmp/"):
            self.assertNotIn(forbidden, encoded)
        self.assertEqual(set(first["privacy"].values()), {0})
        self.assertNotIn('"accuracy"', encoded)

    def test_fit_and_calibration_are_isolated_from_later_roles(self):
        rows = synthetic_rows()
        plan = UJI.build_phone_role_plan(scan_for(rows))
        roles = partition(rows, plan)
        fit = MODULE.fit_centroids(roles["train"])
        baseline_predictions = tuple(
            MODULE.predict_unthresholded(row, fit) for row in roles["calibration"]
        )
        threshold, selection = MODULE.select_threshold(
            roles["calibration"], baseline_predictions
        )

        changed_later = tuple(
            UJI.ModelRow(
                (None,) * len(UJI.WAP_FIELDS), row.building, row.floor, row.phone
            )
            for row in (*roles["validation"], *roles["test"])
        )
        self.assertEqual(fit, MODULE.fit_centroids(roles["train"]))
        self.assertEqual(
            (threshold, selection),
            MODULE.select_threshold(roles["calibration"], baseline_predictions),
        )
        self.assertTrue(changed_later)

    def test_validation_gate_prevents_test_read(self):
        rows = synthetic_rows()
        plan = UJI.build_phone_role_plan(scan_for(rows))
        roles = partition(rows, plan)
        bad_validation = tuple(
            UJI.ModelRow(
                (None,) * len(UJI.WAP_FIELDS), row.building, row.floor, row.phone
            )
            for row in roles["validation"]
        )

        report, reads, _ = run_protocol(rows, override={"validation": bad_validation})

        self.assertEqual(reads, ["train", "calibration", "validation"])
        self.assertFalse(report["validation"]["gate"]["passed"])
        self.assertEqual(report["status"], "validation_gate_failed")
        self.assertEqual(report["reconciliation"]["model_row_read_counts"]["test"], 0)
        self.assertEqual(
            report["test"], {"read": False, "evaluated": False, "metrics": None}
        )

    def test_failed_gate_does_not_parse_test_role_rssi(self):
        rows = synthetic_rows()
        plan = UJI.build_phone_role_plan(scan_for(rows))
        test_phones = {
            phone for phone, role in plan.phone_roles.items() if role == "test"
        }
        validation_phones = {
            phone for phone, role in plan.phone_roles.items() if role == "validation"
        }
        csv_rows = []
        for row in rows:
            values = FIXTURES.row(
                user=row.phone,
                phone=row.phone,
                building=row.building,
                floor=row.floor,
                space=1,
            )
            values[0] = "100"
            if row.phone in test_phones:
                values[0] = "not-rssi"
            elif row.phone not in validation_phones:
                class_index = MODULE.TARGET_CLASSES.index(row.target)
                values[class_index] = str(-30 - (row.phone % 2))
                values[len(MODULE.TARGET_CLASSES)] = str(-80 + class_index)
            csv_rows.append(values)
        root = self.temporary_directory()
        archive, receipt, contract = FIXTURES.fixture(
            root,
            train_rows=csv_rows[:52],
            validation_rows=csv_rows[52:],
        )

        report = MODULE.evaluate_archive(archive, receipt, contract)

        self.assertEqual(report["status"], "validation_gate_failed")
        self.assertFalse(report["test"]["read"])
        self.assertFalse(report["test"]["evaluated"])

    def test_test_values_change_only_test_metrics(self):
        rows = synthetic_rows()
        baseline, _, plan = run_protocol(rows)
        roles = partition(rows, plan)
        changed_test = tuple(
            UJI.ModelRow(
                (None,) * len(UJI.WAP_FIELDS), row.building, row.floor, row.phone
            )
            for row in roles["test"]
        )
        changed, reads, _ = run_protocol(rows, override={"test": changed_test})

        self.assertEqual(reads, list(UJI.ROLES))
        self.assertEqual(baseline["fit"], changed["fit"])
        self.assertEqual(baseline["calibration"], changed["calibration"])
        self.assertEqual(baseline["validation"], changed["validation"])
        self.assertNotEqual(baseline["test"]["metrics"], changed["test"]["metrics"])

    def test_reconciliation_mismatch_fails_closed(self):
        rows = synthetic_rows()
        scan = scan_for(rows)
        plan = UJI.build_phone_role_plan(scan)
        roles = partition(rows, plan)
        wrong_counts = dict(plan.row_counts)
        wrong_counts["train"] += 1

        with self.assertRaises(MODULE.BaselineError) as raised:
            MODULE.evaluate_protocol(
                lambda role: roles[role],
                integrity=scan.integrity,
                publisher_rows=scan.publisher_rows,
                role_rows=wrong_counts,
                role_phones=plan.phone_counts,
                role_targets=plan.target_counts,
            )
        self.assertEqual(raised.exception.code, "role_read_reconciliation_failed")

    def test_rendered_report_has_stable_json_bytes(self):
        report, _, _ = run_protocol(synthetic_rows())
        payload = MODULE.render_report(report)

        self.assertTrue(payload.endswith(b"\n"))
        self.assertEqual(json.loads(payload), report)
        self.assertEqual(payload, MODULE.render_report(report))

    def test_report_path_cannot_alias_archive_or_receipt(self):
        root = self.temporary_directory()
        archive = root / "archive.zip"
        receipt = root / "receipt.json"
        archive.write_bytes(b"archive-sentinel")
        receipt.write_bytes(b"receipt-sentinel")

        for input_path in (archive, receipt):
            with self.subTest(input_path=input_path.name):
                alias_parent = root / "must-not-be-created"
                report = alias_parent / ".." / input_path.name
                stderr = io.StringIO()
                with redirect_stderr(stderr):
                    result = MODULE.main(
                        [
                            "--archive",
                            str(archive),
                            "--receipt",
                            str(receipt),
                            "--report",
                            str(report),
                        ]
                    )
                self.assertEqual(result, 2)
                self.assertEqual(stderr.getvalue().strip(), "report_aliases_input")
                self.assertEqual(archive.read_bytes(), b"archive-sentinel")
                self.assertEqual(receipt.read_bytes(), b"receipt-sentinel")
                self.assertFalse(alias_parent.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
