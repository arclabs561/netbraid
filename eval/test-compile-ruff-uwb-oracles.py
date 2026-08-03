#!/usr/bin/env python3
"""Hermetic tests for the bounded RUFF-UWB oracle compiler."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "compile_ruff_uwb_oracles", HERE / "compile-ruff-uwb-oracles.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

PRIVATE_SOURCE_VALUES = (918_273_641, 918_273_642, 918_273_643)
PRIVATE_LOCATION_VALUES = (564_738_291, 564_738_292, 564_738_293)
PRIVATE_VARIANT = "PRIVATE_DWM3001CDK_VARIANT"


def npy_labels(rows, *, fields=2, descriptor="<i8"):
    shape = (len(rows), fields)
    header = repr({"descr": descriptor, "fortran_order": False, "shape": shape}).encode(
        "latin1"
    )
    padding = 16 - (10 + len(header) + 1) % 16
    header += b" " * padding + b"\n"
    prefix = b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header))
    payload = b"".join(struct.pack("<" + "q" * fields, *row) for row in rows)
    return prefix + header + payload


def write_archive(path, key, rows, *, malformed=None, duplicate_member=False):
    label_name = f"PRIVATE_{key}.labels.npy"
    waveform_name = f"PRIVATE_{key}.data.npy"
    if malformed == "fields":
        labels = npy_labels([(1, 2, 3)], fields=3)
    elif malformed == "dtype":
        labels = npy_labels(rows, descriptor=">i8")
    else:
        labels = npy_labels(rows)
    waveform = b"PRIVATE_WAVEFORM_PAYLOAD_MUST_NOT_BE_READ"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(waveform_name, waveform)
        archive.writestr(label_name, labels)
        if duplicate_member:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(label_name, labels)
    encoded = path.read_bytes()
    contract = MODULE.ArchiveContract(
        key=key,
        filename=path.name,
        archive_bytes=len(encoded),
        archive_md5=hashlib.md5(encoded, usedforsecurity=False).hexdigest(),
        archive_sha256=hashlib.sha256(encoded).hexdigest(),
        label_member=label_name,
        label_member_bytes=len(labels),
        waveform_member=waveform_name,
        waveform_member_bytes=len(waveform),
        configuration_token=f"PRIVATE_CONFIG_{key}",
    )
    return contract


class Fixture:
    def __init__(self, case):
        temporary = tempfile.TemporaryDirectory()
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.first_path = self.root / "PRIVATE_FIRST_ARCHIVE.zip"
        self.second_path = self.root / "PRIVATE_SECOND_ARCHIVE.zip"
        self.first_rows = [
            (PRIVATE_SOURCE_VALUES[0], PRIVATE_LOCATION_VALUES[0]),
            (PRIVATE_SOURCE_VALUES[0], PRIVATE_LOCATION_VALUES[0]),
            (PRIVATE_SOURCE_VALUES[1], PRIVATE_LOCATION_VALUES[1]),
            (PRIVATE_SOURCE_VALUES[2], PRIVATE_LOCATION_VALUES[2]),
        ]
        self.second_rows = [
            (PRIVATE_SOURCE_VALUES[0], PRIVATE_LOCATION_VALUES[0]),
            (PRIVATE_SOURCE_VALUES[1], PRIVATE_LOCATION_VALUES[2]),
            (PRIVATE_SOURCE_VALUES[2], PRIVATE_LOCATION_VALUES[1]),
        ]
        self.first = write_archive(
            self.first_path, "PRIVATE_CAMPAIGN_A", self.first_rows
        )
        self.second = write_archive(
            self.second_path, "PRIVATE_CAMPAIGN_B", self.second_rows
        )
        self.claim = MODULE.PublisherClaim(
            source_count=3,
            location_count=3,
            variant_token=PRIVATE_VARIANT,
        )

    def compile(self):
        return MODULE.compile_inventory(
            (
                (self.first, self.first_path),
                (self.second, self.second_path),
            ),
            self.claim,
        )


class RuffUwbOracleCompilerTests(unittest.TestCase):
    def test_deterministic_opaque_inventory_preserves_grouping(self):
        fixture = Fixture(self)
        first = fixture.compile()
        second = MODULE.compile_inventory(
            (
                (fixture.second, fixture.second_path),
                (fixture.first, fixture.first_path),
            ),
            fixture.claim,
        )

        self.assertEqual(first, second)
        self.assertEqual(
            MODULE.render_inventory(first), MODULE.render_inventory(second)
        )
        self.assertEqual(first["counts"]["label_rows"], 7)
        self.assertEqual(first["counts"]["observations"], 6)
        self.assertEqual(first["counts"]["distinct_source_location_groups"], 6)
        self.assertEqual(first["publisher_claims"]["physical_sources"], 3)
        self.assertEqual(first["publisher_claims"]["locations"], 3)
        self.assertEqual(first["privacy"]["waveform_payload_bytes_read"], 0)
        self.assertEqual(
            first["required_split_groups"],
            [
                "physical_source_group",
                "location_group",
                "source_location_group",
                "campaign_group",
                "day_group",
            ],
        )
        distinct = first["counts"]["distinct_known_groups"]
        self.assertEqual(distinct["day"], 2)
        self.assertEqual(distinct["receiver"], 1)
        self.assertEqual(distinct["channel"], 1)

        records = first["observations"]
        duplicated = [record for record in records if record["observation_count"] == 2]
        self.assertEqual(len(duplicated), 1)
        self.assertEqual(
            len({record["observation_id"] for record in records}), len(records)
        )
        for record in records:
            self.assertRegex(record["observation_id"], r"^[a-f0-9]{64}$")
            for axis in MODULE.AXES:
                group = record[f"{axis}_group"]
                if axis in MODULE.UNOBSERVED_AXES:
                    self.assertEqual(group, {"state": "not_observed", "group_id": None})
                else:
                    self.assertEqual(group["state"], "known")
                    self.assertRegex(group["group_id"], r"^[a-f0-9]{64}$")
            self.assertRegex(record["campaign_group"]["group_id"], r"^[a-f0-9]{64}$")
            self.assertRegex(
                record["source_location_group"]["group_id"], r"^[a-f0-9]{64}$"
            )

        shared_source = [
            record
            for record in records
            if record["physical_source_group"]["group_id"]
            == records[0]["physical_source_group"]["group_id"]
        ]
        self.assertEqual(len(shared_source), 2)
        self.assertEqual(
            len({item["physical_source_group"]["group_id"] for item in shared_source}),
            1,
        )
        self.assertEqual(
            len({item["physical_device_group"]["group_id"] for item in shared_source}),
            1,
        )
        self.assertEqual(
            len({item["day_group"]["group_id"] for item in shared_source}),
            2,
        )
        self.assertEqual(
            len({item["source_location_group"]["group_id"] for item in shared_source}),
            2,
        )
        self.assertEqual(
            len({item["location_group"]["group_id"] for item in shared_source}),
            2,
        )
        self.assertEqual(
            len({item["variant_group"]["group_id"] for item in records}), 1
        )
        self.assertEqual(len({item["domain_group"]["group_id"] for item in records}), 1)

        encoded = MODULE.render_inventory(first).decode("utf-8")
        private_values = (
            *(str(value) for value in PRIVATE_SOURCE_VALUES),
            *(str(value) for value in PRIVATE_LOCATION_VALUES),
            PRIVATE_VARIANT,
            fixture.first.filename,
            fixture.second.filename,
            str(fixture.root),
            "PRIVATE_CAMPAIGN_A",
            "PRIVATE_CAMPAIGN_B",
            "PRIVATE_CONFIG",
            "PRIVATE_WAVEFORM",
        )
        for value in private_values:
            self.assertNotIn(value, encoded)

    def test_waveform_member_is_never_opened(self):
        fixture = Fixture(self)
        original_open = MODULE.zipfile.ZipFile.open

        def guarded_open(archive, name, *args, **kwargs):
            candidate = name.filename if isinstance(name, zipfile.ZipInfo) else name
            if candidate.endswith(".data.npy"):
                raise AssertionError("waveform member opened")
            return original_open(archive, name, *args, **kwargs)

        with mock.patch.object(MODULE.zipfile.ZipFile, "open", guarded_open):
            inventory = fixture.compile()
        self.assertEqual(inventory["privacy"]["waveform_members_opened"], 0)

    def test_absent_combinations_are_not_synthesized(self):
        fixture = Fixture(self)
        inventory = fixture.compile()

        self.assertEqual(len(inventory["observations"]), 6)
        self.assertLess(
            len(inventory["observations"]),
            2 * fixture.claim.source_count * fixture.claim.location_count,
        )

    def test_duplicate_archives_members_and_generated_records_fail_closed(self):
        fixture = Fixture(self)
        with self.assertRaisesRegex(MODULE.OracleCompileError, "duplicate_archive_key"):
            MODULE.compile_inventory(
                (
                    (fixture.first, fixture.first_path),
                    (fixture.first, fixture.second_path),
                ),
                fixture.claim,
            )
        with self.assertRaisesRegex(
            MODULE.OracleCompileError, "duplicate_archive_path"
        ):
            MODULE.compile_inventory(
                (
                    (fixture.first, fixture.first_path),
                    (fixture.second, fixture.first_path),
                ),
                fixture.claim,
            )

        duplicate_path = fixture.root / "PRIVATE_DUPLICATE_MEMBER.zip"
        duplicate = write_archive(
            duplicate_path,
            "PRIVATE_CAMPAIGN_C",
            fixture.first_rows,
            duplicate_member=True,
        )
        with self.assertRaisesRegex(MODULE.OracleCompileError, "archive_member_count"):
            MODULE.inspect_archive(duplicate_path, duplicate, require_receipt=False)

        with mock.patch.object(MODULE, "_opaque_id", return_value="a" * 64):
            with self.assertRaisesRegex(
                MODULE.OracleCompileError, "duplicate_observation_record"
            ):
                fixture.compile()

    def test_malformed_labels_and_bounds_fail_closed(self):
        fixture = Fixture(self)
        for malformed, error in (
            ("fields", "invalid_label_shape"),
            ("dtype", "unsupported_label_array"),
        ):
            with self.subTest(malformed=malformed):
                path = fixture.root / f"PRIVATE_{malformed}.zip"
                contract = write_archive(
                    path,
                    f"PRIVATE_{malformed}",
                    fixture.first_rows,
                    malformed=malformed,
                )
                with self.assertRaisesRegex(MODULE.OracleCompileError, error):
                    MODULE.inspect_archive(path, contract, require_receipt=False)

        with mock.patch.object(MODULE, "MAX_ROWS_PER_ARCHIVE", 3):
            with self.assertRaisesRegex(
                MODULE.OracleCompileError, "invalid_label_shape"
            ):
                MODULE.inspect_archive(
                    fixture.first_path, fixture.first, require_receipt=False
                )
        with mock.patch.object(MODULE, "MAX_OBSERVATIONS_PER_RECORD", 1):
            with self.assertRaisesRegex(
                MODULE.OracleCompileError, "record_observation_count_limit"
            ):
                fixture.compile()

    def test_publisher_count_mismatch_fails_closed(self):
        fixture = Fixture(self)
        bad_claims = (
            MODULE.PublisherClaim(4, 3, PRIVATE_VARIANT),
            MODULE.PublisherClaim(3, 4, PRIVATE_VARIANT),
        )
        for claim, error in zip(
            bad_claims,
            ("publisher_source_count_mismatch", "publisher_location_count_mismatch"),
        ):
            with self.subTest(error=error):
                with self.assertRaisesRegex(MODULE.OracleCompileError, error):
                    MODULE.compile_inventory(
                        (
                            (fixture.first, fixture.first_path),
                            (fixture.second, fixture.second_path),
                        ),
                        claim,
                    )

    def test_catalog_claim_is_strict_and_bounded(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(root))
        catalog = root / "catalog.json"
        entry = {
            "id": MODULE.CATALOG_ENTRY_ID,
            "modalities": [
                "physical_source_observation",
                "location_observation",
            ],
            "roles": ["source_location_split_eval"],
            "note": (
                "The record covers 13 boards across 100 positions using identical "
                "DWM3001CDK hardware, one fixed receiver and channel 5, and two "
                "distinct collection days."
            ),
        }
        catalog.write_text(
            json.dumps(
                {
                    "schema": MODULE.CATALOG_SCHEMA,
                    "source_batch": "PRIVATE_BATCH",
                    "entries": [entry],
                }
            ),
            encoding="utf-8",
        )
        claim = MODULE.load_publisher_claim(catalog)
        self.assertEqual((claim.source_count, claim.location_count), (13, 100))
        self.assertEqual(claim.variant_token, "DWM3001CDK")

        catalog.write_text(
            '{"schema":"netbraid.public_source_leads.v1",'
            '"schema":"duplicate","entries":[]}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MODULE.OracleCompileError, "duplicate_json_key"):
            MODULE.load_publisher_claim(catalog)


if __name__ == "__main__":
    unittest.main()
