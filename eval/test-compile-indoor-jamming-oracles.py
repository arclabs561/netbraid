#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["h5py==3.16.0", "xlrd==2.0.2"]
# ///

"""Hermetic tests for the indoor controlled-jamming oracle compiler."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import h5py
import xlrd

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "compile_indoor_jamming_oracles",
    HERE / "compile-indoor-jamming-oracles.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

PRIVATE_TX = 918_273_641
PRIVATE_RX = 918_273_642
DISTANCES = (3.0, 5.0, 7.0, 10.0, 13.0, 16.0, 19.0, 21.0)


class FakeSheet:
    def __init__(self, rows):
        self.rows = rows
        self.nrows = len(rows)
        self.ncols = max((len(row) for row in rows), default=0)

    def row_values(self, row):
        return list(self.rows[row])

    def cell_value(self, row, column):
        return self.rows[row][column]

    def cell_type(self, row, column):
        value = self.cell_value(row, column)
        if value == "":
            return xlrd.XL_CELL_EMPTY
        if isinstance(value, str):
            return xlrd.XL_CELL_TEXT
        return xlrd.XL_CELL_NUMBER


class FakeBook:
    def __init__(self, rows, *, sheet_names=None):
        self.sheet = FakeSheet(rows)
        self.names = ["README"] if sheet_names is None else sheet_names

    def sheet_names(self):
        return self.names

    def sheet_by_index(self, index):
        if index != 0:
            raise IndexError(index)
        return self.sheet

    def release_resources(self):
        return None


def workbook_rows():
    rows = [list(MODULE.EXPECTED_HEADERS), [""] * 8, [""] * 8]
    for index in range(1, 32):
        jammer = 4 + (index - 1) % 5
        power = ((index - 1) % 8 + 1) / 10
        distance = DISTANCES[(index - 1) % len(DISTANCES)]
        rows.extend(
            [
                [
                    f"w{index}",
                    PRIVATE_TX,
                    PRIVATE_RX,
                    jammer,
                    "No",
                    0.0,
                    distance,
                    "600s",
                ],
                [
                    "",
                    PRIVATE_TX,
                    PRIVATE_RX,
                    jammer,
                    "Sin",
                    power,
                    distance,
                    "600s",
                ],
                [
                    "",
                    PRIVATE_TX,
                    PRIVATE_RX,
                    jammer,
                    "Gauss",
                    power,
                    distance,
                    "600s",
                ],
                [""] * 8,
                [""] * 8,
            ]
        )
    return rows


def digest(path):
    encoded = path.read_bytes()
    return (
        len(encoded),
        hashlib.md5(encoded, usedforsecurity=False).hexdigest(),
        hashlib.sha256(encoded).hexdigest(),
    )


def write_mat(
    path,
    group_index,
    *,
    names=MODULE.EXPECTED_DATASETS,
    dtype="float64",
    first_dimension=2,
    compression="gzip",
    matlab_class=True,
    root_attribute=False,
):
    with h5py.File(path, "w", userblock_size=512) as mat:
        if root_attribute:
            mat.attrs["PRIVATE_EXTRA"] = "value"
        for offset, name in enumerate(names, 1):
            if name == "PRIVATE_EXTRA_GROUP":
                mat.create_group(name)
                continue
            dataset = mat.create_dataset(
                name,
                shape=(first_dimension, group_index * 10 + offset),
                dtype=dtype,
                compression=compression,
                chunks=True,
            )
            if matlab_class:
                dataset.attrs.create("MATLAB_class", b"double", dtype="S6")
    with path.open("r+b") as output:
        output.write(b"MATLAB 7.3 MAT-file, hermetic fixture")


def artifact_value(filename, artifact_bytes, md5):
    return {
        "filename": filename,
        "content_url": (
            f"https://zenodo.org/api/records/{MODULE.RECORD_ID}/files/"
            f"{filename}/content"
        ),
        "bytes": artifact_bytes,
        "md5": md5,
    }


def artifact_from_path(path):
    artifact_bytes, md5, _ = digest(path)
    return MODULE.Artifact(
        record_id=MODULE.RECORD_ID,
        doi=MODULE.EXPECTED_DOI,
        license=MODULE.EXPECTED_LICENSE,
        license_id=MODULE.EXPECTED_LICENSE_ID,
        filename=path.name,
        content_url=(
            f"https://zenodo.org/api/records/{MODULE.RECORD_ID}/files/"
            f"{path.name}/content"
        ),
        bytes=artifact_bytes,
        md5=md5,
    )


class Fixture:
    def __init__(self, case):
        temporary = tempfile.TemporaryDirectory()
        case.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.raw_dir = self.root / "raw"
        self.receipt_dir = self.root / "receipts"
        self.record_raw = self.raw_dir / str(MODULE.RECORD_ID)
        self.record_receipts = self.receipt_dir / str(MODULE.RECORD_ID)
        self.record_raw.mkdir(parents=True)
        self.record_receipts.mkdir(parents=True)
        self.rows = workbook_rows()
        (self.record_raw / "README.xls").write_bytes(b"PRIVATE_WORKBOOK_BYTES")
        for index, filename in enumerate(MODULE.EXPECTED_MAT_NAMES, 1):
            write_mat(self.record_raw / filename, index)
        self.manifest_document = self._manifest_document()
        self.manifest = self.root / "manifest.json"
        self.write_manifest()
        self.write_receipts()
        self.record = MODULE.load_record(self.manifest)

    def _manifest_document(self):
        artifacts = []
        for filename in ("README.xls", *MODULE.EXPECTED_MAT_NAMES):
            path = self.record_raw / filename
            artifact_bytes, md5, _ = digest(path)
            artifacts.append(artifact_value(filename, artifact_bytes, md5))
        total_bytes = sum(item["bytes"] for item in artifacts)
        record = {
            "record_id": MODULE.RECORD_ID,
            "api_url": MODULE.EXPECTED_API_URL,
            "doi": MODULE.EXPECTED_DOI,
            "license": MODULE.EXPECTED_LICENSE,
            "license_id": MODULE.EXPECTED_LICENSE_ID,
            "expected_artifact_count": len(artifacts),
            "expected_total_bytes": total_bytes,
            "artifacts": list(reversed(artifacts)),
        }
        return {
            "schema": MODULE.MANIFEST_SCHEMA,
            "publisher": "Zenodo",
            "expected_record_count": 1,
            "expected_artifact_count": len(artifacts),
            "expected_total_bytes": total_bytes,
            "records": [record],
        }

    def write_manifest(self, document=None):
        value = self.manifest_document if document is None else document
        self.manifest.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    def write_receipts(self):
        for artifact in MODULE.load_record(self.manifest).artifacts:
            path = self.record_raw / artifact.filename
            _, _, sha256 = digest(path)
            receipt = MODULE._expected_receipt(artifact, sha256)
            (self.record_receipts / f"{artifact.filename}.json").write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    def compile(self, *, full_digest=False, rows=None):
        selected_rows = copy.deepcopy(self.rows if rows is None else rows)
        with mock.patch.object(
            MODULE.xlrd,
            "open_workbook",
            side_effect=lambda **_kwargs: FakeBook(selected_rows),
        ):
            return MODULE.compile_inventory(
                self.record,
                self.raw_dir,
                self.receipt_dir,
                full_digest=full_digest,
            )


class IndoorJammingOracleCompilerTests(unittest.TestCase):
    def test_exact_mapping_is_deterministic_opaque_and_unassigned(self):
        fixture = Fixture(self)
        first = fixture.compile()
        second = fixture.compile()

        self.assertEqual(first, second)
        self.assertEqual(
            MODULE.render_inventory(first), MODULE.render_inventory(second)
        )
        self.assertEqual(first["counts"]["scenario_segments"], 93)
        self.assertEqual(first["counts"]["paired_three_condition_groups"], 31)
        self.assertEqual(
            first["counts"]["causes"], {"gaussian": 31, "silent": 31, "sine": 31}
        )
        self.assertEqual(first["counts"]["distinct_tx_rx_setups"], 1)
        self.assertEqual(first["counts"]["distinct_assigned_jammer_setups"], 5)
        self.assertEqual(first["counts"]["distinct_power_setups"], 8)
        self.assertEqual(first["counts"]["distinct_distance_setups"], 8)
        self.assertEqual(
            first["required_split_groups"], list(MODULE.REQUIRED_SPLIT_GROUPS)
        )
        self.assertEqual(
            first["assignment"],
            {
                "roles_assigned": False,
                "partitions_assigned": 0,
                "train_test_split_assigned": False,
            },
        )

        observations = first["observations"]
        self.assertEqual(
            [item["controlled_cause"] for item in observations[:3]],
            ["silent", "sine", "gaussian"],
        )
        self.assertEqual(
            [item["dataset_sample_count"] for item in observations[:3]], [11, 12, 13]
        )
        self.assertEqual(
            [item["condition_relative_jamming_power"] for item in observations[:3]],
            [0.0, 0.1, 0.1],
        )
        for group_field in MODULE.REQUIRED_SPLIT_GROUPS:
            self.assertEqual(
                len({item[group_field]["group_id"] for item in observations[:3]}), 1
            )
        self.assertEqual(len({item["observation_id"] for item in observations}), 93)
        for observation in observations:
            self.assertRegex(observation["observation_id"], r"^[a-f0-9]{64}$")
            self.assertNotIn("role", observation)
            self.assertNotIn("split", observation)
            for field in MODULE.UNSUPPORTED_IDENTITIES:
                self.assertEqual(
                    observation[field],
                    {
                        "state": "not_observed",
                        "support": "unsupported",
                        "group_id": None,
                    },
                )
        self.assertEqual(
            observations[0]["physical_source_identity"]["state"], "not_observed"
        )

        encoded = MODULE.render_inventory(first).decode("utf-8")
        self.assertNotIn(str(fixture.root), encoded)
        self.assertNotIn(str(PRIVATE_TX), encoded)
        self.assertNotIn(str(PRIVATE_RX), encoded)
        self.assertNotIn("README.xls", encoded)
        self.assertNotIn("w1.mat", encoded)
        self.assertNotIn('"tx"', encoded)
        self.assertNotIn('"rx"', encoded)
        self.assertNotIn('"jammer"', encoded)

    def test_dataset_elements_are_never_read(self):
        fixture = Fixture(self)
        with mock.patch.object(
            MODULE.h5py.Dataset,
            "__getitem__",
            side_effect=AssertionError("dataset element read"),
        ):
            inventory = fixture.compile()
        self.assertEqual(inventory["privacy"]["dataset_elements_read"], 0)

    def test_receipt_only_is_honest_and_full_digest_is_explicit(self):
        fixture = Fixture(self)
        target = fixture.record_raw / "w1.mat"
        with target.open("r+b") as output:
            output.seek(100)
            output.write(b"X")

        receipt_only = fixture.compile()
        self.assertFalse(receipt_only["provenance"]["all_artifact_bytes_rehashed"])
        self.assertEqual(
            receipt_only["provenance"]["integrity_basis"],
            "exact_size_and_exact_fetch_receipts_without_local_rehash",
        )
        with self.assertRaisesRegex(
            MODULE.OracleCompileError, "artifact_digest_mismatch"
        ):
            fixture.compile(full_digest=True)

    def test_full_digest_success_reports_rehash_basis(self):
        fixture = Fixture(self)
        inventory = fixture.compile(full_digest=True)
        self.assertTrue(inventory["provenance"]["all_artifact_bytes_rehashed"])
        self.assertEqual(
            inventory["provenance"]["integrity_basis"],
            "full_local_md5_sha256_rehash_and_exact_fetch_receipts",
        )

    def test_workbook_grammar_and_mapping_fail_closed(self):
        valid = workbook_rows()
        MODULE._parse_workbook(FakeBook(copy.deepcopy(valid)))
        cases = []

        wrong_header = copy.deepcopy(valid)
        wrong_header[0][4] = "type"
        cases.append(wrong_header)

        missing_group = copy.deepcopy(valid)
        del missing_group[-5:]
        cases.append(missing_group)

        duplicate_group = copy.deepcopy(valid)
        duplicate_group[8][0] = "w1"
        cases.append(duplicate_group)

        cause_order = copy.deepcopy(valid)
        cause_order[4][4], cause_order[5][4] = cause_order[5][4], cause_order[4][4]
        cases.append(cause_order)

        duration = copy.deepcopy(valid)
        duration[3][7] = "599s"
        cases.append(duration)

        tx_changed = copy.deepcopy(valid)
        tx_changed[4][1] += 1
        cases.append(tx_changed)

        bad_jammer = copy.deepcopy(valid)
        bad_jammer[3][3] = 9
        cases.append(bad_jammer)

        bad_power = copy.deepcopy(valid)
        bad_power[5][5] = 0.2
        cases.append(bad_power)

        partial = copy.deepcopy(valid)
        partial[3][6] = ""
        cases.append(partial)

        short_group = copy.deepcopy(valid)
        del short_group[5]
        cases.append(short_group)

        for index, rows in enumerate(cases):
            with self.subTest(index=index):
                with self.assertRaises(MODULE.OracleCompileError):
                    MODULE._parse_workbook(FakeBook(rows))
        with self.assertRaisesRegex(MODULE.OracleCompileError, "workbook_sheet_schema"):
            MODULE._parse_workbook(FakeBook(valid, sheet_names=["PRIVATE_WRONG"]))

    def test_hdf5_grammar_is_exact_and_dataset_mapping_is_metadata_only(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        valid = root / "w1.mat"
        write_mat(valid, 1)
        valid_identity = MODULE._identity(valid.stat())
        self.assertEqual(
            MODULE.inspect_mat(valid, artifact_from_path(valid), valid_identity),
            {"Nojamming": 11, "Sine": 12, "Gaussian": 13},
        )

        cases = (
            {"names": ("Nojamming", "Sine")},
            {"names": (*MODULE.EXPECTED_DATASETS, "PRIVATE_EXTRA_GROUP")},
            {"dtype": "float32"},
            {"first_dimension": 1},
            {"compression": None},
            {"matlab_class": False},
            {"root_attribute": True},
        )
        for index, options in enumerate(cases):
            with self.subTest(options=options):
                path = root / f"w{index + 2}.mat"
                write_mat(path, index + 2, **options)
                with self.assertRaises(MODULE.OracleCompileError):
                    MODULE.inspect_mat(
                        path, artifact_from_path(path), MODULE._identity(path.stat())
                    )

        invalid_header = root / "w20.mat"
        write_mat(invalid_header, 20)
        with invalid_header.open("r+b") as output:
            output.write(b"PRIVATE INVALID HEADER")
        with self.assertRaisesRegex(
            MODULE.OracleCompileError, "unsupported_mat_header"
        ):
            MODULE.inspect_mat(
                invalid_header,
                artifact_from_path(invalid_header),
                MODULE._identity(invalid_header.stat()),
            )

        current_identity = MODULE._identity(valid.stat())
        stale_identity = MODULE.FileIdentity(
            device=current_identity.device,
            inode=current_identity.inode,
            size=current_identity.size,
            mtime_ns=current_identity.mtime_ns + 1,
        )
        with self.assertRaisesRegex(
            MODULE.OracleCompileError, "artifact_changed_during_compile"
        ):
            MODULE.inspect_mat(valid, artifact_from_path(valid), stale_identity)

    def test_manifest_requires_exact_target_structure_and_rejects_duplicates(self):
        fixture = Fixture(self)
        MODULE.load_record(fixture.manifest)

        malformed_documents = []
        missing_key = copy.deepcopy(fixture.manifest_document)
        del missing_key["publisher"]
        malformed_documents.append(missing_key)

        wrong_url = copy.deepcopy(fixture.manifest_document)
        wrong_url["records"][0]["artifacts"][0]["content_url"] = "https://invalid"
        malformed_documents.append(wrong_url)

        duplicate_artifact = copy.deepcopy(fixture.manifest_document)
        first = duplicate_artifact["records"][0]["artifacts"][0]
        duplicate_artifact["records"][0]["artifacts"][1] = copy.deepcopy(first)
        old_total = duplicate_artifact["records"][0]["expected_total_bytes"]
        replacement = fixture.manifest_document["records"][0]["artifacts"][1]
        new_total = old_total - replacement["bytes"] + first["bytes"]
        duplicate_artifact["records"][0]["expected_total_bytes"] = new_total
        duplicate_artifact["expected_total_bytes"] = new_total
        malformed_documents.append(duplicate_artifact)

        missing_artifact = copy.deepcopy(fixture.manifest_document)
        removed = missing_artifact["records"][0]["artifacts"].pop()
        missing_artifact["records"][0]["expected_artifact_count"] -= 1
        missing_artifact["records"][0]["expected_total_bytes"] -= removed["bytes"]
        missing_artifact["expected_artifact_count"] -= 1
        missing_artifact["expected_total_bytes"] -= removed["bytes"]
        malformed_documents.append(missing_artifact)

        for index, document in enumerate(malformed_documents):
            with self.subTest(index=index):
                fixture.write_manifest(document)
                with self.assertRaises(MODULE.OracleCompileError):
                    MODULE.load_record(fixture.manifest)

        fixture.manifest.write_text(
            '{"schema":"netbraid.controlled_jamming_artifacts.v1",'
            '"schema":"duplicate"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MODULE.OracleCompileError, "duplicate_json_key"):
            MODULE.load_record(fixture.manifest)

    def test_receipts_are_exact_and_missing_or_malformed_receipts_fail_closed(self):
        for mutation in ("missing", "extra", "wrong_source", "duplicate_key"):
            with self.subTest(mutation=mutation):
                fixture = Fixture(self)
                receipt_path = fixture.record_receipts / "w1.mat.json"
                if mutation == "missing":
                    receipt_path.unlink()
                elif mutation == "duplicate_key":
                    receipt_path.write_text(
                        '{"schema":"one","schema":"two"}', encoding="utf-8"
                    )
                else:
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    if mutation == "extra":
                        receipt["PRIVATE_EXTRA"] = True
                    else:
                        receipt["source"]["filename"] = "PRIVATE_WRONG.mat"
                    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
                with self.assertRaises(MODULE.OracleCompileError):
                    fixture.compile()

    def test_missing_nonregular_and_duplicate_artifact_files_fail_closed(self):
        fixture = Fixture(self)
        missing = fixture.record_raw / "w1.mat"
        missing.unlink()
        with self.assertRaisesRegex(
            MODULE.OracleCompileError, "record_directory_schema"
        ):
            fixture.compile()

        fixture = Fixture(self)
        (fixture.record_raw / "PRIVATE_EXTRA.mat").write_bytes(b"extra")
        with self.assertRaisesRegex(
            MODULE.OracleCompileError, "record_directory_schema"
        ):
            fixture.compile()

        fixture = Fixture(self)
        target = fixture.record_raw / "w1.mat"
        target.unlink()
        target.symlink_to(fixture.record_raw / "w2.mat")
        with self.assertRaisesRegex(
            MODULE.OracleCompileError, "artifact_missing_or_unsafe"
        ):
            fixture.compile()

        fixture = Fixture(self)
        first = fixture.record_raw / "w1.mat"
        second = fixture.record_raw / "w2.mat"
        second.unlink()
        os.link(first, second)
        first_artifact = next(
            artifact
            for artifact in fixture.record.artifacts
            if artifact.filename == "w1.mat"
        )
        second_artifact = MODULE.Artifact(
            **{
                **first_artifact.__dict__,
                "filename": "w2.mat",
                "content_url": (
                    f"https://zenodo.org/api/records/{MODULE.RECORD_ID}/files/w2.mat/content"
                ),
            }
        )
        artifacts = tuple(
            second_artifact if item.filename == "w2.mat" else item
            for item in fixture.record.artifacts
        )
        fixture.record = MODULE.Record(MODULE.RECORD_ID, artifacts)
        _, _, sha256 = digest(second)
        receipt = MODULE._expected_receipt(second_artifact, sha256)
        (fixture.record_receipts / "w2.mat.json").write_text(
            json.dumps(receipt), encoding="utf-8"
        )
        with self.assertRaisesRegex(
            MODULE.OracleCompileError, "duplicate_artifact_file"
        ):
            fixture.compile()


if __name__ == "__main__":
    unittest.main()
