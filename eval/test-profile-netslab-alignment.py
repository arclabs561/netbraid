#!/usr/bin/env python3
"""Hermetic tests for the bounded NetsLab aggregate metadata profiler."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
import stat
import sys
import tempfile
import unittest
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "profile_netslab_alignment", HERE / "profile-netslab-alignment.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

PRIVATE_MARKERS = (
    "PRIVATE_MEMBER_NAME",
    "PRIVATE_UID_VALUE",
    "PRIVATE_SOURCE_ENDPOINT",
    "PRIVATE_DESTINATION_ENDPOINT",
    "PRIVATE_RADIO_IDENTIFIER",
    "PRIVATE_CATEGORY_VALUE",
)


def fixed_info(name: str, *, directory: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    if directory:
        info.external_attr = (stat.S_IFDIR | 0o755) << 16
        info.compress_type = zipfile.ZIP_STORED
    else:
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
    return info


def build_archive(directory: Path, *, unsafe_name: str | None = None) -> Path:
    path = directory / "fixture-benign.zip"
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        archive.writestr(fixed_info("public/", directory=True), b"")
        archive.writestr(fixed_info("public/aggregate.csv"), b"aggregate\n")
        archive.writestr(
            fixed_info("public/metadata.txt"), PRIVATE_MARKERS[0].encode("ascii")
        )
        if unsafe_name is not None:
            archive.writestr(fixed_info(unsafe_name), b"unsafe\n")
    return path


def quote_identifier(identifier: str) -> str:
    return f'"{identifier}"'


def fixture_row(
    table: Any, seed: int, overrides: dict[str, Any] | None = None
) -> tuple[Any, ...]:
    values: dict[str, Any] = {
        name: (f"text-{seed}" if kind == "TEXT" else seed)
        for name, kind in table.columns
    }
    if overrides:
        values.update(overrides)
    return tuple(values[name] for name, _ in table.columns)


def build_database(
    path: Path,
    table: Any,
    rows: list[tuple[Any, ...]],
    *,
    columns: tuple[tuple[str, str], ...] | None = None,
) -> None:
    selected_columns = table.columns if columns is None else columns
    definitions = ", ".join(
        f"{quote_identifier(name)} {kind}" for name, kind in selected_columns
    )
    placeholders = ", ".join("?" for _ in selected_columns)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            f"CREATE TABLE {quote_identifier(table.name)} ({definitions})"
        )
        connection.executemany(
            f"INSERT INTO {quote_identifier(table.name)} VALUES ({placeholders})",
            rows,
        )
        connection.commit()
    finally:
        connection.close()


def artifact_contract(path: Path) -> Any:
    data = path.read_bytes()
    return MODULE.ArtifactContract(
        filename=path.name,
        expected_bytes=len(data),
        expected_md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
    )


def build_corpus(directory: Path) -> Any:
    archive = build_archive(directory)
    lower_path = directory / "fixture-lower.db"
    lower_rows = [
        fixture_row(
            MODULE.LOWER_TABLE,
            1,
            {
                "rnti": PRIVATE_MARKERS[4],
                "attack_category": PRIVATE_MARKERS[5] + "-lower-a",
                "attack_subcategory": PRIVATE_MARKERS[5] + "-sub-a",
                "timestamp": 1.5,
            },
        ),
        fixture_row(
            MODULE.LOWER_TABLE,
            2,
            {
                "pmi": None,
                "attack_category": PRIVATE_MARKERS[5] + "-lower-b",
                "attack_subcategory": None,
                "timestamp": None,
            },
        ),
    ]
    build_database(lower_path, MODULE.LOWER_TABLE, lower_rows)

    network_path = directory / "fixture-network.db"
    network_rows = [
        fixture_row(
            MODULE.NETWORK_TABLE,
            1,
            {
                "uid": PRIVATE_MARKERS[1],
                "src_ip": PRIVATE_MARKERS[2],
                "dst_ip": PRIVATE_MARKERS[3],
                "attack_category": PRIVATE_MARKERS[5] + "-network-a",
                "attack_type": PRIVATE_MARKERS[5] + "-type-a",
            },
        ),
        fixture_row(
            MODULE.NETWORK_TABLE,
            2,
            {
                "service": None,
                "attack_category": PRIVATE_MARKERS[5] + "-network-b",
                "attack_type": None,
            },
        ),
    ]
    build_database(network_path, MODULE.NETWORK_TABLE, network_rows)
    return MODULE.CorpusContract(
        artifact_contract(archive),
        artifact_contract(lower_path),
        artifact_contract(network_path),
    )


class FailingMmapConnection:
    def execute(self, _query: str) -> Any:
        raise sqlite3.OperationalError("mmap is unavailable")


class NetsLabAlignmentTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_profiles_deterministically_without_values_paths_or_member_names(self):
        directory = self.temporary_directory()
        contract = build_corpus(directory)

        first = MODULE.profile_corpus(directory, contract, mmap_bytes=8 * MODULE.MIB)
        second = MODULE.profile_corpus(directory, contract, mmap_bytes=8 * MODULE.MIB)

        self.assertEqual(first, second)
        self.assertEqual(first["status"], "pass")
        lower = first["artifacts"]["lower_layer_summary"]["sqlite"]
        network = first["artifacts"]["network_summary"]["sqlite"]
        self.assertEqual(lower["rows"], 2)
        self.assertEqual(lower["null_counts"]["timestamp"], 1)
        self.assertEqual(lower["category_cardinalities"]["attack_category"], 2)
        self.assertTrue(lower["time_axis"]["available"])
        self.assertEqual(network["rows"], 2)
        self.assertFalse(network["time_axis"]["available"])
        self.assertEqual(first["limits"]["row_values_retained"], 0)
        self.assertEqual(first["limits"]["member_paths_retained"], 0)

        rendered = MODULE.render_report(first).decode("utf-8")
        self.assertEqual(rendered, MODULE.render_report(second).decode("utf-8"))
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, rendered)
        self.assertNotIn(str(directory), rendered)
        self.assertNotIn("public/aggregate.csv", rendered)
        self.assertNotIn(contract.archive.filename, rendered)
        self.assertNotIn(contract.lower_database.filename, rendered)
        self.assertNotIn(contract.network_database.filename, rendered)

    def test_reports_missing_network_timestamp_and_no_cross_layer_join(self):
        directory = self.temporary_directory()
        report = MODULE.profile_corpus(directory, build_corpus(directory))

        self.assertFalse(
            report["artifacts"]["network_summary"]["sqlite"]["time_axis"]["available"]
        )
        self.assertEqual(
            report["cross_layer_alignment"],
            {
                "established": False,
                "reason": "network_data lacks timestamp; cross-layer join is not established.",
            },
        )
        self.assertIn("cross_layer_join", report["not_established"])

    def test_validates_exact_size_and_md5(self):
        directory = self.temporary_directory()
        contract = build_corpus(directory)
        with self.assertRaisesRegex(RuntimeError, "byte count"):
            MODULE.profile_archive(
                directory, replace(contract.archive, expected_bytes=1)
            )
        with self.assertRaisesRegex(RuntimeError, "MD5"):
            MODULE.profile_archive(
                directory, replace(contract.archive, expected_md5="0" * 32)
            )

    def test_rejects_unsafe_and_overbound_central_directories(self):
        directory = self.temporary_directory()
        unsafe = build_archive(directory, unsafe_name="../PRIVATE_MEMBER_NAME")
        with self.assertRaisesRegex(RuntimeError, "unsafe"):
            MODULE.profile_archive(directory, artifact_contract(unsafe))

        safe_directory = self.temporary_directory()
        safe = build_archive(safe_directory)
        with mock.patch.object(MODULE, "MAX_ARCHIVE_MEMBERS", 1):
            with self.assertRaisesRegex(RuntimeError, "central directory"):
                MODULE.profile_archive(safe_directory, artifact_contract(safe))

    def test_rejects_sqlite_schema_drift(self):
        directory = self.temporary_directory()
        path = directory / "drifted-network.db"
        drifted_columns = MODULE.NETWORK_TABLE.columns[:-1]
        full_row = fixture_row(MODULE.NETWORK_TABLE, 1)
        build_database(
            path,
            MODULE.NETWORK_TABLE,
            [full_row[:-1]],
            columns=drifted_columns,
        )
        with self.assertRaisesRegex(RuntimeError, "column schema drifted"):
            MODULE.profile_database(
                directory,
                artifact_contract(path),
                MODULE.NETWORK_TABLE,
                MODULE.DEFAULT_MMAP_BYTES,
            )

    def test_configures_bounded_mmap_and_falls_back_to_zero(self):
        directory = self.temporary_directory()
        contract = build_corpus(directory)
        requested = 8 * MODULE.MIB
        report = MODULE.profile_database(
            directory,
            contract.lower_database,
            MODULE.LOWER_TABLE,
            requested,
        )
        mmap = report["sqlite"]["mmap"]
        self.assertEqual(mmap["requested_bytes"], requested)
        self.assertGreaterEqual(mmap["effective_bytes"], 0)
        self.assertLessEqual(mmap["effective_bytes"], requested)
        self.assertEqual(mmap["fallback"], mmap["effective_bytes"] < requested)

        self.assertEqual(MODULE.apply_mmap_size(FailingMmapConnection(), requested), 0)
        with self.assertRaisesRegex(RuntimeError, "outside"):
            MODULE.bounded_mmap_bytes(MODULE.MAX_MMAP_BYTES + 1)

    def test_writes_deterministic_report_atomically(self):
        directory = self.temporary_directory()
        report = MODULE.profile_corpus(directory, build_corpus(directory))
        rendered = MODULE.render_report(report)
        output = directory / "reports" / "profile.json"

        MODULE.write_report(output, rendered)

        self.assertEqual(output.read_bytes(), rendered)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(
            list(output.parent.glob(f".{output.name}.*")),
            [],
        )
        self.assertEqual(json.loads(output.read_text()), report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
