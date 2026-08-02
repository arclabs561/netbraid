#!/usr/bin/env python3
"""Hermetic tests for the bounded Data4Cyber alignment profiler."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import struct
import sys
import tempfile
import unittest
import warnings
import zipfile
from dataclasses import replace
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "profile_data4cyber_alignment", HERE / "profile-data4cyber-alignment.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FIXTURE_SCENARIO = "S0_fixture"
PAYLOAD_MARKER = b"PAYLOAD_MARKER"


def pcapng_block(block_type: int, body: bytes, byte_order: str = "<") -> bytes:
    padding = b"\x00" * (-len(body) % 4)
    total_length = 12 + len(body) + len(padding)
    return (
        struct.pack(f"{byte_order}II", block_type, total_length)
        + body
        + padding
        + struct.pack(f"{byte_order}I", total_length)
    )


def pcapng_fixture() -> bytes:
    section = pcapng_block(
        0x0A0D0D0A,
        struct.pack("<IHHq", MODULE.BYTE_ORDER_MAGIC, 1, 0, -1),
    )
    interface = pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    first_packet = pcapng_block(6, struct.pack("<IIIII", 0, 0, 1, 0, 0))
    second_packet = pcapng_block(
        6,
        struct.pack("<IIIII", 0, 0, 2, len(PAYLOAD_MARKER), len(PAYLOAD_MARKER))
        + PAYLOAD_MARKER,
    )
    return section + interface + first_packet + second_packet


def empty_pcapng_fixture() -> bytes:
    section = pcapng_block(
        0x0A0D0D0A,
        struct.pack("<IHHq", MODULE.BYTE_ORDER_MAGIC, 1, 0, -1),
    )
    interface = pcapng_block(1, struct.pack("<HHI", 1, 0, 65535))
    return section + interface


def fixed_info(name: str, *, directory: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    if directory:
        info.external_attr = (stat.S_IFDIR | 0o755) << 16
        info.compress_type = zipfile.ZIP_STORED
    else:
        info.external_attr = (stat.S_IFREG | 0o644) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
    return info


def valid_entries() -> Dict[str, bytes]:
    prefix = f"{MODULE.ROOT_MEMBER}/{FIXTURE_SCENARIO}/"
    readme = (
        b"# Fixture scenario\n"
        b"dataset.csv and network_tap.pcapng are synchronized artifacts.\n"
    )
    dataset = b"timestamp,signal,attack_active,attack_phase\n0,1,0,none\n"
    capture = pcapng_fixture()
    entries = {
        f"{MODULE.ROOT_MEMBER}/LICENSE.txt": b"fixture license\n",
        f"{MODULE.ROOT_MEMBER}/README.md": b"# Fixture corpus\nScenario archive.\n",
        prefix + "README.md": readme,
        prefix + "attack-phases.json": b"{}\n",
        prefix + "attacker_only.pcapng": capture,
        prefix + "attacker_only_meta.json": b"{}\n",
        prefix + "benign_only.pcapng": capture,
        prefix + "benign_only_meta.json": b"{}\n",
        prefix + "dataset.csv": dataset,
        prefix + "dataset_attack.csv": dataset,
        prefix + "dataset_benign.csv": dataset,
        prefix + "experiment_overview.json": b"{}\n",
        prefix + "ip_device_mapping.csv": b"kind\nfixture\n",
        prefix + "metadata.json": b"{}\n",
        prefix + "modbus_variable_mapping.csv": b"kind\nfixture\n",
        prefix + "network_tap.pcapng": capture,
        prefix + "plots/01_power_timeseries.pdf": b"%PDF-1.4\n%%EOF\n",
        prefix + "plots/02_context_and_communication.pdf": b"%PDF-1.4\n%%EOF\n",
        prefix + "scenario_definition.json": b"{}\n",
        prefix + "state.jsonl.gz": b"fixture\n",
    }
    return entries


def build_archive(
    directory: Path,
    *,
    overrides: Optional[Dict[str, bytes]] = None,
    omitted: Iterable[str] = (),
    extras: Iterable[Tuple[str, bytes]] = (),
    duplicate: Optional[str] = None,
) -> Path:
    path = directory / "fixture.zip"
    entries = valid_entries()
    if overrides:
        entries.update(overrides)
    for name in omitted:
        entries.pop(name)

    directories = [
        f"{MODULE.ROOT_MEMBER}/",
        f"{MODULE.ROOT_MEMBER}/{FIXTURE_SCENARIO}/",
        f"{MODULE.ROOT_MEMBER}/{FIXTURE_SCENARIO}/plots/",
    ]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w") as archive:
            for name in directories:
                archive.writestr(fixed_info(name, directory=True), b"")
            for name, data in sorted(entries.items()):
                archive.writestr(fixed_info(name), data)
            for name, data in extras:
                archive.writestr(fixed_info(name), data)
            if duplicate is not None:
                archive.writestr(fixed_info(duplicate), entries[duplicate])
    return path


def fixture_contract(path: Path, *, pcap_scan_bytes: int = 88):
    data = path.read_bytes()
    return MODULE.ArchiveContract(
        expected_bytes=len(data),
        expected_md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        expected_scenarios=(FIXTURE_SCENARIO,),
        pcap_scan_bytes=pcap_scan_bytes,
    )


class Data4CyberAlignmentTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_profiles_tiny_archive_deterministically_without_values(self):
        path = build_archive(self.temporary_directory())
        contract = fixture_contract(path)

        first = MODULE.profile_archive(path, contract)
        second = MODULE.profile_archive(path, contract)

        self.assertEqual(first, second)
        self.assertEqual(first["status"], "pass")
        self.assertEqual(first["archive"]["members"], 23)
        self.assertEqual(len(first["scenarios"]), 1)
        scenario = first["scenarios"][0]
        self.assertEqual(scenario["dataset_headers"]["columns"], 4)
        self.assertTrue(scenario["dataset_headers"]["headers_identical"])
        self.assertTrue(scenario["alignment_evidence"]["tabular_time_axis_present"])
        self.assertTrue(
            scenario["alignment_evidence"]["full_capture_timestamp_records_observed"]
        )
        self.assertEqual(len(scenario["pcapng"]), 3)
        for capture in scenario["pcapng"]:
            structure = capture["structure"]
            self.assertEqual(structure["packet_blocks"], 1)
            self.assertFalse(structure["scan_complete"])
            self.assertEqual(structure["stop_reason"], "byte_limit")
        rendered = json.dumps(first, sort_keys=True)
        self.assertNotIn(PAYLOAD_MARKER.decode(), rendered)
        self.assertNotIn("0,1,0,none", rendered)

    def test_accepts_structurally_valid_empty_split_capture(self):
        prefix = f"{MODULE.ROOT_MEMBER}/{FIXTURE_SCENARIO}/"
        path = build_archive(
            self.temporary_directory(),
            overrides={prefix + "attacker_only.pcapng": empty_pcapng_fixture()},
        )
        report = MODULE.profile_archive(path, fixture_contract(path))
        attack_split = report["scenarios"][0]["pcapng"][2]
        self.assertEqual(attack_split["role"], "attack_split")
        self.assertEqual(attack_split["structure"]["packet_blocks"], 0)
        self.assertTrue(attack_split["structure"]["scan_complete"])

    def test_validates_exact_archive_size_and_md5(self):
        path = build_archive(self.temporary_directory())
        contract = fixture_contract(path)
        with self.assertRaisesRegex(RuntimeError, "byte count"):
            MODULE.profile_archive(path, replace(contract, expected_bytes=1))
        with self.assertRaisesRegex(RuntimeError, "MD5"):
            MODULE.profile_archive(path, replace(contract, expected_md5="0" * 32))

    def test_rejects_unsafe_and_duplicate_member_paths(self):
        directory = self.temporary_directory()
        unsafe = build_archive(
            directory,
            extras=(("../outside", b"fixture\n"),),
        )
        with self.assertRaisesRegex(RuntimeError, "unsafe"):
            MODULE.profile_archive(unsafe, fixture_contract(unsafe))

        duplicate_directory = self.temporary_directory()
        duplicate_name = f"{MODULE.ROOT_MEMBER}/README.md"
        duplicate = build_archive(
            duplicate_directory,
            duplicate=duplicate_name,
        )
        with self.assertRaisesRegex(RuntimeError, "duplicate"):
            MODULE.profile_archive(duplicate, fixture_contract(duplicate))

    def test_rejects_member_and_dataset_schema_mismatches(self):
        prefix = f"{MODULE.ROOT_MEMBER}/{FIXTURE_SCENARIO}/"
        missing = build_archive(
            self.temporary_directory(),
            omitted=(prefix + "metadata.json",),
        )
        with self.assertRaisesRegex(RuntimeError, "member schema"):
            MODULE.profile_archive(missing, fixture_contract(missing))

        bad_header = b"timestamp,signal,attack_active\n0,1,0\n"
        mismatched = build_archive(
            self.temporary_directory(),
            overrides={
                prefix + "dataset.csv": bad_header,
                prefix + "dataset_attack.csv": bad_header,
                prefix + "dataset_benign.csv": bad_header,
            },
        )
        with self.assertRaisesRegex(RuntimeError, "alignment schema"):
            MODULE.profile_archive(mismatched, fixture_contract(mismatched))

    def test_rejects_malformed_pcapng_structure(self):
        prefix = f"{MODULE.ROOT_MEMBER}/{FIXTURE_SCENARIO}/"
        malformed = b"not a pcapng file".ljust(32, b"x")
        path = build_archive(
            self.temporary_directory(),
            overrides={
                prefix + "network_tap.pcapng": malformed,
                prefix + "benign_only.pcapng": malformed,
                prefix + "attacker_only.pcapng": malformed,
            },
        )
        with self.assertRaisesRegex(RuntimeError, "PCAPNG"):
            MODULE.profile_archive(path, fixture_contract(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
