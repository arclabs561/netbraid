#!/usr/bin/env python3
"""Hermetic tests for bounded XRF55 NPY-header profiling."""

from __future__ import annotations

import importlib.util
import io
import json
import struct
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "profile_xrf55_npy_shapes", HERE / "profile-xrf55-npy-shapes.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def npy_bytes(dtype, shape, fill=b"\x00"):
    header = repr(
        {"descr": dtype, "fortran_order": False, "shape": tuple(shape)}
    ).encode("latin1")
    padding = 16 - (10 + len(header) + 1) % 16
    header += b" " * padding + b"\n"
    item_bytes = int(dtype.lstrip("<>=|")[1:])
    element_count = 1
    for value in shape:
        element_count *= value
    payload = fill * (element_count * item_bytes)
    return b"\x93NUMPY\x01\x00" + struct.pack("<H", len(header)) + header + payload


def contract(subjects):
    return {
        "subject_groups": subjects,
        "scenes": frozenset({1}),
        "actions": frozenset({1}),
        "repetitions": frozenset({1}),
    }


def write_archive(path, subject_shapes, *, dtype="<f4"):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for subject, wifi_shape in enumerate(subject_shapes, 1):
            name = f"{subject:02d}_01_01.npy"
            archive.writestr(f"Scene1/WiFi/{name}", npy_bytes(dtype, wifi_shape))
            archive.writestr(f"Scene1/RFID/{name}", npy_bytes(dtype, (3, 2)))
            archive.writestr(f"Scene1/mmWave/{name}", npy_bytes(dtype, (2, 4, 2)))


class Xrf55NpyShapeProfileTests(unittest.TestCase):
    def test_profiles_one_header_per_size_class_without_retaining_names(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "processed.zip"
            write_archive(archive_path, [(2, 2), (2, 3)])

            first = MODULE.profile_shape_archive(
                archive_path, archive_path.stat().st_size, contract(2)
            )
            second = MODULE.profile_shape_archive(
                archive_path, archive_path.stat().st_size, contract(2)
            )

        self.assertEqual(first, second)
        self.assertEqual(first["header_reads"], 4)
        self.assertEqual(first["modalities"]["wifi"]["members"], 2)
        self.assertEqual(
            [item["shape"] for item in first["modalities"]["wifi"]["size_classes"]],
            [[2, 2], [2, 3]],
        )
        self.assertEqual(
            len(first["modalities"]["rfid"]["size_classes"]),
            1,
        )
        encoded = json.dumps(first, sort_keys=True)
        for forbidden in ("Scene1", "WiFi", "RFID", "mmWave", "01_01_01"):
            self.assertNotIn(forbidden, encoded)

    def test_rejects_unsupported_dtype_before_array_elements_are_read(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "processed.zip"
            write_archive(archive_path, [(2, 2)], dtype="|O8")
            with self.assertRaisesRegex(
                MODULE.Xrf55ShapeProfileError, "unsupported_npy_dtype"
            ):
                MODULE.profile_shape_archive(
                    archive_path, archive_path.stat().st_size, contract(1)
                )

    def test_rejects_excessive_size_class_cardinality(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "processed.zip"
            shapes = [(2, width) for width in range(1, 18)]
            write_archive(archive_path, shapes)
            with self.assertRaisesRegex(
                MODULE.Xrf55ShapeProfileError, "too_many_npy_size_classes"
            ):
                MODULE.profile_shape_archive(
                    archive_path, archive_path.stat().st_size, contract(17)
                )

    def test_npy_extent_mismatch_fails_closed(self):
        encoded = npy_bytes("<f4", (2, 2))
        with self.assertRaisesRegex(
            MODULE.Xrf55ShapeProfileError, "npy_member_extent_mismatch"
        ):
            MODULE.parse_npy_header(io.BytesIO(encoded), len(encoded) + 1)

    def test_header_parser_does_not_read_array_elements(self):
        encoded = npy_bytes("<f4", (64, 64), fill=b"\x7f")
        source = io.BytesIO(encoded)
        header = MODULE.parse_npy_header(source, len(encoded))
        self.assertEqual(source.tell(), header.header_bytes)
        self.assertLess(source.tell(), len(encoded))


if __name__ == "__main__":
    unittest.main(verbosity=2)
