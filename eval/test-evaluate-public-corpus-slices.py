#!/usr/bin/env python3
"""Hermetic contracts for the bounded public-corpus evaluator."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


EVALUATOR_PATH = Path(__file__).with_name("evaluate-public-corpus-slices.py")
SPEC = importlib.util.spec_from_file_location(
    "netbraid_public_corpus_eval", EVALUATOR_PATH
)
assert SPEC is not None and SPEC.loader is not None
EVALUATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = EVALUATOR
SPEC.loader.exec_module(EVALUATOR)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def write_external_source(directory: Path, capture: bytes) -> tuple[dict, Path]:
    filename = "external-conformance.pcapng"
    capture_path = directory / filename
    capture_path.write_bytes(capture)
    md5 = hashlib.md5(capture, usedforsecurity=False).hexdigest()
    sha256 = hashlib.sha256(capture).hexdigest()
    receipt = {
        "archive": filename,
        "bytes": len(capture),
        "md5": md5,
        "schema": EVALUATOR.PUBLIC_ARCHIVE_RECEIPT_SCHEMA,
        "sha256": sha256,
        "source": {
            "bytes": len(capture),
            "filename": filename,
            "format": "file",
            "md5": md5,
        },
    }
    receipt_bytes = json.dumps(receipt, indent=2, sort_keys=True).encode() + b"\n"
    receipt_filename = f"{filename}.json"
    (directory / receipt_filename).write_bytes(receipt_bytes)
    archive = {
        "bytes": len(capture),
        "filename": filename,
        "format": "file",
        "md5": md5,
        "receipt": {
            "bytes": len(receipt_bytes),
            "filename": receipt_filename,
            "sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        },
        "sha256": sha256,
    }
    return archive, capture_path


def expectation() -> dict:
    return {
        "address_forms": {
            "destination": {
                "absent_frames": 2,
                "extended_frames": 0,
                "short_frames": 0,
            },
            "source": {
                "absent_frames": 2,
                "extended_frames": 0,
                "short_frames": 0,
            },
        },
        "commands": {
            "command_mix": [],
            "present_frames": 0,
            "unavailable_frames": 2,
        },
        "completeness": {
            "packet_limit": 2,
            "packet_limit_reached": True,
            "scope": "normalized_packet_subset",
            "state": "partial",
        },
        "counts": {
            "ieee802154_frames": 2,
            "other_packet_envelopes": 0,
            "packet_envelopes": 2,
            "packet_quarantines": 0,
            "packet_rows_inspected": 2,
        },
        "fcs": {"invalid_frames": 0, "unavailable_frames": 2, "valid_frames": 0},
        "frame_type_version_mix": [{"frame_type": 1, "frame_version": 0, "frames": 2}],
        EVALUATOR.IEEE802154_RECORD_ORACLE_KEY: {"total_length_exceeds_frame": 1},
    }


def case_for(archive: dict) -> dict:
    return {
        "archive": "external",
        "expect": expectation(),
        "id": "external-receipt-bound",
        "member": {
            "bytes": archive["bytes"],
            "name": archive["filename"],
            "sha256": archive["sha256"],
        },
        "mode": "netbraid-ieee802154",
        "packet_limit": 2,
    }


def projection_for(case: dict) -> dict:
    expected = case["expect"]
    return {
        "schema": EVALUATOR.IEEE802154_PROJECTION_SCHEMA,
        "source": {
            "artifact": {
                "content_sha256": f"sha256:{case['member']['sha256']}",
                "size_bytes": case["member"]["bytes"],
            },
            "extractor": {
                "adapter": "hermetic-adapter",
                "adapter_version": "v0",
                "tool": "hermetic-tool",
                "tool_version": "v0",
                "configuration_sha256": f"sha256:{'1' * 64}",
                "field_registry": "hermetic-fields-v0",
            },
            "normalized_records_sha256": f"sha256:{'2' * 64}",
        },
        "completeness": expected["completeness"],
        "counts": expected["counts"],
        "frame_type_version_mix": expected["frame_type_version_mix"],
        "address_forms": expected["address_forms"],
        "commands": expected["commands"],
        "fcs": expected["fcs"],
        "limitations": EVALUATOR.IEEE802154_LIMITATIONS,
    }


def records_for(case: dict) -> bytes:
    capture_id = f"sha256:{case['member']['sha256']}"
    documents = [
        {
            "schema": EVALUATOR.CAPTURE_MANIFEST_SCHEMA,
            "capture_id": capture_id,
            "artifact": {
                "content_sha256": capture_id,
                "size_bytes": case["member"]["bytes"],
            },
        },
        {
            "schema": EVALUATOR.PACKET_ENVELOPE_SCHEMA,
            "capture_id": capture_id,
            "frame": {
                "original_len": 20,
                "protocols": ["wpan", "6lowpan", "ipv6"],
            },
            "ipv6": {"total_length_octets": 48},
        },
        {
            "schema": EVALUATOR.PACKET_ENVELOPE_SCHEMA,
            "capture_id": capture_id,
            "frame": {
                "original_len": 60,
                "protocols": ["wpan", "6lowpan", "ipv6"],
            },
            "ipv6": {"total_length_octets": 48},
        },
    ]
    return b"".join(canonical_json(document) for document in documents)


def write_fake_binary(path: Path, projection: bytes, records: bytes) -> None:
    script = (
        "#!/bin/sh\n"
        'case "$*" in\n'
        f"  *--ieee802154-json*) printf '%s' '{projection.decode()}' ;;\n"
        f"  *--records-jsonl*) printf '%s' '{records.decode()}' ;;\n"
        "  *) exit 64 ;;\n"
        "esac\n"
    )
    path.write_text(script, encoding="utf-8")
    path.chmod(0o700)


class PublicCorpusEvaluatorTest(unittest.TestCase):
    def test_default_manifest_declares_bounded_matter_conformance_case(self):
        archives, cases, _ = EVALUATOR.validate_manifest(EVALUATOR.DEFAULT_MANIFEST)

        case = next(
            item for item in cases if item["id"] == "matter-data1813-thread-n1-prefix"
        )

        self.assertEqual(archives[case["archive"]]["format"], "file")
        self.assertEqual(case["packet_limit"], 32)
        self.assertEqual(case["expect"]["counts"]["packet_envelopes"], 32)
        self.assertEqual(case["expect"]["counts"]["packet_quarantines"], 0)
        self.assertEqual(case["expect"]["fcs"]["unavailable_frames"], 32)
        self.assertEqual(
            case["expect"][EVALUATOR.IEEE802154_RECORD_ORACLE_KEY][
                "total_length_exceeds_frame"
            ],
            2,
        )

    def test_receipt_bound_external_case_runs_without_identifier_output(self):
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            archive, _ = write_external_source(directory, b"bounded capture bytes")
            case = case_for(archive)
            manifest = {
                "schema": EVALUATOR.MANIFEST_SCHEMA,
                "archives": {"external": archive},
                "cases": [case],
            }
            manifest_path = directory / "manifest.json"
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            binary = directory / "fake-netbraid"
            write_fake_binary(
                binary, canonical_json(projection_for(case)), records_for(case)
            )

            with mock.patch.object(
                EVALUATOR, "netbraid_git_revision", return_value="0" * 40
            ):
                code, report = EVALUATOR.evaluate(manifest_path, directory, binary, 2)

        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "pass")
        result = report["results"][0]
        self.assertEqual(result["normalized_packets"], 2)
        self.assertEqual(result["packet_quarantines"], 0)
        self.assertEqual(
            result[EVALUATOR.IEEE802154_RECORD_ORACLE_KEY][
                "total_length_exceeds_frame"
            ],
            1,
        )
        rendered = json.dumps(report)
        for forbidden in EVALUATOR.IEEE802154_FORBIDDEN_KEYS | {"path"}:
            self.assertNotIn(f'"{forbidden}"', rendered)

    def test_external_file_requires_the_exact_fetch_receipt(self):
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            archive, capture_path = write_external_source(
                directory, b"bounded capture bytes"
            )
            receipt_path = directory / archive["receipt"]["filename"]
            receipt_path.write_bytes(receipt_path.read_bytes() + b" ")

            with self.assertRaises(EVALUATOR.EvaluationError) as raised:
                EVALUATOR.digest_archive(capture_path, archive)

        self.assertEqual(raised.exception.stage, "archive_receipt_verification")


if __name__ == "__main__":
    unittest.main()
