#!/usr/bin/env python3
"""Report which relation-split claims the SMoRFFI row adapter can support."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ADAPTER = ROOT / "data" / "derived" / "eval" / "smorffi-row-adapter.json"
DEFAULT_REPORT = (
    ROOT / "data" / "derived" / "eval" / "smorffi-relation-split-capability.json"
)
ADAPTER_SCHEMA = "netbraid.smorffi_csv_iq_adapter.v0"
SCHEMA = "netbraid.smorffi_split_capability.v0"
MAX_ADAPTER_BYTES = 4 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
ARTIFACT_ID = re.compile(r"artifact-[0-9a-f]{24}\Z")
SOURCE_ID = re.compile(r"source-[0-9a-f]{24}\Z")


class CapabilityError(RuntimeError):
    """Stable, path-free reason for rejecting an adapter or report boundary."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class DuplicateJsonKeyError(ValueError):
    """Raised when strict JSON repeats an object key."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateJsonKeyError(key)
        value[key] = item
    return value


def _read_adapter(path: Path) -> tuple[Mapping[str, Any], str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        expected = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CapabilityError("unsafe_adapter") from error
    try:
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if (
                stat.S_ISLNK(expected.st_mode)
                or not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_size > MAX_ADAPTER_BYTES
                or (expected.st_dev, expected.st_ino, expected.st_size)
                != (before.st_dev, before.st_ino, before.st_size)
            ):
                raise CapabilityError("unsafe_adapter")
            payload = source.read(MAX_ADAPTER_BYTES + 1)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise CapabilityError("adapter_read_failed") from error
    if (
        len(payload) > MAX_ADAPTER_BYTES
        or len(payload) != before.st_size
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise CapabilityError("adapter_changed_during_read")
    try:
        value = json.loads(payload, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJsonKeyError) as error:
        raise CapabilityError("invalid_adapter_json") from error
    if not isinstance(value, Mapping):
        raise CapabilityError("invalid_adapter_schema")
    return value, hashlib.sha256(payload).hexdigest()


def _exact_mapping(value: Any, keys: set[str], code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise CapabilityError(code)
    return value


def _positive_int(value: Any, code: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise CapabilityError(code)
    return value


def evaluate(adapter_path: Path) -> Mapping[str, Any]:
    adapter, adapter_sha256 = _read_adapter(adapter_path)
    if (
        set(adapter)
        != {
            "schema",
            "provenance",
            "artifacts",
            "axes",
            "counts",
            "source_spans",
            "privacy",
            "limitations",
        }
        or adapter.get("schema") != ADAPTER_SCHEMA
    ):
        raise CapabilityError("invalid_adapter_schema")
    provenance = _exact_mapping(
        adapter["provenance"],
        {
            "dataset_version",
            "receipt_schema",
            "receipt_sha256",
            "local_inventory_sha256",
            "integrity_basis",
            "publisher_checksum_available",
            "header_errata_applied",
        },
        "invalid_provenance",
    )
    if (
        provenance["dataset_version"] != 3
        or provenance["receipt_schema"] != "local.netbraid.smorffi.v1"
        or not isinstance(provenance["receipt_sha256"], str)
        or SHA256.fullmatch(provenance["receipt_sha256"]) is None
        or not isinstance(provenance["local_inventory_sha256"], str)
        or SHA256.fullmatch(provenance["local_inventory_sha256"]) is None
        or provenance["integrity_basis"] != "local_sha256_after_version_pinned_download"
        or provenance["publisher_checksum_available"] is not False
        or provenance["header_errata_applied"] != 1
    ):
        raise CapabilityError("invalid_provenance")
    counts = _exact_mapping(
        adapter["counts"],
        {
            "files",
            "rows",
            "samples",
            "spans",
            "minimum_samples_per_row",
            "maximum_samples_per_row",
            "rows_with_288_samples",
        },
        "invalid_counts",
    )
    files = _positive_int(counts["files"], "invalid_counts")
    rows = _positive_int(counts["rows"], "invalid_counts")
    samples = _positive_int(counts["samples"], "invalid_counts")
    spans_count = _positive_int(counts["spans"], "invalid_counts")
    if (
        files != 123
        or rows != 122_511
        or samples != 38_561_309
        or spans_count != files
        or counts["minimum_samples_per_row"] != 288
        or counts["maximum_samples_per_row"] != 579
        or counts["rows_with_288_samples"] != 37_288
    ):
        raise CapabilityError("unexpected_corpus_cardinality")
    axes = _exact_mapping(
        adapter["axes"],
        {"physical_source", "acquisition_session", "receiver", "location"},
        "invalid_axes",
    )
    physical = _exact_mapping(
        axes["physical_source"], {"state", "groups"}, "invalid_physical_source_axis"
    )
    if physical != {"state": "publisher_claimed", "groups": 123}:
        raise CapabilityError("invalid_physical_source_axis")
    for axis_name in ("acquisition_session", "receiver", "location"):
        axis = _exact_mapping(
            axes[axis_name], {"state", "reason"}, "invalid_unknown_axis"
        )
        if axis != {
            "state": "unknown",
            "reason": "not_exposed_by_publisher_metadata",
        }:
            raise CapabilityError("invalid_unknown_axis")
    privacy = _exact_mapping(
        adapter["privacy"],
        {
            "absolute_paths_retained",
            "relative_paths_retained",
            "publisher_device_values_retained",
            "publisher_address_values_retained",
            "iq_values_retained_in_adapter",
        },
        "invalid_privacy_contract",
    )
    if any(value is not False for value in privacy.values()):
        raise CapabilityError("privacy_contract_not_satisfied")
    spans = adapter["source_spans"]
    if not isinstance(spans, list) or len(spans) != spans_count:
        raise CapabilityError("invalid_source_spans")
    cursor = 0
    source_ids: set[str] = set()
    artifact_ids: set[str] = set()
    for span in spans:
        span = _exact_mapping(
            span,
            {"source_file", "physical_source", "row_start", "row_end"},
            "invalid_source_span",
        )
        if (
            not isinstance(span["source_file"], str)
            or ARTIFACT_ID.fullmatch(span["source_file"]) is None
            or not isinstance(span["physical_source"], str)
            or SOURCE_ID.fullmatch(span["physical_source"]) is None
            or span["row_start"] != cursor
            or not isinstance(span["row_end"], int)
            or isinstance(span["row_end"], bool)
            or span["row_end"] <= cursor
        ):
            raise CapabilityError("invalid_source_span")
        cursor = span["row_end"]
        source_ids.add(span["physical_source"])
        artifact_ids.add(span["source_file"])
    if cursor != rows or len(source_ids) != 123 or len(artifact_ids) != files:
        raise CapabilityError("invalid_source_spans")
    artifacts = _exact_mapping(
        adapter["artifacts"], {"iq", "row_offsets"}, "invalid_artifacts"
    )
    expected_artifacts = {
        "iq": ("<c16", [samples]),
        "row_offsets": ("<u8", [rows + 1]),
    }
    for name, (dtype, shape) in expected_artifacts.items():
        artifact = _exact_mapping(
            artifacts[name], {"format", "dtype", "shape", "sha256"}, "invalid_artifact"
        )
        if (
            artifact["format"] != "npy"
            or artifact["dtype"] != dtype
            or artifact["shape"] != shape
            or not isinstance(artifact["sha256"], str)
            or SHA256.fullmatch(artifact["sha256"]) is None
        ):
            raise CapabilityError("invalid_artifact")
    limitations = adapter["limitations"]
    if not isinstance(limitations, list) or not all(
        isinstance(item, str) for item in limitations
    ):
        raise CapabilityError("invalid_limitations")

    return {
        "schema": SCHEMA,
        "status": "pass",
        "input": {
            "adapter_schema": ADAPTER_SCHEMA,
            "adapter_sha256": adapter_sha256,
        },
        "axes": {
            "physical_source": {
                "state": "publisher_claimed",
                "groups": len(source_ids),
            },
            "session": {
                "state": "unknown",
                "reason": "not_exposed_by_publisher_metadata",
            },
        },
        "relation_split": {
            "status": "blocked",
            "blocker": "unbounded_session_axis",
            "partitions_assigned": 0,
            "manifest_published": False,
        },
        "privacy": {
            "iq_payload_bytes_read": 0,
            "row_offset_payload_bytes_read": 0,
            "source_identifiers_retained": 0,
            "input_paths_retained": 0,
        },
    }


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    encoded = (
        json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = path.parent.lstat()
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
            raise CapabilityError("unsafe_report_directory")
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise CapabilityError("unsafe_report_path")
        descriptor, name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".json", dir=path.parent
        )
        temporary = Path(name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            with suppress(FileNotFoundError):
                temporary.unlink()
    except CapabilityError:
        raise
    except OSError as error:
        raise CapabilityError("report_write_failed") from error


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", type=Path, default=DEFAULT_ADAPTER)
    parser.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = evaluate(args.adapter)
        write_report(args.report, report)
    except CapabilityError as error:
        print(error.code, file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"schema": SCHEMA, "relation_split": report["relation_split"]},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
