#!/usr/bin/env python3
"""Validate and summarize Netbraid's eval-facing modality registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "eval" / "fixtures" / "modality-coverage-v0.json"
SOURCE_CATALOG = ROOT / "data" / "catalog" / "research-leads-v1.json"
MAX_INPUT_BYTES = 256 * 1024
SCHEMA = "netbraid.modality_coverage.v0"
REPORT_SCHEMA = "netbraid.modality_coverage_audit.v0"
READINESS = {"blocked", "candidate", "evaluated", "profiled"}
SCOPES = {
    "cross_modality",
    "cross_representation_alignment",
    "multimodal_fusion",
    "single_modality",
}
FIELDS = {
    "carrier_regimes",
    "evaluator",
    "evidence_record",
    "id",
    "limitation",
    "observation_levels",
    "readiness",
    "representations",
    "scope",
    "source_lead",
    "technologies",
    "test",
}
TOKEN = re.compile(r"[a-z0-9]+(?:_[a-z0-9]+)*\Z")
ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
PRIVATE = re.compile(
    r"(?i)(/users/|documents/dev|localhost|api[_-]?key|password|secret)"
)


class CoverageError(ValueError):
    pass


def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoverageError("duplicate_json_key")
        result[key] = value
    return result


def read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise CoverageError("input_not_regular")
    payload = path.read_bytes()
    if not payload or len(payload) > MAX_INPUT_BYTES:
        raise CoverageError("input_size")
    try:
        value = json.loads(payload, object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CoverageError("invalid_json") from None
    if not isinstance(value, dict):
        raise CoverageError("document_shape")
    return value, payload


def validate_tokens(value: Any, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not TOKEN.fullmatch(item) for item in value)
        or value != sorted(set(value))
    ):
        raise CoverageError(f"{field}_shape")
    return value


def validate_repo_file(value: Any, field: str) -> None:
    if not isinstance(value, str) or not value or PRIVATE.search(value):
        raise CoverageError(f"{field}_shape")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise CoverageError(f"{field}_path")
    resolved = ROOT / relative
    if resolved.is_symlink() or not resolved.is_file():
        raise CoverageError(f"{field}_missing")


def source_lead_ids() -> set[str]:
    document, _ = read_json(SOURCE_CATALOG)
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise CoverageError("source_catalog_shape")
    return {
        entry["id"]
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    }


def validate_registry(
    path: Path = DEFAULT_REGISTRY,
) -> tuple[list[dict[str, Any]], bytes]:
    document, payload = read_json(path)
    if set(document) != {"schema", "surfaces"} or document["schema"] != SCHEMA:
        raise CoverageError("document_shape")
    surfaces = document["surfaces"]
    if not isinstance(surfaces, list) or not 1 <= len(surfaces) <= 128:
        raise CoverageError("surface_count")
    leads = source_lead_ids()
    ids: list[str] = []
    for surface in surfaces:
        if not isinstance(surface, dict) or set(surface) != FIELDS:
            raise CoverageError("surface_shape")
        surface_id = surface["id"]
        if not isinstance(surface_id, str) or not ID.fullmatch(surface_id):
            raise CoverageError("surface_id")
        ids.append(surface_id)
        validate_tokens(surface["technologies"], "technologies")
        validate_tokens(surface["carrier_regimes"], "carrier_regimes")
        validate_tokens(surface["representations"], "representations")
        validate_tokens(surface["observation_levels"], "observation_levels")
        if surface["readiness"] not in READINESS or surface["scope"] not in SCOPES:
            raise CoverageError("surface_state")
        limitation = surface["limitation"]
        if (
            not isinstance(limitation, str)
            or not 20 <= len(limitation) <= 500
            or PRIVATE.search(limitation)
        ):
            raise CoverageError("limitation_shape")
        source_lead = surface["source_lead"]
        if source_lead is not None and source_lead not in leads:
            raise CoverageError("unknown_source_lead")
        if surface["readiness"] == "candidate":
            if (
                source_lead is None
                or surface["evaluator"] is not None
                or surface["test"] is not None
                or surface["evidence_record"] is not None
            ):
                raise CoverageError("candidate_boundary")
        else:
            for field in ("evaluator", "test", "evidence_record"):
                validate_repo_file(surface[field], field)
        if surface["scope"] == "multimodal_fusion" and len(surface["technologies"]) < 2:
            raise CoverageError("fusion_technology_count")
    if len(ids) != len(set(ids)):
        raise CoverageError("duplicate_surface_id")
    return surfaces, payload


def build_report(path: Path = DEFAULT_REGISTRY) -> dict[str, Any]:
    surfaces, payload = validate_registry(path)
    readiness = Counter(surface["readiness"] for surface in surfaces)
    return {
        "schema": REPORT_SCHEMA,
        "registry_sha256": hashlib.sha256(payload).hexdigest(),
        "surfaces": len(surfaces),
        "readiness": {key: readiness.get(key, 0) for key in sorted(READINESS)},
        "technologies": sorted(
            {item for surface in surfaces for item in surface["technologies"]}
        ),
        "carrier_regimes": sorted(
            {item for surface in surfaces for item in surface["carrier_regimes"]}
        ),
        "representations": sorted(
            {item for surface in surfaces for item in surface["representations"]}
        ),
        "observation_levels": sorted(
            {item for surface in surfaces for item in surface["observation_levels"]}
        ),
        "candidate_surfaces": sorted(
            surface["id"] for surface in surfaces if surface["readiness"] == "candidate"
        ),
        "fusion_surfaces": sorted(
            surface["id"]
            for surface in surfaces
            if surface["scope"] == "multimodal_fusion"
        ),
        "cross_modality_surfaces": sorted(
            surface["id"]
            for surface in surfaces
            if surface["scope"] == "cross_modality"
        ),
        "alignment_surfaces": sorted(
            surface["id"]
            for surface in surfaces
            if surface["scope"] == "cross_representation_alignment"
        ),
    }


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def write_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.is_dir():
        raise CoverageError("unsafe_report_path")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--report", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        payload = canonical_json(build_report(args.registry))
        if args.report is not None:
            write_private(args.report, payload)
        print(payload.decode(), end="")
    except (CoverageError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
