#!/usr/bin/env python3
"""Shared strict I/O for tracked experiment summaries and ignored reports."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

MAX_EXPERIMENT_BYTES = 256 * 1024
MAX_REPORT_BYTES = 2 * 1024 * 1024
JSON_BLOCK = re.compile(r"```json\n(?P<payload>.*?)\n```", re.DOTALL)


class VerificationError(ValueError):
    """Stable, path-free result-summary verification failure."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("duplicate_json_key")
        result[key] = value
    return result


def _read_text(path: Path, limit: int, error_code: str) -> str:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
            raise VerificationError(error_code)
        payload = path.read_bytes()
    except OSError as error:
        raise VerificationError(error_code) from error
    if len(payload) > limit:
        raise VerificationError(error_code)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError(error_code) from error


def _load_json_text(payload: str, error_code: str) -> Mapping[str, Any]:
    try:
        value = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, VerificationError) as error:
        raise VerificationError(error_code) from error
    if not isinstance(value, Mapping):
        raise VerificationError(error_code)
    return value


def load_summary(path: Path, schema: str) -> Mapping[str, Any]:
    document = _read_text(path, MAX_EXPERIMENT_BYTES, "experiment_unavailable")
    matches: list[Mapping[str, Any]] = []
    for match in JSON_BLOCK.finditer(document):
        value = _load_json_text(match.group("payload"), "invalid_result_summary")
        if value.get("schema") == schema:
            matches.append(value)
    if len(matches) != 1:
        raise VerificationError("result_summary_count")
    return matches[0]


def load_report(path: Path) -> Mapping[str, Any]:
    return _load_json_text(
        _read_text(path, MAX_REPORT_BYTES, "report_unavailable"),
        "invalid_report",
    )


def verify(
    experiment_path: Path,
    report_path: Path,
    summary_schema: str,
    project_report: Callable[[Mapping[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    expected = load_summary(experiment_path, summary_schema)
    actual = project_report(load_report(report_path))
    if expected != actual:
        raise VerificationError("result_summary_mismatch")
    return actual
