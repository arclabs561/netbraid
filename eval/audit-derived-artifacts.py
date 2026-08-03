#!/usr/bin/env python3
"""Audit ignored derived artifacts without reading their contents."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "netbraid.derived_artifact_contract.v0"
REPORT_SCHEMA = "netbraid.derived_artifact_audit.v0"
DEFAULT_CONTRACT = PurePosixPath("eval/derived-artifact-contract-v0.json")
DEFAULT_JUSTFILE = PurePosixPath("justfile")
CONTRACT_KEYS = frozenset({"schema", "derived_root", "artifacts"})
ARTIFACT_KEYS = frozenset({"path", "format", "retention", "producer", "recipe"})
FORMATS = frozenset({"json", "tsv"})
RETENTIONS = frozenset({"legacy/unknown", "reproducibility_output"})
RECIPE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")
WINDOWS_ABSOLUTE = re.compile(r"[A-Za-z]:[\\/]")
PRIVATE_PATH_FRAGMENT = re.compile(
    r"(?:^|[/\\])(?:Users|home|private|Volumes)(?:[/\\])"
)
MAX_CONTRACT_BYTES = 1024 * 1024
MAX_JUSTFILE_BYTES = 2 * 1024 * 1024
MAX_PRODUCER_BYTES = 4 * 1024 * 1024
MAX_TRACKED_BYTES = 16 * 1024 * 1024
MAX_ARTIFACTS = 512
MAX_DIRECTORIES = 128
MAX_PATH_BYTES = 512
MAX_REPORT_BYTES = 16 * 1024


@dataclass(frozen=True)
class Artifact:
    path: str
    format: str
    retention: str
    producer: str
    recipe: str


@dataclass(frozen=True)
class Contract:
    derived_root: str
    artifacts: tuple[Artifact, ...]
    declared_entries: int


class AuditInputError(Exception):
    """A bounded, path-free error suitable for the aggregate report."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _relative_path(value: str) -> PurePosixPath | None:
    if (
        not value
        or len(value.encode("utf-8")) > MAX_PATH_BYTES
        or value.startswith(("/", "\\", "~"))
        or "\\" in value
        or WINDOWS_ABSOLUTE.match(value)
    ):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path


def _contains_private_path(value: Any) -> int:
    if isinstance(value, str):
        return int(
            value.startswith(("/", "\\", "~"))
            or bool(WINDOWS_ABSOLUTE.match(value))
            or bool(PRIVATE_PATH_FRAGMENT.search(value))
        )
    if isinstance(value, list):
        return sum(_contains_private_path(item) for item in value)
    if isinstance(value, dict):
        return sum(
            _contains_private_path(key) + _contains_private_path(item)
            for key, item in value.items()
        )
    return 0


def _safe_file_path(root: Path, relative: PurePosixPath) -> Path | None:
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        try:
            metadata = current.lstat()
        except OSError:
            return None
        final = index == len(relative.parts) - 1
        if stat.S_ISLNK(metadata.st_mode):
            return None
        if final:
            if not stat.S_ISREG(metadata.st_mode):
                return None
        elif not stat.S_ISDIR(metadata.st_mode):
            return None
    return current


def _read_bounded_file(
    root: Path, relative: PurePosixPath, limit: int, code: str
) -> str:
    path = _safe_file_path(root, relative)
    if path is None:
        raise AuditInputError(code)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AuditInputError(code) from error
    with os.fdopen(descriptor, "rb") as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
            raise AuditInputError(code)
        payload = source.read(limit + 1)
    if len(payload) > limit:
        raise AuditInputError(code)
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AuditInputError(code) from error


def _load_contract(
    root: Path, relative: PurePosixPath, errors: Counter[str]
) -> Contract:
    try:
        text = _read_bounded_file(root, relative, MAX_CONTRACT_BYTES, "unsafe_contract")
        value = json.loads(text)
    except json.JSONDecodeError:
        errors["invalid_contract_json"] += 1
        return Contract("", (), 0)
    except AuditInputError as error:
        errors[error.code] += 1
        return Contract("", (), 0)

    private_values = _contains_private_path(value)
    if private_values:
        errors["private_or_absolute_contract_path"] += private_values
    if not isinstance(value, dict):
        errors["invalid_contract_schema"] += 1
        return Contract("", (), 0)
    if set(value) != CONTRACT_KEYS or value.get("schema") != SCHEMA:
        errors["invalid_contract_schema"] += 1

    raw_root = value.get("derived_root")
    root_path = _relative_path(raw_root) if isinstance(raw_root, str) else None
    if root_path is None:
        errors["invalid_derived_root"] += 1
        derived_root = ""
    else:
        derived_root = root_path.as_posix()

    raw_artifacts = value.get("artifacts")
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) > MAX_ARTIFACTS:
        errors["invalid_contract_schema"] += 1
        return Contract(derived_root, (), 0)

    artifacts: list[Artifact] = []
    seen: set[str] = set()
    for raw in raw_artifacts:
        if not isinstance(raw, dict) or set(raw) != ARTIFACT_KEYS:
            errors["invalid_contract_entry"] += 1
            continue
        if not all(isinstance(raw[key], str) for key in ARTIFACT_KEYS):
            errors["invalid_contract_entry"] += 1
            continue

        artifact_path = _relative_path(raw["path"])
        producer_path = _relative_path(raw["producer"])
        valid = True
        if artifact_path is None or root_path is None:
            errors["invalid_artifact_path"] += 1
            valid = False
        elif artifact_path.parts[: len(root_path.parts)] != root_path.parts or len(
            artifact_path.parts
        ) <= len(root_path.parts):
            errors["artifact_outside_derived_root"] += 1
            valid = False
        if producer_path is None or producer_path.suffix != ".py":
            errors["invalid_producer_path"] += 1
            valid = False
        if raw["format"] not in FORMATS:
            errors["invalid_artifact_format"] += 1
            valid = False
        elif artifact_path is not None and artifact_path.suffix != f".{raw['format']}":
            errors["artifact_format_mismatch"] += 1
            valid = False
        if raw["retention"] not in RETENTIONS:
            errors["invalid_retention"] += 1
            valid = False
        if RECIPE_NAME.fullmatch(raw["recipe"]) is None:
            errors["invalid_recipe_name"] += 1
            valid = False
        normalized = (
            artifact_path.as_posix() if artifact_path is not None else raw["path"]
        )
        if normalized in seen:
            errors["duplicate_contract_entry"] += 1
            valid = False
        seen.add(normalized)
        if valid:
            artifacts.append(
                Artifact(
                    path=normalized,
                    format=raw["format"],
                    retention=raw["retention"],
                    producer=producer_path.as_posix(),
                    recipe=raw["recipe"],
                )
            )
    return Contract(derived_root, tuple(artifacts), len(raw_artifacts))


def _parse_justfile(text: str, errors: Counter[str]) -> dict[str, str]:
    recipes: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line[:1].isspace():
            command = line.strip()
            if current is not None and command and not command.startswith("#"):
                recipes[current].append(command)
            continue
        current = None
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "[")) or ":=" in line:
            continue
        header, separator, inline = line.partition(":")
        if not separator:
            continue
        name = header.split(maxsplit=1)[0]
        if RECIPE_NAME.fullmatch(name) is None:
            continue
        if name in recipes:
            errors["duplicate_recipe_definition"] += 1
            continue
        recipes[name] = [inline.strip()] if inline.strip() else []
        current = name
    return {name: "\n".join(body) for name, body in recipes.items()}


def _tracked_paths(root: Path) -> set[str]:
    try:
        completed = subprocess.run(
            ["git", "-C", os.fspath(root), "ls-files", "-z"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        raise AuditInputError("tracked_inventory_unavailable") from error
    if completed.returncode != 0 or len(completed.stdout) > MAX_TRACKED_BYTES:
        raise AuditInputError("tracked_inventory_unavailable")
    try:
        return {item.decode("utf-8") for item in completed.stdout.split(b"\0") if item}
    except UnicodeDecodeError as error:
        raise AuditInputError("tracked_inventory_unavailable") from error


def _inventory_derived(
    root: Path, relative: PurePosixPath, errors: Counter[str]
) -> set[str]:
    directory = root
    for part in relative.parts:
        directory = directory / part
        try:
            metadata = directory.lstat()
        except OSError:
            errors["missing_derived_root"] += 1
            return set()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            errors["unsafe_derived_root"] += 1
            return set()

    files: set[str] = set()
    directory_count = 0

    def visit(current: Path, parts: tuple[str, ...]) -> None:
        nonlocal directory_count
        directory_count += 1
        if directory_count > MAX_DIRECTORIES:
            errors["inventory_bound_exceeded"] += 1
            return
        try:
            with os.scandir(current) as iterator:
                entries = list(iterator)
        except OSError:
            errors["unsafe_artifact_type"] += 1
            return
        for entry in entries:
            if len(files) >= MAX_ARTIFACTS:
                errors["inventory_bound_exceeded"] += 1
                return
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                errors["unsafe_artifact_type"] += 1
                continue
            child_parts = (*parts, entry.name)
            if stat.S_ISLNK(metadata.st_mode):
                errors["unsafe_artifact_type"] += 1
            elif stat.S_ISDIR(metadata.st_mode):
                visit(Path(entry.path), child_parts)
            elif stat.S_ISREG(metadata.st_mode):
                relative_file = PurePosixPath(*relative.parts, *child_parts).as_posix()
                if len(relative_file.encode("utf-8")) > MAX_PATH_BYTES:
                    errors["inventory_bound_exceeded"] += 1
                else:
                    files.add(relative_file)
            else:
                errors["unsafe_artifact_type"] += 1

    visit(directory, ())
    return files


def _mentions_path(text: str, path: str) -> bool:
    token_characters = r"A-Za-z0-9_./-"
    return (
        re.search(
            rf"(?<![{token_characters}]){re.escape(path)}(?![{token_characters}])",
            text,
        )
        is not None
    )


def _mentions_filename(text: str, filename: str) -> bool:
    token_characters = r"A-Za-z0-9_.-"
    return (
        re.search(
            rf"(?<![{token_characters}]){re.escape(filename)}(?![{token_characters}])",
            text,
        )
        is not None
    )


def audit_repository(
    root: Path,
    contract_path: PurePosixPath = DEFAULT_CONTRACT,
    justfile_path: PurePosixPath = DEFAULT_JUSTFILE,
    *,
    tracked_paths: set[str] | None = None,
) -> dict[str, Any]:
    root = root.absolute()
    errors: Counter[str] = Counter()
    contract = _load_contract(root, contract_path, errors)

    derived_path = (
        _relative_path(contract.derived_root) if contract.derived_root else None
    )
    actual_files = (
        _inventory_derived(root, derived_path, errors)
        if derived_path is not None
        else set()
    )
    declared_files = {artifact.path for artifact in contract.artifacts}
    errors["unclassified_artifact"] += len(actual_files - declared_files)

    try:
        justfile_text = _read_bounded_file(
            root, justfile_path, MAX_JUSTFILE_BYTES, "unsafe_justfile"
        )
    except AuditInputError as error:
        errors[error.code] += 1
        justfile_text = ""
    recipes = _parse_justfile(justfile_text, errors)

    if tracked_paths is None:
        try:
            tracked_paths = _tracked_paths(root)
        except AuditInputError as error:
            errors[error.code] += 1
            tracked_paths = set()
    if justfile_path.as_posix() not in tracked_paths:
        errors["untracked_justfile"] += 1

    producer_texts: dict[str, str | None] = {}
    for producer in sorted({artifact.producer for artifact in contract.artifacts}):
        relative = PurePosixPath(producer)
        try:
            producer_texts[producer] = _read_bounded_file(
                root, relative, MAX_PRODUCER_BYTES, "missing_or_unsafe_producer"
            )
        except AuditInputError as error:
            errors[error.code] += 1
            producer_texts[producer] = None
            continue
        if producer not in tracked_paths:
            errors["untracked_producer"] += 1

    for artifact in contract.artifacts:
        recipe_body = recipes.get(artifact.recipe)
        if recipe_body is None:
            errors["missing_recipe"] += 1
            continue
        if not _mentions_path(recipe_body, artifact.producer):
            errors["producer_not_invoked_by_recipe"] += 1
        producer_text = producer_texts.get(artifact.producer)
        if producer_text is not None:
            basename = PurePosixPath(artifact.path).name
            if not _mentions_filename(
                producer_text, basename
            ) and not _mentions_filename(
                recipe_body,
                basename,
            ):
                errors["artifact_not_declared_by_producer_or_recipe"] += 1

    error_counts = {key: count for key, count in sorted(errors.items()) if count}
    artifacts_by_path = {artifact.path: artifact for artifact in contract.artifacts}
    retained_artifacts = [
        artifacts_by_path[path] for path in actual_files if path in artifacts_by_path
    ]
    retention_counts = Counter(artifact.retention for artifact in retained_artifacts)
    format_counts = Counter(artifact.format for artifact in retained_artifacts)
    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "ok": not error_counts,
        "artifact_count": len(actual_files),
        "contract_entry_count": contract.declared_entries,
        "producer_count": len(producer_texts),
        "recipe_count": len({artifact.recipe for artifact in contract.artifacts}),
        "retention_counts": {
            retention: retention_counts[retention] for retention in sorted(RETENTIONS)
        },
        "format_counts": {
            artifact_format: format_counts[artifact_format]
            for artifact_format in sorted(FORMATS)
        },
        "error_counts": error_counts,
    }
    if len(json.dumps(report, sort_keys=True).encode("utf-8")) > MAX_REPORT_BYTES:
        raise RuntimeError("aggregate report exceeded fixed bound")
    return report


def _arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--contract", type=PurePosixPath, default=DEFAULT_CONTRACT)
    parser.add_argument("--justfile", type=PurePosixPath, default=DEFAULT_JUSTFILE)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = _arguments(argv)
    if arguments.contract.is_absolute() or arguments.justfile.is_absolute():
        report = {
            "schema": REPORT_SCHEMA,
            "ok": False,
            "artifact_count": 0,
            "contract_entry_count": 0,
            "producer_count": 0,
            "recipe_count": 0,
            "retention_counts": {name: 0 for name in sorted(RETENTIONS)},
            "format_counts": {name: 0 for name in sorted(FORMATS)},
            "error_counts": {"absolute_cli_path": 1},
        }
    else:
        report = audit_repository(
            arguments.root, arguments.contract, arguments.justfile
        )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        fallback = {
            "schema": REPORT_SCHEMA,
            "ok": False,
            "artifact_count": 0,
            "contract_entry_count": 0,
            "producer_count": 0,
            "recipe_count": 0,
            "retention_counts": {name: 0 for name in sorted(RETENTIONS)},
            "format_counts": {name: 0 for name in sorted(FORMATS)},
            "error_counts": {"internal_error": 1},
        }
        print(json.dumps(fallback, sort_keys=True, separators=(",", ":")))
        raise SystemExit(2) from None
