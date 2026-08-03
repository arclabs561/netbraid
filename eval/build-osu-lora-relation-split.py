#!/usr/bin/env python3
"""Build a bounded relation split from opaque OSU LoRa observation oracles."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ORACLE = (
    ROOT / "data" / "derived" / "eval" / "osu-lora-observation-oracles.json"
)
DEFAULT_MANIFEST = (
    ROOT / "data" / "derived" / "eval" / "osu-lora-relation-split-manifest.json"
)
ORACLE_SCHEMA = "netbraid.osu_lora_observation_oracles.v0"
ID_REVISION = "osu-lora-relation-split-v0"

MAX_ORACLE_INPUT_BYTES = 64 * 1024 * 1024
MAX_SUMMARY_FIELDS = 64
MAX_SUMMARY_KEY_BYTES = 128

ORACLE_FIELDS = (
    "schema",
    "provenance",
    "manifest",
    "counts",
    "privacy",
    "observations",
)
ORACLE_MANIFEST_FIELDS = (
    "local_ignored_manifest",
    "partitions_assigned",
    "train_test_splits_assigned",
)
PRIVACY_FIELDS = (
    "absolute_paths_retained",
    "relative_paths_retained",
    "source_label_values_retained",
    "capture_date_values_retained",
    "frequency_values_retained",
    "author_values_retained",
    "source_urls_retained",
    "raw_metadata_values_retained",
    "iq_payload_bytes_read",
    "fft_payload_bytes_read",
)


class RelationSplitBuildError(RuntimeError):
    """Stable fail-closed reason for invalid input or an unsafe assignment."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _load_auditor() -> ModuleType:
    path = Path(__file__).resolve().with_name("relation_split_audit.py")
    spec = importlib.util.spec_from_file_location("_relation_split_audit", path)
    if spec is None or spec.loader is None:
        raise RelationSplitBuildError("auditor_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


AUDIT = _load_auditor()
AXES = AUDIT.AXES
ROLES = AUDIT.ROLES
ROLE_PAIRS = AUDIT.ROLE_PAIRS

GROUP_FIELDS = ("state", "group_id")
OBSERVATION_FIELDS = ("observation_id",) + tuple(f"{axis}_group" for axis in AXES)


def _expect_fields(value: Mapping[str, Any], fields: Sequence[str], code: str) -> None:
    if set(value) != set(fields):
        raise RelationSplitBuildError(code)


def _parse_opaque_id(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or AUDIT.OPAQUE_ID_PATTERN.fullmatch(value) is None
        or len(value.encode("utf-8")) > AUDIT.MAX_ID_BYTES
    ):
        raise RelationSplitBuildError(code)
    return value


def _parse_group(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationSplitBuildError("invalid_oracle_group_schema")
    _expect_fields(value, GROUP_FIELDS, "invalid_oracle_group_schema")
    state = value["state"]
    if not isinstance(state, str) or state not in AUDIT.GROUP_STATES:
        raise RelationSplitBuildError("invalid_oracle_group_state")
    group_id = value["group_id"]
    if state == "known":
        group_id = _parse_opaque_id(group_id, "invalid_oracle_group_id")
    elif group_id is not None:
        raise RelationSplitBuildError("oracle_group_id_requires_known_state")
    return {"state": state, "group_id": group_id}


def _bounded_summary(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or len(value) > MAX_SUMMARY_FIELDS:
        raise RelationSplitBuildError(code)
    if any(
        not isinstance(key, str) or len(key.encode("utf-8")) > MAX_SUMMARY_KEY_BYTES
        for key in value
    ):
        raise RelationSplitBuildError(code)
    return value


def _validate_oracle_metadata(value: Mapping[str, Any], observation_count: int) -> None:
    _bounded_summary(value["provenance"], "invalid_oracle_provenance")
    manifest = _bounded_summary(value["manifest"], "invalid_oracle_manifest")
    _expect_fields(manifest, ORACLE_MANIFEST_FIELDS, "invalid_oracle_manifest")
    if (
        manifest["local_ignored_manifest"] is not True
        or type(manifest["partitions_assigned"]) is not int
        or manifest["partitions_assigned"] != 0
        or manifest["train_test_splits_assigned"] is not False
    ):
        raise RelationSplitBuildError("oracle_already_partitioned")

    counts = _bounded_summary(value["counts"], "invalid_oracle_counts")
    if type(counts.get("observations")) is not int:
        raise RelationSplitBuildError("invalid_oracle_counts")
    if counts["observations"] != observation_count:
        raise RelationSplitBuildError("oracle_observation_count_mismatch")

    privacy = _bounded_summary(value["privacy"], "invalid_oracle_privacy")
    _expect_fields(privacy, PRIVACY_FIELDS, "invalid_oracle_privacy")
    if any(type(item) is not int or item != 0 for item in privacy.values()):
        raise RelationSplitBuildError("input_privacy_contract_failed")


def _parse_observation(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationSplitBuildError("invalid_oracle_observation_schema")
    _expect_fields(value, OBSERVATION_FIELDS, "invalid_oracle_observation_schema")

    observation_id = _parse_opaque_id(
        value["observation_id"], "invalid_oracle_observation_id"
    )
    groups = {axis: _parse_group(value[f"{axis}_group"]) for axis in AXES}
    if groups["event"]["state"] != "known":
        raise RelationSplitBuildError("unbounded_event_axis")
    if groups["session"]["state"] != "known":
        raise RelationSplitBuildError("unbounded_session_axis")
    return {
        "observation_id": observation_id,
        **{f"{axis}_group": groups[axis] for axis in AXES},
    }


class _Components:
    def __init__(self, count: int) -> None:
        self.parents = list(range(count))
        self.sizes = [1] * count

    def find(self, index: int) -> int:
        while self.parents[index] != index:
            self.parents[index] = self.parents[self.parents[index]]
            index = self.parents[index]
        return index

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if self.sizes[left_root] < self.sizes[right_root]:
            left_root, right_root = right_root, left_root
        self.parents[right_root] = left_root
        self.sizes[left_root] += self.sizes[right_root]


def _assignment_components(
    observations: Sequence[dict[str, Any]],
) -> list[list[dict[str, Any]]]:
    components = _Components(len(observations))
    first_by_group: dict[tuple[str, str], int] = {}
    for index, observation in enumerate(observations):
        for axis in ("event", "session"):
            group_id = observation[f"{axis}_group"]["group_id"]
            assert isinstance(group_id, str)
            key = (axis, group_id)
            first = first_by_group.setdefault(key, index)
            components.union(index, first)

    members: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, observation in enumerate(observations):
        members[components.find(index)].append(observation)
    ordered = [
        sorted(items, key=lambda item: item["observation_id"])
        for items in members.values()
    ]
    ordered.sort(key=lambda items: (-len(items), items[0]["observation_id"]))
    return ordered


def _partition_id(role: str, observations: Sequence[dict[str, Any]]) -> str:
    identities = "\0".join(item["observation_id"] for item in observations)
    return hashlib.sha256(
        (ID_REVISION + "\0partition\0" + role + "\0" + identities).encode("utf-8")
    ).hexdigest()[:32]


def _policies() -> dict[str, Any]:
    all_pairs = [list(role_pair) for role_pair in ROLE_PAIRS]
    return {
        axis: {
            "forbidden_role_pairs": all_pairs if axis in ("event", "session") else []
        }
        for axis in AXES
    }


def build_manifest(oracle: Any) -> dict[str, Any]:
    """Validate one v0 oracle and assign every bounded component exactly once."""

    if not isinstance(oracle, Mapping):
        raise RelationSplitBuildError("invalid_oracle_schema")
    _expect_fields(oracle, ORACLE_FIELDS, "invalid_oracle_schema")
    if oracle["schema"] != ORACLE_SCHEMA:
        raise RelationSplitBuildError("unsupported_oracle_schema")
    raw_observations = oracle["observations"]
    if (
        not isinstance(raw_observations, list)
        or not len(ROLES) <= len(raw_observations) <= AUDIT.MAX_TOTAL_OBSERVATIONS
    ):
        raise RelationSplitBuildError("invalid_oracle_observation_count")
    _validate_oracle_metadata(oracle, len(raw_observations))

    observations = sorted(
        (_parse_observation(item) for item in raw_observations),
        key=lambda item: item["observation_id"],
    )
    observation_ids = [item["observation_id"] for item in observations]
    if len(set(observation_ids)) != len(observation_ids):
        raise RelationSplitBuildError("duplicate_oracle_observation_id")

    components = _assignment_components(observations)
    if len(components) < len(ROLES):
        raise RelationSplitBuildError("insufficient_assignment_components")

    assigned: dict[str, list[dict[str, Any]]] = {role: [] for role in ROLES}
    loads = {role: 0 for role in ROLES}
    for component in components:
        role = min(ROLES, key=lambda item: (loads[item], ROLES.index(item)))
        assigned[role].extend(component)
        loads[role] += len(component)

    candidate = {
        "schema": AUDIT.MANIFEST_SCHEMA,
        "policies": _policies(),
        "partitions": [
            {
                "partition_id": _partition_id(role, assigned[role]),
                "role": role,
                "observations": assigned[role],
            }
            for role in ROLES
        ],
    }
    try:
        parsed = AUDIT.parse_manifest(candidate)
        canonical = AUDIT.canonical_manifest(parsed)
        report = AUDIT.audit_manifest(canonical)
    except AUDIT.RelationSplitError as error:
        raise RelationSplitBuildError("invalid_compiled_manifest") from error
    if report["status"] != "pass":
        raise RelationSplitBuildError("split_audit_failed")
    return canonical


def render_manifest(manifest: Mapping[str, Any]) -> bytes:
    try:
        rendered = (
            json.dumps(
                manifest,
                allow_nan=False,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise RelationSplitBuildError("manifest_not_json_serializable") from error
    if len(rendered) > AUDIT.MAX_INPUT_BYTES:
        raise RelationSplitBuildError("manifest_byte_limit_exceeded")
    return rendered


def write_manifest(path: Path, rendered: bytes) -> None:
    if len(rendered) > AUDIT.MAX_INPUT_BYTES:
        raise RelationSplitBuildError("manifest_byte_limit_exceeded")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_metadata = path.parent.lstat()
        if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
            parent_metadata.st_mode
        ):
            raise RelationSplitBuildError("unsafe_manifest_directory")
        if path.is_symlink() or (
            path.exists() and not stat.S_ISREG(path.lstat().st_mode)
        ):
            raise RelationSplitBuildError("unsafe_manifest_path")

        descriptor, temporary = tempfile.mkstemp(
            prefix="." + path.name + ".", dir=path.parent
        )
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(rendered)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_descriptor = os.open(path.parent, directory_flags)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    except RelationSplitBuildError:
        raise
    except OSError as error:
        raise RelationSplitBuildError("manifest_io_error") from error


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RelationSplitBuildError("duplicate_json_key")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise RelationSplitBuildError("invalid_json_constant")


def load_oracle_bytes(data: bytes) -> Mapping[str, Any]:
    if len(data) > MAX_ORACLE_INPUT_BYTES:
        raise RelationSplitBuildError("oracle_too_large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RelationSplitBuildError("invalid_json") from error
    value = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(value, Mapping):
        raise RelationSplitBuildError("invalid_oracle_schema")
    return value


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--oracle",
        type=Path,
        default=DEFAULT_ORACLE,
        help="local ignored OSU LoRa observation-oracle manifest",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="atomic local ignored relation-split manifest",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = parse_args(argv)
    try:
        with arguments.oracle.expanduser().absolute().open("rb") as source:
            oracle = load_oracle_bytes(source.read(MAX_ORACLE_INPUT_BYTES + 1))
        manifest = build_manifest(oracle)
        rendered = render_manifest(manifest)
        write_manifest(arguments.manifest.expanduser().absolute(), rendered)
    except RelationSplitBuildError as error:
        print(error.code, file=sys.stderr)
        return 2
    except json.JSONDecodeError:
        print("invalid_json", file=sys.stderr)
        return 2
    except OSError:
        print("oracle_io_error", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
