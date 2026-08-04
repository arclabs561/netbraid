#!/usr/bin/env python3
"""Build a device-disjoint RUFF-UWB relation split from opaque metadata.

The compiler reads only the ignored observation-oracle inventory. It never
opens a waveform array. A split is published only when source/device aliases
are consistent across both campaigns and the canonical relation-split auditor
can prove event and session separation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ORACLE = (
    ROOT / "data" / "derived" / "eval" / "ruff-uwb-observation-oracles.json"
)
DEFAULT_MANIFEST = (
    ROOT / "data" / "derived" / "eval" / "ruff-uwb-open-set-source-split.json"
)

ORACLE_SCHEMA = "netbraid.ruff_uwb_observation_oracles.v0"
ID_REVISION = "ruff-uwb-open-set-source-split-v0"
ROLE_DEVICE_COUNTS = {
    "train": 4,
    "calibration": 3,
    "validation": 3,
    "test": 3,
}

MAX_ORACLE_INPUT_BYTES = 8 * 1024 * 1024
MAX_SUMMARY_FIELDS = 64
MAX_SUMMARY_KEY_BYTES = 128

ORACLE_FIELDS = (
    "schema",
    "inventory_id",
    "status",
    "provenance",
    "manifest",
    "publisher_claims",
    "required_split_groups",
    "archives",
    "counts",
    "privacy",
    "observations",
)
ORACLE_MANIFEST_FIELDS = (
    "local_ignored_manifest",
    "partitions_assigned",
    "train_test_splits_assigned",
)
PUBLISHER_CLAIM_FIELDS = (
    "physical_sources",
    "physical_devices",
    "locations",
    "variants",
    "receivers",
    "channels",
)
COUNT_FIELDS = (
    "label_rows",
    "observations",
    "distinct_source_location_groups",
    "axis_states",
    "distinct_known_groups",
)
PRIVACY_FIELDS = (
    "absolute_paths_retained",
    "relative_paths_retained",
    "filenames_retained",
    "source_urls_retained",
    "date_values_retained",
    "private_values_retained",
    "waveform_members_opened",
    "waveform_payload_bytes_read",
    "raw_label_values_emitted",
)


class OpenSetSplitError(RuntimeError):
    """Stable fail-closed reason for invalid input or an unsafe split."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _load_auditor() -> ModuleType:
    path = Path(__file__).resolve().with_name("relation_split_audit.py")
    spec = importlib.util.spec_from_file_location("_relation_split_audit", path)
    if spec is None or spec.loader is None:
        raise OpenSetSplitError("auditor_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


AUDIT = _load_auditor()
AXES = AUDIT.AXES
ROLES = AUDIT.ROLES
ROLE_PAIRS = AUDIT.ROLE_PAIRS

GROUP_FIELDS = ("state", "group_id")
OBSERVATION_FIELDS = (
    "observation_id",
    "observation_count",
    *(f"{axis}_group" for axis in AXES),
    "source_location_group",
    "campaign_group",
)


def _expect_fields(value: Mapping[str, Any], fields: Sequence[str], code: str) -> None:
    if set(value) != set(fields):
        raise OpenSetSplitError(code)


def _bounded_summary(value: Any, code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or len(value) > MAX_SUMMARY_FIELDS:
        raise OpenSetSplitError(code)
    if any(
        not isinstance(key, str) or len(key.encode("utf-8")) > MAX_SUMMARY_KEY_BYTES
        for key in value
    ):
        raise OpenSetSplitError(code)
    return value


def _parse_opaque_id(value: Any, code: str) -> str:
    if (
        not isinstance(value, str)
        or AUDIT.OPAQUE_ID_PATTERN.fullmatch(value) is None
        or len(value.encode("utf-8")) > AUDIT.MAX_ID_BYTES
    ):
        raise OpenSetSplitError(code)
    return value


def _parse_group(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise OpenSetSplitError("invalid_oracle_group_schema")
    _expect_fields(value, GROUP_FIELDS, "invalid_oracle_group_schema")
    state = value["state"]
    if not isinstance(state, str) or state not in AUDIT.GROUP_STATES:
        raise OpenSetSplitError("invalid_oracle_group_state")
    group_id = value["group_id"]
    if state == "known":
        group_id = _parse_opaque_id(group_id, "invalid_oracle_group_id")
    elif group_id is not None:
        raise OpenSetSplitError("oracle_group_id_requires_known_state")
    return {"state": state, "group_id": group_id}


def _parse_observation(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise OpenSetSplitError("invalid_oracle_observation_schema")
    _expect_fields(value, OBSERVATION_FIELDS, "invalid_oracle_observation_schema")
    observation_id = _parse_opaque_id(
        value["observation_id"], "invalid_oracle_observation_id"
    )
    observation_count = value["observation_count"]
    if type(observation_count) is not int or not 1 <= observation_count <= 100_000:
        raise OpenSetSplitError("invalid_observation_count")
    groups = {axis: _parse_group(value[f"{axis}_group"]) for axis in AXES}
    source_location = _parse_group(value["source_location_group"])
    campaign = _parse_group(value["campaign_group"])

    for axis in ("physical_source", "physical_device"):
        if groups[axis]["state"] != "known":
            raise OpenSetSplitError(f"unbounded_{axis}_axis")
    if groups["event"]["state"] != "known":
        raise OpenSetSplitError("unbounded_event_axis")
    if groups["session"]["state"] != "known":
        raise OpenSetSplitError("unbounded_session_axis")
    if source_location["state"] != "known":
        raise OpenSetSplitError("unbounded_source_location_group")
    if campaign["state"] != "known":
        raise OpenSetSplitError("unbounded_campaign_group")

    return {
        "observation_id": observation_id,
        "observation_count": observation_count,
        **{f"{axis}_group": groups[axis] for axis in AXES},
        "source_location_group": source_location,
        "campaign_group": campaign,
    }


def _validate_oracle_metadata(value: Mapping[str, Any], observation_count: int) -> None:
    _parse_opaque_id(value["inventory_id"], "invalid_inventory_id")
    if value["status"] != "pass":
        raise OpenSetSplitError("oracle_status_not_pass")
    _bounded_summary(value["provenance"], "invalid_oracle_provenance")

    manifest = _bounded_summary(value["manifest"], "invalid_oracle_manifest")
    _expect_fields(manifest, ORACLE_MANIFEST_FIELDS, "invalid_oracle_manifest")
    if (
        manifest["local_ignored_manifest"] is not True
        or type(manifest["partitions_assigned"]) is not int
        or manifest["partitions_assigned"] != 0
        or manifest["train_test_splits_assigned"] is not False
    ):
        raise OpenSetSplitError("oracle_already_partitioned")

    claims = _bounded_summary(value["publisher_claims"], "invalid_publisher_claims")
    _expect_fields(claims, PUBLISHER_CLAIM_FIELDS, "invalid_publisher_claims")
    if (
        type(claims["physical_sources"]) is not int
        or type(claims["physical_devices"]) is not int
        or claims["physical_sources"] != sum(ROLE_DEVICE_COUNTS.values())
        or claims["physical_devices"] != claims["physical_sources"]
    ):
        raise OpenSetSplitError("unsupported_publisher_device_count")

    required_groups = value["required_split_groups"]
    if not isinstance(required_groups, list) or any(
        not isinstance(item, str) for item in required_groups
    ):
        raise OpenSetSplitError("invalid_required_split_groups")
    required = {"physical_source_group", "source_location_group", "campaign_group"}
    if not required.issubset(required_groups):
        raise OpenSetSplitError("missing_required_split_group")

    archives = value["archives"]
    if (
        not isinstance(archives, list)
        or len(archives) != 2
        or any(not isinstance(item, Mapping) for item in archives)
    ):
        raise OpenSetSplitError("invalid_archive_summary")

    counts = _bounded_summary(value["counts"], "invalid_oracle_counts")
    _expect_fields(counts, COUNT_FIELDS, "invalid_oracle_counts")
    if (
        type(counts["observations"]) is not int
        or counts["observations"] != observation_count
    ):
        raise OpenSetSplitError("oracle_observation_count_mismatch")

    privacy = _bounded_summary(value["privacy"], "invalid_oracle_privacy")
    _expect_fields(privacy, PRIVACY_FIELDS, "invalid_oracle_privacy")
    if any(type(item) is not int or item != 0 for item in privacy.values()):
        raise OpenSetSplitError("input_privacy_contract_failed")


def _device_order(device_id: str) -> tuple[str, str]:
    digest = hashlib.sha256(
        (ID_REVISION + "\0device-role\0" + device_id).encode("utf-8")
    ).hexdigest()
    return digest, device_id


def _role_by_device(observations: Sequence[dict[str, Any]]) -> dict[str, str]:
    source_to_device: dict[str, str] = {}
    device_to_source: dict[str, str] = {}
    campaigns_by_device: dict[str, set[str]] = {}
    event_to_device: dict[str, str] = {}
    session_to_device: dict[str, str] = {}

    for observation in observations:
        source_id = observation["physical_source_group"]["group_id"]
        device_id = observation["physical_device_group"]["group_id"]
        campaign_id = observation["campaign_group"]["group_id"]
        event_id = observation["event_group"]["group_id"]
        session_id = observation["session_group"]["group_id"]
        assert all(
            isinstance(item, str)
            for item in (source_id, device_id, campaign_id, event_id, session_id)
        )

        prior_device = source_to_device.setdefault(source_id, device_id)
        prior_source = device_to_source.setdefault(device_id, source_id)
        if prior_device != device_id or prior_source != source_id:
            raise OpenSetSplitError("physical_source_device_not_bijective")
        campaigns_by_device.setdefault(device_id, set()).add(campaign_id)
        for mapping, group_id, code in (
            (event_to_device, event_id, "event_crosses_physical_device"),
            (session_to_device, session_id, "session_crosses_physical_device"),
        ):
            prior = mapping.setdefault(group_id, device_id)
            if prior != device_id:
                raise OpenSetSplitError(code)

    if len(device_to_source) != sum(ROLE_DEVICE_COUNTS.values()):
        raise OpenSetSplitError("observed_device_count_mismatch")
    campaign_ids = set().union(*campaigns_by_device.values())
    if len(campaign_ids) != 2 or any(
        campaigns != campaign_ids for campaigns in campaigns_by_device.values()
    ):
        raise OpenSetSplitError("incomplete_cross_campaign_device")

    ordered_devices = sorted(device_to_source, key=_device_order)
    assignments: dict[str, str] = {}
    offset = 0
    for role in ROLES:
        count = ROLE_DEVICE_COUNTS[role]
        for device_id in ordered_devices[offset : offset + count]:
            assignments[device_id] = role
        offset += count
    if offset != len(ordered_devices):
        raise OpenSetSplitError("device_role_assignment_mismatch")
    return assignments


def _partition_id(role: str, observations: Sequence[dict[str, Any]]) -> str:
    identities = "\0".join(item["observation_id"] for item in observations)
    return hashlib.sha256(
        (ID_REVISION + "\0partition\0" + role + "\0" + identities).encode("utf-8")
    ).hexdigest()[:32]


def _policies() -> dict[str, Any]:
    all_pairs = [list(role_pair) for role_pair in ROLE_PAIRS]
    separated_axes = {"event", "session", "physical_source", "physical_device"}
    return {
        axis: {"forbidden_role_pairs": all_pairs if axis in separated_axes else []}
        for axis in AXES
    }


def build_manifest(oracle: Any) -> dict[str, Any]:
    """Validate one oracle and assign every physical device exactly once."""

    if not isinstance(oracle, Mapping):
        raise OpenSetSplitError("invalid_oracle_schema")
    _expect_fields(oracle, ORACLE_FIELDS, "invalid_oracle_schema")
    if oracle["schema"] != ORACLE_SCHEMA:
        raise OpenSetSplitError("unsupported_oracle_schema")
    raw_observations = oracle["observations"]
    if (
        not isinstance(raw_observations, list)
        or not len(ROLES) <= len(raw_observations) <= AUDIT.MAX_TOTAL_OBSERVATIONS
    ):
        raise OpenSetSplitError("invalid_oracle_observation_count")
    _validate_oracle_metadata(oracle, len(raw_observations))

    observations = sorted(
        (_parse_observation(item) for item in raw_observations),
        key=lambda item: item["observation_id"],
    )
    observation_ids = [item["observation_id"] for item in observations]
    if len(set(observation_ids)) != len(observation_ids):
        raise OpenSetSplitError("duplicate_oracle_observation_id")
    assignments = _role_by_device(observations)

    assigned: dict[str, list[dict[str, Any]]] = {role: [] for role in ROLES}
    for observation in observations:
        device_id = observation["physical_device_group"]["group_id"]
        assert isinstance(device_id, str)
        assigned[assignments[device_id]].append(
            {
                "observation_id": observation["observation_id"],
                **{f"{axis}_group": observation[f"{axis}_group"] for axis in AXES},
            }
        )

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
        raise OpenSetSplitError("invalid_compiled_manifest") from error
    if report["status"] != "pass":
        raise OpenSetSplitError("split_audit_failed")
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
        raise OpenSetSplitError("manifest_not_json_serializable") from error
    if len(rendered) > AUDIT.MAX_INPUT_BYTES:
        raise OpenSetSplitError("manifest_byte_limit_exceeded")
    return rendered


def write_manifest(path: Path, rendered: bytes) -> None:
    if len(rendered) > AUDIT.MAX_INPUT_BYTES:
        raise OpenSetSplitError("manifest_byte_limit_exceeded")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_metadata = path.parent.lstat()
        if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
            parent_metadata.st_mode
        ):
            raise OpenSetSplitError("unsafe_manifest_directory")
        if path.is_symlink() or (
            path.exists() and not stat.S_ISREG(path.lstat().st_mode)
        ):
            raise OpenSetSplitError("unsafe_manifest_path")

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
    except OpenSetSplitError:
        raise
    except OSError as error:
        raise OpenSetSplitError("manifest_io_error") from error


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise OpenSetSplitError("duplicate_json_key")
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise OpenSetSplitError("invalid_json_constant")


def load_oracle_bytes(data: bytes) -> Mapping[str, Any]:
    if len(data) > MAX_ORACLE_INPUT_BYTES:
        raise OpenSetSplitError("oracle_too_large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise OpenSetSplitError("invalid_json") from error
    value = json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(value, Mapping):
        raise OpenSetSplitError("invalid_oracle_schema")
    return value


def _summary(manifest: Mapping[str, Any], rendered: bytes) -> dict[str, Any]:
    role_device_counts = {}
    for partition in manifest["partitions"]:
        role_device_counts[partition["role"]] = len(
            {
                item["physical_device_group"]["group_id"]
                for item in partition["observations"]
            }
        )
    return {
        "schema": "netbraid.ruff_uwb_open_set_source_split_summary.v0",
        "status": "pass",
        "manifest_sha256": hashlib.sha256(rendered).hexdigest(),
        "observations": sum(
            len(partition["observations"]) for partition in manifest["partitions"]
        ),
        "role_device_counts": role_device_counts,
        "waveform_payload_bytes_read": 0,
    }


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--oracle",
        type=Path,
        default=DEFAULT_ORACLE,
        help="ignored RUFF-UWB observation-oracle inventory",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="atomic ignored device-disjoint split manifest",
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
    except OpenSetSplitError as error:
        print(error.code, file=sys.stderr)
        return 2
    except json.JSONDecodeError:
        print("invalid_json", file=sys.stderr)
        return 2
    except OSError:
        print("oracle_io_error", file=sys.stderr)
        return 2
    print(
        json.dumps(_summary(manifest, rendered), separators=(",", ":"), sort_keys=True)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
