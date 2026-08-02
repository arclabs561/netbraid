#!/usr/bin/env python3
"""Compile local opaque observation oracles from OSU LoRa SigMF metadata."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = (
    ROOT / "data" / "derived" / "eval" / "osu-lora-observation-oracles.json"
)
SCHEMA = "netbraid.osu_lora_observation_oracles.v0"
PROVENANCE_REVISION = "publisher-release-note-v2"
ID_REVISION = "osu-lora-oracle-id-v0"
MAX_MANIFEST_BYTES = 64 * 1024 * 1024

AXES = (
    "event",
    "physical_device",
    "physical_source",
    "variant",
    "session",
    "domain",
    "day",
    "receiver",
    "location",
    "channel",
    "configuration",
)

DAY_SETUPS = frozenset(("days-indoor", "days-outdoor", "days-wired"))
DISTANCES = frozenset(("5m", "10m", "15m", "20m"))
RECEIVER_SCENARIOS = frozenset(
    (
        "Diff_Receivers_Setup_Indoor_DiffTx",
        "Diff_Receivers_Setup_Indoor_SameTx",
        "Diff_Receivers_Setup_Outdoor_DiffTx",
    )
)

DAY_PATTERN = re.compile(r"Day([1-5])\Z")
DEVICE_PATTERN = re.compile(r"Device([1-9]|1[0-9]|2[0-5])\Z")
CONFIGURATION_PATTERN = re.compile(r"Config([1-4])\Z")
LOCATION_PATTERN = re.compile(r"Location([1-3])\Z")
RECEIVER_PATTERN = re.compile(r"(?:Recv|RX)([12])\Z")
PREFIX_REPRESENTATION_PATTERN = re.compile(r"(IQ|iq|FFT|fft)_([0-9]+)\Z")
SUFFIX_REPRESENTATION_PATTERN = re.compile(
    r"Device([1-9]|1[0-9]|2[0-5])_(IQ|iq|FFT|fft)\Z"
)


class OracleCompileError(RuntimeError):
    """Stable fail-closed reason for an invalid oracle input or output."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _load_profiler() -> ModuleType:
    path = Path(__file__).resolve().with_name("profile-osu-lora-sigmf.py")
    spec = importlib.util.spec_from_file_location("_osu_lora_sigmf_profiler", path)
    if spec is None or spec.loader is None:
        raise OracleCompileError("profiler_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PROFILE = _load_profiler()


@dataclass(frozen=True)
class PathFacts:
    representation: str
    event_key: Tuple[Any, ...]
    physical_device_key: Tuple[Any, ...]
    domain_key: Tuple[Any, ...]
    day_key: Optional[Tuple[Any, ...]]
    receiver_key: Tuple[Any, ...]
    location_key: Optional[Tuple[Any, ...]]
    configuration_key: Optional[Tuple[Any, ...]]


@dataclass(frozen=True)
class MetadataOracleFacts:
    physical_source_key: Optional[str]
    variant_key: Optional[str]
    channel_key: Optional[str]
    event_evidence: str


@dataclass(frozen=True)
class CompiledObservation:
    event_key: Tuple[Any, ...]
    representation: str
    event_evidence: str
    document: Dict[str, Any]


class OpaqueIdentifiers:
    """Create deterministic namespace-separated IDs and reject collisions."""

    def __init__(self) -> None:
        self._values: Dict[Tuple[str, str], str] = {}

    def identifier(self, namespace: str, value: Any) -> str:
        canonical = _canonical(value)
        digest = hashlib.sha256(
            (ID_REVISION + "\0" + namespace + "\0" + canonical).encode("utf-8")
        ).hexdigest()[:32]
        key = (namespace, digest)
        previous = self._values.get(key)
        if previous is not None and previous != canonical:
            raise OracleCompileError("opaque_identifier_collision")
        self._values[key] = canonical
        return digest


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _representation(stem: str, maximum: int) -> Tuple[str, int]:
    match = PREFIX_REPRESENTATION_PATTERN.fullmatch(stem)
    if match is None:
        raise OracleCompileError("unsupported_observation_path")
    index = int(match.group(2))
    if not 1 <= index <= maximum:
        raise OracleCompileError("unsupported_observation_path")
    return match.group(1).lower(), index


def _receiver_representation(stem: str) -> Tuple[str, int]:
    prefix = PREFIX_REPRESENTATION_PATTERN.fullmatch(stem)
    if prefix is not None:
        index = int(prefix.group(2))
        if 1 <= index <= 25:
            return prefix.group(1).lower(), index
    suffix = SUFFIX_REPRESENTATION_PATTERN.fullmatch(stem)
    if suffix is not None:
        return suffix.group(2).lower(), int(suffix.group(1))
    raise OracleCompileError("unsupported_observation_path")


def _path_facts(relative: Path) -> PathFacts:
    parts = relative.parts
    if not parts or not relative.name.endswith(".sigmf-meta"):
        raise OracleCompileError("unsupported_observation_path")
    setup = parts[0]
    stem = relative.name[: -len(".sigmf-meta")]

    if setup in DAY_SETUPS:
        if len(parts) != 4:
            raise OracleCompileError("unsupported_observation_path")
        day_match = DAY_PATTERN.fullmatch(parts[1])
        device_match = DEVICE_PATTERN.fullmatch(parts[2])
        if day_match is None or device_match is None:
            raise OracleCompileError("unsupported_observation_path")
        representation, transmission = _representation(stem, 10)
        day = int(day_match.group(1))
        device = int(device_match.group(1))
        return PathFacts(
            representation=representation,
            event_key=("day", setup, day, device, transmission),
            physical_device_key=("publisher_device", setup, device),
            domain_key=("setup", setup),
            day_key=("setup_day", setup, day),
            receiver_key=("setup_single_receiver", setup),
            location_key=None,
            configuration_key=None,
        )

    if setup == "distances":
        if len(parts) != 3 or parts[1] not in DISTANCES:
            raise OracleCompileError("unsupported_observation_path")
        representation, device = _representation(stem, 25)
        condition_key: Tuple[Any, ...] = ("distance", parts[1])
        location_key = None
        configuration_key = None
    elif setup == "configurations":
        if len(parts) != 3:
            raise OracleCompileError("unsupported_observation_path")
        match = CONFIGURATION_PATTERN.fullmatch(parts[1])
        if match is None:
            raise OracleCompileError("unsupported_observation_path")
        representation, device = _representation(stem, 25)
        condition_key = ("configuration", int(match.group(1)))
        location_key = None
        configuration_key = ("configuration", int(match.group(1)))
    elif setup == "locations":
        if len(parts) != 3:
            raise OracleCompileError("unsupported_observation_path")
        match = LOCATION_PATTERN.fullmatch(parts[1])
        if match is None:
            raise OracleCompileError("unsupported_observation_path")
        representation, device = _representation(stem, 25)
        condition_key = ("location", int(match.group(1)))
        location_key = ("location", int(match.group(1)))
        configuration_key = None
    elif setup == "receivers":
        if len(parts) == 3:
            scenario: Optional[str] = None
            receiver_token = parts[1]
        elif len(parts) == 4 and parts[1] in RECEIVER_SCENARIOS:
            scenario = parts[1]
            receiver_token = parts[2]
        else:
            raise OracleCompileError("unsupported_observation_path")
        receiver_match = RECEIVER_PATTERN.fullmatch(receiver_token)
        if receiver_match is None:
            raise OracleCompileError("unsupported_observation_path")
        representation, device = _receiver_representation(stem)
        receiver = int(receiver_match.group(1))
        condition_key = ("receiver", scenario, receiver)
        domain = ("setup", setup, scenario) if scenario else ("setup", setup)
        return PathFacts(
            representation=representation,
            event_key=("receiver", scenario, receiver, device),
            physical_device_key=("publisher_device", setup, scenario, device),
            domain_key=domain,
            day_key=None,
            receiver_key=("receiver", scenario, receiver),
            location_key=None,
            configuration_key=None,
        )
    else:
        raise OracleCompileError("unsupported_observation_path")

    return PathFacts(
        representation=representation,
        event_key=("condition", setup, condition_key, device),
        physical_device_key=("publisher_device", setup, device),
        domain_key=("setup", setup),
        day_key=None,
        receiver_key=("setup_single_receiver", setup),
        location_key=location_key,
        configuration_key=configuration_key,
    )


def _one_canonical(values: Sequence[Any]) -> Optional[str]:
    distinct = {_canonical(value) for value in values}
    if len(distinct) != 1:
        return None
    return next(iter(distinct))


def _metadata_oracle_facts(document: Dict[str, Any], facts: Any) -> MetadataOracleFacts:
    metadata = document["_metadata"]
    source_values: List[Any] = []
    variant_values: List[Any] = []
    for annotation in metadata["annotations"]:
        transmitter = annotation["wines:transmitter"]
        source_values.append(
            {
                "transmitter_id": transmitter["ID"]["Transmitter ID"],
                "model": transmitter["model"],
                "antenna": transmitter["antenna"],
            }
        )
        variant_values.append(
            {
                "model": transmitter["model"],
                "antenna": transmitter["antenna"],
            }
        )

    captures = metadata["captures"]
    channel_key = _one_canonical([capture["frequency"] for capture in captures])
    event_evidence = _canonical(
        {
            "dates": [capture["core:date"] for capture in captures],
            "frequencies": [capture["frequency"] for capture in captures],
            "receivers": facts.receiver_labels,
            "transmitters": facts.transmitter_labels,
        }
    )
    return MetadataOracleFacts(
        physical_source_key=_one_canonical(source_values),
        variant_key=_one_canonical(variant_values),
        channel_key=channel_key,
        event_evidence=event_evidence,
    )


def _known(identifiers: OpaqueIdentifiers, axis: str, value: Any) -> Dict[str, Any]:
    return {
        "state": "known",
        "group_id": identifiers.identifier("axis:" + axis, value),
    }


def _unknown() -> Dict[str, Any]:
    return {"state": "unknown", "group_id": None}


def _not_observed() -> Dict[str, Any]:
    return {"state": "not_observed", "group_id": None}


def _optional_path_group(
    identifiers: OpaqueIdentifiers, axis: str, value: Optional[Tuple[Any, ...]]
) -> Dict[str, Any]:
    if value is None:
        return _not_observed()
    return _known(identifiers, axis, value)


def _metadata_group(
    identifiers: OpaqueIdentifiers, axis: str, value: Optional[str]
) -> Dict[str, Any]:
    if value is None:
        return _unknown()
    return _known(identifiers, axis, value)


def _profile_same_inventory(root: Path, inventory: Any) -> Dict[str, Any]:
    report = PROFILE.profile_tree(root)
    PROFILE._fence_inventory(inventory)
    profile_inventory = report["inventory"]
    if (
        report["status"] != "pass"
        or report["validation"]["total_failures"] != 0
        or profile_inventory["other_files"] != 0
        or profile_inventory["files"] != len(inventory.files)
        or profile_inventory["metadata_files"] != profile_inventory["data_files"]
        or report["pairing"]["paired_metadata_data_files"]
        != profile_inventory["metadata_files"]
    ):
        raise OracleCompileError("profiler_rejected_tree")
    return report


def compile_inventory(root: Path) -> Dict[str, Any]:
    """Compile a deterministic path-free oracle inventory from one local tree."""

    inventory = PROFILE.inventory_tree(root)
    profile_report = _profile_same_inventory(root, inventory)
    metadata_records = tuple(
        record for record in inventory.files if record.kind == "metadata"
    )
    data_paths = {
        record.relative for record in inventory.files if record.kind == "data"
    }
    if not metadata_records:
        raise OracleCompileError("empty_metadata_inventory")

    identifiers = OpaqueIdentifiers()
    compiled: List[CompiledObservation] = []
    for record in metadata_records:
        local_stem = record.path.name[: -len(".sigmf-meta")]
        expected_data = record.relative.with_name(local_stem + ".dat")
        if expected_data not in data_paths:
            raise OracleCompileError("profiler_pairing_invariant_failed")

        document = PROFILE._read_metadata(record)
        facts = PROFILE.parse_metadata(document, local_stem)
        if not facts.declaration_matches_stem:
            raise OracleCompileError("profiler_pairing_invariant_failed")
        path_facts = _path_facts(record.relative)
        metadata_facts = _metadata_oracle_facts(document, facts)

        groups = {
            "event": _known(identifiers, "event", path_facts.event_key),
            "physical_device": _known(
                identifiers, "physical_device", path_facts.physical_device_key
            ),
            "physical_source": _metadata_group(
                identifiers,
                "physical_source",
                (
                    _canonical(
                        (path_facts.domain_key, metadata_facts.physical_source_key)
                    )
                    if metadata_facts.physical_source_key is not None
                    else None
                ),
            ),
            "variant": _metadata_group(
                identifiers, "variant", metadata_facts.variant_key
            ),
            "session": _not_observed(),
            "domain": _known(identifiers, "domain", path_facts.domain_key),
            "day": _optional_path_group(identifiers, "day", path_facts.day_key),
            "receiver": _known(identifiers, "receiver", path_facts.receiver_key),
            "location": _optional_path_group(
                identifiers, "location", path_facts.location_key
            ),
            "channel": _metadata_group(
                identifiers, "channel", metadata_facts.channel_key
            ),
            "configuration": _optional_path_group(
                identifiers,
                "configuration",
                path_facts.configuration_key,
            ),
        }
        observation = {
            "observation_id": identifiers.identifier(
                "observation", record.relative.as_posix()
            ),
            **{axis + "_group": groups[axis] for axis in AXES},
        }
        compiled.append(
            CompiledObservation(
                event_key=path_facts.event_key,
                representation=path_facts.representation,
                event_evidence=metadata_facts.event_evidence,
                document=observation,
            )
        )

    PROFILE._fence_inventory(inventory)

    by_event: Dict[str, List[CompiledObservation]] = defaultdict(list)
    for observation in compiled:
        by_event[_canonical(observation.event_key)].append(observation)

    corresponding_pairs = 0
    singleton_events = 0
    for observations in by_event.values():
        if len(observations) == 1:
            singleton_events += 1
            continue
        representations = {item.representation for item in observations}
        if len(observations) != 2 or representations != {"iq", "fft"}:
            raise OracleCompileError("ambiguous_representation_event")
        if len({item.event_evidence for item in observations}) != 1:
            raise OracleCompileError("representation_metadata_mismatch")
        corresponding_pairs += 1

    documents = sorted(
        (item.document for item in compiled), key=lambda item: item["observation_id"]
    )
    state_counts: Dict[str, Dict[str, int]] = {}
    distinct_groups: Dict[str, int] = {}
    for axis in AXES:
        groups = [item[axis + "_group"] for item in documents]
        counts = Counter(group["state"] for group in groups)
        state_counts[axis] = {
            state: counts[state] for state in ("known", "unknown", "not_observed")
        }
        distinct_groups[axis] = len(
            {group["group_id"] for group in groups if group["state"] == "known"}
        )

    representation_counts = Counter(item.representation for item in compiled)
    return {
        "schema": SCHEMA,
        "provenance": {
            "publisher_release_revision": PROVENANCE_REVISION,
            "profiler_schema": profile_report["schema"],
        },
        "manifest": {
            "local_ignored_manifest": True,
            "partitions_assigned": 0,
            "train_test_splits_assigned": False,
        },
        "counts": {
            "observations": len(documents),
            "events": len(by_event),
            "metadata_data_pairs": len(metadata_records),
            "iq_observations": representation_counts["iq"],
            "fft_observations": representation_counts["fft"],
            "corresponding_iq_fft_events": corresponding_pairs,
            "single_representation_events": singleton_events,
            "axis_states": state_counts,
            "distinct_known_groups": distinct_groups,
        },
        "privacy": {
            "absolute_paths_retained": 0,
            "relative_paths_retained": 0,
            "source_label_values_retained": 0,
            "capture_date_values_retained": 0,
            "frequency_values_retained": 0,
            "author_values_retained": 0,
            "source_urls_retained": 0,
            "raw_metadata_values_retained": 0,
            "iq_payload_bytes_read": 0,
            "fft_payload_bytes_read": 0,
        },
        "observations": documents,
    }


def render_manifest(manifest: Dict[str, Any]) -> bytes:
    rendered = (
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")
    if len(rendered) > MAX_MANIFEST_BYTES:
        raise OracleCompileError("manifest_byte_limit_exceeded")
    return rendered


def write_manifest(path: Path, rendered: bytes) -> None:
    if len(rendered) > MAX_MANIFEST_BYTES:
        raise OracleCompileError("manifest_byte_limit_exceeded")
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent_metadata = path.parent.lstat()
        if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
            parent_metadata.st_mode
        ):
            raise OracleCompileError("unsafe_manifest_directory")
        if path.is_symlink() or (
            path.exists() and not stat.S_ISREG(path.lstat().st_mode)
        ):
            raise OracleCompileError("unsafe_manifest_path")

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
    except OracleCompileError:
        raise
    except OSError as error:
        raise OracleCompileError("manifest_io_error") from error


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT / "data" / "raw" / "osu-lora",
        help="downloaded OSU LoRa setup tree",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST,
        help="atomic local ignored observation-oracle manifest",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    arguments = parse_args(argv)
    try:
        manifest = compile_inventory(arguments.root.expanduser().absolute())
        rendered = render_manifest(manifest)
        write_manifest(arguments.manifest.expanduser().absolute(), rendered)
    except (OracleCompileError, PROFILE.ProfileError) as error:
        print(str(error), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
