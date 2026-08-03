#!/usr/bin/env python3
"""Compile bounded XRF55 multimodal event-performer hypothesis frames."""

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
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
DEFAULT_RAW_DIR = ROOT / "data" / "raw"
DEFAULT_RECEIPT_DIR = ROOT / "data" / "receipts" / "xrf55"
DEFAULT_MANIFEST = ROOT / "data" / "derived" / "eval" / "xrf55-hypothesis-frames.json"
ID_REVISION = "xrf55-hypothesis-frame-v0"
MAX_SAME_EVENTS = 512
MODALITY_PAIRS = (("wifi", "rfid"), ("wifi", "mmwave"), ("rfid", "mmwave"))

ObservationKey = tuple[int, int, int, int]
SubjectGroup = tuple[int, int]


class Xrf55FrameCompileError(RuntimeError):
    """Stable failure at the XRF55 relation-compilation boundary."""


def _load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise Xrf55FrameCompileError("module_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PROFILE = _load_module("_xrf55_layout_profile", HERE / "profile-xrf55-layout.py")
FRAME = _load_module("hypothesis_frame", HERE / "hypothesis_frame.py")


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _digest(namespace: str, value: Any) -> str:
    return hashlib.sha256(
        ID_REVISION.encode("ascii")
        + b"\0"
        + namespace.encode("ascii")
        + b"\0"
        + _canonical(value)
    ).hexdigest()


def _ranked(namespace: str, values: Iterable[Any]) -> list[Any]:
    return sorted(values, key=lambda value: (_digest(namespace, value), value))


def _scenario() -> dict[str, Any]:
    return {
        "cause": "insufficient_evidence",
        "mechanisms": ["unknown"],
        "modification_loci": ["unknown"],
        "authorization": "unknown",
        "intent": "unknown",
        "provenance": "insufficient_evidence",
        "tamper_hypothesis": {
            "disposition": "underdetermined",
            "basis": [
                "insufficient_change_or_interference_evidence",
                "insufficient_policy_evidence",
            ],
        },
    }


def _frame(
    kind: str,
    identity: Any,
    *,
    event_relation: str,
    event_performer_relation: str,
    physical_device_relation: str,
    physical_source_relation: str,
    configuration_relation: str,
    variant_relation: str,
) -> dict[str, Any]:
    return {
        "frame_id": f"xrf55.{kind}.{_digest(kind, identity)[:32]}",
        "artifact_object_relation": "different_object",
        "content_relation": "different",
        "event_relation": event_relation,
        "event_performer_relation": event_performer_relation,
        "claimed_identifier_relation": "not_observed",
        "cryptographic_principal_relation": "not_observed",
        "physical_device_relation": physical_device_relation,
        "physical_source_relation": physical_source_relation,
        "software_relation": "unknown",
        "configuration_relation": configuration_relation,
        "variant_relation": variant_relation,
        "lineage_relation": "unrelated",
        "integrity": "unverifiable",
        "admissibility": "in_domain",
        "freshness": "unknown",
        "continuity": "unknown",
        "transmission": "unknown",
        "scenario": _scenario(),
    }


def compile_frames(observations: Iterable[ObservationKey]) -> dict[str, Any]:
    observed = set(observations)
    if len(observed) < 2:
        raise Xrf55FrameCompileError("insufficient_observations")
    by_subject: defaultdict[SubjectGroup, set[ObservationKey]] = defaultdict(set)
    for observation in observed:
        if (
            not isinstance(observation, tuple)
            or len(observation) != 4
            or any(type(value) is not int or value <= 0 for value in observation)
        ):
            raise Xrf55FrameCompileError("invalid_observation_key")
        by_subject[(observation[0], observation[1])].add(observation)

    documents = []
    same_events = _ranked("same-event-selection", observed)[:MAX_SAME_EVENTS]
    for event in same_events:
        for left, right in MODALITY_PAIRS:
            documents.append(
                _frame(
                    "same-event",
                    (event, left, right),
                    event_relation="same",
                    event_performer_relation="same",
                    physical_device_relation="different",
                    physical_source_relation="different",
                    configuration_relation="different",
                    variant_relation="different",
                )
            )

    for subject, events in sorted(by_subject.items()):
        candidates = _ranked("same-performer-event-selection", events)
        if len(candidates) < 2:
            continue
        documents.append(
            _frame(
                "same-performer",
                (subject, candidates[0], candidates[1]),
                event_relation="different",
                event_performer_relation="same",
                physical_device_relation="unknown",
                physical_source_relation="unknown",
                configuration_relation="unknown",
                variant_relation="unknown",
            )
        )

    subjects = _ranked("different-performer-selection", by_subject)
    for left, right in zip(subjects[::2], subjects[1::2]):
        left_event = _ranked("different-performer-left-event", by_subject[left])[0]
        right_event = _ranked("different-performer-right-event", by_subject[right])[0]
        documents.append(
            _frame(
                "different-performer",
                (left, right, left_event, right_event),
                event_relation="different",
                event_performer_relation="different",
                physical_device_relation="unknown",
                physical_source_relation="unknown",
                configuration_relation="unknown",
                variant_relation="unknown",
            )
        )

    try:
        parsed = tuple(FRAME.parse_frame(document) for document in documents)
        manifest = FRAME.canonical_manifest(parsed)
        FRAME.parse_manifest(manifest)
    except FRAME.HypothesisFrameError as error:
        raise Xrf55FrameCompileError("invalid_compiled_frame_manifest") from error
    return manifest


def load_observations(raw_dir: Path, receipt_dir: Path) -> set[ObservationKey]:
    selected = {
        name: PROFILE.FETCH.SOURCES[name] for name in PROFILE.PROCESSED_CONTRACTS
    }
    status = PROFILE.FETCH.local_status(selected, raw_dir, receipt_dir)
    observations: set[ObservationKey] = set()
    subject_groups: set[SubjectGroup] = set()
    for name, spec in selected.items():
        observed = status["datasets"][name]
        valid_receipt = (
            observed["central_receipt_state"] == "valid"
            or observed["legacy_receipt_state"] == "valid"
        )
        if observed["archive_state"] != "present" or not valid_receipt:
            raise Xrf55FrameCompileError("archive_or_receipt_metadata_unready")
        inspection = PROFILE.profile_archive(
            raw_dir / str(spec["filename"]),
            int(spec["archive_bytes"]),
            PROFILE.PROCESSED_CONTRACTS[name],
        )
        if observations.intersection(
            inspection.observations
        ) or subject_groups.intersection(inspection.subject_groups):
            raise Xrf55FrameCompileError("processed_archive_group_overlap")
        observations.update(inspection.observations)
        subject_groups.update(inspection.subject_groups)
    return observations


def _write_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.parent.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise Xrf55FrameCompileError("unsafe_manifest_directory")
    if os.path.lexists(path):
        target = path.lstat()
        if stat.S_ISLNK(target.st_mode) or not stat.S_ISREG(target.st_mode):
            raise Xrf55FrameCompileError("unsafe_manifest_path")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(manifest, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def _arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir", type=Path, default=DEFAULT_RAW_DIR)
    parser.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPT_DIR)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _arguments(argv)
    try:
        observations = load_observations(arguments.raw_dir, arguments.receipt_dir)
        manifest = compile_frames(observations)
        _write_manifest(arguments.manifest, manifest)
    except (
        OSError,
        ValueError,
        PROFILE.Xrf55ProfileError,
        Xrf55FrameCompileError,
    ) as error:
        print(str(error), file=sys.stderr)
        return 2
    counts = defaultdict(int)
    for frame in manifest["frames"]:
        counts[frame["frame_id"].split(".")[1]] += 1
    print(
        json.dumps(
            {
                "frames": len(manifest["frames"]),
                "kinds": dict(sorted(counts.items())),
                "observations": len(observations),
                "schema": manifest["schema"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
