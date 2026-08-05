#!/usr/bin/env python3
"""Execute the locked Sorbonne structural-reducer contract campaign."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import itertools
import json
import os
import stat
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


CAMPAIGN_SHA256 = "78fb75b94aff5f053debad6dac452969df86a4d543cb25ac8e187b9989fa893e"
CAMPAIGN_SCHEMA = "netbraid.sorbonne_structural_reducer_campaign.v0"
REPORT_SCHEMA = "netbraid.sorbonne_structural_reducer_report.v0"
EXPECTED_ARCHIVE_SHA256 = (
    "7a650d450d339683cf7591bc24a6006238456b8dfa54e352aa1aceda8682c3f8"
)
EXPECTED_OBSERVERS = tuple("S{:02d}".format(index) for index in range(1, 11))
EXPECTED_PACKETS = {
    "S01": 1906,
    "S02": 1923,
    "S03": 1799,
    "S04": 1849,
    "S05": 1892,
    "S06": 1908,
    "S07": 1962,
    "S08": 1885,
    "S09": 1939,
    "S10": 1863,
}
EXPECTED_POSITIVE_DIGEST = (
    "1f5eabf1b88856ab999d4210b380df79ff60ef6b94e1926b660e0b980132996f"
)
EXPECTED_NEGATIVE_POOL_DIGEST = (
    "b096dcec8f0488fadedd19097118031a3e5e14e55af3dfb2038b9b1f21798a86"
)
EXPECTED_NEGATIVE_SELECTED_DIGEST = (
    "aff575a7576307e87d5435adee73e53e30e1b00b451b57b34c03627a07876eb7"
)
EXPECTED_BASIS = {
    "compared_dimensions": ["ieee80211_frame_type", "ieee80211_frame_subtype"],
    "compatible_dimensions": [
        "ieee80211_frame_type",
        "ieee80211_frame_subtype",
    ],
    "conflicting_dimensions": [],
    "missing_dimensions": [],
}
MAX_CAMPAIGN_BYTES = 256 * 1024
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_NORMALIZER_STDOUT_BYTES = 16 * 1024 * 1024
MAX_SUBPROCESS_STDERR_BYTES = 4 * 1024 * 1024
MAX_REDUCER_STDOUT_BYTES = 4 * 1024 * 1024
MAX_JSONL_LINE_BYTES = 256 * 1024
NORMALIZER_TIMEOUT_SECONDS = 120
REDUCER_TIMEOUT_SECONDS = 30
EXPECTED_FIELD_REGISTRY = "netmon.tshark.packet_envelope.v5"
PACKET_SCHEMA = "netmon.packet_envelope.v0"
CLAIM_SCHEMA = "netbraid.finite_hypothesis_claim.v0"
PROJECTION_SCHEMA = "netbraid.finite_hypothesis_projection.v0"
PACKET_EVENT_FAMILY = "netmon.packet_same_event_hypothesis_set.v0"
PACKET_EVENT_REDUCER = "netbraid.packet_same_event.structural.v0"


def load_shared() -> Any:
    path = Path(__file__).with_name("evaluate-sorbonne-same-event.py")
    spec = importlib.util.spec_from_file_location("netbraid_sorbonne_shared", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Sorbonne audit helpers")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SHARED = load_shared()
EvaluationError = SHARED.EvaluationError
Observation = SHARED.Observation


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--netbraid-bin", required=True, type=Path)
    parser.add_argument("--reducer-bin", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    return parser.parse_args(argv)


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        path_state = path.lstat()
    except OSError as error:
        raise EvaluationError("cannot inspect {}: {}".format(label, path)) from error
    if not stat.S_ISREG(path_state.st_mode):
        raise EvaluationError("{} is not a regular non-symlink file".format(label))
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvaluationError(
            "cannot open {} without following links".format(label)
        ) from error
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        data = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    if not 0 < len(data) <= maximum or len(data) != before.st_size:
        raise EvaluationError("{} byte count is outside its bound".format(label))
    if (
        (before.st_dev, before.st_ino) != (path_state.st_dev, path_state.st_ino)
        or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        or after.st_size != before.st_size
        or after.st_mtime_ns != before.st_mtime_ns
        or after.st_ctime_ns != before.st_ctime_ns
    ):
        raise EvaluationError("{} changed while reading".format(label))
    return data


def load_campaign(path: Path) -> Tuple[Dict[str, Any], str]:
    data = read_regular(path, MAX_CAMPAIGN_BYTES, "campaign")
    digest = hashlib.sha256(data).hexdigest()
    if digest != CAMPAIGN_SHA256:
        raise EvaluationError("campaign content differs from locked revision 2")
    try:
        campaign = json.loads(data, object_pairs_hook=SHARED.strict_object)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        SHARED.DuplicateKeyError,
    ) as error:
        raise EvaluationError("campaign is not strict duplicate-free JSON") from error
    if not isinstance(campaign, dict):
        raise EvaluationError("campaign root is not an object")
    preregistration = campaign.get("preregistration")
    if (
        campaign.get("schema") != CAMPAIGN_SCHEMA
        or campaign.get("campaign_id") != "sorbonne-campus-1m-structural-reducer-v0"
        or not isinstance(preregistration, dict)
        or preregistration.get("status") != "revised_before_execution"
        or preregistration.get("revision") != 2
        or preregistration.get("execution_state") != "not_executed"
    ):
        raise EvaluationError("campaign identity or execution state differs from lock")
    return campaign, digest


def executable_content(path: Path) -> Tuple[bytes, Dict[str, Any]]:
    data = read_regular(path, MAX_EXECUTABLE_BYTES, "executable")
    if not os.access(path, os.X_OK):
        raise EvaluationError("executable path is not executable: {}".format(path))
    return data, {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def write_executable_snapshot(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o700)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def selected_pcap_members(archive: zipfile.ZipFile) -> Dict[str, zipfile.ZipInfo]:
    root = "220211012-SU-Outdoors-Campus/220211012-SU-Outdoors-Campus/1m/pcapTraces"
    expected = {
        observer: "{}/01m-{}.pcap".format(root, observer)
        for observer in EXPECTED_OBSERVERS
    }
    by_name = {info.filename: info for info in archive.infolist()}
    if len(by_name) != len(archive.infolist()):
        raise EvaluationError("archive contains duplicate member names")
    selected: Dict[str, zipfile.ZipInfo] = {}
    for observer, name in expected.items():
        info = by_name.get(name)
        if info is None or info.is_dir() or info.flag_bits & 1:
            raise EvaluationError(
                "missing or invalid PCAP member for {}".format(observer)
            )
        if not 0 < info.file_size <= SHARED.MAX_MEMBER_UNCOMPRESSED_BYTES:
            raise EvaluationError("PCAP member exceeds its byte bound")
        selected[observer] = info
    other = [
        info.filename
        for info in archive.infolist()
        if "/1m/pcapTraces/" in info.filename and not info.is_dir()
    ]
    if sorted(other) != sorted(expected.values()):
        raise EvaluationError("1 m PCAP inventory differs from the campaign")
    return selected


def parse_jsonl(data: bytes, label: str) -> List[Tuple[Dict[str, Any], bytes]]:
    if not data.endswith(b"\n"):
        raise EvaluationError("{} output is not newline terminated".format(label))
    result = []
    for line_number, line in enumerate(data.splitlines(), start=1):
        if not line or len(line) > MAX_JSONL_LINE_BYTES:
            raise EvaluationError(
                "{} line {} violates its bound".format(label, line_number)
            )
        try:
            value = json.loads(line, object_pairs_hook=SHARED.strict_object)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            SHARED.DuplicateKeyError,
        ) as error:
            raise EvaluationError(
                "{} line {} is not strict JSON".format(label, line_number)
            ) from error
        if not isinstance(value, dict):
            raise EvaluationError(
                "{} line {} is not an object".format(label, line_number)
            )
        result.append((value, line))
    return result


def run_normalizer(
    binary: Path, pcap_path: Path, observer: str
) -> Tuple[Dict[str, Any], Dict[int, Tuple[Dict[str, Any], str]]]:
    try:
        completed = subprocess.run(
            [str(binary), "pcap", str(pcap_path), "--records-jsonl"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=NORMALIZER_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvaluationError(
            "normalizer failed to execute for {}".format(observer)
        ) from error
    if len(completed.stdout) > MAX_NORMALIZER_STDOUT_BYTES:
        raise EvaluationError("normalizer stdout exceeds its campaign bound")
    if len(completed.stderr) > MAX_SUBPROCESS_STDERR_BYTES:
        raise EvaluationError("normalizer stderr exceeds its campaign bound")
    if completed.returncode != 0:
        raise EvaluationError(
            "normalizer failed for {} with exit {}".format(
                observer, completed.returncode
            )
        )
    records = parse_jsonl(completed.stdout, "normalizer")
    if not records or records[0][0].get("schema") != "netmon.capture_manifest.v0":
        raise EvaluationError("normalizer did not emit one leading capture manifest")
    manifest = records[0][0]
    normalization = manifest.get("normalization")
    if not isinstance(normalization, dict) or normalization.get("state") != "complete":
        raise EvaluationError("normalizer did not report complete normalization")
    if (
        normalization.get("packet_limit_reached") is not False
        or normalization.get("packet_rows_quarantined") != 0
        or normalization.get("packet_rows_emitted") != EXPECTED_PACKETS[observer]
    ):
        raise EvaluationError("normalizer manifest counts differ from the campaign")
    capture_id = manifest.get("capture_id")
    if not isinstance(capture_id, str) or not capture_id:
        raise EvaluationError("normalizer manifest has no capture identity")
    packets: Dict[int, Tuple[Dict[str, Any], str]] = {}
    for value, raw_line in records[1:]:
        if value.get("schema") != "netmon.packet_envelope.v0":
            raise EvaluationError("campaign requires packet-only normalized records")
        if value.get("capture_id") != capture_id:
            raise EvaluationError("packet capture identity differs from its manifest")
        frame = value.get("frame")
        number = frame.get("number") if isinstance(frame, dict) else None
        if not isinstance(number, int) or number <= 0 or number in packets:
            raise EvaluationError(
                "normalizer emitted an invalid or duplicate frame number"
            )
        packets[number] = (value, hashlib.sha256(raw_line).hexdigest())
    return manifest, packets


def pair_id(left: Observation, right: Observation) -> str:
    if (left.observer, left.frame_number) > (right.observer, right.frame_number):
        left, right = right, left
    return "{}:{}|{}:{}".format(
        left.observer, left.frame_number, right.observer, right.frame_number
    )


def population_digest(pair_ids: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for value in sorted(pair_ids):
        digest.update(value.encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def positive_pairs(
    observations: Sequence[Observation],
) -> List[Tuple[str, Observation, Observation]]:
    events: Dict[Tuple[str, int], List[Observation]] = defaultdict(list)
    for item in observations:
        events[item.oracle_key()].append(item)
    result = []
    for group in events.values():
        for left, right in itertools.combinations(
            sorted(group, key=lambda item: (item.observer, item.frame_number)), 2
        ):
            if left.observer != right.observer:
                result.append((pair_id(left, right), left, right))
    return result


def negative_pairs(
    campaign_id: str, by_observer: Dict[str, List[Observation]]
) -> Tuple[List[Tuple[str, Observation, Observation]], Dict[str, Any]]:
    raw_count = 0
    rejected_equal = 0
    candidates = []
    for left_index, left_observer in enumerate(EXPECTED_OBSERVERS):
        for right_observer in EXPECTED_OBSERVERS[left_index + 1 :]:
            left_rows = sorted(
                by_observer[left_observer], key=lambda item: item.frame_number
            )
            right_rows = sorted(
                by_observer[right_observer], key=lambda item: item.frame_number
            )
            preimage = b"\0".join(
                [
                    b"netbraid.sorbonne-negative-offset.v0",
                    campaign_id.encode("utf-8"),
                    left_observer.encode("ascii"),
                    right_observer.encode("ascii"),
                ]
            )
            offset = int.from_bytes(hashlib.sha256(preimage).digest()[:8], "big") % len(
                right_rows
            )
            for index in range(min(len(left_rows), len(right_rows))):
                left = left_rows[index]
                right = right_rows[(index + offset) % len(right_rows)]
                raw_count += 1
                if left.oracle_key() == right.oracle_key():
                    rejected_equal += 1
                    continue
                identifier = pair_id(left, right)
                rank_preimage = b"\0".join(
                    [
                        b"netbraid.sorbonne-negative-rank.v0",
                        campaign_id.encode("utf-8"),
                        identifier.encode("ascii"),
                    ]
                )
                candidates.append(
                    (hashlib.sha256(rank_preimage).digest(), identifier, left, right)
                )
    identifiers = [candidate[1] for candidate in candidates]
    if len(identifiers) != len(set(identifiers)):
        raise EvaluationError("negative candidate IDs are not unique")
    selected = sorted(candidates, key=lambda item: (item[0], item[1].encode("utf-8")))[
        :64_149
    ]
    return (
        [(identifier, left, right) for _, identifier, left, right in selected],
        {
            "raw_candidates": raw_count,
            "equal_key_rejections": rejected_equal,
            "eligible_candidates": len(candidates),
            "eligible_population_sha256": population_digest(identifiers),
            "selected": len(selected),
            "selected_population_sha256": population_digest(
                item[1] for item in selected
            ),
        },
    )


def packet_order(packet: Dict[str, Any], digest: str) -> Tuple[str, str, str]:
    return str(packet.get("capture_id")), str(packet.get("record_id")), digest


def relation_participant(packet: Tuple[Dict[str, Any], str]) -> Tuple[str, str, str]:
    value, digest = packet
    source_id = value.get("record_id")
    if (
        value.get("schema") != PACKET_SCHEMA
        or not isinstance(source_id, str)
        or not source_id
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise EvaluationError("packet cannot identify a relation participant")
    return PACKET_SCHEMA, source_id, digest


def relation_target(
    left: Tuple[Dict[str, Any], str], right: Tuple[Dict[str, Any], str]
) -> Tuple[Tuple[str, str, str], Tuple[str, str, str]]:
    return tuple(sorted((relation_participant(left), relation_participant(right))))


def relation_target_population(
    pairs: Sequence[Tuple[str, Observation, Observation]],
    packets: Dict[Tuple[str, int], Tuple[Dict[str, Any], str]],
) -> Tuple[Dict[str, Any], set]:
    claims = 0
    unique = set()
    for _, left, right in pairs:
        claims += 1
        unique.add(
            relation_target(
                packets[(left.observer, left.frame_number)],
                packets[(right.observer, right.frame_number)],
            )
        )
    return (
        {
            "claims": claims,
            "targets": len(unique),
            "duplicate_target_claims": claims - len(unique),
            "population_sha256": relation_target_digest(unique),
        },
        unique,
    )


def relation_target_digest(targets: set) -> str:
    digest = hashlib.sha256()
    for target in sorted(targets):
        digest.update(
            json.dumps(target, separators=(",", ":"), sort_keys=False).encode("utf-8")
        )
        digest.update(b"\n")
    return digest.hexdigest()


def structural_group_key(
    left: Tuple[Dict[str, Any], str], right: Tuple[Dict[str, Any], str]
) -> Tuple[Any, ...]:
    ordered = sorted([left, right], key=lambda item: packet_order(item[0], item[1]))
    packets = [item[0] for item in ordered]
    if packets[0].get("capture_id") == packets[1].get("capture_id"):
        return ("same_capture",)
    if any(
        packet.get("frame", {}).get("captured_len")
        != packet.get("frame", {}).get("original_len")
        for packet in packets
    ):
        return ("truncated",)
    wlan = [packet.get("ieee80211") for packet in packets]
    if not all(isinstance(value, dict) for value in wlan):
        return ("missing_ieee80211",)
    return (
        "eligible",
        wlan[0].get("frame_type"),
        wlan[0].get("frame_subtype"),
        wlan[1].get("frame_type"),
        wlan[1].get("frame_subtype"),
    )


def group_population(
    pairs: Sequence[Tuple[str, Observation, Observation]],
    packets: Dict[Tuple[str, int], Tuple[Dict[str, Any], str]],
) -> Dict[
    Tuple[Any, ...],
    Tuple[
        int,
        str,
        Tuple[Dict[str, Any], str],
        Tuple[Dict[str, Any], str],
    ],
]:
    grouped = defaultdict(list)
    for identifier, left, right in pairs:
        left_packet = packets[(left.observer, left.frame_number)]
        right_packet = packets[(right.observer, right.frame_number)]
        grouped[structural_group_key(left_packet, right_packet)].append(
            (identifier, left_packet, right_packet)
        )
    result = {}
    for key, members in grouped.items():
        identifier, left, right = min(members, key=lambda item: item[0].encode("utf-8"))
        result[key] = (len(members), identifier, left, right)
    return result


def run_reducer(
    binary: Path,
    populations: Dict[
        str,
        Dict[
            Tuple[Any, ...],
            Tuple[
                int,
                str,
                Tuple[Dict[str, Any], str],
                Tuple[Dict[str, Any], str],
            ],
        ],
    ],
) -> Dict[str, Dict[str, Any]]:
    inputs = []
    weights = {}
    for label in sorted(populations):
        for index, (_, (weight, identifier, left, right)) in enumerate(
            sorted(populations[label].items(), key=lambda item: repr(item[0]))
        ):
            reducer_id = "{}:{}:{}".format(label, index, identifier)
            inputs.append(
                json.dumps(
                    {"pair_id": reducer_id, "left": left[0], "right": right[0]},
                    separators=(",", ":"),
                    sort_keys=False,
                )
            )
            weights[reducer_id] = (label, weight, relation_target(left, right))
    encoded = ("\n".join(inputs) + "\n").encode("utf-8")
    try:
        completed = subprocess.run(
            [str(binary)],
            input=encoded,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=REDUCER_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EvaluationError("reducer failed to execute") from error
    if len(completed.stdout) > MAX_REDUCER_STDOUT_BYTES:
        raise EvaluationError("reducer stdout exceeds its campaign bound")
    if len(completed.stderr) > MAX_SUBPROCESS_STDERR_BYTES:
        raise EvaluationError("reducer stderr exceeds its campaign bound")
    if completed.returncode != 0:
        raise EvaluationError(
            "reducer failed with exit {}".format(completed.returncode)
        )
    outputs = parse_jsonl(completed.stdout, "reducer")
    if len(outputs) != len(inputs):
        raise EvaluationError("reducer output count differs from representative count")
    result: Dict[str, Dict[str, Any]] = {}
    seen = set()
    for output, _ in outputs:
        if set(output) != {"pair_id", "assessment", "claim"}:
            raise EvaluationError("reducer output schema is invalid")
        reducer_id = output.get("pair_id")
        assessment = output.get("assessment")
        claim = output.get("claim")
        if (
            reducer_id not in weights
            or reducer_id in seen
            or not isinstance(assessment, dict)
            or not isinstance(claim, dict)
        ):
            raise EvaluationError("reducer output identity is invalid")
        seen.add(reducer_id)
        label, weight, expected_target = weights[reducer_id]
        validate_packet_event_claim(claim, expected_target)
        decision = {
            key: value
            for key, value in assessment.items()
            if key not in {"left", "right"}
        }
        result[reducer_id] = {"label": label, "weight": weight, "decision": decision}
    return result


def validate_packet_event_claim(
    claim: Dict[str, Any],
    expected_target: Tuple[Tuple[str, str, str], Tuple[str, str, str]],
) -> None:
    if set(claim) != {"schema", "projection", "inputs"}:
        raise EvaluationError("finite claim schema is invalid")
    projection = claim.get("projection")
    inputs = claim.get("inputs")
    if (
        claim.get("schema") != CLAIM_SCHEMA
        or not isinstance(projection, dict)
        or set(projection) != {"schema", "family_schema", "reducer", "alternatives"}
        or projection.get("schema") != PROJECTION_SCHEMA
        or projection.get("family_schema") != PACKET_EVENT_FAMILY
        or projection.get("reducer") != PACKET_EVENT_REDUCER
        or not isinstance(inputs, list)
        or len(inputs) != 2
    ):
        raise EvaluationError("finite claim contract is invalid")
    alternatives = projection.get("alternatives")
    expected_alternatives = [
        {"role": "same_event", "disposition": "underdetermined"},
        {"role": "different_event", "disposition": "underdetermined"},
        {"role": "unknown", "disposition": "supported"},
    ]
    if alternatives != expected_alternatives:
        raise EvaluationError("finite claim does not abstain")
    expected_roles = ("left_packet", "right_packet")
    participants = []
    for value, role in zip(inputs, expected_roles):
        if not isinstance(value, dict) or set(value) != {
            "role",
            "source_schema",
            "source_id",
            "content_sha256",
        }:
            raise EvaluationError("finite claim input schema is invalid")
        if value.get("role") != role:
            raise EvaluationError("finite claim input role is invalid")
        participants.append(
            (
                value.get("source_schema"),
                value.get("source_id"),
                value.get("content_sha256"),
            )
        )
    if tuple(sorted(participants)) != expected_target:
        raise EvaluationError("finite claim target differs from packet evidence")


def disposition_counts(
    label: str, outputs: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    selected = [value for value in outputs.values() if value["label"] == label]
    dispositions = {
        alternative: {
            state: 0 for state in ("supported", "contradicted", "underdetermined")
        }
        for alternative in ("same_event", "different_event", "unknown")
    }
    references: Counter[str] = Counter()
    bases = set()
    classes = set()
    pairs = 0
    for item in selected:
        weight = item["weight"]
        decision = item["decision"]
        pairs += weight
        for alternative in dispositions:
            state = decision.get(alternative)
            if state not in dispositions[alternative]:
                raise EvaluationError("reducer emitted an unknown disposition")
            dispositions[alternative][state] += weight
        reference = decision.get("reference")
        if not isinstance(reference, dict) or not isinstance(
            reference.get("hypothesis"), str
        ):
            raise EvaluationError("reducer emitted an invalid reference")
        reference_key = reference["hypothesis"]
        if "reason" in reference:
            reference_key += ":" + str(reference["reason"])
        references[reference_key] += weight
        basis_bytes = json.dumps(
            decision.get("basis"), sort_keys=True, separators=(",", ":")
        )
        class_bytes = json.dumps(decision, sort_keys=True, separators=(",", ":"))
        bases.add(basis_bytes)
        classes.add(class_bytes)
    return {
        "pairs": pairs,
        "distinct_serialized_bases": len(bases),
        "distinct_assessment_classes": len(classes),
        "basis": json.loads(next(iter(bases))) if len(bases) == 1 else None,
        "dispositions": dispositions,
        "references": dict(sorted(references.items())),
    }


def evaluate_with_snapshots(
    campaign: Dict[str, Any],
    campaign_sha256: str,
    archive_data: bytes,
    archive_md5: str,
    archive_sha256: str,
    netbraid_binary: Path,
    reducer_binary: Path,
    netbraid_identity: Dict[str, Any],
    reducer_identity: Dict[str, Any],
) -> Dict[str, Any]:
    with zipfile.ZipFile(io.BytesIO(archive_data), "r") as archive:
        tsv_members, inventory = SHARED.select_members(archive)
        pcap_members = selected_pcap_members(archive)
        by_observer = {
            observer: SHARED.parse_member(archive, tsv_members[observer], observer)
            for observer in EXPECTED_OBSERVERS
        }
        manifests = {}
        packets: Dict[Tuple[str, int], Tuple[Dict[str, Any], str]] = {}
        with tempfile.TemporaryDirectory(
            prefix="netbraid-sorbonne-reducer-"
        ) as directory:
            root = Path(directory)
            for observer in EXPECTED_OBSERVERS:
                info = pcap_members[observer]
                data = archive.read(info)
                if len(data) != info.file_size:
                    raise EvaluationError(
                        "PCAP extraction byte count differs from ZIP metadata"
                    )
                pcap_path = root / "{}.pcap".format(observer)
                pcap_path.write_bytes(data)
                manifest, observed_packets = run_normalizer(
                    netbraid_binary, pcap_path, observer
                )
                manifests[observer] = manifest
                if len(observed_packets) != EXPECTED_PACKETS[observer]:
                    raise EvaluationError(
                        "normalized packet count differs for {}".format(observer)
                    )
                label_frames = {item.frame_number for item in by_observer[observer]}
                if set(observed_packets) != label_frames:
                    raise EvaluationError(
                        "packet-to-label frame join is not bijective for {}".format(
                            observer
                        )
                    )
                for frame_number, packet in observed_packets.items():
                    packets[(observer, frame_number)] = packet

    observations = [
        item for observer in EXPECTED_OBSERVERS for item in by_observer[observer]
    ]
    if len(observations) != 18_926 or len(packets) != 18_926:
        raise EvaluationError("complete observation count differs from campaign")
    positives = positive_pairs(observations)
    positive_ids = [item[0] for item in positives]
    if (
        len(positive_ids) != 64_149
        or len(set(positive_ids)) != len(positive_ids)
        or population_digest(positive_ids) != EXPECTED_POSITIVE_DIGEST
    ):
        raise EvaluationError("positive population differs from campaign")
    negatives, negative_audit = negative_pairs(campaign["campaign_id"], by_observer)
    negative_ids = [item[0] for item in negatives]
    if set(positive_ids).intersection(negative_ids):
        raise EvaluationError("positive and negative populations overlap")
    expected_negative = {
        "raw_candidates": 83_927,
        "equal_key_rejections": 67,
        "eligible_candidates": 83_860,
        "eligible_population_sha256": EXPECTED_NEGATIVE_POOL_DIGEST,
        "selected": 64_149,
        "selected_population_sha256": EXPECTED_NEGATIVE_SELECTED_DIGEST,
    }
    if negative_audit != expected_negative or len(set(negative_ids)) != len(
        negative_ids
    ):
        raise EvaluationError("negative population differs from campaign")

    positive_target_audit, positive_targets = relation_target_population(
        positives, packets
    )
    negative_target_audit, negative_targets = relation_target_population(
        negatives, packets
    )
    target_intersection = positive_targets.intersection(negative_targets)
    all_targets = positive_targets.union(negative_targets)
    if (
        positive_target_audit["targets"] != len(positives)
        or negative_target_audit["targets"] != len(negatives)
        or target_intersection
        or len(all_targets) != 128_298
    ):
        raise EvaluationError("content-bound relation targets are not one per pair")

    grouped = {
        "different_event_oracle": group_population(negatives, packets),
        "same_event_oracle": group_population(positives, packets),
    }
    outputs = run_reducer(reducer_binary, grouped)
    observed_results = {
        label: disposition_counts(label, outputs)
        for label in ("same_event_oracle", "different_event_oracle")
    }
    observed_results["same_event_supported_total"] = sum(
        result["dispositions"]["same_event"]["supported"]
        for result in observed_results.values()
        if isinstance(result, dict) and "dispositions" in result
    )
    observed_results["representative_reducer_invocations"] = len(outputs)
    if observed_results != campaign["expected_results"]:
        raise EvaluationError("weighted reducer results differ from campaign")
    unresolved_targets = sum(
        result["dispositions"]["unknown"]["supported"]
        for result in observed_results.values()
        if isinstance(result, dict) and "dispositions" in result
    )
    substantive_targets = sum(
        result["dispositions"][alternative]["supported"]
        for result in observed_results.values()
        if isinstance(result, dict) and "dispositions" in result
        for alternative in ("same_event", "different_event")
    )
    if unresolved_targets != len(all_targets) or substantive_targets != 0:
        raise EvaluationError("relation-target resolutions differ from reducer claims")

    tool_versions = sorted(
        {manifest["extractor"]["tool_version"] for manifest in manifests.values()}
    )
    configurations = sorted(
        {
            manifest["extractor"]["configuration_sha256"]
            for manifest in manifests.values()
        }
    )
    registries = sorted(
        {manifest["extractor"]["field_registry"] for manifest in manifests.values()}
    )
    if len(tool_versions) != 1 or len(configurations) != 1 or len(registries) != 1:
        raise EvaluationError("normalizer provenance differs across observers")
    if registries != [EXPECTED_FIELD_REGISTRY]:
        raise EvaluationError(
            "normalizer field registry differs from the replay contract"
        )

    decision_projection = {
        key: {"weight": value["weight"], "decision": value["decision"]}
        for key, value in sorted(outputs.items())
    }
    decision_sha256 = hashlib.sha256(
        json.dumps(decision_projection, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()
    return {
        "schema": REPORT_SCHEMA,
        "campaign": {
            "id": campaign["campaign_id"],
            "sha256": campaign_sha256,
            "registered_against_netbraid_revision": campaign["preregistration"][
                "registered_against_netbraid_revision"
            ],
        },
        "source": {
            "archive_bytes": len(archive_data),
            "archive_md5": archive_md5,
            "archive_sha256": archive_sha256,
            "archive_members": inventory["archive_members"],
            "selected_tsv_bytes": inventory["selected_uncompressed_bytes"],
            "selected_pcap_bytes": sum(
                info.file_size for info in pcap_members.values()
            ),
        },
        "executables": {
            "netbraid": netbraid_identity,
            "packet_same_event_jsonl": reducer_identity,
        },
        "normalization": {
            "packets_by_observer": EXPECTED_PACKETS,
            "total_packets": len(packets),
            "total_quarantines": 0,
            "label_join_unmatched": 0,
            "tool_versions": tool_versions,
            "configuration_sha256": configurations,
            "field_registries": registries,
        },
        "populations": {
            "positive": {
                "count": len(positives),
                "unique_count": len(set(positive_ids)),
                "population_sha256": population_digest(positive_ids),
            },
            "negative": negative_audit,
            "intersection_count": 0,
        },
        "results": observed_results,
        "relation_targets": {
            "axis": "event",
            "positive": positive_target_audit,
            "negative": negative_target_audit,
            "intersection_count": len(target_intersection),
            "combined_population_sha256": relation_target_digest(all_targets),
            "resolutions": {
                "unresolved": unresolved_targets,
                "single_alternative": substantive_targets,
                "conflict": 0,
            },
            "limitation": "single_claim_per_target_does_not_test_conflict_resolution",
        },
        "decision_projection_sha256": decision_sha256,
        "interpretation": "contract_confirmed_not_a_discrimination_benchmark",
    }


def evaluate(args: argparse.Namespace) -> Dict[str, Any]:
    campaign, campaign_sha256 = load_campaign(args.campaign)
    archive_data, archive_md5, archive_sha256 = SHARED.read_archive(args.archive)
    if archive_sha256 != EXPECTED_ARCHIVE_SHA256:
        raise EvaluationError("archive SHA-256 differs from campaign")
    netbraid_data, netbraid_identity = executable_content(args.netbraid_bin)
    reducer_data, reducer_identity = executable_content(args.reducer_bin)
    with tempfile.TemporaryDirectory(prefix="netbraid-sorbonne-binaries-") as directory:
        root = Path(directory)
        netbraid_binary = root / "netbraid"
        reducer_binary = root / "packet_same_event_jsonl"
        write_executable_snapshot(netbraid_binary, netbraid_data)
        write_executable_snapshot(reducer_binary, reducer_data)
        return evaluate_with_snapshots(
            campaign,
            campaign_sha256,
            archive_data,
            archive_md5,
            archive_sha256,
            netbraid_binary,
            reducer_binary,
            netbraid_identity,
            reducer_identity,
        )


def write_report(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".{}-".format(path.name), suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        report = evaluate(args)
        write_report(args.report, report)
    except EvaluationError as error:
        print("error: {}".format(error), file=sys.stderr)
        return 2
    print("wrote Sorbonne structural reducer report: {}".format(args.report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
