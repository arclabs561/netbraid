#!/usr/bin/env python3
"""Evaluate RSSI explanation sensitivity across two Sorbonne conditions."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


CAMPAIGN_SCHEMA = "netbraid.sorbonne_rssi_explanation_campaign.v0"
CAMPAIGN_SHA256 = "c68cc827d6170388e4600c219c013b22fd39de1035e55351d4a8dc8b4234b3df"
REPORT_SCHEMA = "netbraid.sorbonne_rssi_explanation_report.v0"
BRIDGE_SCHEMA = "netbraid.rssi_shift_explanation_eval.v0"
EXPECTED_ARCHIVE_SHA256 = (
    "7a650d450d339683cf7591bc24a6006238456b8dfa54e352aa1aceda8682c3f8"
)
EXPECTED_COLUMNS = (
    "Frame_number",
    "Frame_time_epoch",
    "RSSI_dBm",
    "Channel",
    "Frame_type",
    "Frame_subtype",
    "Retransmission",
    "Source_MAC_address",
    "Sequence_number",
)
EXPECTED_OBSERVERS = tuple("S{:02d}".format(index) for index in range(1, 11))
ROOT = "220211012-SU-Outdoors-Campus/220211012-SU-Outdoors-Campus"
HEADER_ERRATUM_MEMBER = "{}/1m/csvTraces/01m-S03.txt".format(ROOT)
HEADER_ERRATUM_BYTES = 103_064
HEADER_ERRATUM_SHA256 = (
    "14aaedfbaa196d385b5ce05282e458773fbc1ee7eec83bfce8804929a8570deb"
)
MAC_PATTERN = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")

MAX_CAMPAIGN_BYTES = 128 * 1024
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
MAX_MEMBER_BYTES = 1 * 1024 * 1024
MAX_SELECTED_BYTES = 32 * 1024 * 1024
MAX_ROWS_PER_MEMBER = 100_000
MAX_BRIDGE_STDOUT_BYTES = 1 * 1024 * 1024
MAX_BRIDGE_STDERR_BYTES = 1 * 1024 * 1024
BRIDGE_TIMEOUT_SECONDS = 30


def load_shared() -> Any:
    path = Path(__file__).with_name("evaluate-sorbonne-same-event.py")
    spec = importlib.util.spec_from_file_location("netbraid_sorbonne_rssi_shared", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load Sorbonne archive helpers")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SHARED = load_shared()
EvaluationError = SHARED.EvaluationError


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--bridge-bin", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    return parser.parse_args(argv)


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        path_state = path.lstat()
    except OSError as error:
        raise EvaluationError("cannot inspect {}".format(label)) from error
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
        raise EvaluationError("campaign content differs from the locked registration")
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
    protocol_lock = campaign.get("protocol_lock")
    source = campaign.get("source")
    if (
        campaign.get("schema") != CAMPAIGN_SCHEMA
        or campaign.get("campaign_id") != "sorbonne-rssi-condition-contrast-v0"
        or not isinstance(protocol_lock, dict)
        or protocol_lock.get("status") != "locked_before_evaluable_execution"
        or protocol_lock.get("revision") != 1
        or protocol_lock.get("externally_timestamped") is not False
        or not isinstance(source, dict)
        or source.get("archive_sha256") != EXPECTED_ARCHIVE_SHA256
    ):
        raise EvaluationError("campaign identity differs from the locked registration")
    return campaign, digest


def expected_member_names() -> Dict[str, Dict[str, str]]:
    return {
        "control": {
            observer: "{}/1m/csvTraces/01m-{}.txt".format(ROOT, observer)
            for observer in EXPECTED_OBSERVERS
        },
        "contrast": {
            observer: "{}/50m/csvTraces/50m-{}.txt".format(ROOT, observer)
            for observer in EXPECTED_OBSERVERS
        },
    }


def select_members(
    archive: zipfile.ZipFile,
) -> Dict[str, Dict[str, zipfile.ZipInfo]]:
    infos = archive.infolist()
    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        raise EvaluationError("archive contains duplicate member names")

    expected = expected_member_names()
    expected_names = {
        name for by_observer in expected.values() for name in by_observer.values()
    }
    selected: Dict[str, Dict[str, zipfile.ZipInfo]] = {
        "control": {},
        "contrast": {},
    }
    selected_bytes = 0
    target_roots = ("/1m/csvTraces/", "/50m/csvTraces/")
    for info in infos:
        if info.filename.startswith("/") or ".." in info.filename.split("/"):
            raise EvaluationError("archive contains an unsafe member path")
        if info.is_dir() or not any(root in info.filename for root in target_roots):
            continue
        if info.filename not in expected_names:
            raise EvaluationError(
                "selected RSSI directory contains an unregistered member"
            )
        if info.flag_bits & 1 or not 0 < info.file_size <= MAX_MEMBER_BYTES:
            raise EvaluationError("selected RSSI member violates its bounds")
        condition = "control" if "/1m/" in info.filename else "contrast"
        observer = info.filename.rsplit("-", 1)[-1].removesuffix(".txt")
        selected[condition][observer] = info
        selected_bytes += info.file_size
    if selected_bytes > MAX_SELECTED_BYTES:
        raise EvaluationError("selected RSSI members exceed their aggregate byte bound")
    for condition in ("control", "contrast"):
        if tuple(sorted(selected[condition])) != EXPECTED_OBSERVERS:
            raise EvaluationError("selected RSSI member inventory is incomplete")
    return selected


def parse_rssi_member(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo
) -> Tuple[List[int], set[str], bool]:
    with archive.open(info, "r") as source:
        data = source.read(MAX_MEMBER_BYTES + 1)
    if len(data) != info.file_size or len(data) > MAX_MEMBER_BYTES:
        raise EvaluationError("selected RSSI member changed while reading")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise EvaluationError("selected RSSI member is not strict UTF-8") from error
    reader = csv.reader(io.StringIO(text, newline=""), delimiter="\t", strict=True)
    try:
        header = next(reader)
    except StopIteration as error:
        raise EvaluationError("selected RSSI member is empty") from error
    erratum_applied = False
    if tuple(header) != EXPECTED_COLUMNS and (
        info.filename == HEADER_ERRATUM_MEMBER
        and len(data) == HEADER_ERRATUM_BYTES
        and hashlib.sha256(data).hexdigest() == HEADER_ERRATUM_SHA256
        and header
        and header[0] == " Frame_number"
        and tuple(["Frame_number", *header[1:]]) == EXPECTED_COLUMNS
    ):
        header[0] = "Frame_number"
        erratum_applied = True
    if tuple(header) != EXPECTED_COLUMNS:
        raise EvaluationError("selected RSSI member has the wrong schema")

    rssi: List[int] = []
    source_addresses: set[str] = set()
    try:
        for row in reader:
            if len(row) != len(EXPECTED_COLUMNS):
                raise EvaluationError("selected RSSI row has the wrong width")
            if len(rssi) >= MAX_ROWS_PER_MEMBER:
                raise EvaluationError("selected RSSI member exceeds its row bound")
            try:
                value = int(row[2], 10)
            except ValueError as error:
                raise EvaluationError("RSSI value is not a base-10 integer") from error
            if not -128 <= value <= 127:
                raise EvaluationError("RSSI value is outside the registered range")
            if MAC_PATTERN.fullmatch(row[7]) is None:
                raise EvaluationError("source-address integrity field is malformed")
            rssi.append(value)
            source_addresses.add(row[7].lower())
    except csv.Error as error:
        raise EvaluationError("selected RSSI member is malformed TSV") from error
    if len(rssi) < 8:
        raise EvaluationError("selected RSSI member has too few rows")
    return rssi, source_addresses, erratum_applied


def lower_median(values: Sequence[int]) -> int:
    if not values:
        raise EvaluationError("cannot take the lower median of an empty sequence")
    ordered = sorted(values)
    return ordered[(len(ordered) - 1) // 2]


def build_requests(
    campaign: Dict[str, Any],
    observations: Dict[str, Dict[str, List[int]]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    profile = campaign["reference_frame_profile"]
    control_links = []
    contrast_links = []
    rows = {"control": 0, "contrast": 0}
    baseline_samples = 0
    for index, observer in enumerate(EXPECTED_OBSERVERS):
        one_meter = observations["control"][observer]
        fifty_meter = observations["contrast"][observer]
        baseline = one_meter[::2]
        control_recent = lower_median(one_meter[1::2])
        contrast_recent = lower_median(fifty_meter)
        baseline_milli_db = [value * 1_000 for value in baseline]
        common = {
            "observer_id": "observer-{}".format(index),
            "source_id": "source-role-0",
            "baseline_rssi_milli_db": baseline_milli_db,
        }
        control_links.append(dict(common, recent_rssi_milli_db=control_recent * 1_000))
        contrast_links.append(
            dict(common, recent_rssi_milli_db=contrast_recent * 1_000)
        )
        rows["control"] += len(one_meter)
        rows["contrast"] += len(fifty_meter)
        baseline_samples += len(baseline)
    return (
        [
            {
                "case_id": "control",
                "reference_frame_profile": profile,
                "links": control_links,
            },
            {
                "case_id": "contrast",
                "reference_frame_profile": profile,
                "links": contrast_links,
            },
        ],
        {
            "members": {"control": 10, "contrast": 10},
            "rows": rows,
            "baseline_samples": baseline_samples,
        },
    )


def run_bridge(
    binary: Path, requests: Sequence[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], bytes]:
    executable = read_regular(binary, MAX_EXECUTABLE_BYTES, "RSSI bridge")
    if not os.access(binary, os.X_OK):
        raise EvaluationError("RSSI bridge is not executable")
    input_bytes = b"".join(
        json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
        for request in requests
    )
    with tempfile.TemporaryDirectory(prefix="netbraid-rssi-eval-") as directory:
        snapshot = Path(directory) / "rssi-bridge"
        descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(descriptor, "wb") as output:
            output.write(executable)
        try:
            result = subprocess.run(
                [str(snapshot)],
                input=input_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=BRIDGE_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as error:
            raise EvaluationError("RSSI bridge timed out") from error
    if len(result.stdout) > MAX_BRIDGE_STDOUT_BYTES:
        raise EvaluationError("RSSI bridge stdout exceeds its bound")
    if len(result.stderr) > MAX_BRIDGE_STDERR_BYTES:
        raise EvaluationError("RSSI bridge stderr exceeds its bound")
    if result.returncode != 0:
        raise EvaluationError("RSSI bridge failed")
    if result.stderr or not result.stdout.endswith(b"\n"):
        raise EvaluationError("RSSI bridge emitted unexpected stderr or framing")

    outputs = []
    for line in result.stdout.splitlines():
        try:
            output = json.loads(line, object_pairs_hook=SHARED.strict_object)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            SHARED.DuplicateKeyError,
        ) as error:
            raise EvaluationError("RSSI bridge output is not strict JSONL") from error
        if not isinstance(output, dict) or output.get("schema") != BRIDGE_SCHEMA:
            raise EvaluationError("RSSI bridge output has the wrong schema")
        outputs.append(output)
    if [output.get("case_id") for output in outputs] != ["control", "contrast"]:
        raise EvaluationError("RSSI bridge output cases differ from the request")
    return outputs, executable


def nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def validate_belief_summary(
    summary: Any, prefix: str, expected_count: Optional[int]
) -> None:
    expected = {
        "count",
        "{}_relative_belief_ppb_sum".format(prefix),
        "{}_relative_belief_ppb_min".format(prefix),
        "{}_relative_belief_ppb_max".format(prefix),
    }
    if not isinstance(summary, dict) or set(summary) != expected:
        raise EvaluationError("RSSI bridge belief fields differ from the contract")
    count = summary["count"]
    total = summary["{}_relative_belief_ppb_sum".format(prefix)]
    minimum = summary["{}_relative_belief_ppb_min".format(prefix)]
    maximum = summary["{}_relative_belief_ppb_max".format(prefix)]
    if not nonnegative_int(count) or not nonnegative_int(total):
        raise EvaluationError(
            "RSSI bridge belief summary is not nonnegative integer data"
        )
    if expected_count is not None and count != expected_count:
        raise EvaluationError("RSSI bridge belief count differs from model structure")
    if count == 0:
        if total != 0 or minimum is not None or maximum is not None:
            raise EvaluationError("empty RSSI belief summary is inconsistent")
        return
    if (
        not nonnegative_int(minimum)
        or not nonnegative_int(maximum)
        or maximum > 1_000_000_000
        or minimum > maximum
        or not count * minimum <= total <= count * maximum
    ):
        raise EvaluationError("RSSI bridge belief range is inconsistent")


def validate_projection(
    output: Dict[str, Any], baseline_samples: int, explanation_profile: Dict[str, Any]
) -> None:
    expected = {
        "schema",
        "case_id",
        "heuristic_profile",
        "links_seen",
        "baseline_samples_seen",
        "eligible_links",
        "shifted_links",
        "heuristic_weights",
        "outcomes",
        "observer_beliefs",
        "source_beliefs",
        "residual_beliefs",
    }
    if set(output) != expected:
        raise EvaluationError("RSSI bridge output fields differ from the contract")
    if output["heuristic_profile"] != explanation_profile["profile_id"]:
        raise EvaluationError("RSSI bridge used an unexpected heuristic profile")
    expected_weights = dict(explanation_profile)
    del expected_weights["profile_id"]
    if output["heuristic_weights"] != expected_weights:
        raise EvaluationError("RSSI bridge used unexpected heuristic weights")
    for name in (
        "links_seen",
        "baseline_samples_seen",
        "eligible_links",
        "shifted_links",
    ):
        if not nonnegative_int(output[name]):
            raise EvaluationError("RSSI bridge count is not a nonnegative integer")
    if (
        output["links_seen"] != 10
        or output["baseline_samples_seen"] != baseline_samples
        or output["eligible_links"] != 10
        or output["shifted_links"] > output["eligible_links"]
    ):
        raise EvaluationError(
            "RSSI bridge counts differ from submitted corpus structure"
        )
    outcomes = output["outcomes"]
    if not isinstance(outcomes, dict) or set(outcomes) != {
        "exact_components",
        "infeasible_components",
        "abstained_components",
        "assignments_evaluated",
    }:
        raise EvaluationError("RSSI bridge outcome fields differ from the contract")
    if not all(nonnegative_int(value) for value in outcomes.values()):
        raise EvaluationError("RSSI bridge outcomes are not nonnegative integer data")
    component_count = (
        outcomes["exact_components"]
        + outcomes["infeasible_components"]
        + outcomes["abstained_components"]
    )
    if component_count != 1:
        raise EvaluationError(
            "RSSI bridge component count differs from submitted topology"
        )
    exact = outcomes["exact_components"] == 1
    expected_assignments = 2_048 if exact or outcomes["infeasible_components"] else 0
    if outcomes["assignments_evaluated"] != expected_assignments:
        raise EvaluationError(
            "RSSI bridge assignment count differs from model structure"
        )
    validate_belief_summary(output["observer_beliefs"], "shifted", 10 if exact else 0)
    validate_belief_summary(output["source_beliefs"], "shifted", 1 if exact else 0)
    validate_belief_summary(
        output["residual_beliefs"],
        "residual",
        output["shifted_links"] if exact else 0,
    )


def build_report(
    campaign: Dict[str, Any],
    campaign_digest: str,
    archive_bytes: int,
    bridge_bytes: bytes,
    corpus: Dict[str, Any],
    source_address_count: int,
    outputs: Sequence[Dict[str, Any]],
) -> Dict[str, Any]:
    by_case = {output["case_id"]: output for output in outputs}
    control = by_case["control"]
    contrast = by_case["contrast"]
    for output in outputs:
        validate_projection(
            output, corpus["baseline_samples"], campaign["explanation_profile"]
        )
    control_source = control["source_beliefs"]["shifted_relative_belief_ppb_max"]
    contrast_source = contrast["source_beliefs"]["shifted_relative_belief_ppb_max"]
    contrast_observer = contrast["observer_beliefs"]["shifted_relative_belief_ppb_max"]
    endpoint_beliefs_present = all(
        nonnegative_int(value)
        for value in (control_source, contrast_source, contrast_observer)
    )
    gates = {
        "control_shifted_links": control["shifted_links"] == 0,
        "contrast_has_more_shifted_links": (
            contrast["shifted_links"] > control["shifted_links"]
        ),
        "contrast_source_exceeds_control": (
            endpoint_beliefs_present and contrast_source > control_source
        ),
        "contrast_source_exceeds_each_observer": (
            endpoint_beliefs_present and contrast_source > contrast_observer
        ),
        "all_components_exact": all(
            output["outcomes"]["exact_components"] == 1
            and output["outcomes"]["infeasible_components"] == 0
            and output["outcomes"]["abstained_components"] == 0
            for output in outputs
        ),
    }
    return {
        "schema": REPORT_SCHEMA,
        "campaign": {
            "id": "sorbonne-rssi-condition-contrast-v0",
            "sha256": campaign_digest,
        },
        "archive": {
            "bytes": archive_bytes,
            "sha256": EXPECTED_ARCHIVE_SHA256,
        },
        "bridge": {
            "bytes": len(bridge_bytes),
            "sha256": hashlib.sha256(bridge_bytes).hexdigest(),
        },
        "corpus": dict(corpus, distinct_source_address_count=source_address_count),
        "arms": {"control": control, "contrast": contrast},
        "contrasts": {
            "shifted_links_delta": contrast["shifted_links"] - control["shifted_links"],
            "source_belief_ppb_delta": (
                contrast_source - control_source if endpoint_beliefs_present else None
            ),
            "contrast_source_minus_max_observer_belief_ppb": (
                contrast_source - contrast_observer
                if endpoint_beliefs_present
                else None
            ),
        },
        "gates": dict(gates, passed=all(gates.values())),
        "interpretation": {
            "belief_semantics": "heuristic_relative",
            "condition_is_input_selection_not_prediction": True,
            "physical_cause": "not_evaluated",
            "identity": "not_evaluated",
            "location": "not_evaluated",
            "tamper": "not_evaluated",
            "intent": "not_evaluated",
            "generalization": "not_evaluated",
            "probability_calibration": "not_evaluated",
        },
    }


def write_report(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=".{}-".format(path.name)
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def evaluate(
    archive_path: Path, campaign_path: Path, bridge_path: Path
) -> Dict[str, Any]:
    campaign, campaign_digest = load_campaign(campaign_path)
    archive_data, _, archive_digest = SHARED.read_archive(archive_path)
    if archive_digest != EXPECTED_ARCHIVE_SHA256:
        raise EvaluationError("archive SHA-256 differs from the campaign")
    observations: Dict[str, Dict[str, List[int]]] = {
        "control": {},
        "contrast": {},
    }
    source_addresses: set[str] = set()
    header_errata_applied = 0
    with zipfile.ZipFile(io.BytesIO(archive_data), "r") as archive:
        selected = select_members(archive)
        for condition in ("control", "contrast"):
            for observer in EXPECTED_OBSERVERS:
                values, addresses, erratum_applied = parse_rssi_member(
                    archive, selected[condition][observer]
                )
                observations[condition][observer] = values
                source_addresses.update(addresses)
                header_errata_applied += int(erratum_applied)
    if len(source_addresses) != 1:
        raise EvaluationError(
            "selected RSSI rows do not have exactly one source address"
        )
    if header_errata_applied != 1:
        raise EvaluationError("registered RSSI header erratum count differs from one")
    requests, corpus = build_requests(campaign, observations)
    corpus["header_errata_applied"] = header_errata_applied
    outputs, bridge_bytes = run_bridge(bridge_path, requests)
    return build_report(
        campaign,
        campaign_digest,
        len(archive_data),
        bridge_bytes,
        corpus,
        len(source_addresses),
        outputs,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        report = evaluate(args.archive, args.campaign, args.bridge_bin)
        write_report(args.report, report)
    except EvaluationError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
