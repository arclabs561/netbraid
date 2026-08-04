#!/usr/bin/env python3
"""Bluetooth LE oracle logic for the bounded public-corpus evaluator."""

from __future__ import annotations

from typing import Any

ORACLE_KEYS = {
    "completeness",
    "counts",
    "pdu_types",
    "address_fields",
    "address_header_flags",
    "crc",
    "radio",
}
CAPTURE_MANIFEST_SCHEMA = "netmon.capture_manifest.v0"
PACKET_ENVELOPE_SCHEMA = "netmon.packet_envelope.v0"
PACKET_QUARANTINE_SCHEMA = "netmon.packet_quarantine.v0"


class BluetoothLeEvaluationError(Exception):
    def __init__(self, stage: str, case: str) -> None:
        super().__init__(stage, case)
        self.stage = stage
        self.case = case


def validate_count_partition(
    value: Any, total: int, keys: set[str], case_id: str
) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or any(type(value[key]) is not int or value[key] < 0 for key in keys)
        or sum(value.values()) != total
    ):
        raise BluetoothLeEvaluationError("expectation", case_id)


def validate_bluetooth_le_oracle(
    expectation: Any, packet_limit: Any, case_id: str
) -> None:
    if not isinstance(expectation, dict) or set(expectation) != ORACLE_KEYS:
        raise BluetoothLeEvaluationError("expectation", case_id)
    completeness = expectation["completeness"]
    counts = expectation["counts"]
    if (
        not isinstance(completeness, dict)
        or set(completeness)
        != {"state", "scope", "packet_limit", "packet_limit_reached"}
        or completeness["state"] not in {"complete", "partial"}
        or completeness["scope"] not in {"complete_capture", "normalized_packet_subset"}
        or type(completeness["packet_limit"]) is not int
        or completeness["packet_limit"] != packet_limit
        or type(completeness["packet_limit_reached"]) is not bool
        or completeness["state"] == "complete"
        and (
            completeness["scope"] != "complete_capture"
            or completeness["packet_limit_reached"]
        )
        or completeness["state"] == "partial"
        and completeness["scope"] != "normalized_packet_subset"
    ):
        raise BluetoothLeEvaluationError("expectation", case_id)
    count_keys = {
        "packet_envelopes",
        "packet_quarantines",
        "packet_rows_inspected",
        "bluetooth_le_frames",
        "other_packet_envelopes",
    }
    if (
        not isinstance(counts, dict)
        or set(counts) != count_keys
        or any(type(counts[key]) is not int or counts[key] < 0 for key in count_keys)
        or counts["packet_rows_inspected"]
        != counts["packet_envelopes"] + counts["packet_quarantines"]
        or counts["packet_envelopes"]
        != counts["bluetooth_le_frames"] + counts["other_packet_envelopes"]
        or completeness["state"] == "complete"
        and counts["packet_quarantines"] != 0
    ):
        raise BluetoothLeEvaluationError("expectation", case_id)
    bluetooth_frames = counts["bluetooth_le_frames"]

    pdu_types = expectation["pdu_types"]
    if (
        not isinstance(pdu_types, dict)
        or set(pdu_types) != {"present_frames", "unavailable_frames", "mix"}
        or type(pdu_types["present_frames"]) is not int
        or type(pdu_types["unavailable_frames"]) is not int
        or pdu_types["present_frames"] < 0
        or pdu_types["unavailable_frames"] < 0
        or pdu_types["present_frames"] + pdu_types["unavailable_frames"]
        != bluetooth_frames
        or not isinstance(pdu_types["mix"], list)
    ):
        raise BluetoothLeEvaluationError("expectation", case_id)
    pdu_values = []
    pdu_total = 0
    for item in pdu_types["mix"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"pdu_type", "frames"}
            or type(item["pdu_type"]) is not int
            or not 0 <= item["pdu_type"] <= 15
            or type(item["frames"]) is not int
            or item["frames"] <= 0
        ):
            raise BluetoothLeEvaluationError("expectation", case_id)
        pdu_values.append(item["pdu_type"])
        pdu_total += item["frames"]
    if (
        pdu_values != sorted(set(pdu_values))
        or pdu_total != pdu_types["present_frames"]
    ):
        raise BluetoothLeEvaluationError("expectation", case_id)

    address_fields = expectation["address_fields"]
    address_keys = {"advertising", "scanning", "initiator", "target"}
    if (
        not isinstance(address_fields, dict)
        or set(address_fields) != address_keys
        or any(
            type(address_fields[key]) is not int
            or not 0 <= address_fields[key] <= bluetooth_frames
            for key in address_keys
        )
    ):
        raise BluetoothLeEvaluationError("expectation", case_id)
    address_header_flags = expectation["address_header_flags"]
    if not isinstance(address_header_flags, dict) or set(address_header_flags) != {
        "transmitter_random",
        "receiver_random",
    }:
        raise BluetoothLeEvaluationError("expectation", case_id)
    partition_keys = {"true_frames", "false_frames", "unavailable_frames"}
    for role in ("transmitter_random", "receiver_random"):
        validate_count_partition(
            address_header_flags[role], bluetooth_frames, partition_keys, case_id
        )
    validate_count_partition(
        expectation["crc"],
        bluetooth_frames,
        {"valid_frames", "invalid_frames", "unavailable_frames"},
        case_id,
    )

    radio = expectation["radio"]
    if not isinstance(radio, dict) or set(radio) != {
        "channels",
        "signal_dbm",
        "noise_dbm",
    }:
        raise BluetoothLeEvaluationError("expectation", case_id)
    channels = radio["channels"]
    if (
        not isinstance(channels, dict)
        or set(channels) != {"present_frames", "unavailable_frames", "mix"}
        or type(channels["present_frames"]) is not int
        or type(channels["unavailable_frames"]) is not int
        or channels["present_frames"] < 0
        or channels["unavailable_frames"] < 0
        or channels["present_frames"] + channels["unavailable_frames"]
        != bluetooth_frames
        or not isinstance(channels["mix"], list)
    ):
        raise BluetoothLeEvaluationError("expectation", case_id)
    channel_values = []
    channel_total = 0
    for item in channels["mix"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"channel", "frames"}
            or type(item["channel"]) is not int
            or not 0 <= item["channel"] <= 39
            or type(item["frames"]) is not int
            or item["frames"] <= 0
        ):
            raise BluetoothLeEvaluationError("expectation", case_id)
        channel_values.append(item["channel"])
        channel_total += item["frames"]
    if (
        channel_values != sorted(set(channel_values))
        or channel_total != channels["present_frames"]
    ):
        raise BluetoothLeEvaluationError("expectation", case_id)
    summary_keys = {"samples", "sum_dbm", "minimum_dbm", "maximum_dbm"}
    for metric in ("signal_dbm", "noise_dbm"):
        summary = radio[metric]
        if (
            not isinstance(summary, dict)
            or set(summary) != summary_keys
            or type(summary["samples"]) is not int
            or not 0 <= summary["samples"] <= bluetooth_frames
            or type(summary["sum_dbm"]) is not int
            or summary["samples"] == 0
            and (
                summary["minimum_dbm"] is not None or summary["maximum_dbm"] is not None
            )
            or summary["samples"] > 0
            and (
                type(summary["minimum_dbm"]) is not int
                or type(summary["maximum_dbm"]) is not int
                or not -128 <= summary["minimum_dbm"] <= summary["maximum_dbm"] <= 127
            )
        ):
            raise BluetoothLeEvaluationError("expectation", case_id)


def summarize_dbm(values: list[int]) -> dict[str, int | None]:
    return {
        "samples": len(values),
        "sum_dbm": sum(values),
        "minimum_dbm": min(values) if values else None,
        "maximum_dbm": max(values) if values else None,
    }


def parse_bluetooth_le_records_output(
    data: bytes, extracted: Any, parse_records_documents: Any
) -> dict[str, Any]:
    case = extracted.case
    case_id = case["id"]
    documents, manifest, expected_capture_id = parse_records_documents(
        data, extracted, "bluetooth_le"
    )
    normalization = manifest.get("normalization")
    if (
        not isinstance(normalization, dict)
        or set(normalization)
        != {
            "state",
            "packet_limit",
            "packet_limit_reached",
            "packet_rows_emitted",
            "packet_rows_quarantined",
        }
        or normalization["state"] not in {"complete", "partial"}
        or normalization["packet_limit"] != case["packet_limit"]
        or type(normalization["packet_limit_reached"]) is not bool
        or type(normalization["packet_rows_emitted"]) is not int
        or type(normalization["packet_rows_quarantined"]) is not int
    ):
        raise BluetoothLeEvaluationError("bluetooth_le_records_completeness", case_id)

    packet_envelopes = 0
    packet_quarantines = 0
    bluetooth_frames = 0
    pdu_mix: dict[int, int] = {}
    pdu_unavailable = 0
    address_fields = {
        role: 0 for role in ("advertising", "scanning", "initiator", "target")
    }
    flag_counts = {
        role: {"true_frames": 0, "false_frames": 0, "unavailable_frames": 0}
        for role in ("transmitter_random", "receiver_random")
    }
    crc = {"valid_frames": 0, "invalid_frames": 0, "unavailable_frames": 0}
    channel_mix: dict[int, int] = {}
    channel_unavailable = 0
    signal_values: list[int] = []
    noise_values: list[int] = []
    allowed_bluetooth_keys = {
        "access_address",
        "advertising_pdu_type",
        "payload_length_octets",
        "advertising_address",
        "scanning_address",
        "initiator_address",
        "target_address",
        "logical_link_identifier",
        "control_opcode",
        "transmitter_address_random",
        "receiver_address_random",
        "crc_status",
        "radio",
    }

    for document in documents[1:]:
        if not isinstance(document, dict):
            raise BluetoothLeEvaluationError("bluetooth_le_records_shape", case_id)
        schema = document.get("schema")
        if schema == PACKET_QUARANTINE_SCHEMA:
            if document.get("capture_id") != expected_capture_id:
                raise BluetoothLeEvaluationError("bluetooth_le_records_source", case_id)
            packet_quarantines += 1
            continue
        if schema != PACKET_ENVELOPE_SCHEMA:
            raise BluetoothLeEvaluationError("bluetooth_le_records_shape", case_id)
        if document.get("capture_id") != expected_capture_id:
            raise BluetoothLeEvaluationError("bluetooth_le_records_source", case_id)
        packet_envelopes += 1
        bluetooth_le = document.get("bluetooth_le")
        if bluetooth_le is None:
            continue
        if (
            not isinstance(bluetooth_le, dict)
            or not set(bluetooth_le) <= allowed_bluetooth_keys
            or type(bluetooth_le.get("access_address")) is not int
            or not 0 <= bluetooth_le["access_address"] <= 0xFFFF_FFFF
        ):
            raise BluetoothLeEvaluationError("bluetooth_le_records_shape", case_id)
        bluetooth_frames += 1

        pdu_type = bluetooth_le.get("advertising_pdu_type")
        if pdu_type is None:
            pdu_unavailable += 1
        elif type(pdu_type) is int and 0 <= pdu_type <= 15:
            pdu_mix[pdu_type] = pdu_mix.get(pdu_type, 0) + 1
        else:
            raise BluetoothLeEvaluationError("bluetooth_le_records_shape", case_id)

        for role in address_fields:
            value = bluetooth_le.get(f"{role}_address")
            if value is not None:
                if not isinstance(value, str) or not value:
                    raise BluetoothLeEvaluationError(
                        "bluetooth_le_records_shape", case_id
                    )
                address_fields[role] += 1
        for role, field in (
            ("transmitter_random", "transmitter_address_random"),
            ("receiver_random", "receiver_address_random"),
        ):
            value = bluetooth_le.get(field)
            if value is None:
                flag_counts[role]["unavailable_frames"] += 1
            elif type(value) is bool:
                flag_counts[role]["true_frames" if value else "false_frames"] += 1
            else:
                raise BluetoothLeEvaluationError("bluetooth_le_records_shape", case_id)

        crc_status = bluetooth_le.get("crc_status")
        if crc_status is None:
            crc["unavailable_frames"] += 1
        elif crc_status in {"valid", "invalid"}:
            crc[f"{crc_status}_frames"] += 1
        else:
            raise BluetoothLeEvaluationError("bluetooth_le_records_shape", case_id)

        radio = bluetooth_le.get("radio")
        if radio is None:
            channel_unavailable += 1
            continue
        if (
            not isinstance(radio, dict)
            or not radio
            or not set(radio) <= {"channel", "signal_dbm", "noise_dbm"}
        ):
            raise BluetoothLeEvaluationError("bluetooth_le_records_shape", case_id)
        channel = radio.get("channel")
        if channel is None:
            channel_unavailable += 1
        elif type(channel) is int and 0 <= channel <= 39:
            channel_mix[channel] = channel_mix.get(channel, 0) + 1
        else:
            raise BluetoothLeEvaluationError("bluetooth_le_records_shape", case_id)
        for key, values in (("signal_dbm", signal_values), ("noise_dbm", noise_values)):
            value = radio.get(key)
            if value is not None:
                if type(value) is not int or not -128 <= value <= 127:
                    raise BluetoothLeEvaluationError(
                        "bluetooth_le_records_shape", case_id
                    )
                values.append(value)

    if (
        packet_envelopes != normalization["packet_rows_emitted"]
        or packet_quarantines != normalization["packet_rows_quarantined"]
    ):
        raise BluetoothLeEvaluationError("bluetooth_le_records_completeness", case_id)
    state = normalization["state"]
    return {
        "completeness": {
            "state": state,
            "scope": "complete_capture"
            if state == "complete"
            else "normalized_packet_subset",
            "packet_limit": normalization["packet_limit"],
            "packet_limit_reached": normalization["packet_limit_reached"],
        },
        "counts": {
            "packet_envelopes": packet_envelopes,
            "packet_quarantines": packet_quarantines,
            "packet_rows_inspected": packet_envelopes + packet_quarantines,
            "bluetooth_le_frames": bluetooth_frames,
            "other_packet_envelopes": packet_envelopes - bluetooth_frames,
        },
        "pdu_types": {
            "present_frames": sum(pdu_mix.values()),
            "unavailable_frames": pdu_unavailable,
            "mix": [
                {"pdu_type": value, "frames": pdu_mix[value]}
                for value in sorted(pdu_mix)
            ],
        },
        "address_fields": address_fields,
        "address_header_flags": flag_counts,
        "crc": crc,
        "radio": {
            "channels": {
                "present_frames": sum(channel_mix.values()),
                "unavailable_frames": channel_unavailable,
                "mix": [
                    {"channel": value, "frames": channel_mix[value]}
                    for value in sorted(channel_mix)
                ],
            },
            "signal_dbm": summarize_dbm(signal_values),
            "noise_dbm": summarize_dbm(noise_values),
        },
    }


def evaluate_case(
    extracted: Any, observed: dict[str, Any]
) -> tuple[bool, dict[str, Any]]:
    case = extracted.case
    counts = observed["counts"]
    passed = observed == case["expect"]
    return passed, {
        "case": case["id"],
        "input_bytes": len(extracted.capture_bytes),
        "mode": case["mode"],
        "result": "pass" if passed else "expectation_failure",
        "status": "projected",
        "scope": observed["completeness"]["scope"],
        "normalized_packets": counts["packet_envelopes"],
        "packet_quarantines": counts["packet_quarantines"],
        "bluetooth_le_frames": counts["bluetooth_le_frames"],
        "identity_inference": "not_performed",
        "oracle": observed,
    }
