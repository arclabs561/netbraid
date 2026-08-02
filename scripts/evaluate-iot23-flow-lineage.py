#!/usr/bin/env python3
"""Evaluate packet-derived flow lineage against an IoT-23 labeled Zeek log.

This is a bounded oracle evaluator.  It consumes already-sessionized,
packet-derived flow metadata; it does not derive flows from a capture or invoke
Netbraid.  Its JSON report contains aggregate counts only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator, Sequence


SCHEMA_VERSION = "netbraid.iot23_flow_lineage_evaluation.v0"
TIME_TOLERANCE_NS = 1_000
MAX_INPUT_BYTES = 512 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
DEFAULT_MAX_ZEEK_FLOWS = 1_000_000
DEFAULT_MAX_PACKET_FLOWS = 1_000_000
DEFAULT_MAX_MATCH_EDGES = 2_000_000
HARD_MAX_FLOWS = 5_000_000
HARD_MAX_MATCH_EDGES = 10_000_000
MAX_COUNTER = (1 << 63) - 1
MAX_SECONDS = 10**12

ZEEK_FIELDS = (
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "history",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
    "tunnel_parents",
    "label",
    "detailed-label",
)
ZEEK_TYPES = (
    "time",
    "string",
    "addr",
    "port",
    "addr",
    "port",
    "enum",
    "string",
    "interval",
    "count",
    "count",
    "string",
    "bool",
    "bool",
    "count",
    "string",
    "count",
    "count",
    "count",
    "count",
    "set[string]",
    "string",
    "string",
)
PACKET_FLOW_FIELDS = (
    "start_time",
    "end_time",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "orig_packets",
    "orig_ip_bytes",
    "resp_packets",
    "resp_ip_bytes",
)
ZEEK_DIRECTIVES = (
    "separator",
    "set_separator",
    "empty_field",
    "unset_field",
    "path",
    "open",
    "fields",
    "types",
    "close",
)
FIXED_SECONDS = re.compile(r"(?:0|[1-9][0-9]{0,12})(?:\.([0-9]{1,9}))?")
HEADER_TIME = re.compile(r"[0-9]{4}(?:-[0-9]{2}){5}")
TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_.&-]{0,127}")
PROTOCOL = re.compile(r"[a-z][a-z0-9]{0,15}")
UID = re.compile(r"[^\s\t]{1,128}")
MISSING = {"-", "(empty)"}


class EvaluationError(RuntimeError):
    """Raised when an input violates the evaluator contract."""


@dataclass(frozen=True)
class Limits:
    zeek_flows: int = DEFAULT_MAX_ZEEK_FLOWS
    packet_flows: int = DEFAULT_MAX_PACKET_FLOWS
    match_edges: int = DEFAULT_MAX_MATCH_EDGES

    def checked(self) -> Limits:
        for name, value, ceiling in (
            ("zeek_flows", self.zeek_flows, HARD_MAX_FLOWS),
            ("packet_flows", self.packet_flows, HARD_MAX_FLOWS),
            ("match_edges", self.match_edges, HARD_MAX_MATCH_EDGES),
        ):
            if not 1 <= value <= ceiling:
                raise EvaluationError(f"{name} limit is outside [1, {ceiling}]")
        return self


@dataclass(frozen=True)
class FlowKey:
    source_version: int
    source: bytes
    source_port: int
    destination_version: int
    destination: bytes
    destination_port: int
    protocol: str


@dataclass(frozen=True)
class Counters:
    orig_packets: int | None
    orig_ip_bytes: int | None
    resp_packets: int | None
    resp_ip_bytes: int | None


@dataclass(frozen=True)
class PublisherFlow:
    key: FlowKey
    start_ns: int
    end_ns: int
    counters: Counters
    label: str | None
    detailed_rule: str | None
    duration_available: bool


@dataclass(frozen=True)
class PacketFlow:
    key: FlowKey
    start_ns: int
    end_ns: int
    counters: Counters


@contextmanager
def regular_file(path: Path) -> Iterator[BinaryIO]:
    try:
        initial = path.lstat()
    except OSError as error:
        raise EvaluationError("cannot inspect an input file") from error
    if not stat.S_ISREG(initial.st_mode):
        raise EvaluationError("input is not a regular non-symlink file")
    if not 0 < initial.st_size <= MAX_INPUT_BYTES:
        raise EvaluationError(f"input byte count is outside (0, {MAX_INPUT_BYTES}]")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvaluationError("cannot open an input without following links") from error

    with os.fdopen(descriptor, "rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino):
            raise EvaluationError("input changed between inspection and open")
        yield source
        final = os.fstat(source.fileno())

    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(opened, field) != getattr(final, field) for field in stable_fields):
        raise EvaluationError("input changed while reading")


def bounded_lines(source: BinaryIO, source_name: str) -> Iterator[tuple[int, str]]:
    line_number = 0
    while True:
        raw = source.readline(MAX_LINE_BYTES + 1)
        if not raw:
            return
        line_number += 1
        if len(raw) > MAX_LINE_BYTES:
            raise EvaluationError(
                f"{source_name} line {line_number}: line exceeds {MAX_LINE_BYTES} bytes"
            )
        try:
            line = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise EvaluationError(
                f"{source_name} line {line_number}: input is not UTF-8"
            ) from error
        if "\x00" in line:
            raise EvaluationError(
                f"{source_name} line {line_number}: NUL byte is forbidden"
            )
        if line.endswith("\n"):
            line = line[:-1]
        if line.endswith("\r"):
            line = line[:-1]
        yield line_number, line


def parse_fixed_seconds(value: str, field: str, line_number: int) -> int:
    match = FIXED_SECONDS.fullmatch(value)
    if match is None:
        raise EvaluationError(
            f"line {line_number}: {field} is not bounded fixed-point seconds"
        )
    whole, _, fraction = value.partition(".")
    seconds = int(whole, 10)
    if seconds > MAX_SECONDS:
        raise EvaluationError(f"line {line_number}: {field} exceeds its time bound")
    nanos = int(fraction.ljust(9, "0"), 10) if fraction else 0
    return seconds * 1_000_000_000 + nanos


def parse_uint(
    value: str,
    field: str,
    line_number: int,
    maximum: int = MAX_COUNTER,
    *,
    optional: bool = False,
) -> int | None:
    if optional and value in MISSING:
        return None
    if not value.isascii() or not value.isdecimal():
        raise EvaluationError(f"line {line_number}: {field} is not an unsigned integer")
    parsed = int(value, 10)
    if parsed > maximum:
        raise EvaluationError(f"line {line_number}: {field} exceeds {maximum}")
    return parsed


def parse_required_uint(
    value: str, field: str, line_number: int, maximum: int = MAX_COUNTER
) -> int:
    parsed = parse_uint(value, field, line_number, maximum)
    assert parsed is not None
    return parsed


def parse_address(value: str, field: str, line_number: int) -> tuple[int, bytes]:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise EvaluationError(
            f"line {line_number}: {field} is not an IP address"
        ) from error
    return address.version, address.packed


def parse_category(value: str, field: str, line_number: int) -> str | None:
    if value in MISSING:
        return None
    if TOKEN.fullmatch(value) is None:
        raise EvaluationError(
            f"line {line_number}: {field} is not a bounded label token"
        )
    return value


def parse_flow_key(
    source: str,
    source_port: str,
    destination: str,
    destination_port: str,
    protocol: str,
    line_number: int,
) -> FlowKey:
    source_version, source_bytes = parse_address(source, "source address", line_number)
    destination_version, destination_bytes = parse_address(
        destination, "destination address", line_number
    )
    parsed_source_port = parse_required_uint(
        source_port, "source port", line_number, 65_535
    )
    parsed_destination_port = parse_required_uint(
        destination_port, "destination port", line_number, 65_535
    )
    if PROTOCOL.fullmatch(protocol) is None:
        raise EvaluationError(
            f"line {line_number}: protocol is not a bounded lowercase token"
        )
    return FlowKey(
        source_version,
        source_bytes,
        parsed_source_port,
        destination_version,
        destination_bytes,
        parsed_destination_port,
        protocol,
    )


def split_publisher_columns(payload: str, line_number: int) -> list[str]:
    columns = payload.split("\t")
    if len(columns) == len(ZEEK_FIELDS):
        return columns
    if len(columns) == len(ZEEK_FIELDS) - 2:
        tail = columns[-1].split("   ")
        if len(tail) == 3 and all(tail):
            return [*columns[:-1], *tail]
    raise EvaluationError(
        f"publisher line {line_number}: expected {len(ZEEK_FIELDS)} columns"
    )


def require_unique_fields(fields: Sequence[str], source_name: str) -> None:
    duplicates = sorted(name for name, count in Counter(fields).items() if count > 1)
    if duplicates:
        raise EvaluationError(f"{source_name} schema contains duplicate fields")


def parse_publisher_row(columns: list[str], line_number: int) -> PublisherFlow:
    values = dict(zip(ZEEK_FIELDS, columns))
    if UID.fullmatch(values["uid"]) is None:
        raise EvaluationError(f"publisher line {line_number}: uid is malformed")
    key = parse_flow_key(
        values["id.orig_h"],
        values["id.orig_p"],
        values["id.resp_h"],
        values["id.resp_p"],
        values["proto"],
        line_number,
    )
    start_ns = parse_fixed_seconds(values["ts"], "ts", line_number)
    duration_available = values["duration"] not in MISSING
    duration_ns = (
        parse_fixed_seconds(values["duration"], "duration", line_number)
        if duration_available
        else 0
    )
    assert duration_ns is not None
    if start_ns + duration_ns > (MAX_SECONDS + 1) * 1_000_000_000:
        raise EvaluationError(f"publisher line {line_number}: time envelope overflows")

    for field in ("orig_bytes", "resp_bytes"):
        parse_uint(values[field], field, line_number, optional=True)
    parse_uint(values["missed_bytes"], "missed_bytes", line_number, optional=True)
    for field in ("local_orig", "local_resp"):
        if values[field] not in {"T", "F", *MISSING}:
            raise EvaluationError(f"publisher line {line_number}: {field} is malformed")
    for field in ("service", "conn_state", "history", "tunnel_parents"):
        if not 1 <= len(values[field]) <= 1024 or "\t" in values[field]:
            raise EvaluationError(f"publisher line {line_number}: {field} is malformed")

    return PublisherFlow(
        key=key,
        start_ns=start_ns,
        end_ns=start_ns + duration_ns,
        counters=Counters(
            parse_uint(values["orig_pkts"], "orig_pkts", line_number, optional=True),
            parse_uint(
                values["orig_ip_bytes"], "orig_ip_bytes", line_number, optional=True
            ),
            parse_uint(values["resp_pkts"], "resp_pkts", line_number, optional=True),
            parse_uint(
                values["resp_ip_bytes"], "resp_ip_bytes", line_number, optional=True
            ),
        ),
        label=parse_category(values["label"], "label", line_number),
        detailed_rule=parse_category(
            values["detailed-label"], "detailed-label", line_number
        ),
        duration_available=duration_available,
    )


def parse_zeek(path: Path, row_limit: int) -> list[PublisherFlow]:
    flows: list[PublisherFlow] = []
    directives: list[str] = []
    seen: set[str] = set()
    fields_seen = False
    types_seen = False
    closed = False

    with regular_file(path) as source:
        for line_number, line in bounded_lines(source, "publisher"):
            if not line:
                raise EvaluationError(
                    f"publisher line {line_number}: blank line is forbidden"
                )
            if line.startswith("#"):
                match = re.fullmatch(r"#([^\t ]+)[\t ](.*)", line)
                if match is None:
                    raise EvaluationError(
                        f"publisher line {line_number}: malformed Zeek directive"
                    )
                directive, payload = match.groups()
                if directive in seen:
                    raise EvaluationError(
                        f"publisher line {line_number}: duplicate #{directive} directive"
                    )
                if directive not in ZEEK_DIRECTIVES:
                    raise EvaluationError(
                        f"publisher line {line_number}: unexpected Zeek directive"
                    )
                seen.add(directive)
                directives.append(directive)
                if directive == "separator" and payload != r"\x09":
                    raise EvaluationError("publisher separator is not a tab")
                if directive == "set_separator" and payload != ",":
                    raise EvaluationError("publisher set separator differs from schema")
                if directive == "empty_field" and payload != "(empty)":
                    raise EvaluationError(
                        "publisher empty-field sentinel differs from schema"
                    )
                if directive == "unset_field" and payload != "-":
                    raise EvaluationError(
                        "publisher unset-field sentinel differs from schema"
                    )
                if directive == "path" and payload != "conn":
                    raise EvaluationError("publisher path is not conn")
                if (
                    directive in {"open", "close"}
                    and HEADER_TIME.fullmatch(payload) is None
                ):
                    raise EvaluationError(
                        f"publisher line {line_number}: malformed #{directive} time"
                    )
                if directive == "fields":
                    fields = split_publisher_columns(payload, line_number)
                    require_unique_fields(fields, "publisher")
                    if tuple(fields) != ZEEK_FIELDS:
                        raise EvaluationError(
                            "publisher fields differ from the locked schema"
                        )
                    fields_seen = True
                if directive == "types":
                    types = split_publisher_columns(payload, line_number)
                    if tuple(types) != ZEEK_TYPES:
                        raise EvaluationError(
                            "publisher types differ from the locked schema"
                        )
                    types_seen = True
                if directive == "close":
                    closed = True
                continue

            if closed:
                raise EvaluationError(
                    f"publisher line {line_number}: data appears after #close"
                )
            if not fields_seen or not types_seen:
                raise EvaluationError(
                    f"publisher line {line_number}: data precedes #fields/#types"
                )
            flows.append(
                parse_publisher_row(
                    split_publisher_columns(line, line_number), line_number
                )
            )
            if len(flows) > row_limit:
                raise EvaluationError(f"publisher flow count exceeds limit {row_limit}")

    if tuple(directives) != ZEEK_DIRECTIVES:
        raise EvaluationError(
            "publisher directives differ from the locked Zeek sequence"
        )
    if not flows:
        raise EvaluationError("publisher input contains no flow rows")
    return flows


def parse_packet_row(columns: list[str], line_number: int) -> PacketFlow:
    values = dict(zip(PACKET_FLOW_FIELDS, columns))
    start_ns = parse_fixed_seconds(values["start_time"], "start_time", line_number)
    end_ns = parse_fixed_seconds(values["end_time"], "end_time", line_number)
    if end_ns < start_ns:
        raise EvaluationError(
            f"packet line {line_number}: end_time precedes start_time"
        )
    key = parse_flow_key(
        values["src_ip"],
        values["src_port"],
        values["dst_ip"],
        values["dst_port"],
        values["protocol"],
        line_number,
    )
    counters = Counters(
        parse_required_uint(values["orig_packets"], "orig_packets", line_number),
        parse_required_uint(values["orig_ip_bytes"], "orig_ip_bytes", line_number),
        parse_required_uint(values["resp_packets"], "resp_packets", line_number),
        parse_required_uint(values["resp_ip_bytes"], "resp_ip_bytes", line_number),
    )
    if counters.orig_packets + counters.resp_packets == 0:
        raise EvaluationError(f"packet line {line_number}: flow has no packets")
    if (counters.orig_packets == 0) != (counters.orig_ip_bytes == 0):
        raise EvaluationError(
            f"packet line {line_number}: origin packet/IP-byte counters disagree"
        )
    if (counters.resp_packets == 0) != (counters.resp_ip_bytes == 0):
        raise EvaluationError(
            f"packet line {line_number}: response packet/IP-byte counters disagree"
        )
    return PacketFlow(key, start_ns, end_ns, counters)


def parse_packet_flows(path: Path, row_limit: int) -> list[PacketFlow]:
    flows: list[PacketFlow] = []
    with regular_file(path) as source:
        lines = bounded_lines(source, "packet")
        try:
            header_line_number, header = next(lines)
        except StopIteration as error:
            raise EvaluationError("packet input is empty") from error
        fields = header.split("\t")
        require_unique_fields(fields, "packet")
        if tuple(fields) != PACKET_FLOW_FIELDS:
            raise EvaluationError("packet fields differ from the locked schema")
        for line_number, line in lines:
            if not line or line.startswith("#"):
                raise EvaluationError(
                    f"packet line {line_number}: blank/comment line is forbidden"
                )
            columns = line.split("\t")
            if len(columns) != len(PACKET_FLOW_FIELDS):
                raise EvaluationError(
                    f"packet line {line_number}: expected {len(PACKET_FLOW_FIELDS)} columns"
                )
            flows.append(parse_packet_row(columns, line_number))
            if len(flows) > row_limit:
                raise EvaluationError(f"packet flow count exceeds limit {row_limit}")
    if not flows:
        raise EvaluationError("packet input contains no flow rows")
    return flows


def match_flows(
    publisher: Sequence[PublisherFlow],
    packet: Sequence[PacketFlow],
    edge_limit: int,
) -> tuple[list[set[int]], list[set[int]], int]:
    publisher_by_key: dict[FlowKey, list[int]] = defaultdict(list)
    packet_by_key: dict[FlowKey, list[int]] = defaultdict(list)
    for index, flow in enumerate(publisher):
        publisher_by_key[flow.key].append(index)
    for index, flow in enumerate(packet):
        packet_by_key[flow.key].append(index)

    publisher_edges = [set() for _ in publisher]
    packet_edges = [set() for _ in packet]
    edge_count = 0
    for key in publisher_by_key.keys() & packet_by_key.keys():
        events: list[tuple[int, int, int, int]] = []
        for index in publisher_by_key[key]:
            flow = publisher[index]
            events.append((flow.start_ns - TIME_TOLERANCE_NS, 0, 0, index))
            events.append((flow.end_ns + TIME_TOLERANCE_NS, 1, 0, index))
        for index in packet_by_key[key]:
            flow = packet[index]
            events.append((flow.start_ns, 0, 1, index))
            events.append((flow.end_ns, 1, 1, index))
        events.sort()

        active_publisher: set[int] = set()
        active_packet: set[int] = set()
        for _, event_kind, side, index in events:
            active_same = active_publisher if side == 0 else active_packet
            active_other = active_packet if side == 0 else active_publisher
            if event_kind == 0:
                for other in active_other:
                    publisher_index, packet_index = (
                        (index, other) if side == 0 else (other, index)
                    )
                    publisher_edges[publisher_index].add(packet_index)
                    packet_edges[packet_index].add(publisher_index)
                    edge_count += 1
                    if edge_count > edge_limit:
                        raise EvaluationError(
                            f"match edge count exceeds limit {edge_limit}"
                        )
                active_same.add(index)
            else:
                active_same.remove(index)
    return publisher_edges, packet_edges, edge_count


def ratio(numerator: int, denominator: int) -> dict[str, int]:
    return {"numerator": numerator, "denominator": denominator}


def label_rows(
    publisher: Sequence[PublisherFlow],
    publisher_edges: Sequence[set[int]],
    packet_edges: Sequence[set[int]],
) -> list[dict[str, object]]:
    counts: dict[str | None, Counter[str]] = defaultdict(Counter)
    for flow, edges in zip(publisher, publisher_edges):
        bucket = counts[flow.label]
        bucket["publisher_flows"] += 1
        bucket["matched"] += bool(edges)
        bucket["unmatched"] += not edges
        bucket["split"] += len(edges) > 1
        bucket["one_to_one"] += (
            len(edges) == 1 and len(packet_edges[next(iter(edges))]) == 1
        )
    return [
        {"label": label, **dict(sorted(counts[label].items()))}
        for label in sorted(counts, key=lambda item: item or "")
    ]


def detailed_rule_report(
    publisher: Sequence[PublisherFlow], publisher_edges: Sequence[set[int]]
) -> dict[str, object]:
    rules: dict[str, Counter[str]] = defaultdict(Counter)
    missing_by_label: Counter[str | None] = Counter()
    available = 0
    missing = 0
    missing_malicious = 0
    for flow, edges in zip(publisher, publisher_edges):
        if flow.detailed_rule is None:
            missing += 1
            missing_by_label[flow.label] += 1
            missing_malicious += flow.label == "Malicious"
            continue
        available += 1
        bucket = rules[flow.detailed_rule]
        bucket["publisher_flows"] += 1
        bucket["matched"] += bool(edges)
        bucket["unmatched"] += not edges
    return {
        "available_publisher_flows": available,
        "missing_publisher_flows": missing,
        "missing_malicious_publisher_flows": missing_malicious,
        "missing_by_label": [
            {"label": label, "publisher_flows": missing_by_label[label]}
            for label in sorted(missing_by_label, key=lambda item: item or "")
        ],
        "rules": [
            {"detailed_label": rule, **dict(sorted(rules[rule].items()))}
            for rule in sorted(rules)
        ],
    }


def delta_report(
    publisher: Sequence[PublisherFlow],
    packet: Sequence[PacketFlow],
    publisher_edges: Sequence[set[int]],
    packet_edges: Sequence[set[int]],
) -> dict[str, object]:
    pairs = [
        (publisher[index], packet[next(iter(edges))])
        for index, edges in enumerate(publisher_edges)
        if len(edges) == 1 and len(packet_edges[next(iter(edges))]) == 1
    ]

    def metric(name: str) -> dict[str, int]:
        publisher_total = 0
        packet_total = 0
        absolute_delta = 0
        compared = 0
        for publisher_flow, packet_flow in pairs:
            publisher_value = getattr(publisher_flow.counters, name)
            packet_value = getattr(packet_flow.counters, name)
            if publisher_value is None or packet_value is None:
                continue
            publisher_total += publisher_value
            packet_total += packet_value
            absolute_delta += abs(packet_value - publisher_value)
            compared += 1
        return {
            "compared_pairs": compared,
            "missing_publisher_counter_pairs": len(pairs) - compared,
            "publisher_total": publisher_total,
            "packet_derived_total": packet_total,
            "signed_packet_minus_publisher": packet_total - publisher_total,
            "absolute_pair_delta_sum": absolute_delta,
        }

    def combined(left: str, right: str) -> dict[str, int]:
        publisher_total = 0
        packet_total = 0
        absolute_delta = 0
        compared = 0
        for publisher_flow, packet_flow in pairs:
            publisher_values = (
                getattr(publisher_flow.counters, left),
                getattr(publisher_flow.counters, right),
            )
            packet_values = (
                getattr(packet_flow.counters, left),
                getattr(packet_flow.counters, right),
            )
            if None in publisher_values or None in packet_values:
                continue
            publisher_value = publisher_values[0] + publisher_values[1]
            packet_value = packet_values[0] + packet_values[1]
            publisher_total += publisher_value
            packet_total += packet_value
            absolute_delta += abs(packet_value - publisher_value)
            compared += 1
        return {
            "compared_pairs": compared,
            "missing_publisher_counter_pairs": len(pairs) - compared,
            "publisher_total": publisher_total,
            "packet_derived_total": packet_total,
            "signed_packet_minus_publisher": packet_total - publisher_total,
            "absolute_pair_delta_sum": absolute_delta,
        }

    return {
        "scope": "unambiguous_one_to_one_matches_only",
        "one_to_one_pairs": len(pairs),
        "orig_packets": metric("orig_packets"),
        "resp_packets": metric("resp_packets"),
        "total_packets": combined("orig_packets", "resp_packets"),
        "orig_ip_bytes": metric("orig_ip_bytes"),
        "resp_ip_bytes": metric("resp_ip_bytes"),
        "total_ip_bytes": combined("orig_ip_bytes", "resp_ip_bytes"),
    }


def evaluate(
    zeek_path: Path,
    packet_path: Path,
    limits: Limits = Limits(),
) -> dict[str, object]:
    checked_limits = limits.checked()
    publisher = parse_zeek(zeek_path, checked_limits.zeek_flows)
    packet = parse_packet_flows(packet_path, checked_limits.packet_flows)
    publisher_edges, packet_edges, edge_count = match_flows(
        publisher, packet, checked_limits.match_edges
    )

    matched_publisher = sum(bool(edges) for edges in publisher_edges)
    matched_packet = sum(bool(edges) for edges in packet_edges)
    split_publisher = sum(len(edges) > 1 for edges in publisher_edges)
    merged_packet = sum(len(edges) > 1 for edges in packet_edges)
    one_to_one = sum(
        len(edges) == 1 and len(packet_edges[next(iter(edges))]) == 1
        for edges in publisher_edges
        if edges
    )

    return {
        "schema": SCHEMA_VERSION,
        "status": "evaluated_oracle_only",
        "preregistration": {
            "join_key": "fixed_directional_source_destination_five_tuple",
            "time_envelope": "closed_interval_overlap",
            "publisher_envelope_tolerance_ns": TIME_TOLERANCE_NS,
            "unset_publisher_duration_policy": "point_envelope_at_start_time",
            "split_definition": "one_publisher_flow_to_multiple_packet_derived_flows",
            "merge_definition": "one_packet_derived_flow_to_multiple_publisher_flows",
            "delta_scope": "unambiguous_one_to_one_matches_only",
        },
        "inputs": {
            "publisher_flows": len(publisher),
            "packet_derived_flows": len(packet),
            "publisher_flows_without_duration": sum(
                not flow.duration_available for flow in publisher
            ),
        },
        "raw_lineage": {
            "match_edges": edge_count,
            "publisher_matched": ratio(matched_publisher, len(publisher)),
            "publisher_unmatched": ratio(
                len(publisher) - matched_publisher, len(publisher)
            ),
            "packet_derived_matched": ratio(matched_packet, len(packet)),
            "packet_derived_unmatched": ratio(
                len(packet) - matched_packet, len(packet)
            ),
            "publisher_split": ratio(split_publisher, len(publisher)),
            "publisher_split_extra_fragments": sum(
                max(0, len(edges) - 1) for edges in publisher_edges
            ),
            "packet_derived_merge": ratio(merged_packet, len(packet)),
            "packet_derived_merge_extra_publishers": sum(
                max(0, len(edges) - 1) for edges in packet_edges
            ),
            "one_to_one_pairs": one_to_one,
        },
        "counter_deltas": delta_report(
            publisher, packet, publisher_edges, packet_edges
        ),
        "labels": label_rows(publisher, publisher_edges, packet_edges),
        "detailed_rule_lineage": detailed_rule_report(publisher, publisher_edges),
        "limits": {
            "max_input_bytes_each": MAX_INPUT_BYTES,
            "max_line_bytes": MAX_LINE_BYTES,
            "max_publisher_flows": checked_limits.zeek_flows,
            "max_packet_derived_flows": checked_limits.packet_flows,
            "max_match_edges": checked_limits.match_edges,
            "retained_payload_bytes": 0,
            "retained_endpoint_values": 0,
            "retained_hashes": 0,
        },
        "limitations": {
            "claim": "oracle_evaluator_not_production_packet_to_flow_support",
            "candidate_input": (
                "externally sessionized packet-derived metadata with IP-length counters"
            ),
            "current_netbraid_executable": (
                "does not supply IP-length-backed sessionization; its conversation "
                "reducer is capture-wide and explicitly non-sessionized"
            ),
            "not_established": [
                "production_adapter_correctness",
                "cross-capture_clock_alignment",
                "identity_or_device_lineage",
                "generalization_beyond_the_evaluated_scenario",
            ],
        },
    }


def write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zeek-log", required=True, type=Path)
    parser.add_argument("--packet-flows", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--max-zeek-flows", type=int, default=DEFAULT_MAX_ZEEK_FLOWS)
    parser.add_argument(
        "--max-packet-flows", type=int, default=DEFAULT_MAX_PACKET_FLOWS
    )
    parser.add_argument("--max-match-edges", type=int, default=DEFAULT_MAX_MATCH_EDGES)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = evaluate(
            args.zeek_log,
            args.packet_flows,
            Limits(args.max_zeek_flows, args.max_packet_flows, args.max_match_edges),
        )
        write_report(args.report, report)
    except (EvaluationError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
