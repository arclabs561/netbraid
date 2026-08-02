#!/usr/bin/env python3
"""Hermetic tests for the IoT-23 packet-to-flow lineage evaluator."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "evaluate_iot23_flow_lineage", HERE / "evaluate-iot23-flow-lineage.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

PUBLISHER_FIELDS = (
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
PUBLISHER_TYPES = (
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
PACKET_FIELDS = (
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


def publisher_row(
    timestamp: str,
    uid: str,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    duration: str,
    orig_packets: int,
    orig_ip_bytes: int,
    resp_packets: int,
    resp_ip_bytes: int,
    label: str,
    detailed_label: str,
) -> str:
    zeek = [
        timestamp,
        uid,
        source,
        str(source_port),
        destination,
        str(destination_port),
        "tcp",
        "-",
        duration,
        str(orig_ip_bytes - 40 * orig_packets),
        str(resp_ip_bytes - 40 * resp_packets),
        "SF",
        "-",
        "-",
        "0",
        "ShADadf",
        str(orig_packets),
        str(orig_ip_bytes),
        str(resp_packets),
        str(resp_ip_bytes),
        "-",
    ]
    return "\t".join(zeek) + f"   {label}   {detailed_label}"


def publisher_log(rows: list[str], fields: tuple[str, ...] = PUBLISHER_FIELDS) -> str:
    hybrid_fields = "\t".join(fields[:21]) + "   " + "   ".join(fields[21:])
    hybrid_types = (
        "\t".join(PUBLISHER_TYPES[:21]) + "   " + "   ".join(PUBLISHER_TYPES[21:])
    )
    return "\n".join(
        [
            r"#separator \x09",
            "#set_separator\t,",
            "#empty_field\t(empty)",
            "#unset_field\t-",
            "#path\tconn",
            "#open\t2020-01-01-00-00-00",
            f"#fields\t{hybrid_fields}",
            f"#types\t{hybrid_types}",
            *rows,
            "#close\t2020-01-01-00-01-00",
            "",
        ]
    )


def packet_row(
    start: str,
    end: str,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    orig_packets: int,
    orig_ip_bytes: int,
    resp_packets: int,
    resp_ip_bytes: int,
) -> str:
    return "\t".join(
        (
            start,
            end,
            source,
            str(source_port),
            destination,
            str(destination_port),
            "tcp",
            str(orig_packets),
            str(orig_ip_bytes),
            str(resp_packets),
            str(resp_ip_bytes),
        )
    )


def packet_log(rows: list[str], fields: tuple[str, ...] = PACKET_FIELDS) -> str:
    return "\n".join(("\t".join(fields), *rows, ""))


class FlowLineageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.zeek = self.directory / "publisher.log"
        self.packet = self.directory / "packet-flows.tsv"

    def write_fixture(self) -> None:
        self.zeek.write_text(
            publisher_log(
                [
                    publisher_row(
                        "10",
                        "uid-a",
                        "192.0.2.1",
                        40000,
                        "198.51.100.1",
                        443,
                        "2",
                        2,
                        120,
                        1,
                        60,
                        "Malicious",
                        "Scan",
                    ),
                    publisher_row(
                        "20",
                        "uid-b",
                        "192.0.2.2",
                        40001,
                        "198.51.100.2",
                        53,
                        "1",
                        1,
                        60,
                        1,
                        40,
                        "Benign",
                        "-",
                    ),
                    publisher_row(
                        "30",
                        "uid-c",
                        "192.0.2.3",
                        40002,
                        "198.51.100.3",
                        80,
                        "2",
                        4,
                        240,
                        2,
                        120,
                        "Malicious",
                        "Scan",
                    ),
                    publisher_row(
                        "40",
                        "uid-d",
                        "192.0.2.4",
                        40003,
                        "198.51.100.4",
                        22,
                        "2",
                        1,
                        60,
                        1,
                        60,
                        "Malicious",
                        "CommandAndControl",
                    ),
                    publisher_row(
                        "41",
                        "uid-e",
                        "192.0.2.4",
                        40003,
                        "198.51.100.4",
                        22,
                        "2",
                        1,
                        60,
                        1,
                        60,
                        "Malicious",
                        "CommandAndControl",
                    ),
                    publisher_row(
                        "50",
                        "uid-f",
                        "192.0.2.5",
                        40004,
                        "198.51.100.5",
                        25,
                        "1",
                        1,
                        60,
                        0,
                        0,
                        "Malicious",
                        "Spam",
                    ),
                ]
            ),
            encoding="utf-8",
        )
        self.packet.write_text(
            packet_log(
                [
                    packet_row(
                        "10",
                        "12",
                        "192.0.2.1",
                        40000,
                        "198.51.100.1",
                        443,
                        3,
                        135,
                        1,
                        65,
                    ),
                    packet_row(
                        "20",
                        "21",
                        "192.0.2.2",
                        40001,
                        "198.51.100.2",
                        53,
                        1,
                        55,
                        1,
                        35,
                    ),
                    packet_row(
                        "30",
                        "31",
                        "192.0.2.3",
                        40002,
                        "198.51.100.3",
                        80,
                        2,
                        120,
                        1,
                        60,
                    ),
                    packet_row(
                        "31.000000001",
                        "32",
                        "192.0.2.3",
                        40002,
                        "198.51.100.3",
                        80,
                        2,
                        120,
                        1,
                        60,
                    ),
                    packet_row(
                        "40",
                        "43",
                        "192.0.2.4",
                        40003,
                        "198.51.100.4",
                        22,
                        2,
                        120,
                        2,
                        120,
                    ),
                    packet_row(
                        "10",
                        "12",
                        "198.51.100.1",
                        443,
                        "192.0.2.1",
                        40000,
                        1,
                        60,
                        1,
                        60,
                    ),
                ]
            ),
            encoding="utf-8",
        )

    def test_reports_raw_lineage_deltas_labels_and_missing_rules(self) -> None:
        self.write_fixture()
        report = MODULE.evaluate(self.zeek, self.packet)

        self.assertEqual(report["status"], "evaluated_oracle_only")
        self.assertEqual(report["inputs"]["publisher_flows"], 6)
        self.assertEqual(report["inputs"]["packet_derived_flows"], 6)
        lineage = report["raw_lineage"]
        self.assertEqual(lineage["match_edges"], 6)
        self.assertEqual(
            lineage["publisher_matched"], {"numerator": 5, "denominator": 6}
        )
        self.assertEqual(lineage["publisher_unmatched"]["numerator"], 1)
        self.assertEqual(lineage["packet_derived_matched"]["numerator"], 5)
        self.assertEqual(lineage["packet_derived_unmatched"]["numerator"], 1)
        self.assertEqual(lineage["publisher_split"]["numerator"], 1)
        self.assertEqual(lineage["publisher_split_extra_fragments"], 1)
        self.assertEqual(lineage["packet_derived_merge"]["numerator"], 1)
        self.assertEqual(lineage["packet_derived_merge_extra_publishers"], 1)
        self.assertEqual(lineage["one_to_one_pairs"], 2)

        deltas = report["counter_deltas"]
        self.assertEqual(deltas["total_packets"]["publisher_total"], 5)
        self.assertEqual(deltas["total_packets"]["packet_derived_total"], 6)
        self.assertEqual(deltas["total_packets"]["signed_packet_minus_publisher"], 1)
        self.assertEqual(deltas["total_packets"]["absolute_pair_delta_sum"], 1)
        self.assertEqual(deltas["total_ip_bytes"]["publisher_total"], 280)
        self.assertEqual(deltas["total_ip_bytes"]["packet_derived_total"], 290)
        self.assertEqual(deltas["total_ip_bytes"]["signed_packet_minus_publisher"], 10)
        self.assertEqual(deltas["total_ip_bytes"]["absolute_pair_delta_sum"], 30)

        labels = {row["label"]: row for row in report["labels"]}
        self.assertEqual(labels["Malicious"]["publisher_flows"], 5)
        self.assertEqual(labels["Malicious"]["unmatched"], 1)
        self.assertEqual(labels["Benign"]["matched"], 1)
        rules = report["detailed_rule_lineage"]
        self.assertEqual(rules["missing_publisher_flows"], 1)
        self.assertEqual(rules["missing_malicious_publisher_flows"], 0)
        self.assertEqual(
            rules["missing_by_label"],
            [{"label": "Benign", "publisher_flows": 1}],
        )

    def test_report_is_deterministic_aggregate_only_and_states_oracle_gap(self) -> None:
        self.write_fixture()
        first = MODULE.evaluate(self.zeek, self.packet)
        second = MODULE.evaluate(self.zeek, self.packet)
        self.assertEqual(first, second)

        rendered = json.dumps(first, sort_keys=True)
        for forbidden in (
            "192.0.2.",
            "198.51.100.",
            "uid-a",
            str(self.directory),
            "sha256",
        ):
            self.assertNotIn(forbidden, rendered)
        self.assertEqual(first["limits"]["retained_payload_bytes"], 0)
        self.assertEqual(first["limits"]["retained_endpoint_values"], 0)
        self.assertEqual(first["limits"]["retained_hashes"], 0)
        self.assertIn(
            "does not supply IP-length-backed sessionization",
            first["limitations"]["current_netbraid_executable"],
        )

    def test_fixed_direction_and_time_envelope_do_not_invent_matches(self) -> None:
        self.zeek.write_text(
            publisher_log(
                [
                    publisher_row(
                        "10",
                        "uid-a",
                        "192.0.2.10",
                        1234,
                        "198.51.100.10",
                        80,
                        "1",
                        1,
                        60,
                        0,
                        0,
                        "Benign",
                        "-",
                    )
                ]
            ),
            encoding="utf-8",
        )
        self.packet.write_text(
            packet_log(
                [
                    packet_row(
                        "10",
                        "11",
                        "198.51.100.10",
                        80,
                        "192.0.2.10",
                        1234,
                        1,
                        60,
                        0,
                        0,
                    ),
                    packet_row(
                        "12",
                        "13",
                        "192.0.2.10",
                        1234,
                        "198.51.100.10",
                        80,
                        1,
                        60,
                        0,
                        0,
                    ),
                ]
            ),
            encoding="utf-8",
        )
        report = MODULE.evaluate(self.zeek, self.packet)
        self.assertEqual(report["raw_lineage"]["match_edges"], 0)
        self.assertEqual(report["raw_lineage"]["publisher_unmatched"]["numerator"], 1)
        self.assertEqual(
            report["raw_lineage"]["packet_derived_unmatched"]["numerator"], 2
        )

    def test_rejects_duplicate_publisher_and_packet_fields(self) -> None:
        duplicate_publisher = list(PUBLISHER_FIELDS)
        duplicate_publisher[4] = "id.orig_h"
        self.zeek.write_text(
            publisher_log([], tuple(duplicate_publisher)), encoding="utf-8"
        )
        self.packet.write_text(
            packet_log(
                [
                    packet_row(
                        "1",
                        "2",
                        "192.0.2.1",
                        1,
                        "198.51.100.1",
                        2,
                        1,
                        60,
                        0,
                        0,
                    )
                ]
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MODULE.EvaluationError, "duplicate fields"):
            MODULE.evaluate(self.zeek, self.packet)

        duplicate_packet = list(PACKET_FIELDS)
        duplicate_packet[4] = "src_ip"
        self.zeek.write_text(
            publisher_log(
                [
                    publisher_row(
                        "1",
                        "uid-a",
                        "192.0.2.1",
                        1,
                        "198.51.100.1",
                        2,
                        "1",
                        1,
                        60,
                        0,
                        0,
                        "Benign",
                        "-",
                    )
                ]
            ),
            encoding="utf-8",
        )
        self.packet.write_text(
            packet_log([], tuple(duplicate_packet)), encoding="utf-8"
        )
        with self.assertRaisesRegex(MODULE.EvaluationError, "duplicate fields"):
            MODULE.evaluate(self.zeek, self.packet)

    def test_rejects_malformed_rows_and_enforces_limits(self) -> None:
        self.write_fixture()
        with self.assertRaisesRegex(
            MODULE.EvaluationError, "flow count exceeds limit 1"
        ):
            MODULE.evaluate(self.zeek, self.packet, MODULE.Limits(1, 10, 10))
        with self.assertRaisesRegex(
            MODULE.EvaluationError, "match edge count exceeds limit 1"
        ):
            MODULE.evaluate(self.zeek, self.packet, MODULE.Limits(10, 10, 1))

        self.packet.write_text(
            packet_log(
                [
                    packet_row(
                        "2",
                        "1",
                        "192.0.2.1",
                        1,
                        "198.51.100.1",
                        2,
                        1,
                        60,
                        0,
                        0,
                    )
                ]
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MODULE.EvaluationError, "end_time precedes"):
            MODULE.evaluate(self.zeek, self.packet)

    def test_cli_writes_no_partial_report_after_closed_failure(self) -> None:
        self.write_fixture()
        report_path = self.directory / "report.json"
        exit_code = MODULE.main(
            [
                "--zeek-log",
                str(self.zeek),
                "--packet-flows",
                str(self.packet),
                "--report",
                str(report_path),
            ]
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(
            json.loads(report_path.read_text()), MODULE.evaluate(self.zeek, self.packet)
        )

        report_path.unlink()
        self.packet.write_text("start_time\tstart_time\n", encoding="utf-8")
        exit_code = MODULE.main(
            [
                "--zeek-log",
                str(self.zeek),
                "--packet-flows",
                str(self.packet),
                "--report",
                str(report_path),
            ]
        )
        self.assertEqual(exit_code, 2)
        self.assertFalse(report_path.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
