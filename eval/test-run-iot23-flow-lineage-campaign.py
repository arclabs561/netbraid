#!/usr/bin/env python3
"""Hermetic checks for the complete IoT-23 lineage campaign runner."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
RUNNER = HERE / "run-iot23-flow-lineage-campaign.py"
FLOW_HEADER = (
    "start_time\tend_time\tsrc_ip\tsrc_port\tdst_ip\tdst_port\tprotocol\t"
    "orig_packets\torig_ip_bytes\tresp_packets\tresp_ip_bytes"
)


class CampaignRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.capture = self.root / "capture.pcap"
        self.zeek = self.root / "conn.log"
        self.capture.write_bytes(b"pcap fixture")
        self.zeek.write_bytes(b"zeek fixture")
        self.evaluator = self.root / "evaluator.py"
        self.evaluator.write_text(
            """#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--zeek-log')
parser.add_argument('--packet-flows')
parser.add_argument('--report')
args = parser.parse_args()
payload = Path(args.packet_flows).read_bytes()
report = {
    'flow_sha256': hashlib.sha256(payload).hexdigest(),
    'status': 'ok',
    'inputs': {'publisher_flows': 1, 'publisher_flows_without_duration': 0},
}
Path(args.report).write_text(json.dumps(report, sort_keys=True) + '\\n')
""",
            encoding="utf-8",
        )
        self.profiler = self.write_profiler()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_producer(self, body: str) -> Path:
        producer = self.root / "netbraid"
        producer.write_text(f"#!/usr/bin/env python3\n{body}\n", encoding="utf-8")
        producer.chmod(0o700)
        return producer

    def write_profiler(
        self, connection_count: int = 1, missing_duration_count: int = 0
    ) -> Path:
        profiler = self.root / "zeek-profiler"
        profile = {
            "schema": "netbraid.zeek_conn_adapter_profile.v0",
            "connection_count": connection_count,
            "protocol_counts": {
                "icmp": 0,
                "tcp": 0,
                "udp": connection_count,
                "unknown_transport": 0,
            },
            "missing_duration_count": missing_duration_count,
            "missing_counter_counts": {
                "orig_ip_bytes": 0,
                "orig_packets": 0,
                "resp_ip_bytes": 0,
                "resp_packets": 0,
            },
            "projection_sha256": "0" * 64,
        }
        profiler.write_text(
            "#!/usr/bin/env python3\n"
            f"import json\nprint(json.dumps({profile!r}, sort_keys=True))\n",
            encoding="utf-8",
        )
        profiler.chmod(0o700)
        return profiler

    def run_campaign(
        self, producer: Path, output: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--capture",
                str(self.capture),
                "--zeek-log",
                str(self.zeek),
                "--netbraid-bin",
                str(producer),
                "--zeek-profile-bin",
                str(self.profiler),
                "--evaluator",
                str(self.evaluator),
                "--output-dir",
                str(output or self.root / "derived"),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_complete_campaign_repeats_and_writes_path_free_receipt(self) -> None:
        producer = self.write_producer(
            f"print({FLOW_HEADER!r})\n"
            "print('1.0\\t1.0\\t192.0.2.1\\t1\\t198.51.100.2\\t2\\tudp\\t1\\t20\\t0\\t0')"
        )
        output = self.root / "derived"
        result = self.run_campaign(producer, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            (output / "packet-flows.tsv").read_bytes(),
            (output / "packet-flows-repeat.tsv").read_bytes(),
        )
        self.assertEqual(
            (output / "report.json").read_bytes(),
            (output / "report-repeat.json").read_bytes(),
        )
        receipt_bytes = (output / "campaign-receipt.json").read_text(encoding="utf-8")
        receipt = json.loads(receipt_bytes)
        self.assertEqual(receipt["status"], "complete_deterministic")
        self.assertEqual(receipt["repetitions"], 2)
        self.assertEqual(receipt["producer"]["tcp_inactivity_seconds"], 300)
        self.assertEqual(receipt["producer"]["udp_inactivity_seconds"], 60)
        self.assertEqual(
            receipt["zeek_adapter"]["schema"],
            "netbraid.zeek_conn_adapter_profile.v0",
        )
        self.assertNotIn(str(self.root), receipt_bytes)
        self.assertNotIn("192.0.2.1", receipt_bytes)

    def test_adapter_and_evaluator_count_mismatch_fails_closed(self) -> None:
        producer = self.write_producer(
            f"print({FLOW_HEADER!r})\n"
            "print('1.0\\t1.0\\t192.0.2.1\\t1\\t198.51.100.2\\t2\\tudp\\t1\\t20\\t0\\t0')"
        )
        self.profiler = self.write_profiler(connection_count=2)

        result = self.run_campaign(producer)

        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "Zeek adapter and evaluator connection counts differ", result.stderr
        )
        self.assertFalse((self.root / "derived" / "campaign-receipt.json").exists())

    def test_nondeterministic_producer_fails_closed(self) -> None:
        state = self.root / "state"
        producer = self.write_producer(
            "from pathlib import Path\n"
            f"state = Path({str(state)!r})\n"
            "value = int(state.read_text()) + 1 if state.exists() else 1\n"
            "state.write_text(str(value))\n"
            f"print({FLOW_HEADER!r})\n"
            "print(f'{value}.0\\t{value}.0\\t192.0.2.1\\t1\\t198.51.100.2\\t2\\tudp\\t1\\t20\\t0\\t0')"
        )
        result = self.run_campaign(producer)
        self.assertEqual(result.returncode, 2)
        self.assertIn(
            "packet-flow TSV was not byte-for-byte deterministic", result.stderr
        )
        self.assertFalse((self.root / "derived" / "campaign-receipt.json").exists())

    def test_producer_failure_is_reported_without_forwarding_stderr(self) -> None:
        producer = self.write_producer(
            "import sys\nprint('private path and endpoint', file=sys.stderr)\nsys.exit(7)"
        )
        result = self.run_campaign(producer)
        self.assertEqual(result.returncode, 2)
        self.assertIn("failed with exit code 7", result.stderr)
        self.assertNotIn("private path", result.stderr)

    def test_symlink_input_and_output_are_rejected(self) -> None:
        producer = self.write_producer(f"print({FLOW_HEADER!r})")
        capture_link = self.root / "capture-link.pcap"
        capture_link.symlink_to(self.capture)
        original = self.capture
        self.capture = capture_link
        try:
            result = self.run_campaign(producer)
        finally:
            self.capture = original
        self.assertEqual(result.returncode, 2)
        self.assertIn("capture is not a regular non-symlink file", result.stderr)

        output_target = self.root / "output-target"
        output_target.mkdir()
        output_link = self.root / "output-link"
        output_link.symlink_to(output_target, target_is_directory=True)
        result = self.run_campaign(producer, output_link)
        self.assertEqual(result.returncode, 2)
        self.assertIn("output path is not a non-symlink directory", result.stderr)

    def test_policy_values_are_bounded_before_execution(self) -> None:
        producer = self.write_producer(f"print({FLOW_HEADER!r})")
        result = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                "--capture",
                str(self.capture),
                "--zeek-log",
                str(self.zeek),
                "--netbraid-bin",
                str(producer),
                "--zeek-profile-bin",
                str(self.profiler),
                "--evaluator",
                str(self.evaluator),
                "--output-dir",
                str(self.root / "derived"),
                "--tcp-inactivity-seconds",
                "300.0",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("must be an integer", result.stderr)


if __name__ == "__main__":
    unittest.main()
