#!/usr/bin/env python3
"""Hermetic tests for the RUFF-UWB open-set source split compiler."""

from __future__ import annotations

import copy
import importlib.util
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "build_ruff_uwb_open_set_source_split",
    HERE / "build-ruff-uwb-open-set-source-split.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def opaque(seed: int) -> str:
    return f"{seed:064x}"


def group(seed: int, state: str = "known") -> dict[str, object]:
    return {
        "state": state,
        "group_id": opaque(seed) if state == "known" else None,
    }


def observation(device: int, campaign: int) -> dict[str, object]:
    seed = device * 10 + campaign
    groups = {
        axis: group((index + 1) * 100_000 + seed)
        for index, axis in enumerate(MODULE.AXES)
    }
    groups["physical_source"] = group(20_000 + device)
    groups["physical_device"] = group(30_000 + device)
    groups["event"] = group(40_000 + seed)
    groups["session"] = group(50_000 + seed)
    return {
        "observation_id": opaque(seed),
        "observation_count": 2,
        **{f"{axis}_group": groups[axis] for axis in MODULE.AXES},
        "source_location_group": group(60_000 + seed),
        "campaign_group": group(70_000 + campaign),
    }


def synthetic_observations() -> list[dict[str, object]]:
    return [
        observation(device, campaign) for device in range(13) for campaign in range(2)
    ]


def oracle(
    observations: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if observations is None:
        observations = synthetic_observations()
    return {
        "schema": MODULE.ORACLE_SCHEMA,
        "inventory_id": opaque(900_000),
        "status": "pass",
        "provenance": {"archive_integrity": "synthetic"},
        "manifest": {
            "local_ignored_manifest": True,
            "partitions_assigned": 0,
            "train_test_splits_assigned": False,
        },
        "publisher_claims": {
            "physical_sources": 13,
            "physical_devices": 13,
            "locations": 2,
            "variants": 1,
            "receivers": 1,
            "channels": 1,
        },
        "required_split_groups": [
            "physical_source_group",
            "location_group",
            "source_location_group",
            "campaign_group",
            "day_group",
        ],
        "archives": [{"archive_id": opaque(800_000 + item)} for item in range(2)],
        "counts": {
            "label_rows": len(observations) * 2,
            "observations": len(observations),
            "distinct_source_location_groups": len(observations),
            "axis_states": {},
            "distinct_known_groups": {},
        },
        "privacy": {field: 0 for field in MODULE.PRIVACY_FIELDS},
        "observations": observations,
    }


def axis_report(report: dict[str, object], axis: str) -> dict[str, object]:
    axes = report["axes"]
    assert isinstance(axes, list)
    return next(item for item in axes if item["axis"] == axis)


class RuffUwbOpenSetSourceSplitTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_consumes_the_current_oracle_contract(self):
        self.assertEqual(
            MODULE.ORACLE_SCHEMA, "netbraid.ruff_uwb_observation_oracles.v0"
        )

    def test_assigns_whole_devices_to_fixed_four_role_counts(self):
        manifest = MODULE.build_manifest(oracle())
        roles_by_device: dict[str, set[str]] = {}
        campaigns_by_device: dict[str, set[str]] = {}
        assigned = []
        for partition in manifest["partitions"]:
            for item in partition["observations"]:
                assigned.append(item["observation_id"])
                device = item["physical_device_group"]["group_id"]
                roles_by_device.setdefault(device, set()).add(partition["role"])
                campaigns_by_device.setdefault(device, set()).add(
                    item["day_group"]["group_id"]
                )

        self.assertEqual(len(assigned), 26)
        self.assertEqual(len(set(assigned)), 26)
        self.assertTrue(all(len(roles) == 1 for roles in roles_by_device.values()))
        self.assertTrue(
            all(len(campaigns) == 2 for campaigns in campaigns_by_device.values())
        )
        self.assertEqual(
            {
                partition["role"]: len(
                    {
                        item["physical_device_group"]["group_id"]
                        for item in partition["observations"]
                    }
                )
                for partition in manifest["partitions"]
            },
            MODULE.ROLE_DEVICE_COUNTS,
        )

    def test_input_order_and_paths_do_not_change_manifest(self):
        first_root = self.temporary_directory() / "first"
        second_root = self.temporary_directory() / "second"
        first_root.mkdir()
        second_root.mkdir()
        value = oracle()
        permuted = copy.deepcopy(value)
        permuted["observations"].reverse()

        outputs = []
        for root, source in ((first_root, value), (second_root, permuted)):
            oracle_path = root / "oracle.json"
            manifest_path = root / "split.json"
            oracle_path.write_text(json.dumps(source), encoding="utf-8")
            process = subprocess.run(
                [
                    sys.executable,
                    str(HERE / "build-ruff-uwb-open-set-source-split.py"),
                    "--oracle",
                    str(oracle_path),
                    "--manifest",
                    str(manifest_path),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            summary = json.loads(process.stdout)
            self.assertEqual(summary["waveform_payload_bytes_read"], 0)
            self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
            outputs.append(manifest_path.read_bytes())

        self.assertEqual(outputs[0], outputs[1])
        self.assertNotIn(str(first_root).encode(), outputs[0])
        self.assertNotIn(str(second_root).encode(), outputs[0])

    def test_canonical_auditor_proves_all_four_separation_axes(self):
        manifest = MODULE.build_manifest(oracle())
        report = MODULE.AUDIT.audit_manifest(manifest)

        self.assertEqual(report["status"], "pass")
        for axis in ("event", "session", "physical_source", "physical_device"):
            with self.subTest(axis=axis):
                pairs = axis_report(report, axis)["pair_intersections"]
                self.assertEqual(len(pairs), 6)
                self.assertTrue(all(item["forbidden"] for item in pairs))
                self.assertTrue(all(item["status"] == "pass" for item in pairs))
                self.assertTrue(
                    all(item["known_group_intersection_count"] == 0 for item in pairs)
                )

    def test_not_observed_event_fails_closed(self):
        value = oracle()
        value["observations"][0]["event_group"] = group(0, "not_observed")

        with self.assertRaises(MODULE.OpenSetSplitError) as raised:
            MODULE.build_manifest(value)

        self.assertEqual(raised.exception.code, "unbounded_event_axis")

    def test_not_observed_session_fails_closed(self):
        value = oracle()
        value["observations"][0]["session_group"] = group(0, "not_observed")

        with self.assertRaises(MODULE.OpenSetSplitError) as raised:
            MODULE.build_manifest(value)

        self.assertEqual(raised.exception.code, "unbounded_session_axis")

    def test_rejects_non_bijective_source_device_aliases(self):
        value = oracle()
        value["observations"][0]["physical_device_group"] = group(30_001)

        with self.assertRaises(MODULE.OpenSetSplitError) as raised:
            MODULE.build_manifest(value)

        self.assertEqual(raised.exception.code, "physical_source_device_not_bijective")

    def test_rejects_a_device_missing_from_one_campaign(self):
        observations = synthetic_observations()
        observations.pop()
        value = oracle(observations)

        with self.assertRaises(MODULE.OpenSetSplitError) as raised:
            MODULE.build_manifest(value)

        self.assertEqual(raised.exception.code, "incomplete_cross_campaign_device")

    def test_rejects_event_or_session_linkage_across_devices(self):
        for axis, code in (
            ("event", "event_crosses_physical_device"),
            ("session", "session_crosses_physical_device"),
        ):
            with self.subTest(axis=axis):
                value = oracle()
                value["observations"][2][f"{axis}_group"] = copy.deepcopy(
                    value["observations"][0][f"{axis}_group"]
                )
                with self.assertRaises(MODULE.OpenSetSplitError) as raised:
                    MODULE.build_manifest(value)
                self.assertEqual(raised.exception.code, code)

    def test_cli_failure_does_not_publish_a_manifest(self):
        directory = self.temporary_directory()
        oracle_path = directory / "oracle.json"
        manifest_path = directory / "split.json"
        value = oracle()
        value["observations"][0]["event_group"] = group(0, "not_observed")
        oracle_path.write_text(json.dumps(value), encoding="utf-8")

        process = subprocess.run(
            [
                sys.executable,
                str(HERE / "build-ruff-uwb-open-set-source-split.py"),
                "--oracle",
                str(oracle_path),
                "--manifest",
                str(manifest_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, "")
        self.assertEqual(process.stderr, "unbounded_event_axis\n")
        self.assertFalse(manifest_path.exists())

    def test_rejects_nonzero_input_privacy_counters(self):
        value = oracle()
        value["privacy"]["waveform_payload_bytes_read"] = 1

        with self.assertRaises(MODULE.OpenSetSplitError) as raised:
            MODULE.build_manifest(value)

        self.assertEqual(raised.exception.code, "input_privacy_contract_failed")

    def test_boolean_partition_count_does_not_pass_as_zero(self):
        value = oracle()
        value["manifest"]["partitions_assigned"] = False

        with self.assertRaises(MODULE.OpenSetSplitError) as raised:
            MODULE.build_manifest(value)

        self.assertEqual(raised.exception.code, "oracle_already_partitioned")


if __name__ == "__main__":
    unittest.main(verbosity=2)
