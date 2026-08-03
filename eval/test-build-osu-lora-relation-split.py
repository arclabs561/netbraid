#!/usr/bin/env python3
"""Hermetic tests for the OSU LoRa relation-split compiler."""

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
    "build_osu_lora_relation_split", HERE / "build-osu-lora-relation-split.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def opaque(seed: int) -> str:
    return f"{seed:032x}"


def group(seed: int, state: str = "known") -> dict[str, object]:
    return {
        "state": state,
        "group_id": opaque(seed) if state == "known" else None,
    }


def observation(
    seed: int,
    *,
    event: int,
    session: int,
    session_state: str = "known",
) -> dict[str, object]:
    groups = {
        axis: group((index + 1) * 100_000 + seed)
        for index, axis in enumerate(MODULE.AXES)
    }
    groups["event"] = group(event)
    groups["session"] = group(session, session_state)
    return {
        "observation_id": opaque(seed),
        **{f"{axis}_group": groups[axis] for axis in MODULE.AXES},
    }


def synthetic_observations() -> list[dict[str, object]]:
    observations = []
    for component in range(4):
        event = 20_000 + component
        session = 30_000 + component
        observations.extend(
            (
                observation(2 * component + 1, event=event, session=session),
                observation(2 * component + 2, event=event, session=session),
            )
        )
    return observations


def oracle(
    observations: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    if observations is None:
        observations = synthetic_observations()
    return {
        "schema": MODULE.ORACLE_SCHEMA,
        "provenance": {
            "publisher_release_revision": "opaque-revision",
            "private_input_root_marker": "PRIVATE_ROOT_PATH",
        },
        "manifest": {
            "local_ignored_manifest": True,
            "partitions_assigned": 0,
            "train_test_splits_assigned": False,
        },
        "counts": {"observations": len(observations)},
        "privacy": {field: 0 for field in MODULE.PRIVACY_FIELDS},
        "observations": observations,
    }


def axis_report(report: dict[str, object], axis: str) -> dict[str, object]:
    axes = report["axes"]
    assert isinstance(axes, list)
    return next(item for item in axes if item["axis"] == axis)


class OsuLoraRelationSplitTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_consumes_the_current_v0_oracle_contract(self):
        self.assertEqual(
            MODULE.ORACLE_SCHEMA, "netbraid.osu_lora_observation_oracles.v0"
        )

    def test_assigns_every_observation_once_across_four_roles(self):
        source = oracle()
        manifest = MODULE.build_manifest(source)
        partitions = manifest["partitions"]
        assigned = [
            item["observation_id"]
            for partition in partitions
            for item in partition["observations"]
        ]

        self.assertEqual({item["role"] for item in partitions}, set(MODULE.ROLES))
        self.assertTrue(all(partition["observations"] for partition in partitions))
        self.assertEqual(len(assigned), len(source["observations"]))
        self.assertEqual(len(set(assigned)), len(assigned))
        self.assertEqual(
            set(assigned),
            {item["observation_id"] for item in source["observations"]},
        )

    def test_alternate_representations_of_one_event_are_co_located(self):
        manifest = MODULE.build_manifest(oracle())
        roles_by_event: dict[str, set[str]] = {}
        for partition in manifest["partitions"]:
            for item in partition["observations"]:
                event_id = item["event_group"]["group_id"]
                roles_by_event.setdefault(event_id, set()).add(partition["role"])

        self.assertEqual(
            sorted(len(roles) for roles in roles_by_event.values()), [1] * 4
        )
        self.assertEqual(
            sorted(
                sum(
                    item["event_group"]["group_id"] == event_id
                    for partition in manifest["partitions"]
                    for item in partition["observations"]
                )
                for event_id in roles_by_event
            ),
            [2, 2, 2, 2],
        )

    def test_session_components_keep_distinct_events_together(self):
        observations = synthetic_observations()
        observations[2]["session_group"] = group(30_000)
        observations[3]["session_group"] = group(30_000)
        observations.extend(
            (
                observation(9, event=20_004, session=30_004),
                observation(10, event=20_004, session=30_004),
            )
        )
        manifest = MODULE.build_manifest(oracle(observations))
        role_by_id = {
            item["observation_id"]: partition["role"]
            for partition in manifest["partitions"]
            for item in partition["observations"]
        }

        self.assertEqual(role_by_id[opaque(1)], role_by_id[opaque(3)])
        self.assertEqual(role_by_id[opaque(2)], role_by_id[opaque(4)])

    def test_input_order_and_oracle_root_path_do_not_change_output(self):
        first_root = self.temporary_directory() / "first"
        second_root = self.temporary_directory() / "second"
        first_root.mkdir()
        second_root.mkdir()
        first_oracle = first_root / "oracles.json"
        second_oracle = second_root / "renamed.json"
        first_manifest = first_root / "split.json"
        second_manifest = second_root / "other-name.json"
        value = oracle()
        first_oracle.write_text(json.dumps(value), encoding="utf-8")
        permuted = copy.deepcopy(value)
        permuted["observations"].reverse()
        second_oracle.write_text(json.dumps(permuted), encoding="utf-8")

        processes = [
            subprocess.run(
                [
                    sys.executable,
                    str(HERE / "build-osu-lora-relation-split.py"),
                    "--oracle",
                    str(input_path),
                    "--manifest",
                    str(output_path),
                ],
                capture_output=True,
                check=False,
            )
            for input_path, output_path in (
                (first_oracle, first_manifest),
                (second_oracle, second_manifest),
            )
        ]

        for process in processes:
            self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(processes[0].stdout, processes[1].stdout)
        self.assertEqual(first_manifest.read_bytes(), second_manifest.read_bytes())
        self.assertEqual(stat.S_IMODE(first_manifest.stat().st_mode), 0o600)
        self.assertNotIn(b"PRIVATE_ROOT_PATH", first_manifest.read_bytes())
        self.assertNotIn(str(first_root).encode(), first_manifest.read_bytes())

    def test_compiled_manifest_passes_the_canonical_auditor(self):
        manifest = MODULE.build_manifest(oracle())

        parsed = MODULE.AUDIT.parse_manifest(manifest)
        report = MODULE.AUDIT.audit_manifest(manifest)

        self.assertEqual(report["status"], "pass")
        self.assertEqual(
            MODULE.AUDIT.canonical_manifest(parsed),
            manifest,
        )
        self.assertEqual(report["counts"]["observations"], 8)

    def test_all_six_forbidden_role_pairs_are_clean_for_event_and_session(self):
        report = MODULE.AUDIT.audit_manifest(MODULE.build_manifest(oracle()))

        for axis in ("event", "session"):
            with self.subTest(axis=axis):
                pairs = axis_report(report, axis)["pair_intersections"]
                self.assertEqual(len(pairs), 6)
                self.assertTrue(all(item["forbidden"] for item in pairs))
                self.assertTrue(all(item["status"] == "pass" for item in pairs))
                self.assertTrue(
                    all(item["known_group_intersection_count"] == 0 for item in pairs)
                )

    def test_not_observed_session_fails_closed(self):
        observations = synthetic_observations()
        observations[0]["session_group"] = group(30_000, "not_observed")
        value = oracle(observations)

        with self.assertRaises(MODULE.RelationSplitBuildError) as raised:
            MODULE.build_manifest(value)

        self.assertEqual(raised.exception.code, "unbounded_session_axis")

    def test_rejects_an_undeclared_session_containment_extension(self):
        value = oracle()
        value["observations"][0]["session_containment_group"] = group(90_000)

        with self.assertRaises(MODULE.RelationSplitBuildError) as raised:
            MODULE.build_manifest(value)

        self.assertEqual(raised.exception.code, "invalid_oracle_observation_schema")

    def test_cli_fails_closed_without_publishing_an_unbounded_split(self):
        directory = self.temporary_directory()
        input_path = directory / "oracles.json"
        output_path = directory / "split.json"
        observations = synthetic_observations()
        observations[-1]["session_group"] = group(30_003, "not_observed")
        input_path.write_text(json.dumps(oracle(observations)), encoding="utf-8")

        process = subprocess.run(
            [
                sys.executable,
                str(HERE / "build-osu-lora-relation-split.py"),
                "--oracle",
                str(input_path),
                "--manifest",
                str(output_path),
            ],
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(process.returncode, 2)
        self.assertEqual(process.stdout, "")
        self.assertEqual(process.stderr, "unbounded_session_axis\n")
        self.assertFalse(output_path.exists())

    def test_rejects_nonzero_input_privacy_counters(self):
        value = oracle()
        value["privacy"]["relative_paths_retained"] = 1

        with self.assertRaises(MODULE.RelationSplitBuildError) as raised:
            MODULE.build_manifest(value)

        self.assertEqual(raised.exception.code, "input_privacy_contract_failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
