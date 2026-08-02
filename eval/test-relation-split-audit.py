#!/usr/bin/env python3
"""Hermetic checks for the evaluation-only relation-split auditor."""

import copy
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "relation_split_audit", HERE / "relation_split_audit.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def opaque(seed):
    return f"{seed:016x}"


def group(state="known", seed=1):
    return {
        "state": state,
        "group_id": opaque(seed) if state == "known" else None,
    }


def observation(seed, **axis_groups):
    groups = {
        axis: group(seed=(index + 1) * 10_000 + seed)
        for index, axis in enumerate(MODULE.AXES)
    }
    groups.update(axis_groups)
    return {
        "observation_id": opaque(seed),
        **{f"{axis}_group": groups[axis] for axis in MODULE.AXES},
    }


def policy(forbidden_role_pairs=MODULE.ROLE_PAIRS):
    return {
        "forbidden_role_pairs": [list(role_pair) for role_pair in forbidden_role_pairs]
    }


def manifest(role_observations=None, **policies):
    if role_observations is None:
        role_observations = {
            role: [observation(index + 1)] for index, role in enumerate(MODULE.ROLES)
        }
    declared = {axis: policy() for axis in MODULE.AXES}
    declared.update({axis: policy(role_pairs) for axis, role_pairs in policies.items()})
    return {
        "schema": MODULE.MANIFEST_SCHEMA,
        "policies": declared,
        "partitions": [
            {
                "partition_id": opaque(7001 + index),
                "role": role,
                "observations": role_observations[role],
            }
            for index, role in enumerate(MODULE.ROLES)
        ],
    }


def axis_report(report, axis):
    return next(item for item in report["axes"] if item["axis"] == axis)


def pair_report(report, axis, role_pair):
    return next(
        item
        for item in axis_report(report, axis)["pair_intersections"]
        if tuple(item["roles"]) == role_pair
    )


def assert_error(test, value, code):
    with test.assertRaises(MODULE.RelationSplitError) as raised:
        MODULE.audit_manifest(value)
    test.assertEqual(raised.exception.code, code)


class RelationSplitAuditTests(unittest.TestCase):
    def test_contract_has_exact_roles_axes_and_six_role_pairs(self):
        self.assertEqual(
            MODULE.AXES,
            (
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
            ),
        )
        self.assertEqual(MODULE.ROLES, ("train", "calibration", "validation", "test"))
        self.assertEqual(len(MODULE.ROLE_PAIRS), 6)
        value = manifest()
        self.assertEqual(set(value["policies"]), set(MODULE.AXES))
        for axis in MODULE.AXES:
            self.assertIn("forbidden_role_pairs", value["policies"][axis])

    def test_source_policy_allows_train_calibration_but_holds_out_test(self):
        shared_source = group(seed=91)
        role_observations = {
            "train": [observation(1, physical_source=shared_source)],
            "calibration": [
                observation(2, physical_source=copy.deepcopy(shared_source))
            ],
            "validation": [observation(3)],
            "test": [observation(4)],
        }
        test_holdout_pairs = tuple(
            role_pair for role_pair in MODULE.ROLE_PAIRS if "test" in role_pair
        )
        clean = MODULE.audit_manifest(
            manifest(role_observations, physical_source=test_holdout_pairs)
        )

        self.assertEqual(clean["status"], "pass")
        allowed = pair_report(clean, "physical_source", ("train", "calibration"))
        self.assertFalse(allowed["forbidden"])
        self.assertEqual(allowed["status"], "allowed")
        self.assertEqual(allowed["known_group_intersection_count"], 1)
        self.assertEqual(
            pair_report(clean, "physical_source", ("train", "test"))["status"],
            "pass",
        )

        role_observations["test"] = [
            observation(4, physical_source=copy.deepcopy(shared_source))
        ]
        leaking = MODULE.audit_manifest(
            manifest(role_observations, physical_source=test_holdout_pairs)
        )
        self.assertEqual(leaking["status"], "fail")
        self.assertEqual(
            pair_report(leaking, "physical_source", ("train", "test"))["status"],
            "fail",
        )

    def test_all_six_pairwise_intersections_are_counted(self):
        shared = group(seed=91)
        report = MODULE.audit_manifest(
            manifest(
                {
                    "train": [observation(1, day=shared)],
                    "calibration": [observation(2)],
                    "validation": [observation(3, day=copy.deepcopy(shared))],
                    "test": [observation(4, day=copy.deepcopy(shared))],
                }
            )
        )
        pairs = axis_report(report, "day")["pair_intersections"]

        self.assertEqual(
            [tuple(item["roles"]) for item in pairs], list(MODULE.ROLE_PAIRS)
        )
        self.assertEqual(
            [item["known_group_intersection_count"] for item in pairs],
            [0, 1, 1, 0, 0, 1],
        )
        self.assertEqual(
            pair_report(report, "day", ("train", "validation"))[
                "known_observations_in_intersection"
            ],
            {"train": 1, "validation": 1},
        )

    def test_incomplete_forbidden_pair_coverage_is_unknown_and_cli_fails_closed(self):
        for incomplete_role in ("train", "test"):
            for incomplete_state in ("unknown", "not_observed"):
                with self.subTest(role=incomplete_role, state=incomplete_state):
                    role_observations = {
                        "train": [observation(1)],
                        "calibration": [observation(2)],
                        "validation": [observation(3)],
                        "test": [observation(4)],
                    }
                    role_observations[incomplete_role].append(
                        observation(10, physical_source=group(incomplete_state))
                    )
                    value = manifest(
                        role_observations,
                        physical_source=(("train", "test"),),
                    )
                    report = MODULE.audit_manifest(value)
                    source = axis_report(report, "physical_source")

                    self.assertEqual(report["status"], "unknown")
                    self.assertEqual(source["status"], "unknown")
                    self.assertEqual(
                        pair_report(report, "physical_source", ("train", "test"))[
                            "status"
                        ],
                        "unknown",
                    )
                    process = subprocess.run(
                        [sys.executable, str(HERE / "relation_split_audit.py")],
                        input=json.dumps(value),
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(process.returncode, 1, process.stderr)

    def test_every_axis_detects_its_forbidden_train_test_overlap(self):
        for index, axis in enumerate(MODULE.AXES):
            with self.subTest(axis=axis):
                shared = group(seed=900 + index)
                report = MODULE.audit_manifest(
                    manifest(
                        {
                            "train": [observation(1, **{axis: shared})],
                            "calibration": [observation(2)],
                            "validation": [observation(3)],
                            "test": [observation(4, **{axis: copy.deepcopy(shared)})],
                        }
                    )
                )
                self.assertEqual(report["status"], "fail")
                self.assertEqual(
                    [
                        item["axis"]
                        for item in report["axes"]
                        if item["status"] == "fail"
                    ],
                    [axis],
                )
                pair = pair_report(report, axis, ("train", "test"))
                self.assertEqual(pair["known_group_intersection_count"], 1)

    def test_event_and_session_require_all_six_forbidden_pairs(self):
        for axis in MODULE.MANDATORY_ALL_PAIR_AXES:
            with self.subTest(axis=axis):
                value = manifest(**{axis: MODULE.ROLE_PAIRS[:-1]})
                assert_error(self, value, "mandatory_axis_requires_all_role_pairs")

    def test_all_four_roles_are_nonempty(self):
        missing_role = manifest()
        missing_role["partitions"][-1]["role"] = "train"
        assert_error(self, missing_role, "missing_required_role")

        empty_role = manifest()
        empty_role["partitions"][-1]["observations"] = []
        assert_error(self, empty_role, "invalid_partition_observation_count")

    def test_duplicate_observations_fail_closed_across_partitions(self):
        duplicate = observation(1)
        value = manifest()
        value["partitions"][0]["observations"] = [duplicate]
        value["partitions"][1]["observations"] = [copy.deepcopy(duplicate)]
        assert_error(self, value, "duplicate_observation_id")

    def test_malformed_values_and_extra_sensitive_fields_fail_closed(self):
        cases = []

        extra_observation_field = manifest()
        extra_observation_field["partitions"][1]["observations"][0]["mac_address"] = (
            "00:11:22:33:44:55"
        )
        cases.append((extra_observation_field, "invalid_observation_schema"))

        extra_group_field = manifest()
        extra_group_field["partitions"][0]["observations"][0]["physical_source_group"][
            "raw_label"
        ] = "device-name"
        cases.append((extra_group_field, "invalid_group_schema"))

        nonopaque_group = manifest()
        nonopaque_group["partitions"][0]["observations"][0]["physical_source_group"] = {
            "state": "known",
            "group_id": "person@example.com",
        }
        cases.append((nonopaque_group, "invalid_group_id"))

        implicit_missing = manifest()
        implicit_missing["partitions"][0]["observations"][0][
            "physical_source_group"
        ] = {
            "state": "unknown",
            "group_id": opaque(99),
        }
        cases.append(
            (implicit_missing, "physical_source_group_id_requires_known_state")
        )

        extra_policy = manifest()
        extra_policy["policies"]["address"] = policy()
        cases.append((extra_policy, "invalid_policy_schema"))

        old_global_policy = manifest()
        old_global_policy["policies"]["day"] = "forbid_known_overlap"
        cases.append((old_global_policy, "invalid_axis_policy_schema"))

        duplicate_pair = manifest()
        duplicate_pair["policies"]["day"] = policy(
            (("train", "test"), ("test", "train"))
        )
        cases.append((duplicate_pair, "duplicate_forbidden_role_pair"))

        excessive_pair_list = manifest()
        excessive_pair_list["policies"]["day"] = policy((("train", "test"),) * 7)
        cases.append((excessive_pair_list, "invalid_forbidden_role_pairs"))

        invalid_role = manifest()
        invalid_role["partitions"][0]["role"] = "fit"
        cases.append((invalid_role, "invalid_partition_role"))

        for value, code in cases:
            with self.subTest(code=code):
                assert_error(self, value, code)

    def test_report_and_canonical_manifest_order_are_deterministic(self):
        shared_source = group(seed=91)
        value = manifest(
            {
                "train": [
                    observation(5, physical_source=shared_source),
                    observation(1),
                ],
                "calibration": [observation(2)],
                "validation": [observation(3)],
                "test": [observation(4, physical_source=copy.deepcopy(shared_source))],
            },
            physical_source=(),
        )
        permuted = copy.deepcopy(value)
        permuted["partitions"].reverse()
        for partition in permuted["partitions"]:
            partition["observations"].reverse()
        permuted["policies"]["event"]["forbidden_role_pairs"] = [
            list(reversed(role_pair)) for role_pair in reversed(MODULE.ROLE_PAIRS)
        ]

        self.assertEqual(MODULE.audit_manifest(value), MODULE.audit_manifest(permuted))
        canonical = MODULE.canonical_manifest(MODULE.parse_manifest(permuted))
        self.assertEqual(
            [item["partition_id"] for item in canonical["partitions"]],
            [opaque(7001), opaque(7002), opaque(7003), opaque(7004)],
        )
        self.assertEqual(
            [
                item["observation_id"]
                for item in canonical["partitions"][0]["observations"]
            ],
            [opaque(1), opaque(5)],
        )
        self.assertEqual(canonical["partitions"][0]["role"], "train")
        self.assertEqual(
            canonical["policies"]["event"]["forbidden_role_pairs"],
            [list(role_pair) for role_pair in MODULE.ROLE_PAIRS],
        )

    def test_opaque_identifiers_bounds_and_cli_json_boundary_are_enforced(self):
        too_many = manifest()
        too_many["partitions"][0]["observations"] = [
            observation(seed)
            for seed in range(1, MODULE.MAX_OBSERVATIONS_PER_PARTITION + 2)
        ]
        assert_error(self, too_many, "invalid_partition_observation_count")

        maximum_id = manifest()
        maximum_id["partitions"][0]["partition_id"] = "a" * MODULE.MAX_ID_BYTES
        MODULE.audit_manifest(maximum_id)

        for bad_id in ("A" * 16, "a" * (MODULE.MAX_ID_BYTES + 1), "private-name"):
            with self.subTest(bad_id=bad_id[:16]):
                invalid_id = manifest()
                invalid_id["partitions"][0]["partition_id"] = bad_id
                assert_error(self, invalid_id, "invalid_partition_id")

        malformed_payloads = (
            ("{", "invalid_json"),
            ('{"schema":"x","schema":"x"}', "duplicate_json_key"),
            ('{"schema":NaN}', "invalid_json_constant"),
        )
        for payload, code in malformed_payloads:
            process = subprocess.run(
                [sys.executable, str(HERE / "relation_split_audit.py")],
                input=payload,
                text=True,
                capture_output=True,
                check=False,
            )
            with self.subTest(code=code):
                self.assertEqual(process.returncode, 2)
                self.assertEqual(process.stdout, "")
                self.assertEqual(process.stderr, f"{code}\n")

        oversized = subprocess.run(
            [sys.executable, str(HERE / "relation_split_audit.py")],
            input=b" " * (MODULE.MAX_INPUT_BYTES + 1),
            capture_output=True,
            check=False,
        )
        self.assertEqual(oversized.returncode, 2)
        self.assertEqual(oversized.stdout, b"")
        self.assertEqual(oversized.stderr, b"manifest_too_large\n")

    def test_report_and_cli_never_disclose_group_values(self):
        private_marker = "deadbeefdeadbeefdeadbeefdeadbeef"
        shared_day = {"state": "known", "group_id": private_marker}
        value = manifest(
            {
                "train": [observation(1, day=shared_day)],
                "calibration": [observation(2)],
                "validation": [observation(3)],
                "test": [observation(4, day=copy.deepcopy(shared_day))],
            }
        )
        report = MODULE.audit_manifest(value)
        encoded_report = json.dumps(report, sort_keys=True)
        self.assertNotIn(private_marker, encoded_report)
        self.assertNotIn("group_id", encoded_report)
        self.assertEqual(
            pair_report(report, "day", ("train", "test"))[
                "known_group_intersection_count"
            ],
            1,
        )

        process = subprocess.run(
            [sys.executable, str(HERE / "relation_split_audit.py")],
            input=json.dumps(value),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(process.returncode, 1, process.stderr)
        cli_report = json.loads(process.stdout)
        self.assertEqual(
            cli_report["counts"],
            {"partitions": 4, "observations": 4, "roles": 4},
        )
        self.assertEqual(cli_report["interpretation"]["reported_values"], "raw_counts")
        encoded = process.stdout.lower()
        self.assertNotIn(private_marker, encoded)
        self.assertNotIn("group_id", encoded)
        self.assertNotIn("p_value", encoded)
        self.assertNotIn("confidence", encoded)
        self.assertNotIn("percent", encoded)
        self.assertEqual(process.stdout.count("\n"), 1)

    def test_cli_returns_zero_only_for_a_clean_audit(self):
        process = subprocess.run(
            [sys.executable, str(HERE / "relation_split_audit.py")],
            input=json.dumps(manifest()),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["status"], "pass")


if __name__ == "__main__":
    unittest.main(verbosity=2)
