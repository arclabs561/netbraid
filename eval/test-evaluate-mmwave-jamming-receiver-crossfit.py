#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///
"""Hermetic tests for the mmWave receiver cross-fit evaluator."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
MODULE_PATH = HERE / "evaluate-mmwave-jamming-receiver-crossfit.py"
SPEC = importlib.util.spec_from_file_location(
    "evaluate_mmwave_jamming_receiver_crossfit", MODULE_PATH
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("evaluator_import_failed")
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def opaque(*parts: object) -> str:
    return hashlib.sha256("\x00".join(map(str, parts)).encode()).hexdigest()


def known(identifier: str) -> dict[str, str]:
    return {"state": "known", "group_id": identifier}


def policy() -> dict[str, object]:
    return json.loads(
        (HERE / "fixtures/mmwave-jamming-receiver-crossfit-v0.json").read_text()
    )


def synthetic_corpus(
    *, pair_mean: bool = False
) -> tuple[dict[str, object], dict[str, object], np.ndarray]:
    observations = []
    rows = []
    matrix = np.empty((80, *MODULE.EXPECTED_GRID_SHAPE), dtype="<f4")
    row = 0
    for receiver in range(4):
        receiver_group = opaque("receiver", receiver)
        for pair_index in range(10):
            regime = pair_index // 5
            configuration_group = opaque("configuration", receiver, regime)
            pair_group = opaque("pair", receiver, pair_index)
            index = np.indices((16, 16, 8), dtype=np.float64)
            shape_pattern = 1.0 + 0.002 * index[0] + 0.003 * index[1] + 0.004 * index[2]
            for cause_index, cause in enumerate(MODULE.CAUSES):
                identifier = opaque("observation", receiver, pair_index, cause)
                amplitude = 1.0 + 0.02 * receiver + 0.001 * pair_index
                if cause_index and not pair_mean:
                    amplitude += 2.0
                real = amplitude * shape_pattern
                imaginary = 0.1 * real
                matrix[row, ..., 0] = real
                matrix[row, ..., 1] = imaginary
                observations.append(
                    {
                        "observation_id": identifier,
                        "controlled_jamming_cause": cause,
                        "receiver_group": known(receiver_group),
                        "radar_configuration_group": known(configuration_group),
                        "paired_cell_group": known(pair_group),
                    }
                )
                rows.append({"observation_id": identifier, "row": row})
                row += 1
    inventory_id = opaque("inventory")
    oracle = {
        "schema": MODULE.ORACLE_SCHEMA,
        "status": "pass",
        "inventory_id": inventory_id,
        "observations": observations,
    }
    adapter = {
        "schema": MODULE.ADAPTER_SCHEMA,
        "provenance": {
            "oracle_schema": MODULE.ORACLE_SCHEMA,
            "oracle_inventory_id": inventory_id,
        },
        "rows": rows,
    }
    return oracle, adapter, matrix


def full_adapter(adapter: dict[str, object], matrix_path: Path) -> dict[str, object]:
    payload = matrix_path.read_bytes()
    return {
        **adapter,
        "counts": {
            "observations": 80,
            "paired_cells": 40,
            "values_per_observation": 4096,
        },
        "grid_policy": {
            "components": ["real", "imaginary"],
            "dtype": "<f4",
            "grid_shape": [16, 16, 8, 2],
        },
        "matrix": {
            "bytes": len(payload),
            "dtype": "<f4",
            "format": "npy",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "shape": [80, 16, 16, 8, 2],
        },
        "privacy": {},
    }


class ReceiverCrossfitTests(unittest.TestCase):
    def test_features_are_phase_invariant(self) -> None:
        rng = np.random.default_rng(7)
        complex_grid = rng.normal(size=(16, 16, 8)) + 1j * rng.normal(size=(16, 16, 8))
        grid = np.stack((complex_grid.real, complex_grid.imag), axis=-1)
        rotated = complex_grid * np.exp(1j * 0.73)
        rotated_grid = np.stack((rotated.real, rotated.imag), axis=-1)

        np.testing.assert_allclose(
            MODULE.extract_features(grid),
            MODULE.extract_features(rotated_grid),
            rtol=1e-12,
            atol=1e-12,
        )

    def test_crossfit_scores_every_row_once_and_passes_clear_signal(self) -> None:
        oracle, adapter, matrix = synthetic_corpus()
        report = MODULE.evaluate(
            oracle, adapter, matrix, policy(), policy_sha256="0" * 64
        )

        self.assertEqual(report["status"], "inference_blocked")
        self.assertEqual(report["heldout_metrics"]["observations"], 80)
        self.assertEqual(report["paired_ranking"]["wins"], 40)
        self.assertEqual(report["paired_ranking"]["ties"], 0)
        self.assertTrue(report["paired_ranking"]["gate"]["mechanical_terms_passed"])
        self.assertFalse(report["paired_ranking"]["gate"]["passed"])
        self.assertGreaterEqual(
            report["paired_ranking"]["both_members_correct_pairs"], 39
        )
        self.assertGreater(report["heldout_metrics"]["balanced_accuracy"], 0.95)
        self.assertEqual(len(report["per_fold_metrics_without_group_identifiers"]), 4)

    def test_pair_mean_control_ties_and_fails_gate(self) -> None:
        oracle, adapter, matrix = synthetic_corpus(pair_mean=True)
        report = MODULE.evaluate(
            oracle, adapter, matrix, policy(), policy_sha256="0" * 64
        )

        self.assertEqual(report["status"], "inference_blocked")
        self.assertEqual(report["paired_ranking"]["ties"], 40)
        self.assertEqual(report["paired_ranking"]["non_tied_pairs"], 0)
        self.assertFalse(report["paired_ranking"]["gate"]["passed"])

    def test_oracle_and_adapter_order_do_not_change_report(self) -> None:
        oracle, adapter, matrix = synthetic_corpus()
        first = MODULE.evaluate(
            oracle, adapter, matrix, policy(), policy_sha256="0" * 64
        )
        oracle["observations"] = list(reversed(oracle["observations"]))
        adapter["rows"] = list(reversed(adapter["rows"]))
        second = MODULE.evaluate(
            oracle, adapter, matrix, policy(), policy_sha256="0" * 64
        )

        self.assertEqual(MODULE.render_report(first), MODULE.render_report(second))

    def test_pair_may_not_cross_receiver_groups(self) -> None:
        oracle, adapter, matrix = synthetic_corpus()
        oracle["observations"][1]["receiver_group"] = known(opaque("wrong"))

        with self.assertRaisesRegex(MODULE.CrossfitError, "group_contract_mismatch"):
            MODULE.bind_observations(oracle, adapter, matrix)

    def test_unknown_policy_field_is_rejected(self) -> None:
        value = policy()
        value["model"]["surprise"] = True

        with self.assertRaisesRegex(
            MODULE.CrossfitError, "policy_semantic_digest_mismatch"
        ):
            MODULE.validate_policy(value)

    def test_model_rejects_a_receiver_seen_during_fit(self) -> None:
        oracle, adapter, matrix = synthetic_corpus()
        observations = MODULE.bind_observations(oracle, adapter, matrix)
        receiver = observations[0].receiver_group
        train = tuple(item for item in observations if item.receiver_group != receiver)
        model = MODULE.fit_model(train)
        heldout = next(item for item in observations if item.receiver_group == receiver)
        MODULE.predict(heldout, model)

        leaked = next(item for item in observations if item.receiver_group != receiver)
        with self.assertRaisesRegex(
            MODULE.CrossfitError, "test_receiver_present_in_training"
        ):
            MODULE.predict(leaked, model)

    def test_output_may_not_alias_any_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = []
            for name in ("oracle.json", "adapter.json", "matrix.npy", "policy.json"):
                path = root / name
                path.write_bytes(b"input")
                inputs.append(path)

            for path in inputs:
                with self.assertRaisesRegex(
                    MODULE.CrossfitError, "output_aliases_input"
                ):
                    MODULE.validate_output_path(path, inputs)

            alias = root / "alias.json"
            alias.hardlink_to(inputs[0])
            with self.assertRaisesRegex(MODULE.CrossfitError, "output_aliases_input"):
                MODULE.validate_output_path(alias, inputs)

    def test_cli_rejects_output_alias_before_replacing_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "policy.json"
            original = b'{"sentinel":true}\n'
            policy_path.write_bytes(original)

            with redirect_stderr(io.StringIO()):
                result = MODULE.main(
                    [
                        "--oracle",
                        str(root / "missing-oracle.json"),
                        "--adapter",
                        str(root / "missing-adapter.json"),
                        "--matrix",
                        str(root / "missing-matrix.npy"),
                        "--policy",
                        str(policy_path),
                        "--output",
                        str(policy_path),
                    ]
                )

            self.assertEqual(result, 2)
            self.assertEqual(policy_path.read_bytes(), original)

    def test_oracle_inventory_id_must_be_opaque_sha256(self) -> None:
        oracle, adapter, matrix = synthetic_corpus()
        oracle["inventory_id"] = "/sensitive/source.mat"
        adapter["provenance"]["oracle_inventory_id"] = oracle["inventory_id"]
        with self.assertRaisesRegex(MODULE.CrossfitError, "oracle_schema_mismatch"):
            MODULE.bind_observations(oracle, adapter, matrix)

    def test_json_reader_rejects_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target.json"
            target.write_text("{}")
            link = root / "link.json"
            link.symlink_to(target)

            with self.assertRaisesRegex(MODULE.CrossfitError, "json_missing_or_unsafe"):
                MODULE.read_json(link)

    def test_matrix_digest_and_read_only_mmap_are_enforced(self) -> None:
        _oracle, adapter, matrix = synthetic_corpus()
        with tempfile.TemporaryDirectory() as directory:
            matrix_path = Path(directory) / "matrix.npy"
            np.save(matrix_path, matrix, allow_pickle=False)
            complete = full_adapter(adapter, matrix_path)
            opened = MODULE.open_matrix(matrix_path, complete)
            self.assertIsInstance(opened, np.memmap)
            self.assertFalse(opened.flags.writeable)

            complete["matrix"]["sha256"] = "f" * 64
            with self.assertRaisesRegex(MODULE.CrossfitError, "matrix_digest_mismatch"):
                MODULE.open_matrix(matrix_path, complete)

    def test_report_rejects_direct_bindings(self) -> None:
        with self.assertRaisesRegex(
            MODULE.CrossfitError, "report_contains_forbidden_binding"
        ):
            MODULE.render_report({"observation_id": opaque("private")})

    def test_one_sided_sign_probability_is_exact(self) -> None:
        self.assertEqual(MODULE._one_sided_sign_p(10, 0), 1 / 1024)
        self.assertEqual(MODULE._one_sided_sign_p(0, 10), 1.0)
        self.assertEqual(MODULE._one_sided_sign_p(0, 0), 1.0)


if __name__ == "__main__":
    unittest.main()
