#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.4.2", "scipy==1.17.1"]
# ///
"""Hermetic tests for the bounded OPERAnet semantic-alignment profiler."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np
from scipy.io import savemat

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "profile_operanet_semantic_alignment",
    HERE / "profile-operanet-semantic-alignment.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def semantic_rows(
    labels: tuple[str, ...],
    *,
    person: str = "participant-fixture",
    room: str = "room-fixture",
) -> list[tuple[str, str, str, str, str]]:
    timestamps = ("00:00:00.000", "00:00:00.100", "00:00:00.200")
    return [
        (MODULE.EXPERIMENT_TOKEN, timestamp, label, person, room)
        for timestamp, label in zip(timestamps, labels)
    ]


class OperanetSemanticAlignmentTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def protocol(self) -> object:
        return MODULE.load_protocol()

    def timelines(
        self,
        *,
        uwb2_labels: tuple[str, ...] = ("noactivity", "noactivity", "walk"),
    ) -> dict[str, object]:
        protocol = self.protocol()
        common = ("noactivity", "noactivity", "walk")
        labels = {
            "kinect": common,
            "pwr": common,
            "uwb1": common,
            "uwb2": uwb2_labels,
        }
        return {
            key: MODULE._build_timeline(
                key,
                semantic_rows(values),
                protocol,
                unreadable_reason="fixture_unreadable",
            )
            for key, values in labels.items()
        }

    def test_protocol_locks_development_scope_and_modalities(self) -> None:
        protocol = self.protocol()

        self.assertEqual(tuple(protocol.modalities), MODULE.MODALITY_KEYS)
        self.assertEqual(protocol.grid_step_us, 100_000)
        self.assertEqual(protocol.maximum_sample_age_us, 150_000)
        self.assertEqual(protocol.transition_exclusion_us, 50_000)
        self.assertEqual(
            protocol.labels,
            (
                "bodyrotate",
                "liedown",
                "noactivity",
                "sit",
                "stand",
                "standfromlie",
                "walk",
            ),
        )

    def test_protocol_rejects_unreviewed_scope_change(self) -> None:
        directory = self.temporary_directory()
        path = directory / "protocol.json"
        raw = json.loads(MODULE.PROTOCOL_PATH.read_text(encoding="utf-8"))
        raw["scope"]["experiment_number"] = 19
        path.write_text(json.dumps(raw), encoding="utf-8")

        with self.assertRaisesRegex(MODULE.SemanticProfileError, "scope_contract"):
            MODULE.load_protocol(path)

    def test_mat_reader_uses_publisher_headers_and_required_semantics(self) -> None:
        modality = self.protocol().modalities["kinect"]
        rows = semantic_rows(("noactivity", "noactivity", "walk"))
        values = np.empty((len(rows) + 1, len(modality.headers)), dtype=object)
        values[0, :] = modality.headers
        for row_index, row in enumerate(rows, start=1):
            values[row_index, :5] = row
            values[row_index, 5:] = ("marker-a", "marker-b")
        payload = io.BytesIO()
        savemat(payload, {modality.variable: values}, do_compression=False)

        parsed = list(MODULE._mat_rows(payload.getvalue(), modality))

        self.assertEqual(parsed, rows)

    def test_csv_reader_rejects_header_drift(self) -> None:
        modality = MODULE.ModalityProtocol(
            key="fixture",
            archive_key="fixture",
            member="fixture.csv",
            data_format="streamed_csv",
            headers=("timestamp", "activity", "exp_no", "person_id", "room_no"),
            variable=None,
        )
        source = io.BytesIO(
            b"timestamp,activity,exp_no,person_id,wrong\n"
            b"00:00:00.000,noactivity,exp_018,p1,r1\n"
        )

        with self.assertRaisesRegex(
            MODULE.SemanticProfileError, "unexpected_csv_schema"
        ):
            list(MODULE._csv_rows(source, modality))

    def test_establishes_exp018_joinability_from_measured_rows(self) -> None:
        report = MODULE._profile_report(self.timelines(), self.protocol())

        grid = report["alignment"]["fixed_grid_all_modality_activity"]
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["result"]["joinability"], "established_for_exp018")
        self.assertEqual(grid["candidate_points"], 3)
        self.assertEqual(grid["transition_boundary_excluded_points"], 1)
        self.assertEqual(grid["assessed_points"], 2)
        self.assertEqual(grid["agreement_points"], 2)
        self.assertEqual(grid["disagreement_points"], 0)
        self.assertFalse(report["publisher"]["statement_used_as_alignment_result"])

    def test_blocks_joinability_when_one_modality_disagrees(self) -> None:
        report = MODULE._profile_report(
            self.timelines(uwb2_labels=("sit", "sit", "sit")), self.protocol()
        )

        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["result"]["joinability"], "not_established")
        self.assertIn("fixed_grid_activity_disagreement", report["result"]["blockers"])
        self.assertGreater(
            report["alignment"]["fixed_grid_all_modality_activity"][
                "disagreement_points"
            ],
            0,
        )

    def test_report_retains_aggregates_without_identifiers_or_timestamps(self) -> None:
        protocol = self.protocol()
        secret_person = "private-participant-value"
        secret_room = "private-room-value"
        timelines = {
            key: MODULE._build_timeline(
                key,
                semantic_rows(
                    ("noactivity", "noactivity", "walk"),
                    person=secret_person,
                    room=secret_room,
                ),
                protocol,
                unreadable_reason="fixture_unreadable",
            )
            for key in MODULE.MODALITY_KEYS
        }

        rendered = MODULE.render_report(MODULE._profile_report(timelines, protocol))

        self.assertNotIn(secret_person.encode(), rendered)
        self.assertNotIn(secret_room.encode(), rendered)
        self.assertNotIn(b"00:00:00.100", rendered)
        report = json.loads(rendered)
        self.assertEqual(report["privacy"]["participant_identifier_values_retained"], 0)
        self.assertEqual(report["privacy"]["raw_timestamp_values_retained"], 0)
        self.assertEqual(report["modalities"]["uwb1"]["person"]["cardinality"], 1)

    def test_archive_profile_attributes_reader_failure_to_modality(self) -> None:
        directory = self.temporary_directory()
        protocol = self.protocol()
        timelines = self.timelines()

        def read_timeline(
            _path: Path,
            contract: object,
            _protocol: object,
            *,
            verify_receipt: bool,
        ) -> tuple[object, int]:
            self.assertTrue(verify_receipt)
            key = contract.modality.key
            if key == "uwb1":
                raise MODULE.SemanticProfileError("nonmonotonic_timestamp")
            return timelines[key], 1

        with mock.patch.object(MODULE, "_read_timeline", side_effect=read_timeline):
            with self.assertRaisesRegex(
                MODULE.SemanticProfileError, "uwb1_nonmonotonic_timestamp"
            ):
                MODULE.profile_archives(directory, protocol)


if __name__ == "__main__":
    unittest.main(verbosity=2)
