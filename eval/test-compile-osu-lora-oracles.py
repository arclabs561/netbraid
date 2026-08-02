#!/usr/bin/env python3
"""Hermetic tests for the OSU LoRa observation-oracle compiler."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "compile_osu_lora_oracles", HERE / "compile-osu-lora-oracles.py"
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

OPAQUE_ID = re.compile(r"[a-f0-9]{16,64}\Z")
PRIVATE_VALUES = (
    "PRIVATE_AUTHOR",
    "PRIVATE_DESCRIPTION",
    "PRIVATE_DATE_A",
    "PRIVATE_DATE_B",
    "PRIVATE_FREQUENCY_A",
    "PRIVATE_FREQUENCY_B",
    "PRIVATE_RECEIVER",
    "PRIVATE_SOURCE_A",
    "PRIVATE_SOURCE_B",
    "PRIVATE_VARIANT_A",
    "PRIVATE_VARIANT_B",
    "PRIVATE_ANTENNA",
)


def antenna() -> dict[str, object]:
    return {
        "gain": 1,
        "model": PRIVATE_VALUES[11],
        "type": "omnidirectional",
    }


def annotation(
    transmission: int, sample_start: int, source: str, variant: str
) -> dict[str, object]:
    return {
        "core:sample_count": 1,
        "core:sample_start": sample_start,
        "wines:reciever": {
            "antenna": antenna(),
            "model": PRIVATE_VALUES[6],
        },
        "wines:transmitter": {
            "ID": {
                "Transmission ID": transmission,
                "Transmitter ID": source,
            },
            "antenna": antenna(),
            "model": variant,
        },
    }


def metadata_document(
    stem: str,
    *,
    transmission: int,
    transmitters=None,
    frequencies=None,
) -> dict[str, object]:
    if transmitters is None:
        transmitters = [(PRIVATE_VALUES[7], PRIVATE_VALUES[9])]
    if frequencies is None:
        frequencies = [PRIVATE_VALUES[4]]
    captures = [
        {
            "core:date": PRIVATE_VALUES[2 + (index % 2)],
            "core:sample_start": index,
            "frequency": frequency,
        }
        for index, frequency in enumerate(frequencies)
    ]
    annotations = [
        annotation(transmission, index, source, variant)
        for index, (source, variant) in enumerate(transmitters)
    ]
    return {
        "version": "1.0.0",
        "schema": {"global": {}, "captures": {}, "annotations": {}},
        "_metadata": {
            "global": {
                "core:author": PRIVATE_VALUES[0],
                "core:datatype": "cf32",
                "core:description": PRIVATE_VALUES[1],
                "core:sample_rate": "1 MS/s",
            },
            "captures": captures,
            "annotations": annotations,
        },
        "data_file": stem + ".dat",
    }


class OsuLoraOracleCompilerTests(unittest.TestCase):
    def temporary_directory(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def root(self) -> Path:
        root = self.temporary_directory() / "root"
        root.mkdir()
        return root

    def add_representation(
        self,
        root: Path,
        relative_stem: str,
        *,
        source: str = PRIVATE_VALUES[7],
        variant: str = PRIVATE_VALUES[9],
        transmission: int = 1,
        transmitters=None,
        frequencies=None,
    ) -> tuple[Path, Path]:
        stem_path = root / relative_stem
        stem_path.parent.mkdir(parents=True, exist_ok=True)
        document = metadata_document(
            stem_path.name,
            transmission=transmission,
            transmitters=(
                transmitters if transmitters is not None else [(source, variant)]
            ),
            frequencies=frequencies,
        )
        metadata_path = stem_path.with_name(stem_path.name + ".sigmf-meta")
        metadata_path.write_text(json.dumps(document), encoding="utf-8")
        data_path = stem_path.with_name(stem_path.name + ".dat")
        data_path.write_bytes(b"\0" * (8 * len(document["_metadata"]["annotations"])))
        return metadata_path, data_path

    def assert_all_identifiers_are_opaque(self, manifest) -> None:
        for observation in manifest["observations"]:
            self.assertRegex(observation["observation_id"], OPAQUE_ID)
            for axis in MODULE.AXES:
                group = observation[axis + "_group"]
                if group["state"] == "known":
                    self.assertRegex(group["group_id"], OPAQUE_ID)
                else:
                    self.assertIsNone(group["group_id"])

    def test_output_is_opaque_local_inventory_with_privacy_counters(self):
        root = self.root()
        self.add_representation(root, "distances/5m/IQ_1")
        self.add_representation(root, "distances/5m/fft_1")

        manifest = MODULE.compile_inventory(root)
        rendered = MODULE.render_manifest(manifest)

        self.assertEqual(manifest["counts"]["observations"], 2)
        self.assertEqual(manifest["counts"]["events"], 1)
        self.assertEqual(manifest["counts"]["metadata_data_pairs"], 2)
        self.assertEqual(
            manifest["provenance"]["publisher_release_revision"],
            MODULE.PROVENANCE_REVISION,
        )
        self.assertTrue(manifest["manifest"]["local_ignored_manifest"])
        self.assertFalse(manifest["manifest"]["train_test_splits_assigned"])
        self.assertEqual(manifest["manifest"]["partitions_assigned"], 0)
        self.assertTrue(all(value == 0 for value in manifest["privacy"].values()))
        self.assert_all_identifiers_are_opaque(manifest)

        text = rendered.decode("utf-8")
        for value in PRIVATE_VALUES:
            self.assertNotIn(value, text)
        self.assertNotIn(str(root), text)
        self.assertNotIn(".sigmf-meta", text)
        self.assertNotIn("https://", text)

    def test_groups_representations_but_separates_sources_and_devices(self):
        root = self.root()
        for device, source in ((1, PRIVATE_VALUES[7]), (2, PRIVATE_VALUES[8])):
            for representation in ("IQ", "fft"):
                self.add_representation(
                    root,
                    "configurations/Config1/{}_{}".format(representation, device),
                    source=source,
                    variant=PRIVATE_VALUES[9],
                    transmission=device,
                )

        manifest = MODULE.compile_inventory(root)
        observations = manifest["observations"]
        by_event = defaultdict(list)
        for observation in observations:
            by_event[observation["event_group"]["group_id"]].append(observation)

        self.assertEqual(sorted(len(items) for items in by_event.values()), [2, 2])
        self.assertEqual(manifest["counts"]["corresponding_iq_fft_events"], 2)
        self.assertEqual(
            len({item["physical_device_group"]["group_id"] for item in observations}),
            2,
        )
        self.assertEqual(
            len({item["physical_source_group"]["group_id"] for item in observations}),
            2,
        )
        self.assertEqual(
            len({item["variant_group"]["group_id"] for item in observations}), 1
        )
        for items in by_event.values():
            self.assertEqual(
                len({item["physical_source_group"]["group_id"] for item in items}),
                1,
            )

    def test_marks_unestablished_axes_unknown_or_not_observed(self):
        root = self.root()
        self.add_representation(
            root,
            "locations/Location1/IQ_1",
            transmitters=[
                (PRIVATE_VALUES[7], PRIVATE_VALUES[9]),
                (PRIVATE_VALUES[8], PRIVATE_VALUES[10]),
            ],
            frequencies=[PRIVATE_VALUES[4], PRIVATE_VALUES[5]],
        )

        observation = MODULE.compile_inventory(root)["observations"][0]

        self.assertEqual(observation["physical_source_group"]["state"], "unknown")
        self.assertEqual(observation["variant_group"]["state"], "unknown")
        self.assertEqual(observation["channel_group"]["state"], "unknown")
        self.assertEqual(observation["session_group"]["state"], "not_observed")
        self.assertEqual(observation["day_group"]["state"], "not_observed")
        self.assertEqual(observation["configuration_group"]["state"], "not_observed")
        self.assertEqual(observation["location_group"]["state"], "known")

    def test_source_and_device_identity_are_fenced_between_setup_families(self):
        root = self.root()
        self.add_representation(root, "distances/5m/IQ_1")
        self.add_representation(root, "locations/Location1/IQ_1")

        observations = MODULE.compile_inventory(root)["observations"]

        self.assertEqual(len(observations), 2)
        self.assertEqual(
            len({item["physical_device_group"]["group_id"] for item in observations}),
            2,
        )
        self.assertEqual(
            len({item["physical_source_group"]["group_id"] for item in observations}),
            2,
        )
        self.assertEqual(
            len({item["variant_group"]["group_id"] for item in observations}),
            1,
        )

    def test_traversal_order_and_root_location_do_not_change_output(self):
        roots = [self.root(), self.root()]
        specifications = [
            ("configurations/Config2/IQ_2", PRIVATE_VALUES[8], 2),
            ("configurations/Config1/fft_1", PRIVATE_VALUES[7], 1),
            ("configurations/Config1/IQ_1", PRIVATE_VALUES[7], 1),
            ("configurations/Config2/fft_2", PRIVATE_VALUES[8], 2),
        ]
        for root, ordered in zip(
            roots, (specifications, list(reversed(specifications)))
        ):
            for relative, source, transmission in ordered:
                self.add_representation(
                    root,
                    relative,
                    source=source,
                    transmission=transmission,
                )

        first = MODULE.render_manifest(MODULE.compile_inventory(roots[0]))
        second = MODULE.render_manifest(MODULE.compile_inventory(roots[1]))

        self.assertEqual(first, second)

    def test_rejects_malformed_publisher_paths(self):
        root = self.root()
        self.add_representation(root, "configurations/Config5/IQ_1")

        with self.assertRaisesRegex(
            MODULE.OracleCompileError, "unsupported_observation_path"
        ):
            MODULE.compile_inventory(root)

    def test_never_opens_iq_or_fft_payloads(self):
        root = self.root()
        self.add_representation(root, "distances/10m/IQ_1")
        self.add_representation(root, "distances/10m/fft_1")
        real_open = MODULE.PROFILE.os.open
        opened = []

        def guarded_open(path, flags, *args, **kwargs):
            opened.append(os.fspath(path))
            if os.fspath(path).endswith(".dat"):
                raise AssertionError("payload was opened")
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(MODULE.PROFILE.os, "open", side_effect=guarded_open):
            manifest = MODULE.compile_inventory(root)

        self.assertEqual(manifest["privacy"]["iq_payload_bytes_read"], 0)
        self.assertEqual(manifest["privacy"]["fft_payload_bytes_read"], 0)
        self.assertFalse(any(path.endswith(".dat") for path in opened))

    def test_partial_tree_is_rejected_by_profiler_gate(self):
        root = self.root()
        _metadata_path, data_path = self.add_representation(root, "distances/15m/IQ_1")
        data_path.unlink()

        with self.assertRaisesRegex(
            MODULE.OracleCompileError, "profiler_rejected_tree"
        ):
            MODULE.compile_inventory(root)

    def test_identity_fence_rejects_metadata_mutation(self):
        root = self.root()
        metadata_path, _data_path = self.add_representation(root, "distances/20m/IQ_1")
        real_read = MODULE.PROFILE._read_metadata

        def mutating_read(record):
            document = real_read(record)
            metadata_path.write_text(
                metadata_path.read_text(encoding="utf-8") + " ", encoding="utf-8"
            )
            return document

        with mock.patch.object(
            MODULE.PROFILE, "_read_metadata", side_effect=mutating_read
        ):
            with self.assertRaisesRegex(
                MODULE.PROFILE.ProfileError, "tree_file_changed_during_profile"
            ):
                MODULE.compile_inventory(root)

    def test_conflicting_representation_metadata_is_not_grouped(self):
        root = self.root()
        self.add_representation(root, "distances/5m/IQ_1", source=PRIVATE_VALUES[7])
        self.add_representation(root, "distances/5m/fft_1", source=PRIVATE_VALUES[8])

        with self.assertRaisesRegex(
            MODULE.OracleCompileError, "representation_metadata_mismatch"
        ):
            MODULE.compile_inventory(root)

    def test_writes_manifest_atomically_with_private_mode(self):
        root = self.root()
        self.add_representation(root, "locations/Location2/IQ_2")
        rendered = MODULE.render_manifest(MODULE.compile_inventory(root))
        output = self.temporary_directory() / "derived" / "manifest.json"

        MODULE.write_manifest(output, rendered)

        self.assertEqual(output.read_bytes(), rendered)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(list(output.parent.glob("." + output.name + ".*")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
