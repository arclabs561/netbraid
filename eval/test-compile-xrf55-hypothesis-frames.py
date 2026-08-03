#!/usr/bin/env python3
"""Hermetic tests for bounded XRF55 hypothesis-frame compilation."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "compile_xrf55_hypothesis_frames",
    HERE / "compile-xrf55-hypothesis-frames.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def observations():
    return {
        (1, 1, 1, 1),
        (1, 1, 2, 1),
        (1, 2, 1, 1),
    }


class Xrf55FrameCompilerTests(unittest.TestCase):
    def test_compiles_cross_modal_and_performer_controls(self):
        manifest = MODULE.compile_frames(observations())
        parsed = MODULE.FRAME.parse_manifest(manifest)
        by_kind = {}
        for frame in parsed:
            kind = frame.frame_id.split(".")[1]
            by_kind.setdefault(kind, []).append(frame)

        self.assertEqual(len(by_kind["same-event"]), 9)
        self.assertEqual(len(by_kind["same-performer"]), 1)
        self.assertEqual(len(by_kind["different-performer"]), 1)
        cross_modal = by_kind["same-event"][0]
        self.assertEqual(cross_modal.event_relation, "same")
        self.assertEqual(cross_modal.event_performer_relation, "same")
        self.assertEqual(cross_modal.physical_device_relation, "different")
        self.assertEqual(cross_modal.physical_source_relation, "different")
        self.assertEqual(
            by_kind["different-performer"][0].event_performer_relation,
            "different",
        )

    def test_input_order_does_not_change_manifest(self):
        values = list(observations())
        self.assertEqual(
            MODULE.compile_frames(values), MODULE.compile_frames(reversed(values))
        )

    def test_same_event_sampling_is_bounded(self):
        values = {(1, 1, action, 1) for action in range(1, 601)}
        manifest = MODULE.compile_frames(values)
        same_event = [
            frame
            for frame in manifest["frames"]
            if frame["frame_id"].startswith("xrf55.same-event.")
        ]
        self.assertEqual(len(same_event), MODULE.MAX_SAME_EVENTS * 3)
        self.assertLessEqual(len(manifest["frames"]), MODULE.FRAME.MAX_FRAMES)

    def test_invalid_or_insufficient_observations_fail_closed(self):
        with self.assertRaisesRegex(
            MODULE.Xrf55FrameCompileError, "insufficient_observations"
        ):
            MODULE.compile_frames({(1, 1, 1, 1)})
        with self.assertRaisesRegex(
            MODULE.Xrf55FrameCompileError, "invalid_observation_key"
        ):
            MODULE.compile_frames({(1, 1, 1, 1), (1, 1, 0, 2)})

    def test_main_writes_only_opaque_frame_documents(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "derived" / "frames.json"
            with (
                mock.patch.object(
                    MODULE, "load_observations", return_value=observations()
                ),
                mock.patch("builtins.print"),
            ):
                first = MODULE.main(["--manifest", str(target)])
                first_bytes = target.read_bytes()
                second = MODULE.main(["--manifest", str(target)])
            self.assertEqual((first, second), (0, 0))
            self.assertEqual(first_bytes, target.read_bytes())
            document = json.loads(first_bytes)
            self.assertEqual(set(document), {"frames", "schema"})
            self.assertNotIn(str(base), first_bytes.decode("utf-8"))
            self.assertTrue(
                all(
                    set(frame) == set(MODULE.FRAME.FRAME_FIELDS)
                    for frame in document["frames"]
                )
            )

    def test_main_reports_profile_boundary_failure(self):
        with (
            mock.patch.object(
                MODULE,
                "load_observations",
                side_effect=MODULE.PROFILE.Xrf55ProfileError("archive_unavailable"),
            ),
            mock.patch("builtins.print") as output,
        ):
            result = MODULE.main([])
        self.assertEqual(result, 2)
        output.assert_called_once_with("archive_unavailable", file=sys.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
