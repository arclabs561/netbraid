#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11,<3.12"
# dependencies = ["numpy==2.0.2"]
# ///

"""Hermetic tests for the private XRF55 joint role-cache compiler."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import numpy as np

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "compile_xrf55_joint_role_cache",
    HERE / "compile-xrf55-joint-role-cache.py",
)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

FEATURES = MODULE.FEATURES
JOINT = MODULE.JOINT
TEST_LAYOUTS = {
    "wifi": FEATURES.ArrayLayout("<f8", False, (8, 16)),
    "rfid": FEATURES.ArrayLayout("<f8", False, (8, 16)),
    "mmwave": FEATURES.ArrayLayout("<f4", True, (1, 8, 4, 4)),
}
SOURCE_BINDING = MODULE.SourceBinding(
    archive_count=1,
    archive_profile_set_sha256="a" * 64,
    archive_receipt_set_sha256="b" * 64,
)


def _contract(subject_groups=20):
    return {
        "subject_groups": subject_groups,
        "scenes": frozenset({1}),
        "actions": frozenset({1}),
        "repetitions": frozenset(FEATURES.PUBLISHER_REPETITIONS),
    }


def _array(modality, subject, repetition):
    layout = TEST_LAYOUTS[modality]
    values = np.arange(np.prod(layout.shape), dtype=np.float64).reshape(layout.shape)
    values += subject * 1000 + repetition * 10 + FEATURES.MODALITIES.index(modality)
    array = values.astype(layout.dtype)
    if layout.fortran_order:
        array = np.asfortranarray(array)
    return array


def _write_archive(path):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for subject in range(1, JOINT.RANKED_GROUP_COUNT + 1):
            for repetition in FEATURES.PUBLISHER_REPETITIONS:
                stem = f"{subject:02d}_01_{repetition:02d}.npy"
                for modality, directory in (
                    ("wifi", "WiFi"),
                    ("rfid", "RFID"),
                    ("mmwave", "mmWave"),
                ):
                    with tempfile.SpooledTemporaryFile() as output:
                        np.save(
                            output,
                            _array(modality, subject, repetition),
                            allow_pickle=False,
                        )
                        output.seek(0)
                        archive.writestr(f"Scene1/{directory}/{stem}", output.read())


def _source(path):
    contract = _contract()
    inspection = MODULE.BASE.PROFILE.profile_archive(
        path, path.stat().st_size, contract
    )
    return MODULE.BASE.ArchiveSource(path, path.stat().st_size, contract, inspection)


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_paths(root):
    outputs = {role: MODULE.role_output_set(root, role) for role in MODULE.ROLE_ORDER}
    return tuple(
        path
        for role in MODULE.ROLE_ORDER
        for path in (
            outputs[role].adapter,
            *(outputs[role].matrices[modality] for modality in FEATURES.MODALITIES),
        )
    )


def _publication_paths(root):
    return (*_canonical_paths(root), root / MODULE.MANIFEST_FILENAME)


def _snapshot(root):
    return {path.name: path.read_bytes() for path in _publication_paths(root)}


def _transaction_residue(root):
    return {
        path.name
        for path in root.iterdir()
        if path.name.startswith(MODULE.JOURNAL_FILENAME)
        or "xrf55-backup" in path.name
        or "xrf55-restore" in path.name
    }


def _write_private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    path.chmod(0o600)


def _seed_publication(root, label):
    root.mkdir(parents=True, exist_ok=True)
    for path in _publication_paths(root):
        _write_private(path, f"{label}:{path.name}".encode())


def _publication_fixture(root, staging, label):
    outputs = {role: MODULE.role_output_set(root, role) for role in MODULE.ROLE_ORDER}
    matrix_temporaries = {role: {} for role in MODULE.ROLE_ORDER}
    adapter_temporaries = {}
    for role in MODULE.ROLE_ORDER:
        for modality in FEATURES.MODALITIES:
            temporary = staging / f"{label}-{role}-{modality}.npy"
            _write_private(temporary, f"{label}:{role}:{modality}".encode())
            matrix_temporaries[role][modality] = temporary
        temporary = staging / f"{label}-{role}-adapter.json"
        _write_private(temporary, f"{label}:{role}:adapter".encode())
        adapter_temporaries[role] = temporary
    role_publications = MODULE._role_publications(
        root, matrix_temporaries, adapter_temporaries
    )
    manifest = MODULE._generation_manifest(role_publications, SOURCE_BINDING)
    manifest_temporary = staging / f"{label}-manifest.json"
    _write_private(
        manifest_temporary,
        json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n",
    )
    return outputs, matrix_temporaries, adapter_temporaries, manifest_temporary


class Xrf55JointRoleCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        cls.archive = Path(cls.fixture.name) / "processed.zip"
        _write_archive(cls.archive)
        cls.source = _source(cls.archive)
        cls.events = JOINT.select_role_events(cls.source.inspection.observations)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def test_default_contract_has_exact_schema_directory_roles_and_filenames(self):
        self.assertEqual(MODULE.SCHEMA, "netbraid.xrf55_joint_role_cache.v0")
        self.assertEqual(
            MODULE.DEFAULT_OUTPUT_DIR,
            MODULE.ROOT / "data" / "derived" / "eval" / "xrf55-joint-representation-v0",
        )
        self.assertEqual(MODULE.ROLE_ORDER, ("train", "calibration", "validation"))
        self.assertEqual(
            {
                MODULE.OUTPUT_FILENAMES[role][kind]
                for role in MODULE.ROLE_ORDER
                for kind in ("adapter", *FEATURES.MODALITIES)
            },
            {
                "xrf55-joint-train-adapter.json",
                "xrf55-joint-train-wifi.npy",
                "xrf55-joint-train-rfid.npy",
                "xrf55-joint-train-mmwave.npy",
                "xrf55-joint-calibration-adapter.json",
                "xrf55-joint-calibration-wifi.npy",
                "xrf55-joint-calibration-rfid.npy",
                "xrf55-joint-calibration-mmwave.npy",
                "xrf55-joint-validation-adapter.json",
                "xrf55-joint-validation-wifi.npy",
                "xrf55-joint-validation-rfid.npy",
                "xrf55-joint-validation-mmwave.npy",
            },
        )
        self.assertEqual(
            MODULE.MANIFEST_FILENAME, "xrf55-joint-generation-manifest.json"
        )

    def test_streams_only_selected_members_and_writes_deterministic_bound_caches(self):
        selected = {
            event.observation
            for role_events in self.events.values()
            for event in role_events
        }
        quarantined = set(self.source.inspection.observations) - selected
        opened = []
        original_open = zipfile.ZipFile.open

        def guarded_open(archive, member, *args, **kwargs):
            subject, action, repetition = (
                int(value) for value in Path(member.filename).stem.split("_")
            )
            observation = (1, subject, action, repetition)
            if observation in quarantined:
                self.fail("quarantined member payload was opened")
            opened.append(observation)
            return original_open(archive, member, *args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first_root = root / "first"
            second_root = root / "second"
            with mock.patch.object(zipfile.ZipFile, "open", guarded_open):
                first = MODULE.compile_joint_role_cache(
                    (self.source,),
                    first_root,
                    SOURCE_BINDING,
                    layouts=TEST_LAYOUTS,
                )
            second = MODULE.compile_joint_role_cache(
                (self.source,),
                second_root,
                SOURCE_BINDING,
                layouts=TEST_LAYOUTS,
            )

            self.assertEqual(
                len(opened),
                sum(JOINT.ROLE_EVENT_COUNTS.values()) * len(FEATURES.MODALITIES),
            )
            self.assertTrue(set(opened).isdisjoint(quarantined))
            self.assertEqual(first, second)

            expected_names = {
                MODULE.OUTPUT_FILENAMES[role][kind]
                for role in MODULE.ROLE_ORDER
                for kind in ("adapter", *FEATURES.MODALITIES)
            }
            expected_names.add(MODULE.MANIFEST_FILENAME)
            self.assertEqual(
                {path.name for path in first_root.iterdir()}, expected_names
            )
            self.assertEqual(
                {path.name for path in second_root.iterdir()}, expected_names
            )

            groups_by_role = {}
            for role in MODULE.ROLE_ORDER:
                first_outputs = MODULE.role_output_set(first_root, role)
                second_outputs = MODULE.role_output_set(second_root, role)
                self.assertEqual(
                    first_outputs.adapter.read_bytes(),
                    second_outputs.adapter.read_bytes(),
                )
                adapter = json.loads(first_outputs.adapter.read_bytes())
                self.assertEqual(adapter["schema"], MODULE.SCHEMA)
                self.assertEqual(
                    set(adapter),
                    {
                        "counts",
                        "events",
                        "feature_policy",
                        "integrity",
                        "privacy",
                        "provenance",
                        "role_policy",
                        "schema",
                    },
                )
                self.assertEqual(adapter["role_policy"]["role"], role)
                self.assertEqual(
                    adapter["counts"]["events"], JOINT.ROLE_EVENT_COUNTS[role]
                )
                first_rank, last_rank = JOINT.ROLE_GROUP_RANKS[role]
                self.assertEqual(
                    adapter["counts"]["groups"], last_rank - first_rank + 1
                )
                self.assertEqual(adapter["counts"]["roles"], 1)
                self.assertEqual(
                    [event["row"] for event in adapter["events"]],
                    list(range(JOINT.ROLE_EVENT_COUNTS[role])),
                )
                self.assertTrue(
                    all(
                        set(event) == {"event_id", "group_id", "role", "row"}
                        for event in adapter["events"]
                    )
                )
                groups_by_role[role] = {
                    event["group_id"] for event in adapter["events"]
                }
                self.assertTrue(
                    all(value == 0 for value in adapter["privacy"].values())
                )
                self.assertEqual(
                    adapter["integrity"]["feature_policy_sha256"],
                    MODULE._content_digest(
                        "netbraid.xrf55-joint.feature-policy.v0",
                        adapter["feature_policy"],
                    ),
                )
                self.assertEqual(
                    adapter["integrity"]["role_policy_sha256"],
                    MODULE._content_digest(
                        "netbraid.xrf55-joint.role-policy.v0",
                        JOINT.role_policy_document(),
                    ),
                )
                self.assertEqual(
                    adapter["integrity"]["source"],
                    {
                        "archive_profile_set_sha256": "a" * 64,
                        "archive_receipt_set_sha256": "b" * 64,
                    },
                )

                for modality in FEATURES.MODALITIES:
                    first_path = first_outputs.matrices[modality]
                    second_path = second_outputs.matrices[modality]
                    self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
                    artifact = adapter["integrity"]["artifacts"][modality]
                    self.assertEqual(artifact["sha256"], _sha256(first_path))
                    self.assertEqual(artifact["bytes"], first_path.stat().st_size)
                    self.assertEqual(
                        artifact["shape"],
                        [JOINT.ROLE_EVENT_COUNTS[role], JOINT.FEATURE_COUNT],
                    )
                    self.assertEqual(artifact["dtype"], "<f8")
                    matrix = np.load(first_path, mmap_mode="r", allow_pickle=False)
                    self.assertIsInstance(matrix, np.memmap)
                    self.assertFalse(matrix.flags.writeable)
                    self.assertEqual(
                        matrix.shape,
                        (JOINT.ROLE_EVENT_COUNTS[role], JOINT.FEATURE_COUNT),
                    )
                    self.assertEqual(matrix.dtype.str, "<f8")

            for index, role in enumerate(MODULE.ROLE_ORDER):
                for other in MODULE.ROLE_ORDER[index + 1 :]:
                    self.assertTrue(
                        groups_by_role[role].isdisjoint(groups_by_role[other])
                    )

            encoded = json.dumps(first, sort_keys=True)
            for forbidden in (
                str(root),
                self.archive.name,
                "Scene1/",
                "01_01_01.npy",
                "locked_test",
            ):
                self.assertNotIn(forbidden, encoded)
            for path in _publication_paths(first_root):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

            manifest = json.loads((first_root / MODULE.MANIFEST_FILENAME).read_bytes())
            self.assertEqual(manifest["schema"], MODULE.MANIFEST_SCHEMA)
            self.assertEqual(
                set(manifest["outputs"]),
                {path.name for path in _canonical_paths(first_root)},
            )
            for path in _canonical_paths(first_root):
                self.assertEqual(
                    manifest["outputs"][path.name],
                    {"bytes": path.stat().st_size, "sha256": _sha256(path)},
                )
            self.assertEqual(
                manifest["binding"]["source"],
                {
                    "archive_count": 1,
                    "archive_profile_set_sha256": "a" * 64,
                    "archive_receipt_set_sha256": "b" * 64,
                },
            )
            self.assertEqual(
                manifest["binding"]["feature_policy_sha256"],
                MODULE._content_digest(
                    "netbraid.xrf55-joint.feature-policy.v0",
                    JOINT.feature_policy_document(),
                ),
            )
            self.assertEqual(
                manifest["binding"]["role_policy_sha256"],
                MODULE._content_digest(
                    "netbraid.xrf55-joint.role-policy.v0",
                    JOINT.role_policy_document(),
                ),
            )
            self.assertNotIn(str(root), json.dumps(manifest, sort_keys=True))

    def test_source_digest_changes_adapter_without_changing_artifact_contract(self):
        role = "calibration"
        events = self.events[role]
        artifacts = {
            modality: {
                "bytes": 1,
                "dtype": "<f8",
                "sha256": str(index) * 64,
                "shape": [len(events), JOINT.FEATURE_COUNT],
            }
            for index, modality in enumerate(FEATURES.MODALITIES, start=1)
        }
        first = MODULE._adapter_document(role, events, artifacts, SOURCE_BINDING)
        changed = MODULE._adapter_document(
            role,
            events,
            artifacts,
            MODULE.SourceBinding(1, "c" * 64, "d" * 64),
        )

        self.assertNotEqual(
            first["integrity"]["source"], changed["integrity"]["source"]
        )
        self.assertEqual(
            first["integrity"]["artifacts"], changed["integrity"]["artifacts"]
        )
        self.assertEqual(first["events"], changed["events"])

    def test_failed_extraction_leaves_existing_publication_byte_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            MODULE.compile_joint_role_cache(
                (self.source,), root, SOURCE_BINDING, layouts=TEST_LAYOUTS
            )
            before = _snapshot(root)
            calls = 0

            def failing_extractor(modality, array, *, layouts):
                nonlocal calls
                calls += 1
                if calls == 7:
                    raise RuntimeError("injected_extraction_failure")
                return JOINT.feature_vector(modality, array, layouts=layouts)

            with self.assertRaisesRegex(RuntimeError, "injected_extraction_failure"):
                MODULE.compile_joint_role_cache(
                    (self.source,),
                    root,
                    SOURCE_BINDING,
                    layouts=TEST_LAYOUTS,
                    extractor=failing_extractor,
                )

            after = _snapshot(root)
            self.assertEqual(after, before)
            self.assertEqual({path.name for path in root.iterdir()}, set(before))

            original_replace = os.replace
            validation_adapter = MODULE.role_output_set(root, "validation").adapter
            publication_order = []
            injected = False

            def failing_publish(source, target):
                nonlocal injected
                source_path = Path(source)
                target_path = Path(target)
                if (
                    target_path in _canonical_paths(root)
                    and "xrf55-restore" not in source_path.name
                ):
                    publication_order.append(target_path)
                if (
                    target_path == validation_adapter
                    and "xrf55-restore" not in source_path.name
                    and not injected
                ):
                    injected = True
                    raise OSError("injected_publication_failure")
                return original_replace(source, target)

            with (
                mock.patch.object(os, "replace", side_effect=failing_publish),
                self.assertRaisesRegex(OSError, "injected_publication_failure"),
            ):
                MODULE.compile_joint_role_cache(
                    (self.source,), root, SOURCE_BINDING, layouts=TEST_LAYOUTS
                )

            self.assertTrue(injected)
            self.assertEqual(
                publication_order[: len(MODULE.ROLE_ORDER) * len(FEATURES.MODALITIES)],
                [
                    MODULE.role_output_set(root, role).matrices[modality]
                    for role in MODULE.ROLE_ORDER
                    for modality in FEATURES.MODALITIES
                ],
            )
            self.assertTrue(
                all(
                    path.name.endswith("-adapter.json")
                    for path in publication_order[
                        len(MODULE.ROLE_ORDER) * len(FEATURES.MODALITIES) :
                    ]
                )
            )
            after_publish_failure = _snapshot(root)
            self.assertEqual(after_publish_failure, before)
            self.assertEqual({path.name for path in root.iterdir()}, set(before))

    def test_every_replace_exception_restores_old_bytes_and_manifest_is_last(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            replacement_count = len(_publication_paths(parent / "unused")) + 1
            for failure_index in range(replacement_count):
                root = parent / f"output-{failure_index}"
                staging = parent / f"staging-{failure_index}"
                _seed_publication(root, "old")
                before = _snapshot(root)
                fixture = _publication_fixture(root, staging, "new")
                original_replace = os.replace
                observed = []
                injected = False

                def failing_replace(source, target):
                    nonlocal injected
                    target_path = Path(target)
                    boundaries = {
                        root / MODULE.JOURNAL_FILENAME,
                        *_publication_paths(root),
                    }
                    if target_path in boundaries:
                        observed.append(target_path)
                        if len(observed) - 1 == failure_index and not injected:
                            injected = True
                            raise OSError("injected_replace_failure")
                    return original_replace(source, target)

                with (
                    mock.patch.object(os, "replace", side_effect=failing_replace),
                    self.assertRaisesRegex(OSError, "injected_replace_failure"),
                ):
                    MODULE._publish(root, *fixture)

                self.assertTrue(injected)
                self.assertEqual(_snapshot(root), before)
                self.assertFalse(_transaction_residue(root))
                self.assertTrue(all(path.exists() for path in _canonical_paths(root)))

            root = parent / "successful-output"
            staging = parent / "successful-staging"
            _seed_publication(root, "old")
            fixture = _publication_fixture(root, staging, "new")
            original_replace = os.replace
            observed = []

            def recording_replace(source, target):
                target_path = Path(target)
                if target_path == root / MODULE.JOURNAL_FILENAME or target_path in set(
                    _publication_paths(root)
                ):
                    observed.append(target_path)
                return original_replace(source, target)

            with mock.patch.object(os, "replace", side_effect=recording_replace):
                MODULE._publish(root, *fixture)

            self.assertEqual(observed[0], root / MODULE.JOURNAL_FILENAME)
            self.assertEqual(observed[-1], root / MODULE.MANIFEST_FILENAME)
            self.assertEqual(set(observed[1:-1]), set(_canonical_paths(root)))
            self.assertFalse(_transaction_residue(root))

    def test_kill_after_every_replace_recovers_at_next_compile(self):
        if not hasattr(os, "fork"):
            self.skipTest("fork unavailable")

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            replacement_count = len(_publication_paths(parent / "unused")) + 1
            for kill_index in range(replacement_count):
                root = parent / f"output-{kill_index}"
                staging = parent / f"staging-{kill_index}"
                _seed_publication(root, "old")
                before = _snapshot(root)
                fixture = _publication_fixture(root, staging, "new")
                process = os.fork()
                if process == 0:
                    original_replace = os.replace
                    boundary_count = 0

                    def killing_replace(source, target):
                        nonlocal boundary_count
                        target_path = Path(target)
                        boundaries = {
                            root / MODULE.JOURNAL_FILENAME,
                            *_publication_paths(root),
                        }
                        result = original_replace(source, target)
                        if target_path in boundaries:
                            if boundary_count == kill_index:
                                os._exit(91)
                            boundary_count += 1
                        return result

                    with mock.patch.object(os, "replace", side_effect=killing_replace):
                        MODULE._publish(root, *fixture)
                    os._exit(92)

                _, wait_status = os.waitpid(process, 0)
                self.assertTrue(os.WIFEXITED(wait_status))
                self.assertEqual(os.WEXITSTATUS(wait_status), 91)
                self.assertTrue(all(path.exists() for path in _publication_paths(root)))

                def failing_extractor(modality, array, *, layouts):
                    raise RuntimeError("stop_after_recovery")

                with self.assertRaisesRegex(RuntimeError, "stop_after_recovery"):
                    MODULE.compile_joint_role_cache(
                        (self.source,),
                        root,
                        SOURCE_BINDING,
                        layouts=TEST_LAYOUTS,
                        extractor=failing_extractor,
                    )

                self.assertEqual(_snapshot(root), before)
                self.assertFalse(_transaction_residue(root))

    def test_rejects_malformed_or_symlink_transaction_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "output"
            _seed_publication(root, "old")
            outputs = {
                role: MODULE.role_output_set(root, role) for role in MODULE.ROLE_ORDER
            }
            journal = root / MODULE.JOURNAL_FILENAME
            _write_private(journal, b'{"schema":"wrong","targets":[]}\n')
            with self.assertRaisesRegex(
                MODULE.Xrf55JointCacheCompileError,
                "invalid_transaction_journal",
            ):
                MODULE._recover_interrupted_publication(root, outputs)
            journal.unlink()
            before = _snapshot(root)
            targets = MODULE._transaction_targets(outputs)
            _write_private(
                journal,
                MODULE._canonical_bytes(MODULE._journal_document(targets)) + b"\n",
            )
            with self.assertRaisesRegex(
                MODULE.Xrf55JointCacheCompileError,
                "unsafe_transaction_path",
            ):
                MODULE._recover_interrupted_publication(root, outputs)
            self.assertEqual(_snapshot(root), before)
            journal.unlink()
            target = Path(directory) / "journal-target"
            _write_private(target, b"{}\n")
            journal.symlink_to(target)
            with self.assertRaisesRegex(
                MODULE.Xrf55JointCacheCompileError,
                "unsafe_transaction_journal",
            ):
                MODULE._recover_interrupted_publication(root, outputs)

    def test_rejects_symlink_directory_target_and_source_alias_before_compilation(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlink unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            linked = root / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(
                MODULE.Xrf55JointCacheCompileError, "unsafe_output_directory"
            ):
                MODULE.compile_joint_role_cache(
                    (self.source,), linked, SOURCE_BINDING, layouts=TEST_LAYOUTS
                )

            output = root / "output"
            output.mkdir()
            adapter = MODULE.role_output_set(output, "train").adapter
            target = root / "adapter-target.json"
            target.write_text("{}\n", encoding="utf-8")
            adapter.symlink_to(target)
            with self.assertRaisesRegex(
                MODULE.Xrf55JointCacheCompileError, "unsafe_output_path"
            ):
                MODULE.compile_joint_role_cache(
                    (self.source,), output, SOURCE_BINDING, layouts=TEST_LAYOUTS
                )

            outputs = {
                role: MODULE.role_output_set(root / "alias", role)
                for role in MODULE.ROLE_ORDER
            }
            outputs["train"] = MODULE.OutputSet(
                outputs["train"].adapter,
                {
                    **outputs["train"].matrices,
                    "wifi": self.archive,
                },
            )
            with self.assertRaisesRegex(
                MODULE.Xrf55JointCacheCompileError, "output_aliases_source"
            ):
                MODULE._prepare_outputs(outputs, (self.source,))

    def test_load_source_set_reuses_exact_existing_admission_and_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw"
            receipts = root / "receipts"
            raw.mkdir()
            receipts.mkdir()
            admitted = []
            local_status = {"datasets": {}}
            for index, (name, spec) in enumerate(
                {
                    name: MODULE.BASE.PROFILE.FETCH.SOURCES[name]
                    for name in MODULE.BASE.PROFILE.PROCESSED_CONTRACTS
                }.items()
            ):
                path = raw / str(spec["filename"])
                receipt = MODULE.BASE.PROFILE.FETCH.source_receipt(
                    spec, int(spec["archive_bytes"]), str(index + 1) * 64
                )
                receipt_path = MODULE.BASE.PROFILE.FETCH.receipt_path(path, receipts)
                receipt_path.write_text(
                    json.dumps(receipt, sort_keys=True), encoding="utf-8"
                )
                admitted.append(
                    SimpleNamespace(
                        path=path,
                        contract=MODULE.BASE.PROFILE.PROCESSED_CONTRACTS[name],
                        inspection=SimpleNamespace(report={"slot": index}),
                    )
                )
                local_status["datasets"][name] = {
                    "central_receipt_state": "valid",
                    "legacy_receipt_state": "absent",
                }

            with (
                mock.patch.object(
                    MODULE.BASE,
                    "load_archive_sources",
                    return_value=tuple(admitted),
                ) as admission,
                mock.patch.object(
                    MODULE.BASE.PROFILE.FETCH,
                    "local_status",
                    return_value=local_status,
                ),
            ):
                sources, binding = MODULE.load_source_set(raw, receipts)

            admission.assert_called_once_with(raw, receipts)
            self.assertEqual(sources, tuple(admitted))
            self.assertEqual(binding.archive_count, len(admitted))
            self.assertTrue(MODULE._valid_digest(binding.archive_profile_set_sha256))
            self.assertTrue(MODULE._valid_digest(binding.archive_receipt_set_sha256))


if __name__ == "__main__":
    unittest.main(verbosity=2)
