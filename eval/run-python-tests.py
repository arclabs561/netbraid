#!/usr/bin/env python3
"""Run every tracked hermetic Python test with its declared interpreter."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Optional, Sequence, Tuple


ROOT = Path(__file__).resolve().parents[1]
MAX_TEST_FILES = 128
INTERPRETER_OVERRIDES = {
    PurePosixPath("data/tests/test-fetch-controlled-jamming.py"): "3.11",
    PurePosixPath("data/tests/test-fetch-smorffi.py"): "3.10",
}


class TestRunnerError(RuntimeError):
    """Stable error for invalid repository test inventory."""


def _tracked_files() -> Tuple[PurePosixPath, ...]:
    completed = subprocess.run(
        ["git", "-C", os.fspath(ROOT), "ls-files", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise TestRunnerError("tracked_inventory_unavailable")
    try:
        values = tuple(
            PurePosixPath(item.decode("utf-8"))
            for item in completed.stdout.split(b"\0")
            if item
        )
    except UnicodeDecodeError as error:
        raise TestRunnerError("tracked_inventory_not_utf8") from error
    return values


def discover_tests() -> Tuple[PurePosixPath, ...]:
    tests = tuple(
        sorted(
            path
            for path in _tracked_files()
            if path.suffix == ".py"
            and (
                (path.parts[:2] == ("data", "tests") and path.name.startswith("test"))
                or (path.parts[:1] == ("eval",) and path.name.startswith("test"))
            )
        )
    )
    if not tests or len(tests) > MAX_TEST_FILES:
        raise TestRunnerError("python_test_count_outside_bound")
    for relative in tests:
        absolute = ROOT.joinpath(*relative.parts)
        if not absolute.is_file() or absolute.is_symlink():
            raise TestRunnerError("python_test_not_regular")
    return tests


def _has_inline_metadata(path: Path) -> bool:
    with path.open("rb") as source:
        prefix = source.read(4 * 1024)
    return b"# /// script" in prefix


def command_for(relative: PurePosixPath) -> Tuple[str, ...]:
    absolute = ROOT.joinpath(*relative.parts)
    version = INTERPRETER_OVERRIDES.get(relative)
    if version is not None:
        return ("uv", "run", "--python", version, os.fspath(relative))
    if _has_inline_metadata(absolute):
        return ("uv", "run", "--script", os.fspath(relative))
    return (sys.executable, os.fspath(relative))


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--list", action="store_true", help="print the tracked test inventory only"
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        tests = discover_tests()
    except TestRunnerError as error:
        print(str(error), file=sys.stderr)
        return 2
    if args.list:
        for test in tests:
            print(test)
        return 0
    if (
        any(command_for(test)[0] == "uv" for test in tests)
        and shutil.which("uv") is None
    ):
        print("uv_unavailable", file=sys.stderr)
        return 2

    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    failures = []
    for index, test in enumerate(tests, start=1):
        command = command_for(test)
        print(f"[{index}/{len(tests)}] {' '.join(command)}", flush=True)
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            check=False,
        )
        if completed.returncode != 0:
            failures.append((test, completed.returncode))
    if failures:
        for test, returncode in failures:
            print(f"FAILED {test} exit={returncode}", file=sys.stderr)
        return 1
    print(f"Python test files passed: {len(tests)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
