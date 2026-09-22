#!/usr/bin/env python3
"""Safe orchestration for the repository's receipt-aware dataset fetchers.

This command deliberately has no default source or selection. ``plan`` is
read-only and prints the pinned byte estimate and terms. ``fetch`` prints the
same plan and requires ``--confirm`` before delegating to the existing
fetcher. It never reads or writes payload bytes itself.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[2]
FETCHERS = {
    "public-eval": ("data/fetch/fetch-public-eval-corpus.py", "public"),
    "curated-eval": ("data/fetch/fetch-curated-eval.py", "curated"),
    "controlled-jamming": ("data/fetch/fetch-controlled-jamming.py", "controlled"),
    "osu-lora": ("data/fetch/fetch-osu-lora.py", "osu"),
    "xrf55": ("data/fetch/fetch-xrf55.py", "xrf55"),
    "smorffi": ("data/fetch/fetch-smorffi.py", "smorffi"),
}


class OrchestrationError(RuntimeError):
    """A safe orchestration boundary failed."""


def _run(fetcher: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    path = ROOT / fetcher
    command = (
        ["uv", "run", "--script", str(path)]
        if "# /// script" in path.read_text(encoding="utf-8")[:4096]
        else [sys.executable, str(path)]
    )
    if command[0] == "uv" and shutil.which("uv") is None:
        raise OrchestrationError("uv_required_for_fetcher")
    return subprocess.run(
        [*command, *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def _json(fetcher: str, *arguments: str) -> dict[str, Any]:
    completed = _run(fetcher, *arguments)
    if completed.returncode != 0:
        raise OrchestrationError(completed.stderr.strip() or "fetcher_failed")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise OrchestrationError("fetcher_returned_non_json") from error
    if not isinstance(value, dict):
        raise OrchestrationError("fetcher_returned_non_object")
    return value


def _selection_args(source: str, selection: str, action: str) -> tuple[str, ...]:
    if source in {"public-eval", "curated-eval", "controlled-jamming"}:
        if source == "public-eval" and action == "status":
            return ("status", "--status-selection", selection)
        return (action, selection)
    if source == "osu-lora":
        return ("discover" if action == "status" else action, *selection.split(","))
    if source == "xrf55":
        return ("status" if action == "status" else selection,)
    if source == "smorffi":
        return (action,)
    raise OrchestrationError("unknown_source")


def _plan(source: str, selection: str) -> dict[str, Any]:
    fetcher, kind = FETCHERS[source]
    if kind == "public":
        catalog = _json(fetcher, "list")
        specs = catalog
        selected = specs if selection == "all" else {
            key: value for key, value in specs.items() if key == selection or value.get("group") == selection
        }
        if not selected:
            raise OrchestrationError("selection_not_found")
        return {
            "source": source,
            "selection": selection,
            "estimated_bytes": sum(item["bytes"] for item in selected.values()),
            "terms": sorted({item.get("license", "terms_unspecified") for item in selected.values()}),
            "fetcher": fetcher,
            "integrity": "pinned MD5 plus local SHA-256 receipt",
        }
    if kind == "curated":
        listing = _json(fetcher, "list", selection)
        summary = listing["summary"]
        terms = sorted({record["license"] for record in listing["records"]})
        return {"source": source, "selection": selection, "estimated_bytes": summary["expected_bytes"], "terms": terms, "fetcher": fetcher, "integrity": "pinned MD5 plus local SHA-256 receipt"}
    if kind == "controlled":
        listing = _json(fetcher, "list", selection)
        summary = listing["summary"]
        terms = sorted({record["license"] for record in listing["records"]})
        return {"source": source, "selection": selection, "estimated_bytes": summary["expected_bytes"], "terms": terms, "fetcher": fetcher, "integrity": "pinned MD5 plus local SHA-256 receipt"}
    if kind == "xrf55":
        catalog = _json(fetcher, "list")
        selected = catalog if selection == "all" else {selection: catalog[selection]}
        return {"source": source, "selection": selection, "estimated_bytes": sum(item["archive_bytes"] for item in selected.values()), "terms": sorted({item["license"] for item in selected.values()}), "fetcher": fetcher, "integrity": "publisher MD5 plus local SHA-256 receipt"}
    if kind == "smorffi":
        catalog = _json(fetcher, "list")
        return {"source": source, "selection": selection, "estimated_bytes": None, "terms": ["Kaggle terms; review before acquisition"], "bounds": catalog["default_bounds"], "fetcher": fetcher, "integrity": "local inventory receipt"}
    catalog = _json(fetcher, "list")
    names = {item["setup"] for item in catalog["setups"]}
    selected = names if selection == "all" else set(selection.split(","))
    if not selected <= names:
        raise OrchestrationError("selection_not_found")
    return {"source": source, "selection": selection, "estimated_bytes": None, "terms": ["research use; citation requested; redistribution not stated"], "note": "Run discover first to obtain byte totals; fetcher enforces aggregate and per-file caps.", "fetcher": fetcher, "integrity": "inventory-bound SHA-256 receipts"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    for action in ("sources", "plan", "status", "fetch"):
        command = subparsers.add_parser(action)
        if action != "sources":
            command.add_argument("source", choices=sorted(FETCHERS))
            command.add_argument("selection", help="named selection; comma-separated for osu-lora")
        if action == "fetch":
            command.add_argument("--confirm", action="store_true", help="approve the printed plan")
            command.add_argument("--acknowledge-terms", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.action == "sources":
        print("\n".join(sorted(FETCHERS)))
        return 0
    try:
        plan = _plan(args.source, args.selection)
        if args.action == "plan":
            print(json.dumps(plan, indent=2, sort_keys=True))
            return 0
        if args.action == "status":
            fetcher, _ = FETCHERS[args.source]
            completed = _run(fetcher, *_selection_args(args.source, args.selection, "status"))
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            return completed.returncode
        print(json.dumps({"action": "fetch", "plan": plan}, indent=2, sort_keys=True))
        if not args.confirm:
            print("fetch not started: rerun with --confirm", file=sys.stderr)
            return 3
        fetcher, kind = FETCHERS[args.source]
        fetch_args = list(_selection_args(args.source, args.selection, "fetch"))
        if kind == "public" and args.acknowledge_terms:
            fetch_args.append("--acknowledge-license-restrictions")
        if kind == "osu":
            if args.acknowledge_terms:
                fetch_args.append("--acknowledge-research-terms")
        completed = _run(fetcher, *fetch_args)
        sys.stdout.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        return completed.returncode
    except (KeyError, OrchestrationError) as error:
        print(f"dataset-fetch: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
