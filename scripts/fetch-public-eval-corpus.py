#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["truststore==0.10.4"]
# ///

"""Fetch and inspect approved public wireless evaluation archives.

Archives are stored outside Git under ``eval-data/`` by default. The source
allowlist, byte count, and MD5 digest are kept here so a local fetch is
repeatable and fails closed on a changed download.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import stat
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import truststore


SOURCES: dict[str, dict[str, Any]] = {
    "v2i-80211ad": {
        "url": "https://zenodo.org/api/records/7026551/files/v2i-80211ad-dataset.zip/content",
        "filename": "v2i-80211ad-dataset.zip",
        "bytes": 660_248_364,
        "md5": "a37836cce4f3d37f8ef374850069fc9e",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.7026551",
    },
    "zbds2023": {
        "url": "https://entrepot.recherche.data.gouv.fr/api/access/datafile/156780",
        "filename": "zigbee_dataset.zip",
        "bytes": 1_251_060_836,
        "md5": "6e8d9fc1c76688393ccdfb6364436ac1",
        "license": "Etalab Open License 2.0",
        "doi": "10.57745/NDW74U",
    },
    "sdr4iot-ble-zigbee": {
        "url": "https://zenodo.org/api/records/4639390/files/dataset.zip/content",
        "filename": "sdr4iot-ble-zigbee-dataset.zip",
        "bytes": 78_658_727,
        "md5": "c966c5cbf1243b5a16f59675451de84e",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.4639390",
    },
    "wifi-management-frames": {
        "url": "https://zenodo.org/api/records/8003772/files/datasets.zip/content",
        "filename": "wifi-management-frames.zip",
        "bytes": 4_126_124,
        "md5": "835320ace908243f23cb03fc48ce44fc",
        "license": "MIT",
        "doi": "10.5281/zenodo.8003772",
    },
    "wifi-probe-requests": {
        "url": "https://zenodo.org/api/records/7503594/files/Dataset.zip/content",
        "filename": "wifi-probe-requests.zip",
        "bytes": 49_977_913,
        "md5": "3eeab562d6140adc0891aa122e829b8b",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.7503594",
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", choices=["list", "all", *SOURCES])
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "eval-data",
        help="ignored local archive directory",
    )
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="list archive members after verifying the downloaded archive",
    )
    parser.add_argument(
        "--inspect-output",
        type=Path,
        help="write the member inventory as JSON instead of printing it",
    )
    parser.add_argument(
        "--extract-member",
        action="append",
        default=[],
        metavar="MEMBER",
        help="extract one verified archive member; may be repeated",
    )
    parser.add_argument(
        "--extract-dir",
        type=Path,
        help="ignored directory for selected members and their receipt",
    )
    parser.add_argument(
        "--max-extract-bytes",
        type=int,
        default=100_000_000,
        help="aggregate uncompressed extraction limit (default: 100 MiB)",
    )
    return parser.parse_args()


def print_catalog() -> None:
    print(json.dumps(SOURCES, indent=2, sort_keys=True))


def digest_file(path: Path) -> tuple[int, str, str]:
    size = 0
    md5 = hashlib.md5(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            md5.update(chunk)
            sha256.update(chunk)
    return size, md5.hexdigest(), sha256.hexdigest()


def write_archive_receipt(
    archive: Path,
    spec: dict[str, Any],
    size: int,
    md5: str,
    sha256: str,
) -> None:
    metadata = {
        "schema": "local.public_wireless_archive.v1",
        "source": spec,
        "bytes": size,
        "md5": md5,
        "sha256": sha256,
        "archive": archive.name,
    }
    archive.with_suffix(archive.suffix + ".json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def download(spec: dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    archive = output_dir / spec["filename"]
    if archive.exists():
        size, md5, sha256 = digest_file(archive)
        if size == spec["bytes"] and md5 == spec["md5"]:
            write_archive_receipt(archive, spec, size, md5, sha256)
            print(f"reusing verified archive: {archive}")
            return archive
        raise RuntimeError(f"existing archive failed verification: {archive}")

    partial = archive.with_name(f".{archive.name}.part")
    if partial.exists():
        raise RuntimeError(f"refusing to overwrite partial download: {partial}")

    request = urllib.request.Request(
        spec["url"], headers={"User-Agent": "netbraid-local-eval/1"}
    )
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with (
        urllib.request.urlopen(request, timeout=60, context=context) as response,
        partial.open("xb") as target,
    ):
        content_length = response.headers.get("Content-Length")
        if content_length is not None and int(content_length) != spec["bytes"]:
            raise RuntimeError(
                f"content length {content_length} differs from expected {spec['bytes']}"
            )
        received = 0
        md5 = hashlib.md5(usedforsecurity=False)
        sha256 = hashlib.sha256()
        while chunk := response.read(1024 * 1024):
            received += len(chunk)
            if received > spec["bytes"]:
                raise RuntimeError("download exceeded declared byte bound")
            target.write(chunk)
            md5.update(chunk)
            sha256.update(chunk)

    if received != spec["bytes"] or md5.hexdigest() != spec["md5"]:
        raise RuntimeError(
            f"download verification failed: bytes={received}, md5={md5.hexdigest()}"
        )
    os.replace(partial, archive)
    write_archive_receipt(
        archive,
        spec,
        received,
        md5.hexdigest(),
        sha256.hexdigest(),
    )
    print(f"downloaded and verified: {archive}")
    return archive


def inspect_archive(archive: Path) -> dict[str, Any]:
    with zipfile.ZipFile(archive) as source:
        members = []
        for member in source.infolist():
            parts = Path(member.filename).parts
            mode = member.external_attr >> 16
            if member.filename.startswith("/") or ".." in parts or stat.S_ISLNK(mode):
                raise RuntimeError(f"unsafe archive member: {member.filename}")
            members.append(
                {
                    "name": member.filename,
                    "bytes": member.file_size,
                    "compressed_bytes": member.compress_size,
                    "directory": member.is_dir(),
                }
            )
        return {"archive": str(archive), "members": members}


def extract_members(
    archive: Path,
    member_names: list[str],
    output_dir: Path,
    max_bytes: int,
) -> None:
    if max_bytes <= 0:
        raise RuntimeError("--max-extract-bytes must be positive")
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    extracted: list[dict[str, Any]] = []
    total_bytes = 0
    with zipfile.ZipFile(archive) as source:
        for member_name in member_names:
            try:
                member = source.getinfo(member_name)
            except KeyError as error:
                raise RuntimeError(
                    f"archive member not found: {member_name}"
                ) from error
            parts = Path(member.filename).parts
            mode = member.external_attr >> 16
            if (
                member.filename.startswith("/")
                or ".." in parts
                or member.is_dir()
                or stat.S_ISLNK(mode)
                or member.filename.startswith("__MACOSX/")
            ):
                raise RuntimeError(
                    f"refusing unsafe or metadata member: {member.filename}"
                )
            total_bytes += member.file_size
            if total_bytes > max_bytes:
                raise RuntimeError(
                    f"selected members exceed extraction limit: {total_bytes} > {max_bytes}"
                )
            target = output_dir / Path(member.filename).name
            if target.exists():
                raise RuntimeError(f"refusing to overwrite extracted member: {target}")
            partial = target.with_name(f".{target.name}.part")
            if partial.exists():
                raise RuntimeError(
                    f"refusing to overwrite partial extraction: {partial}"
                )
            sha256 = hashlib.sha256()
            with source.open(member) as source_file, partial.open("xb") as target_file:
                while chunk := source_file.read(1024 * 1024):
                    target_file.write(chunk)
                    sha256.update(chunk)
            os.replace(partial, target)
            extracted.append(
                {
                    "member": member.filename,
                    "output": target.name,
                    "bytes": member.file_size,
                    "sha256": sha256.hexdigest(),
                }
            )
    receipt = {
        "schema": "local.public_wireless_extraction.v1",
        "archive": archive.name,
        "members": extracted,
        "total_bytes": total_bytes,
    }
    (output_dir / "extraction.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"extracted {len(extracted)} member(s) to {output_dir}")


def main() -> int:
    args = parse_args()
    if args.dataset == "list":
        print_catalog()
        return 0
    if args.dataset == "all" and args.extract_member:
        raise RuntimeError("--extract-member requires one named dataset")

    selected = (
        SOURCES if args.dataset == "all" else {args.dataset: SOURCES[args.dataset]}
    )
    inventories: dict[str, dict[str, Any]] = {}
    for dataset, spec in selected.items():
        archive = download(spec, args.output_dir.resolve())
        if args.inspect:
            inventories[dataset] = inspect_archive(archive)
        if args.extract_member:
            extract_members(
                archive,
                args.extract_member,
                (
                    args.extract_dir or args.output_dir / f"extracted-{dataset}"
                ).resolve(),
                args.max_extract_bytes,
            )

    if args.inspect:
        inventory: dict[str, Any]
        if args.dataset == "all":
            inventory = {
                "schema": "local.public_wireless_archive_inventory.v1",
                "datasets": inventories,
            }
        else:
            inventory = inventories[args.dataset]
        rendered = json.dumps(inventory, indent=2, sort_keys=True) + "\n"
        if args.inspect_output is None:
            print(rendered, end="")
        else:
            args.inspect_output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            args.inspect_output.write_text(rendered, encoding="utf-8")
            print(f"wrote member inventory: {args.inspect_output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, urllib.error.URLError, zipfile.BadZipFile) as error:
        print(f"fetch-public-eval-corpus: {error}", file=sys.stderr)
        raise SystemExit(1) from error
