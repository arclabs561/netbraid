#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["truststore==0.10.4"]
# ///

"""Fetch and inspect allowlisted public network evaluation artifacts.

Archives are stored outside Git under ``data/raw/`` by default. The source
allowlist, byte count, and pinned digests are kept here so a local fetch is
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
import tempfile
import tarfile
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
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
        "group": "baseline",
    },
    "zbds2023": {
        "url": "https://entrepot.recherche.data.gouv.fr/api/access/datafile/156780",
        "filename": "zigbee_dataset.zip",
        "bytes": 1_251_060_836,
        "md5": "6e8d9fc1c76688393ccdfb6364436ac1",
        "license": "Etalab Open License 2.0",
        "doi": "10.57745/NDW74U",
        "group": "baseline",
    },
    "sdr4iot-ble-zigbee": {
        "url": "https://zenodo.org/api/records/4639390/files/dataset.zip/content",
        "filename": "sdr4iot-ble-zigbee-dataset.zip",
        "bytes": 78_658_727,
        "md5": "c966c5cbf1243b5a16f59675451de84e",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.4639390",
        "group": "baseline",
    },
    "wifi-management-frames": {
        "url": "https://zenodo.org/api/records/8003772/files/datasets.zip/content",
        "filename": "wifi-management-frames.zip",
        "bytes": 4_126_124,
        "md5": "835320ace908243f23cb03fc48ce44fc",
        "license": "MIT",
        "doi": "10.5281/zenodo.8003772",
        "group": "baseline",
    },
    "wifi-probe-requests": {
        "url": "https://zenodo.org/api/records/7503594/files/Dataset.zip/content",
        "filename": "wifi-probe-requests.zip",
        "bytes": 49_977_913,
        "md5": "3eeab562d6140adc0891aa122e829b8b",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.7503594",
        "group": "baseline",
    },
    "sorbonne-campus-rssi": {
        "url": "https://entrepot.recherche.data.gouv.fr/api/access/datafile/617311",
        "filename": "220211012-SU-Outdoors-Campus.zip",
        "bytes": 3_144_312,
        "md5": "3ce2868b97eb1a8750233e67fb3cfbe3",
        "license": "Etalab Open License 2.0",
        "doi": "10.57745/HAOPHF",
        "group": "baseline",
    },
    "iot23v2-hakai-pcap": {
        "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-8-1/pcap/2018-07-31-15-15-09-192.168.100.113.pcap",
        "filename": "iot23v2-hakai-capture-8-1.pcap",
        "bytes": 2_098_362,
        "md5": "e1d2e236a6e399614c675766f04e05e5",
        "sha256": "80dcc2602519479ddcde889fa902fee19a76696630811452f8df38888af894f2",
        "format": "file",
        "license": "CC BY (version unspecified)",
        "group": "motivating",
    },
    "iot23v2-hakai-zeek": {
        "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-8-1/2018-07-31-15-15-09-192.168.100.113-zeek-conn-log.labeled",
        "filename": "iot23v2-hakai-capture-8-1-zeek.log.labeled",
        "bytes": 1_431_000,
        "md5": "669ed9d8acbe254e2efa768fecae91d5",
        "sha256": "4877ca8f0f01902fbd18d28b7d06cb3d0be082355b7f2c8862c9deef1782eb8a",
        "format": "file",
        "license": "CC BY (version unspecified)",
        "group": "motivating",
    },
    "iot23v2-hakai-labels": {
        "url": "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset-v2/CTU-IoT-Malware-Capture-8-1/2018-07-31-15-15-09-192.168.100.113-labels.config",
        "filename": "iot23v2-hakai-capture-8-1-labels.config",
        "bytes": 1_778,
        "md5": "1069166d74b3e2754af26b86955d5e98",
        "sha256": "39014291d4220f3e85c45b574c43d5c769093926af99843371c93b9365d407e1",
        "format": "file",
        "license": "CC BY (version unspecified)",
        "group": "motivating",
    },
    "wisig-single-day": {
        "url": "https://drive.usercontent.google.com/download?id=1lWf9BuUZTSNcABVFWYoBT_-EH8ctXEcZ&export=download&confirm=t",
        "filename": "WiSig-SingleDay.pkl.zip",
        "bytes": 1_119_463_474,
        "md5": "8878d4ca2b1622d9f8ae9fed645a887c",
        "sha256": "bb4af37ebbdbfa2c99e1fe589c6a5be7f03f101cdaf3fc9440245e3b48a17965",
        "license": "CC BY-NC-SA 4.0",
        "group": "motivating",
    },
    "wisig-many-rx": {
        "url": "https://drive.usercontent.google.com/download?id=1TtdydJCuhkvDQ1RWb3PkxakkWo2-X5Uv&export=download&confirm=t",
        "filename": "WiSig-ManyRx.pkl.zip",
        "bytes": 1_249_528_063,
        "md5": "56c68c2a7d723a0ed90e178d963a54b3",
        "sha256": "d2b23108c3f6f63a10ebbb149d7b08d6e1c1961cf5184926fbab452def3049de",
        "license": "CC BY-NC-SA 4.0",
        "group": "motivating",
    },
    "wisig-many-tx": {
        "url": "https://drive.usercontent.google.com/download?id=17EnvGFoflJEh1xhFC8wx5fhCuPYhWt2l&export=download&confirm=t",
        "filename": "WiSig-ManyTx.pkl.zip",
        "bytes": 2_631_104_718,
        "md5": "0aed3049a7f81935faa16058de6163c0",
        "sha256": "a8fc3e35134a240bfb4dab8862a6e482cef44de000b813d42417b853c47ccc7e",
        "license": "CC BY-NC-SA 4.0",
        "group": "motivating",
    },
    "wisig-many-sig": {
        "url": "https://drive.usercontent.google.com/download?id=1szuns8MhcYocdbipK9t9TM9MLgEMklxk&export=download&confirm=t",
        "filename": "WiSig-ManySig.pkl.zip",
        "bytes": 1_454_577_503,
        "md5": "1081d373308bcb95b8f81a3e41d3a94a",
        "sha256": "5c3d6f5aece87a86ecd8cf5a0f6bdc56535f34cfd3e8a32e8ce6dbc448c85bac",
        "license": "CC BY-NC-SA 4.0",
        "group": "motivating",
    },
    "caez-wifi-indoor-lshape": {
        "url": "https://iis-people.ee.ethz.ch/~caez/wifi/caez-wifi-indoor-Lshape.tar.gz",
        "filename": "caez-wifi-indoor-Lshape.tar.gz",
        "bytes": 1_933_783_040,
        "md5": "a6127a35dd7397fe592da9e6b942eb25",
        "sha256": "3ee1fd4f2746b1ac6ac8e7c5172c35b4abe5d507353981359218b0e7fd868bdf",
        "format": "tar",
        "license": "CAEZ Dataset License v1.0 (no original-data redistribution)",
        "group": "motivating",
    },
    "operanet-pwr": {
        "url": "https://ndownloader.figshare.com/files/30686384",
        "filename": "OPERAnet-pwr.zip",
        "bytes": 1_048_378_050,
        "md5": "ac1301876899ff51b3826afaff6634a7",
        "sha256": "bb1a1478ab624f76c40677101fb36ae8102dd7e7b85512c0bb8213cf0ceb5bf5",
        "license": "CC0",
        "doi": "10.6084/m9.figshare.16578203.v1",
        "group": "motivating",
    },
    "operanet-wificsi1": {
        "url": "https://ndownloader.figshare.com/files/30689729",
        "filename": "OPERAnet-wificsi1.zip",
        "bytes": 36_490_626_012,
        "md5": "0bd15bc2577c6479a6fa6aaaea89087b",
        "license": "CC0",
        "doi": "10.6084/m9.figshare.16578428.v1",
        "group": "motivating",
    },
    "operanet-wificsi2": {
        "url": "https://ndownloader.figshare.com/files/30694595",
        "filename": "OPERAnet-wificsi2.zip",
        "bytes": 34_352_781_492,
        "md5": "1eee5528687b42f5e866c232a68bb411",
        "license": "CC0",
        "doi": "10.6084/m9.figshare.16578431.v1",
        "group": "motivating",
    },
    "operanet-uwb1": {
        "url": "https://ndownloader.figshare.com/files/30686474",
        "filename": "OPERAnet-uwb1.zip",
        "bytes": 2_908_466_535,
        "md5": "41cb357326a9b2911dcb5801aa6c483f",
        "license": "CC0",
        "doi": "10.6084/m9.figshare.16578245.v1",
        "group": "motivating",
    },
    "operanet-uwb2": {
        "url": "https://ndownloader.figshare.com/files/30686552",
        "filename": "OPERAnet-uwb2.zip",
        "bytes": 2_091_091_120,
        "md5": "cf794dbaf7fb31629c9f9888571177f2",
        "license": "CC0",
        "doi": "10.6084/m9.figshare.16578251.v1",
        "group": "motivating",
    },
    "operanet-codes": {
        "url": "https://ndownloader.figshare.com/files/30686756",
        "filename": "OPERAnet-codes.zip",
        "bytes": 13_983,
        "md5": "6b9d2068629bc3f0f139301447b69898",
        "license": "CC0",
        "doi": "10.6084/m9.figshare.16578299.v1",
        "group": "motivating",
    },
    "operanet-kinect": {
        "url": "https://ndownloader.figshare.com/files/30686327",
        "filename": "OPERAnet-kinect.zip",
        "bytes": 190_903_745,
        "md5": "5a333a86da131f2ebae5730f1bf22ffc",
        "license": "CC0",
        "doi": "10.6084/m9.figshare.16578191.v1",
        "group": "motivating",
    },
    "gotham-iot-2025": {
        "url": "https://zenodo.org/api/records/14502760/files/GothamDataset2025.zip/content",
        "filename": "GothamDataset2025.zip",
        "bytes": 23_824_968_355,
        "md5": "7ca78c0517ccb3d2854e823678e0f206",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.14502760",
        "group": "motivating",
    },
    "data4cyber": {
        "url": "https://zenodo.org/api/records/19965384/files/data4cyber_dataset.zip/content",
        "filename": "data4cyber_dataset.zip",
        "bytes": 134_034_872,
        "md5": "a540979c63120c9a0295ff974933580f",
        "license": "CC BY 4.0 (archive LICENSE.txt)",
        "doi": "10.5281/zenodo.19965384",
        "group": "fusion",
    },
    "netslab-5g-oran-benign": {
        "url": "https://zenodo.org/api/records/18923275/files/Benign.zip/content",
        "filename": "netslab-5g-oran-benign.zip",
        "bytes": 5_936_426_197,
        "md5": "3739c67aab617d0937629ac29633992b",
        "license": "unspecified on the Zenodo record",
        "doi": "10.1109/IEEEDATA.2025.3614167",
        "group": "fusion",
    },
    "netslab-5g-oran-lower-summary": {
        "url": "https://zenodo.org/api/records/18923275/files/Lower_Layer_Data.db/content",
        "filename": "netslab-5g-oran-lower-layer.db",
        "bytes": 5_402_624,
        "md5": "c3af05f535b12c547a4dbaf858a25458",
        "format": "file",
        "license": "unspecified on the Zenodo record",
        "doi": "10.1109/IEEEDATA.2025.3614167",
        "group": "fusion",
    },
    "netslab-5g-oran-network-summary": {
        "url": "https://zenodo.org/api/records/18923275/files/Network_Dataset.db/content",
        "filename": "netslab-5g-oran-network.db",
        "bytes": 210_690_048,
        "md5": "03a235bd089cc2e7c01f96f82b14f065",
        "format": "file",
        "license": "unspecified on the Zenodo record",
        "doi": "10.1109/IEEEDATA.2025.3614167",
        "group": "fusion",
    },
    "gnss-rff-readme": {
        "url": "https://zenodo.org/api/records/13846381/files/readme.txt/content",
        "filename": "gnss-rff-readme.txt",
        "bytes": 2_556,
        "md5": "7a19ff1553fba9030567d5e724d45467",
        "format": "file",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.13846381",
        "record": "gnss-rff",
        "record_bytes": 6_358_042_574,
        "group": "rf-fingerprinting",
    },
    "gnss-rff-demo": {
        "url": "https://zenodo.org/api/records/13846381/files/demo.py/content",
        "filename": "gnss-rff-demo.py",
        "bytes": 4_712,
        "md5": "80283bad9185b09aeaad154ae541fdba",
        "format": "file",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.13846381",
        "record": "gnss-rff",
        "record_bytes": 6_358_042_574,
        "group": "rf-fingerprinting",
    },
    "gnss-rff-data": {
        "url": "https://zenodo.org/api/records/13846381/files/Data.zip/content",
        "filename": "gnss-rff-Data.zip",
        "bytes": 6_358_035_306,
        "md5": "e6ded5b0cb014265d321f61a801686c4",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.13846381",
        "record": "gnss-rff",
        "record_bytes": 6_358_042_574,
        "group": "rf-fingerprinting",
    },
    "mmwave-5g-rff-bfk06002-long": {
        "url": "https://zenodo.org/api/records/18481702/files/bfk06002_long.mat/content",
        "filename": "mmwave-5g-rff-bfk06002_long.mat",
        "bytes": 11_796_492_464,
        "md5": "6986b42361428742020b361cf4160ed6",
        "format": "file",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.18481702",
        "record": "mmwave-5g-rff",
        "record_bytes": 35_878_437_473,
        "group": "rf-fingerprinting",
    },
    "mmwave-5g-rff-bfk06003-long": {
        "url": "https://zenodo.org/api/records/18481702/files/bfk06003_long.mat/content",
        "filename": "mmwave-5g-rff-bfk06003_long.mat",
        "bytes": 11_796_492_464,
        "md5": "71f034ea573bd985d4702d5f8ae3f963",
        "format": "file",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.18481702",
        "record": "mmwave-5g-rff",
        "record_bytes": 35_878_437_473,
        "group": "rf-fingerprinting",
    },
    "mmwave-5g-rff-bfk06003-20ms": {
        "url": "https://zenodo.org/api/records/18481702/files/bfk06003_20ms.mat/content",
        "filename": "mmwave-5g-rff-bfk06003_20ms.mat",
        "bytes": 157_298_864,
        "md5": "bed9b0f9f706622ab9fa2c55d453de0b",
        "format": "file",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.18481702",
        "record": "mmwave-5g-rff",
        "record_bytes": 35_878_437_473,
        "group": "rf-fingerprinting",
    },
    "mmwave-5g-rff-box-long": {
        "url": "https://zenodo.org/api/records/18481702/files/box_long.mat/content",
        "filename": "mmwave-5g-rff-box_long.mat",
        "bytes": 11_796_492_464,
        "md5": "d0c06d6cb219258ed14f643698618e7a",
        "format": "file",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.18481702",
        "record": "mmwave-5g-rff",
        "record_bytes": 35_878_437_473,
        "group": "rf-fingerprinting",
    },
    "mmwave-5g-rff-tx-5g-ssb": {
        "url": "https://zenodo.org/api/records/18481702/files/TX_5G_SSB.mat/content",
        "filename": "mmwave-5g-rff-TX_5G_SSB.mat",
        "bytes": 17_063_489,
        "md5": "87fae9fd1d1a03d967637b13806e16cc",
        "format": "file",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.18481702",
        "record": "mmwave-5g-rff",
        "record_bytes": 35_878_437_473,
        "group": "rf-fingerprinting",
    },
    "mmwave-5g-rff-box-20ms": {
        "url": "https://zenodo.org/api/records/18481702/files/box_20ms.mat/content",
        "filename": "mmwave-5g-rff-box_20ms.mat",
        "bytes": 157_298_864,
        "md5": "12c70486fac2feef1fe01a16fe3be1f7",
        "format": "file",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.18481702",
        "record": "mmwave-5g-rff",
        "record_bytes": 35_878_437_473,
        "group": "rf-fingerprinting",
    },
    "mmwave-5g-rff-bfk06002-20ms": {
        "url": "https://zenodo.org/api/records/18481702/files/bfk06002_20ms.mat/content",
        "filename": "mmwave-5g-rff-bfk06002_20ms.mat",
        "bytes": 157_298_864,
        "md5": "97fbe537ac0069fc805ed2af9e9da74c",
        "format": "file",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.18481702",
        "record": "mmwave-5g-rff",
        "record_bytes": 35_878_437_473,
        "group": "rf-fingerprinting",
    },
    "inria-pla-rff": {
        "url": "https://zenodo.org/api/records/18268648/files/PLA_dataset.zip/content",
        "filename": "inria-PLA_dataset.zip",
        "bytes": 710_685_409,
        "md5": "aff583bee6f4efccd08fe78c731bf03d",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.18268648",
        "record": "inria-pla-rff",
        "record_bytes": 710_685_409,
        "group": "rf-fingerprinting",
    },
    "ruff-uwb-2m-npy": {
        "url": "https://zenodo.org/api/records/11083153/files/UWB_mesures2meters.npy_format.zip/content",
        "filename": "RUFF-UWB_mesures2meters.npy_format.zip",
        "bytes": 1_724_857_002,
        "md5": "cf0a3274285bb6fc58fecfb4cb252d7d",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.11083153",
        "record": "ruff-uwb-rff",
        "record_bytes": 3_835_056_792,
        "representation": "npy",
        "group": "rf-fingerprinting",
    },
    "ruff-uwb-1m-npy": {
        "url": "https://zenodo.org/api/records/11083153/files/UWB_mesures1meter.npy_format.zip/content",
        "filename": "RUFF-UWB_mesures1meter.npy_format.zip",
        "bytes": 793_083_301,
        "md5": "035d22d657c84b77df980a482cff47b1",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.11083153",
        "record": "ruff-uwb-rff",
        "record_bytes": 3_835_056_792,
        "representation": "npy",
        "group": "rf-fingerprinting",
    },
    "wlan-rff-anechoic": {
        "url": "https://zenodo.org/api/records/18515187/files/anechoic_chamber.zip/content",
        "filename": "wlan-rff-anechoic_chamber.zip",
        "bytes": 137_021_472,
        "md5": "9af7491dc891d89969832f0efdee89de",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.18515187",
        "record": "wlan-rff",
        "record_bytes": 244_817_005,
        "group": "rf-fingerprinting",
    },
    "wlan-rff-office": {
        "url": "https://zenodo.org/api/records/18515187/files/office_room.zip/content",
        "filename": "wlan-rff-office_room.zip",
        "bytes": 107_795_533,
        "md5": "8cb50121448016a6c7a1293051b26e1b",
        "license": "CC BY 4.0",
        "doi": "10.5281/zenodo.18515187",
        "record": "wlan-rff",
        "record_bytes": 244_817_005,
        "group": "rf-fingerprinting",
    },
}

GROUPS = frozenset(spec["group"] for spec in SOURCES.values())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "dataset",
        choices=["list", *sorted(GROUPS), "all", *SOURCES],
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).resolve().parents[2] / "data" / "raw",
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
    parser.add_argument(
        "--verify-workers",
        type=int,
        default=min(4, os.cpu_count() or 1),
        help="parallel workers for an existing artifact group (default: up to 4)",
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


def archive_path(spec: dict[str, Any], output_dir: Path) -> Path:
    return output_dir / spec["filename"]


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
    receipt = archive.with_suffix(archive.suffix + ".json")
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{receipt.name}.", dir=receipt.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(metadata, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, receipt)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def download(spec: dict[str, Any], output_dir: Path) -> Path:
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    archive = archive_path(spec, output_dir)
    if archive.is_symlink():
        raise RuntimeError(f"refusing symlink archive path: {archive}")
    if archive.exists():
        verify_existing_archive(archive, spec)
        print(f"reusing verified archive: {archive}")
        return archive

    partial = archive.with_name(f".{archive.name}.part")
    if partial.exists():
        raise RuntimeError(f"refusing to overwrite partial download: {partial}")

    request = urllib.request.Request(
        spec["url"], headers={"User-Agent": "netbraid-local-eval/1"}
    )
    context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cert_file = os.environ.get("SSL_CERT_FILE")
    cert_dir = os.environ.get("SSL_CERT_DIR")
    if cert_file or cert_dir:
        context.load_verify_locations(cafile=cert_file, capath=cert_dir)
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

    if (
        received != spec["bytes"]
        or md5.hexdigest() != spec["md5"]
        or "sha256" in spec
        and sha256.hexdigest() != spec["sha256"]
    ):
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


def verify_existing_archive(archive: Path, spec: dict[str, Any]) -> None:
    if archive.is_symlink() or not archive.is_file():
        raise RuntimeError(f"refusing unsafe archive path: {archive}")
    size, md5, sha256 = digest_file(archive)
    if (
        size != spec["bytes"]
        or md5 != spec["md5"]
        or "sha256" in spec
        and sha256 != spec["sha256"]
    ):
        raise RuntimeError(f"existing archive failed verification: {archive}")
    write_archive_receipt(archive, spec, size, md5, sha256)


def fetch_selected(
    selected: dict[str, dict[str, Any]], output_dir: Path, verify_workers: int
) -> dict[str, Path]:
    if verify_workers <= 0:
        raise RuntimeError("--verify-workers must be positive")
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    items = list(selected.items())
    paths = [archive_path(spec, output_dir) for _, spec in items]
    can_verify_in_parallel = (
        len(items) > 1
        and verify_workers > 1
        and all(path.is_file() and not path.is_symlink() for path in paths)
    )
    if not can_verify_in_parallel:
        return {
            dataset: download(spec, output_dir) for dataset, spec in selected.items()
        }

    worker_count = min(verify_workers, len(items))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(verify_existing_archive, path, spec)
            for (_, spec), path in zip(items, paths, strict=True)
        ]
        archives: dict[str, Path] = {}
        for ((dataset, _), path), future in zip(
            zip(items, paths, strict=True), futures, strict=True
        ):
            future.result()
            print(f"reusing verified archive: {path}")
            archives[dataset] = path
    return archives


def inspect_archive(archive: Path, spec: dict[str, Any]) -> dict[str, Any]:
    artifact_format = spec.get("format", "zip")
    if artifact_format == "file":
        return {
            "archive": str(archive),
            "members": [
                {
                    "name": archive.name,
                    "bytes": archive.stat().st_size,
                    "compressed_bytes": archive.stat().st_size,
                    "directory": False,
                }
            ],
        }
    if artifact_format in {"tar", "tar-gzip"}:
        mode = "r:" if artifact_format == "tar" else "r:gz"
        with tarfile.open(archive, mode) as source:
            members = []
            for member in source.getmembers():
                parts = Path(member.name).parts
                if (
                    member.name.startswith("/")
                    or ".." in parts
                    or member.issym()
                    or member.islnk()
                ):
                    raise RuntimeError(f"unsafe archive member: {member.name}")
                members.append(
                    {
                        "name": member.name,
                        "bytes": member.size,
                        "compressed_bytes": None,
                        "directory": member.isdir(),
                    }
                )
            return {"archive": str(archive), "members": members}
    if artifact_format != "zip":
        raise RuntimeError(f"unsupported artifact format: {artifact_format}")
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
    spec: dict[str, Any],
    member_names: list[str],
    output_dir: Path,
    max_bytes: int,
) -> None:
    if spec.get("format", "zip") != "zip":
        raise RuntimeError("member extraction currently requires a ZIP artifact")
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
    is_group = args.dataset in GROUPS or args.dataset == "all"
    if is_group and args.extract_member:
        raise RuntimeError("--extract-member requires one named artifact")

    if is_group:
        groups = {args.dataset} if args.dataset != "all" else GROUPS
        selected = {
            name: spec for name, spec in SOURCES.items() if spec["group"] in groups
        }
    else:
        selected = {args.dataset: SOURCES[args.dataset]}
    archives = fetch_selected(selected, args.output_dir.resolve(), args.verify_workers)
    inventories: dict[str, dict[str, Any]] = {}
    for dataset, spec in selected.items():
        archive = archives[dataset]
        if args.inspect:
            inventories[dataset] = inspect_archive(archive, spec)
        if args.extract_member:
            extract_members(
                archive,
                spec,
                args.extract_member,
                (
                    args.extract_dir or args.output_dir / f"extracted-{dataset}"
                ).resolve(),
                args.max_extract_bytes,
            )

    if args.inspect:
        inventory: dict[str, Any]
        if is_group:
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
