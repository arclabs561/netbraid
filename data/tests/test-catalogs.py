#!/usr/bin/env python3
"""Hermetic contract tests for tracked public-source catalogs."""

from __future__ import annotations

import ipaddress
import json
import re
import unittest
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "data" / "catalog" / "research-leads-v1.json"

SOURCE_TYPES = {
    "adapter_source",
    "dataset",
    "discussion",
    "discovery_index",
    "format_specification",
    "hardware_reference",
    "implementation_reference",
    "integration_reference",
    "interchange_format",
    "name_collision",
    "paper",
    "system_oracle",
}
ACCESS = {
    "direct_download",
    "discovery_only",
    "documentation_only",
    "gated",
    "public_page",
}
LICENSES = {
    "cc_by_4_0",
    "manual_terms",
    "mit",
    "not_applicable",
    "per_artifact",
    "research_terms",
    "unknown",
}
DISPOSITIONS = {"candidate", "manual_only", "name_collision", "reference_only"}
FETCH_STATES = {
    "existing_fetcher",
    "investigate_before_pinning",
    "manual_access",
    "not_applicable",
}
PRIORITIES = {"P0", "P1", "P2", "P3"}
PRIVATE_TOKEN = re.compile(
    r"(?i)(/users/|documents/dev|localhost|api[_-]?key|password|secret|token)"
)


def load_catalog() -> dict:
    return json.loads(CATALOG.read_text(encoding="utf-8"))


def entry_urls(entry: dict) -> list[str]:
    return [entry["canonical_url"], *entry["related_urls"]]


class CatalogTests(unittest.TestCase):
    def test_catalog_has_stable_shape_and_unique_public_urls(self):
        catalog = load_catalog()
        self.assertEqual(catalog["schema"], "netbraid.public_source_leads.v1")
        entries = catalog["entries"]
        self.assertGreaterEqual(len(entries), 20)

        ids = [entry["id"] for entry in entries]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(
            all(re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", item) for item in ids)
        )

        urls = [url for entry in entries for url in entry_urls(entry)]
        self.assertEqual(len(urls), len(set(urls)))
        for url in urls:
            parsed = urlparse(url)
            self.assertEqual(parsed.scheme, "https")
            self.assertTrue(parsed.hostname)
            self.assertFalse(parsed.hostname.endswith(".local"))
            try:
                address = ipaddress.ip_address(parsed.hostname)
            except ValueError:
                continue
            self.assertFalse(address.is_private or address.is_loopback)

    def test_entry_vocabularies_and_admission_boundaries(self):
        required = {
            "id",
            "title",
            "source_type",
            "canonical_url",
            "related_urls",
            "access",
            "license",
            "modalities",
            "roles",
            "disposition",
            "fetch",
            "priority",
            "note",
        }
        for entry in load_catalog()["entries"]:
            self.assertEqual(set(entry), required, entry["id"])
            self.assertIn(entry["source_type"], SOURCE_TYPES)
            self.assertIn(entry["access"], ACCESS)
            self.assertIn(entry["license"], LICENSES)
            self.assertIn(entry["disposition"], DISPOSITIONS)
            self.assertIn(entry["fetch"], FETCH_STATES)
            self.assertIn(entry["priority"], PRIORITIES)
            self.assertTrue(entry["modalities"])
            self.assertTrue(entry["roles"])

            if entry["access"] == "gated":
                self.assertEqual(entry["fetch"], "manual_access")
                self.assertEqual(entry["disposition"], "manual_only")
            if entry["source_type"] == "discovery_index":
                self.assertEqual(entry["disposition"], "reference_only")
                self.assertEqual(entry["fetch"], "not_applicable")
            if entry["fetch"] == "investigate_before_pinning":
                self.assertEqual(entry["source_type"], "dataset")
                self.assertNotEqual(entry["license"], "not_applicable")

    def test_catalog_contains_no_local_or_secret_bearing_values(self):
        payload = CATALOG.read_text(encoding="utf-8")
        self.assertIsNone(PRIVATE_TOKEN.search(payload))


if __name__ == "__main__":
    unittest.main(verbosity=2)
