# netbraid-replay

`netbraid-replay` provides deterministic JSONL replay, host-path comparison,
saved-capture validation, capture-conversation reduction, bounded triage
projections, and an endpoint-independent packet-shape fingerprint candidate
over `netbraid-evidence` records. It also validates closed, finite
operator-scenario bundles and replays their named checkpoints.

It is a library, not a daemon, store, collector, identity authority, or live
fusion service. Given the same records and bounds, its replay and projections
are deterministic.

`project_saved_pcap_fingerprint_v0` consumes a validated
`SavedPcapTriageV1` projection and emits
`netmon.saved_pcap_fingerprint_candidate.v0`. Only an observed eligible
IP/TCP/UDP conversation produces a digest. The digest excludes endpoint
addresses and ports; partial normalization and unsupported packet evidence
remain typed abstentions. The candidate is not a device identity, a
cross-observer join, or a person, place, or intent claim.

```toml
[dependencies]
netbraid-replay = "0.3"
```

The normal library embeds no scenarios. The non-default
`scenario-fixtures` feature provides exactly four
`netbraid.scenario_bundle.v0` `PUBLIC_SYNTHETIC` bundles. The separate
`scenario-fixtures-capture-derived` feature provides one strict
`netbraid.scenario_bundle.v1` `PUBLIC_REVIEWED` bundle derived from an admitted
public saved capture.

Version 1 separates disclosure sensitivity from source origin, derivation, and
acquisition. It records exact upstream, corpus, digest, size, and SPDX
coordinates; enumerates identifier classes retained in ingestible evidence;
requires a digest-bound `license_text` artifact that cannot be ingested or
cited as evidence; and requires packet payload bytes to be omitted from
ingestible evidence artifacts. The loader derives identifier classes from
every admitted typed saved-capture record and requires an exact declaration;
v1 rejects host-path streams and opaque quarantine rows rather than
distributing bytes outside that closure. Legal notice text is separately
classified and retained verbatim.
Viewport text remains v0-only until presentation bytes have their own
disclosure contract.
Version 0 retains `netbraid.scenario_replay.v0`. Version 1 emits
`netbraid.scenario_replay.v1`, carrying its bundle schema, declared
sensitivity, and declared disclosure review alongside the unchanged checkpoint
projection fields. Structural loading and replay do not authenticate that
declaration.

License: `(MIT OR Unlicense) AND BSD-3-Clause`. Netbraid-authored source is
available under MIT OR Unlicense; the packaged capture-derived fixture and its
notice are BSD-3-Clause.
