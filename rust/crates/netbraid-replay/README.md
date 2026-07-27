# netbraid-replay

`netbraid-replay` provides deterministic JSONL replay, host-path comparison,
saved-capture validation, capture-conversation reduction, and bounded triage
projections over `netbraid-evidence` records.

It is a library, not a daemon, store, collector, identity authority, or live
fusion service. Given the same records and bounds, its replay and projections
are deterministic.

```toml
[dependencies]
netbraid-replay = "0.3"
```

License: MIT OR Unlicense.
