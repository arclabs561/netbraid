# Architecture

Netbraid separates evidence types, deterministic replay, external-tool
adapters, and presentation so that changing a CLI or tool invocation does not
silently change what a record means.

## Dependency direction

```text
                  netbraid::evidence
                    ^           ^
                    |           |
          netbraid::replay   adapters::tshark
                    ^           ^
                    \           /
                     netbraid CLI
```

`evidence` has no CLI, collection, controller, or process dependency. `replay`
parses and reduces those types without contacting the network. The optional
TShark adapter owns subprocess control and saved-capture normalization. The CLI
selects a finite human or machine projection.

## Evidence model

Evidence records preserve:

- a schema and producer identity;
- observer and acquisition provenance when known;
- event and artifact time bounds;
- source extent and normalization completeness;
- typed observed fields;
- quarantined input that could not be represented; and
- limitations needed to interpret absence or inference.

Canonical serialization and domain-separated digests make deterministic record
streams comparable. Occurrence receipts bind one run, its wall-clock interval,
tool invocations, and the digest of the deterministic records. Occurrence
fields are deliberately excluded from `--records-jsonl`.

## Saved-capture path

1. Resolve one regular input file and copy it into a private staging directory.
2. Hash the staged bytes.
3. Run bounded Capinfos for file/container facts.
4. Run bounded TShark with name resolution disabled and an explicit registry.
5. Parse typed rows; preserve invalid rows as quarantines.
6. Re-hash the staged file and reject a mutation.
7. Emit a manifest, packet records, quarantines, and a successful-run receipt.
8. Reduce eligible packet records into conservative capture conversations.

Conversation direction uses canonical endpoint order. It does not infer
initiator, client/server roles, application identity, or intent. Packets with
ambiguous or unsupported layer shapes remain counted as excluded evidence.

## Scenario path

A scenario loader opens a closed directory, verifies the exact digest-bound
inventory, parses the manifest-selected schema, and validates every evidence
reference, checkpoint, coverage row, conclusion, abstention, and viewport.
Replay returns only the finite prefix declared at a named checkpoint.

Scenarios carry authored oracles. Validation proves their structural and
evidence closure; it does not certify arbitrary prose as ground truth.

## Compatibility snapshots

The `net`, `device`, and `here` commands read a historical controller audit
shape. They are a compatibility edge around saved data, not part of the
evidence core and not a live controller client.

## Legacy acquisition

The Go program is a separate live process that writes PCAP and event artifacts.
It shares a repository and binary name for historical reasons but no Rust
runtime or data model. The Docker image contains only that compatibility
binary. New reusable contracts belong in the Rust package.

See [Design decisions](../DECISIONS.md) for the constraints behind this
structure.
