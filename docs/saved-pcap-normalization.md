# Saved-PCAP normalization

Status: experimental

## Problem

Netmon needs a reproducible way to turn a staged packet-capture artifact into
versioned, policy-neutral evidence. Equal staged bytes, field registry, TShark
build, and effective-configuration fingerprint must produce equal records. A
capture is valuable for regression tests, incident handoff, and later reducers,
but raw dissector output is not a stable application contract.

The boundary must preserve what was observed without claiming endpoint identity,
application identity, physical location, or intent. It must also be safe to run
from an operator CLI: no shell interpolation, no live capture, no name
resolution, finite work, and explicit normalization completeness.

## Context

TShark already owns packet-file decoding and protocol dissection. Its documented
`-r` option reads a saved capture, `-n` disables name resolution, and
`-T fields` with repeated `-e` arguments selects an explicit field set. The
`-E` options define field separators, occurrence selection, and quoting. TShark
also offers `-T json` and `-T ek`, but those expose a much
larger dissector-shaped tree and require consumers to handle duplicate and
version-dependent keys.

Sources:

- [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html)
- [Capinfos manual](https://www.wireshark.org/docs/man-pages/capinfos.html)
- [Wireshark configuration files](https://www.wireshark.org/docs/wsug_html_chunked/ChAppFilesConfigurationSection.html)
- [Wireshark Lua startup](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html)

Netmon already separates pure evidence records (`netmon-evidence`) from
deterministic file/replay mechanics (`netmon-replay`). The process boundary has
a different dependency and failure profile from either crate.

Capinfos is part of the same Wireshark tool suite and reads the same capture
formats as TShark. Its table mode can report file type, encapsulation, timestamp
precision, snap length, packet and byte counts, capture span, and capture-file
provenance without deriving those values from the subset of packets emitted by
the normalizer.

## Non-goals

- Live capture, monitor mode, channel control, or privilege management.
- Active discovery or traffic generation.
- DNS, MAC-vendor, or service-name resolution during normalization.
- Payload retention or application-content extraction.
- Reimplementing libpcap, wiretap, or Wireshark dissectors in Rust.
- Flow/session reconstruction, endpoint identity, device role, location, person
  presence, or traffic-fingerprint conclusions.
- Treating a protocol field, port number, hostname, or TLS value as verified
  application identity.
- A daemon, database, retention policy, or background watcher.
- A receipt for failed or interrupted normalization attempts in the v0 schema.
- Hashing the TShark or Capinfos executable files themselves.
- Normalizing detailed pcapng interface-description blocks, name-resolution
  blocks, capture comments, or packet comments in the first metadata schema.

## Options considered

### Expose raw `-T json` or `-T ek`

This keeps implementation small but makes Wireshark's full, evolving dissector
tree Netmon's de facto schema. Duplicate keys, repeated layers, and tool-version
differences would then leak into every consumer. Rejected.

### Decode packets directly in Rust

This could remove the process dependency, but it duplicates mature capture-file
and protocol-dissection work while expanding Netmon's security and maintenance
surface. Rejected.

### Keep the normalizer in the CLI package

This avoids a crate, but mixes process control, resource limits, parser
quarantine, staging, effective-configuration fingerprinting, and tool provenance
into an unrelated compatibility reader. Those invariants and dependencies form
a reusable process boundary independently of presentation. Rejected.

### Add an explicit TShark adapter crate

`netmon-adapter-tshark` owns one offline process boundary. It invokes TShark
without a shell, uses a declared `-T fields` registry, enforces a deadline and
output/input limits, records tool, registry, and effective-configuration
versions, and returns typed records plus quarantined rows. Chosen.

### Infer capture-file metadata from emitted packet envelopes

Summing emitted frame lengths and taking their minimum and maximum timestamps
would be deterministic, but wrong whenever a packet limit is reached, a row is
quarantined, or a capture contains metadata not repeated on packets. Rejected.

### Parse Capinfos' long human-readable report

The long report includes detailed interface information, but its indentation,
localized labels, and repeated prose form a display contract rather than a
machine contract. Rejected for the first schema.

### Parse a bounded Capinfos table

Capinfos table mode supplies a header and one quoted CSV row per input file.
Netmon selects a fixed metadata field set, suppresses free-form capture and
packet comments, maps known headers into a typed record, and ignores additional
headers. This keeps file-level facts separate from packet normalization while
reusing the same isolated Wireshark process boundary. Chosen.

## Chosen approach

The dependency direction is:

```text
netmon-evidence
    ^              ^
    |              |
netmon-replay   netmon-adapter-tshark
                       ^
                       |
                    netmon CLI
```

`netmon-evidence` owns four pure record families:

- a capture manifest with content digest, byte length, observer provenance,
  extractor provenance, optional acquisition policy, and normalization
  completeness;
- packet-envelope records with capture/frame identity, exact event time, frame
  lengths, protocol stack, and first-occurrence link/network/transport fields;
- quarantine records with the source row and a parser reason;
- a successful normalization-run receipt with an occurrence identifier,
  wall-clock interval and monotonic elapsed time, capture-file metadata, bounded
  tool-invocation receipts, and a digest of the emitted manifest, packet, and
  quarantine records.

The adapter uses an ordered field registry and explicitly selects the first
occurrence for every field. That rule is important for tunnels and repeated
headers: the packet's ordered `frame.protocols` stack remains available, while
individual IPv4, IPv6, TCP, and UDP field groups are only the first value TShark
reported for that named field. They are not asserted to form one flattened
conversation.

The initial registry contains frame number and epoch time; original and captured
lengths; section, interface, and encapsulation IDs; ordered protocol names;
Ethernet source/destination; first IPv4 and IPv6 source/destination plus protocol
number; and first TCP/UDP ports plus TCP flags.

The invocation is offline-only:

```text
tshark -n -Q -r INPUT -c PACKET_LIMIT -T fields \
  -E header=n -E separator=/t -E occurrence=f -E quote=n \
  -e FIELD ...
```

Before packet dissection, the adapter invokes Capinfos against the same staged
file:

```text
capinfos -T -R -m -Q -K -P -t -E -F -c -s -d -l -u -a -e -S INPUT
```

`-K` and `-P` suppress capture and packet comments. The selected table fields
describe the file container and its declared capture extent; they do not prove
what traffic, interfaces, channels, or locations were observable when the file
was acquired. Netmon parses quoted CSV using exact header names. Required
file-level fields fail closed; optional snap-length and capture-application
fields remain absent when the installed Capinfos does not report them.

All selected fields have bounded numeric, address, or protocol-stack syntax; no
free-form dissector text or payload field is selected. The adapter sets a stable
locale, removes TShark's documented inherited data/plugin/extcap/build-directory,
format-detection, abort, and logging overrides, captures stdout/stderr without a
shell, drains both concurrently, kills the process at the deadline, and rejects
output beyond configured byte limits.

The input must resolve to a regular file. Netmon copies it into a private
temporary directory while hashing those exact copied bytes, and TShark receives
only the staged path. This prevents TShark's special `-r -` stdin behavior and
ensures the manifest digest identifies the staged artifact TShark reads. The
staged file is hashed again after dissection; a mismatch fails the import.

TShark dissection also depends on preferences, disabled protocols, decode-as
rules, heuristics, and plugins. The adapter redirects the personal configuration
directory to an empty temporary directory, then fingerprints the complete
`--version`, `-G currentprefs`, `-G fields`, `-G plugins`, `-G protocols`,
`-G heuristic-decodes`, and `-G decodes` reports. Report lines are sorted before
hashing because Wireshark does not promise report order. Personal or system
plugins are executable code, not passive data. The default refuses non-empty
personal plugin trees before starting TShark; an operator must explicitly allow
them. System plugins, and explicitly allowed personal plugins, remain part of
the effective-registration fingerprint. This is provenance, not a claim that
TShark is a hermetic sandbox.

The successful-run receipt records the configured executable strings, first
version lines, an argument template using `$STAGED_CAPTURE` instead of the
deleted temporary pathname, the stable environment-policy identifier, process
exit codes, and SHA-256 digests of bounded stdout and stderr. It also records a
versioned digest profile and domain-separated SHA-256 over the schema-ordered
compact JSON encoding of the emitted manifest, packet envelopes, and
quarantines. The profile length-prefixes each record and binds its record kind
and index; this is deterministic framing, not RFC 8785 canonical JSON. Capinfos
stdout includes its staged pathname, so its raw-output digest identifies this
occurrence; typed metadata and the emitted-record digest remain stable across
equivalent runs.

Run identifiers are occurrence identifiers, not content identifiers. The v0
adapter derives one from the capture digest, run start time, process identifier,
and a per-process counter. Started and finished times use the system clock;
elapsed time uses a monotonic clock and remains meaningful if wall time is
adjusted during the run.

Artifact acquisition time, observer identity, and acquisition policy are
optional because a detached PCAP often cannot prove any of them; their absence
remains explicit. Offline normalization is passive, but that does not imply the
original acquisition was passive.

The default CLI is a finite text summary for operators. It distinguishes
capture-file facts from the possibly limited normalized packet subset and
surfaces the successful run identifier and record digest. Its text projection
also uses the pure, capture-wide conversation reducer specified in
[`design/capture-conversation-reduction.md`](design/capture-conversation-reduction.md).
`--jsonl` emits the manifest, occurrence-specific run receipt, packet
envelopes, and quarantines. It is the complete successful-run record, not a
byte-stable rerun projection: the receipt contains its run ID, wall-clock
interval, elapsed time, and raw Capinfos output digest.

`--records-jsonl` emits exactly the normalized-record digest sequence:
manifest, packet envelopes in capture/frame order, and quarantines in source
row order. It omits the run receipt. Equal staged bytes, independently supplied
provenance, extractor/tool versions, effective configuration, field registry,
and limits therefore produce byte-identical record streams. The receipt binds
that stream through `normalized_records_sha256`; consumers do not need to
filter occurrence fields to compare reruns. `--jsonl` and `--records-jsonl`
are mutually exclusive. Neither mode implies a serialized flow or conversation
contract.

Normalization is non-interactive: a future replay TUI may consume these records,
but the normalizer itself should compose predictably in scripts.

### Fixture corpus

Adapter promotion uses two complementary fixture tiers. Hand-authored,
commented hex captures isolate exact packet and container fields using
documentation addresses and locally administered MAC addresses. A curated
upstream corpus exercises behavior that hand-built one-packet files can easily
miss: radiotap/802.11 encapsulation, non-IP Ethernet, PPPoE discovery, severe
snaplen truncation, multi-conversation timing, big-endian PCAPNG, section and
interface fields, and file-embedded capture provenance.

Upstream artifacts are admitted only with a redistribution license, immutable
repository revision and source path, Git blob ID, decoded SHA-256 digest,
bounded size, and a named behavior. The committed representation is exact
binary content rendered as lowercase hex, so source review remains textual.
The normal test suite verifies the ledger, licenses, complete file inventory,
decoded size, and digest without network access or Wireshark. The opt-in smoke
suite additionally normalizes every admitted capture using installed Capinfos
and TShark and checks stable container facts, row coverage, and required
protocol vocabulary.

The corpus does not make the upstream artifact's original observer or
acquisition policy knowable. Those fields remain absent. Public parser fixtures
also do not substitute for private, sealed deployment fixtures when evaluating
Kismet, Hypha, rtl_433, Meshtastic, controller, or fusion adapters.

## Tradeoffs

- TShark remains a runtime dependency for this command, but Netmon does not
  inherit Wireshark's capture or dissector implementation.
- First-occurrence fields are deliberately lossy for nested tunnels. The ordered
  protocol stack and explicit registry semantics prevent that loss from being
  mistaken for a complete decoded tree.
- Staging plus a post-run hash adds disk and I/O cost. It makes the content
  address apply to the private file object actually passed to TShark rather than
  three independent opens of a caller-controlled pathname.
- Effective-configuration probes add TShark startup cost. The resulting digest
  prevents equal tool-version strings from hiding different preferences or
  registered dissectors, but it is not a portable bundle of the plugin code.
- Hitting the packet limit or quarantining rows makes normalization partial. Byte
  limit and subprocess failures emit no successful manifest.
- Quarantining malformed rows retains useful valid evidence, but downstream
  consumers must inspect normalization state rather than assuming every input
  packet was normalized.
- Normalization completeness says nothing about acquisition coverage. A detached
  artifact cannot prove which network, channels, interfaces, or time interval
  the original collector could observe unless separately supplied provenance
  does so.
- Requiring Capinfos adds one bounded process and makes the command depend on
  both standard Wireshark CLI programs. This avoids fabricating file facts from
  partial packet rows.
- A successful-run receipt supports reproduction and comparison, but is not an
  attestation: it is unsigned, the configured tool path is not resolved and
  hashed, and v0 writes no durable receipt when a subprocess fails.

## Implementation plan

1. Add capture-manifest, packet-envelope, and quarantine records plus validation
   to `netmon-evidence`.
2. Add `netmon-adapter-tshark` with a fixed field registry, bounded process
   execution, exact timestamp parsing, artifact hashing, and row quarantine.
3. Add `netmon pcap INPUT` with human text by default, `--jsonl` for a complete
   successful-run record, and `--records-jsonl` for the deterministic
   normalized-record stream.
4. Add parser/golden tests and an opt-in smoke test against an installed TShark
   using readable synthetic captures.
5. Update the public scope and command documentation.
6. Add bounded Capinfos metadata, a successful-run receipt, and PCAPNG replay
   coverage without changing the crate dependency direction.
7. Admit a compact, licensed upstream corpus through a content-addressed
   manifest and run it through the same installed-tool smoke boundary.

## Gates

- The adapter never invokes a shell and never accepts arbitrary TShark
  arguments.
- `-n` is always present; normalization performs no name resolution.
- Documented TShark environment overrides that can redirect executable code or
  alter dissection, format detection, failure, or logging behavior are removed.
  The adapter supplies only its isolated configuration directory and stable
  locale.
- The caller input must be a regular file; TShark receives only a private staged
  path and cannot select stdin or a live interface.
- Input bytes, packet count, stdout, and stderr are bounded; every TShark
  subprocess has a deadline. Host filesystem reads remain subject to operating
  system I/O behavior.
- The staged artifact digest is identical before and after TShark runs.
- Capinfos and TShark read the same private staged file. Capinfos' file byte
  count must equal the staged artifact byte count.
- The effective configuration is fingerprinted from canonicalized TShark
  reports, and repeated normalization proves the fingerprint and records stable.
- Personal Wireshark plugins are refused by default and require an explicit
  operator opt-in.
- The field order and occurrence policy have a versioned registry identifier.
- Epoch timestamps parse without floating-point arithmetic.
- Invalid rows are retained as typed quarantines and make normalization partial.
- Packet order remains capture/frame order.
- Golden tests cover canonical JSON and parser edge cases.
- A real Wireshark-tool-suite smoke test exercises synthetic and curated
  upstream PCAP/PCAPNG across Ethernet, radiotap/802.11, ARP/RARP, PPPoE,
  truncated IPv4, UDP/NTP, DHCP, and both container byte orders.
- Every upstream fixture is pinned by immutable source revision and path, Git
  blob ID, decoded SHA-256, size, license, and named purpose. The manifest and
  directory inventory must agree exactly.
- Successful receipts use a staged-path placeholder rather than retaining a
  private temporary pathname, and bind the emitted records with a canonical
  digest.
- Repeating `--records-jsonl` over the same fixture and effective
  normalization contract produces byte-identical output without a run receipt.
- Text output states file type, encapsulation, declared file extent,
  normalization state, limits, quarantine count, extractor version, run
  identifier, and emitted-record digest.

## Open questions

- Which application-layer fields deserve a second registry after representative
  captures demonstrate an operator question they answer?
- Which detailed pcapng interface metadata warrants a separate schema rather
  than being flattened into file metadata or repeated packet fields?
- What durable failure-receipt destination and redaction policy could preserve
  diagnostics without leaking capture paths or unbounded tool output?
- When should executable resolution and hashing become required provenance
  rather than an operator packaging concern?
- What evidence and evaluation threshold would justify advisory traffic
  fingerprints without turning them into identity claims?
