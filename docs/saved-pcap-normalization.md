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

`netmon-evidence` owns three pure record families:

- a capture manifest with content digest, byte length, observer provenance,
  extractor provenance, optional acquisition policy, and normalization
  completeness;
- packet-envelope records with capture/frame identity, exact event time, frame
  lengths, protocol stack, and first-occurrence link/network/transport fields;
- quarantine records with the source row and a parser reason.

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

Artifact acquisition time, observer identity, and acquisition policy are
optional because a detached PCAP often cannot prove any of them; their absence
remains explicit. Offline normalization is passive, but that does not imply the
original acquisition was passive.

The default CLI is a finite text summary for operators. `--jsonl` emits the
manifest, packet envelopes, and quarantines as versioned records. Normalization
is non-interactive: a future replay TUI may consume these records, but the
normalizer itself should compose predictably in scripts.

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

## Implementation plan

1. Add capture-manifest, packet-envelope, and quarantine records plus validation
   to `netmon-evidence`.
2. Add `netmon-adapter-tshark` with a fixed field registry, bounded process
   execution, exact timestamp parsing, artifact hashing, and row quarantine.
3. Add `netmon pcap INPUT` with human text by default and `--jsonl` for machine
   output.
4. Add parser/golden tests and an opt-in smoke test against an installed TShark
   using Ethernet/IPv4/TCP, Ethernet/IPv6/UDP, and ARP fixtures built only from
   documentation addresses and locally administered MAC addresses.
5. Update the public scope and command documentation.

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
- The effective configuration is fingerprinted from canonicalized TShark
  reports, and repeated normalization proves the fingerprint and records stable.
- Personal Wireshark plugins are refused by default and require an explicit
  operator opt-in.
- The field order and occurrence policy have a versioned registry identifier.
- Epoch timestamps parse without floating-point arithmetic.
- Invalid rows are retained as typed quarantines and make normalization partial.
- Packet order remains capture/frame order.
- Golden tests cover canonical JSON and parser edge cases.
- A real TShark smoke test exercises the process boundary against three
  link/network/transport shapes.
- Text output states normalization state, limits, quarantine count, and
  extractor version.

## Open questions

- Which application-layer fields deserve a second registry after representative
  captures demonstrate an operator question they answer?
- Should later reducers group bidirectional flows before or after
  observer/capture alignment?
- Which capture metadata should be normalized directly from pcapng interface
  blocks rather than repeated packet fields?
- What evidence and evaluation threshold would justify advisory traffic
  fingerprints without turning them into identity claims?
