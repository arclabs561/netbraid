---
status: implemented
consumers:
  - Netmon CLI
future-consumers:
  - Linktop focused wireless-evidence view
related:
  - ../saved-pcap-normalization.md
  - rust-library-boundary.md
  - capture-conversation-reduction.md
---

# Saved-capture IEEE 802.11 evidence

## Problem

The saved-capture adapter can normalize a radiotap capture without loss at the
file or frame boundary, but its v0 packet field registry exposes only the
ordered `radiotap:wlan_radio:wlan` protocol stack. An operator cannot answer the
first useful wireless questions from Netmon records:

- Which IEEE 802.11 frame types and subtypes dominate the artifact?
- Which transmitter, receiver, and BSS identifiers were observed?
- Which channel and center frequency were represented?
- What signal-power range did the capture metadata report?
- Which nonempty SSID elements occurred, as raw bytes rather than guessed text?

The curated libpcap radiotap fixture makes this gap executable. Wireshark 4.6.4
on Linux and 4.6.7 on macOS expose the same candidate fields.

## Context and constraints

`PacketEnvelopeV0` is a released JSON schema and a Rust type in a
`publish = false` experimental workspace. Normalized-record digests bind the
manifest, its field-registry ID, and every packet record. Older Serde readers
ignore unknown object fields, while new optional fields deserialize as absent
from old records. Rust struct literals do not have that source-compatibility:
adding a public field requires consumers to update when they repin.

TShark remains the dissection owner. Netmon must select bounded scalar fields,
use first-occurrence semantics consistently, preserve unknowns, and avoid
free-form display text. Radio metadata describes what the capture supplied for
one frame; it is not a calibrated RF measurement or evidence of complete
channel coverage.

## Options considered

### Add optional groups to `PacketEnvelopeV0`

Add `ieee80211` and `wlan_radio` objects, leave them absent for non-wireless
frames, and bump the adapter field registry from
`netmon.tshark.packet_envelope.v0` to `.v1`. Existing JSON readers continue to
read new records and new readers continue to read old records. Exact-Git Rust
consumers must repin deliberately. Chosen.

### Create `PacketEnvelopeV1`

A parallel full-frame schema would make the source-level break explicit, but it
would duplicate every Ethernet/IP/transport field and force reducers and
consumers to support two nearly identical frame types. Deferred until a change
cannot be represented as optional evidence.

### Emit a separate wireless-frame record

This would compose by `capture_id` and frame number, but changes the normalized
record sequence, receipt digest profile, and replay dispatch for facts that are
already attributes of one dissected frame. Rejected for this slice.

### Parse wireless facts only for terminal output

An extra projection-only TShark path could improve the display quickly, but its
facts would be absent from JSONL, receipts, and deterministic replay. Rejected.

## Chosen record contract

`PacketEnvelopeV0.ieee80211` contains:

- numeric frame type and subtype;
- optional transmitter address (TA), receiver address (RA), source address
  (SA), destination address (DA), and BSSID; and
- an optional nonempty SSID element encoded as lowercase hexadecimal bytes.

Type and subtype are required together. Every address remains optional because
the IEEE 802.11 header shape depends on frame class and distribution-system
bits. Address validation uses the same canonical six-octet form as Ethernet
fields. Empty or absent `wlan.ssid` output remains unknown; Netmon does not turn
that ambiguity into a hidden-network assertion.

`PacketEnvelopeV0.wlan_radio` contains optional channel number, center
frequency in MHz, and signal power in dBm. The group is present when any of
those fields is present. Netmon uses Wireshark's normalized `wlan_radio.*`
fields instead of binding the schema to radiotap-specific duplicates.

The ordered registry adds:

```text
wlan.fc.type
wlan.fc.subtype
wlan.ta
wlan.ra
wlan.sa
wlan.da
wlan.bssid
wlan.ssid
wlan_radio.channel
wlan_radio.frequency
wlan_radio.signal_dbm
```

Changing the registry ID is mandatory. Even Ethernet-only reruns use a
different extractor contract and therefore must not compare equal to v0
normalization.

## Operator projections

Finite text adds an `IEEE 802.11` section before capture conversations when at
least one packet has wireless fields. It answers, in order:

1. coverage: wireless frames, frames with radio metadata, BSSID coverage, and
   transmitter-address coverage;
2. frame mix: ranked expert labels plus numeric type/subtype;
3. radio contexts: channel, center frequency, frame count, and observed signal
   range/median when available;
4. top BSSIDs and transmitter addresses by frame count; and
5. nonempty SSID elements, rendering valid UTF-8 as bounded operator text while
   retaining the authoritative hex bytes.

Every ranked finite-text subsection reports how many unique values it shows
out of the observed total and names the omitted count when bounded. Numeric
type/subtype values remain beside the expert IEEE 802.11 label so a vocabulary
correction cannot erase the underlying evidence.

Raw JSONL remains the complete machine projection. A future Linktop consumer
may place the same evidence in a focused wireless view with paging and
source/coverage context. It must not place an unbounded neighbor table in the
always-visible host-path dashboard, and switching views must not trigger
collection.

## Non-goals

- No device identity, vendor, role, person, activity, or intent inference from
  one address or frame mix.
- No claim that a missing BSSID, SSID, channel, or transmitter was absent from
  the environment; capture coverage is not established.
- No active scan, probe request, deauthentication, association, channel
  control, or Bluetooth behavior.
- No per-antenna radiotap array, PHY-rate/MCS decoding, security-suite
  interpretation, or calibrated signal model in the first registry.
- No new shared reducer API until Linktop or another concrete consumer needs
  the exact aggregation contract.

## Tradeoffs

The additive wire shape is simpler than a parallel envelope but changes Rust
struct construction and every adapter registry digest. Numeric subtype labels
require a small maintained IEEE 802.11 vocabulary in the CLI; JSONL retains the
numbers if a label later needs correction. First-occurrence SSID bytes are
lossy when a malformed frame repeats the element, and empty versus absent
cannot be distinguished through this TShark field projection. Those limits are
explicit and preferable to guessing.

## Implementation plan

1. Add and validate optional IEEE 802.11 and normalized radio groups in
   `netmon-evidence`.
2. Extend the fixed TShark registry, bump its ID, and parse all-or-unknown field
   groups without changing process or acquisition behavior.
3. Update the radiotap corpus expectations and schema fixtures.
4. Add a bounded finite-text projection in the Netmon CLI.
5. Re-run the exact corpus on local Wireshark and Dratini's older Wireshark,
   then rebuild Linktop against the new exact Git revision before it repins.

## Decision gates

- Stop and introduce a new envelope schema if a required field cannot be added
  as optional evidence or changes the meaning of an existing field.
- Stop and introduce a separate record/digest profile if wireless evidence no
  longer has one-to-one frame identity.
- Do not promote SSID absence, role fingerprints, location, or device identity
  until representative fixtures define coverage and an explicit abstention
  contract.
- Extract a reusable wireless reducer only when a second consumer needs the
  exact aggregation, ordering, and coverage semantics.
