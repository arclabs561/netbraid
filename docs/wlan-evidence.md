# IEEE 802.11 evidence

Saved-capture packet envelopes can include optional IEEE 802.11 and normalized
radio facts selected from TShark. They let an operator answer bounded questions
about what the artifact contains without promoting RF metadata into identity or
coverage claims.

## Record fields

The optional IEEE 802.11 group can contain:

- numeric frame type and subtype;
- transmitter, receiver, source, destination, and BSS addresses when present;
- a nonempty SSID element encoded as lowercase hexadecimal bytes.

The optional radio group can contain channel, center frequency in MHz, and
reported signal power in dBm. These are fields supplied by the capture and
dissector. They are not calibrated measurements or proof of complete channel
coverage.

SSID bytes remain authoritative. Text output may render valid UTF-8 for an
operator, but an empty or absent field remains unknown rather than becoming a
hidden-network assertion.

## Operator summary

The finite summary reports:

1. wireless-record and field coverage;
2. ranked frame type/subtype mix with numeric values;
3. observed radio contexts and signal ranges;
4. bounded BSS and transmitter-address pivots; and
5. observed nonempty SSID elements.

Every ranked section reports how much of the observed set is displayed. Machine
JSONL retains the complete normalized records.

## Limits

One address, network name, frame mix, channel, or signal range does not
establish device identity, owner, role, person, place, activity, intent,
association state, attack, or causality. Absence is not supported without
relevant channel/time coverage and complete normalization.

Netbraid does not transmit probes, deauthenticate clients, control channels, or
open a live interface in the Rust saved-capture path.
