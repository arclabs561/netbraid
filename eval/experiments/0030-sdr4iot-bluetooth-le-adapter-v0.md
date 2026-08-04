# SDR4IoT Bluetooth LE adapter conformance v0

## Hypothesis

The bounded TShark adapter can normalize every packet in one complete SDR4IoT
Bluetooth LE capture into typed link-layer evidence with nested radio metadata,
without quarantine or treating an observed address as physical-device identity.

## Method

This hypothesis was written before the corpus evaluation. The implementation
basis is Git commit `7cdaff2`; the producer commit will be recorded with the
result.

The evaluator must verify the 78,658,727-byte parent archive and selected
12,375-byte member, run the normalizer twice with a 1,000-packet bound, require
byte-identical canonical records, and verify that the extracted input remains
unchanged. The committed oracle contains aggregate packet, PDU-type,
address-field-presence, address-header-flag, CRC, channel, signal, and noise
counts only. It must retain no address value, access address, record ID, raw
row, local path, or capture bytes.

Success requires complete normalization of all 227 packets, zero quarantines,
227 typed Bluetooth LE records, and exact agreement with the preregistered
aggregate oracle. Signal and noise are accepted only when the capture header's
corresponding validity bit is set. CRC status is accepted only when the capture
header says the CRC was checked.

## Data provenance

Zenodo record 4639390, DOI `10.5281/zenodo.4639390`, version 1.0, CC BY 4.0.
The selected member is
`ble/scenario1/scene1/20200316_1636/S1_s1_2020-03-16_16-36_server9_mobile5.cap`
with SHA-256
`f15482e4220f533578b0e78734056463f4ab08e256302645ba569213e12bc3ff`.
Publisher server and mobile tokens are collection labels, not independently
verified physical identities.

## Interpretation limits

This is adapter conformance on one saved capture, not BLE coverage in general.
Address recurrence, random-address header bits, access-address equality, signal
strength, and channel overlap do not establish a durable device, radio source,
person, place, event, intent, or cross-protocol relation. The matching
publisher CSV and SigMF-named artifact remain outside this packet-only oracle.
