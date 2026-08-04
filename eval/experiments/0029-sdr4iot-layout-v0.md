# SDR4IoT BLE/Zigbee layout audit v0

## Hypothesis

The pinned archive central directory exposes bounded, deterministic BLE and
Zigbee collection structure sufficient to count candidate packet, table, and
signal-artifact groupings without opening payloads or treating publisher tokens
as physical identity.

## Method

This hypothesis was written before the corpus profile. The implementation basis
is Git commit `ccbdc75`; the exact producer commit is `51d670b`.

The profiler must verify the pinned archive byte count and MD5, reject unsafe or
unknown ZIP members, and run twice with byte-identical reports. It may read the
archive bytes and central directory only. It must not retain member names,
scenario values, scene values, timestamps, receiver values, or mobile-node
values.

The preregistered success condition is that both protocol roots have at least
one complete candidate group containing a packet capture, a tabular extract,
and a publisher-named SigMF artifact. Filename co-grouping is not payload
alignment, event identity, device identity, source identity, location truth, or
SigMF format validation.

## Data provenance

Zenodo record 4639390, DOI `10.5281/zenodo.4639390`, version 1.0: one CC BY 4.0
archive of 78,658,727 bytes with publisher MD5
`c966c5cbf1243b5a16f59675451de84e`. The publisher describes USRP N210
recordings of BLE smartphone/mobile-node and Zigbee 802.15.4 sensor-node traffic
in the w-iLab.2 testbed. Publisher server/mobile tokens are collection labels,
not independently verified physical identities.

## Results

`just sdr4iot-layout-profile` completed twice at producer commit `51d670b` with
byte-identical 3,342-byte reports, both mode 0600. The verified archive contains
702 file members and 173,658,727 uncompressed member bytes. No member payload
was opened.

| Modality | Collection runs | Observation groups | Complete three-layer groups |
|---|---:|---:|---:|
| BLE | 37 | 102 | 95 |
| Zigbee | 31 | 123 | 123 |

The remaining seven BLE groups are explicit: five have packet and table
artifacts, one has only a publisher-named SigMF artifact, and one has SigMF and
table artifacts. The two modality roots reuse four receiver tokens but no
mobile token. The report also counts 24 irregular filename date tokens and 35
supplemental or archive-metadata files without retaining their names or token
values.

## Conclusion

The hypothesis held. The archive can support protocol-specific completeness
and layer-pairing evals without payload I/O, and it supplies a concrete BLE
corpus in addition to the existing Zigbee packet slice. It does not yet support
a cross-protocol same-event eval: shared receiver tokens alone are insufficient.

The next high-information step is to admit one complete BLE packet capture and
compare its bounded TShark projection with the corresponding publisher table.
The publisher-named `.sigmf` artifact requires independent format inspection
before Netbraid's SigMF adapter can consume it.
