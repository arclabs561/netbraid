# SDR4IoT BLE/Zigbee layout audit v0

## Hypothesis

The pinned archive central directory exposes bounded, deterministic BLE and
Zigbee collection structure sufficient to count candidate packet, table, and
signal-artifact groupings without opening payloads or treating publisher tokens
as physical identity.

## Method

This hypothesis was written before the corpus profile. The implementation basis
is Git commit `ccbdc75`; the exact producer commit and command results will be
recorded after the preregistered checks pass.

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

Not run yet.

## Conclusion

Pending the real corpus profile.
