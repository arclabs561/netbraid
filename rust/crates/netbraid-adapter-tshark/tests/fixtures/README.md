# Saved-capture fixture corpus

This directory has two fixture tiers:

- the root `*.hex` files are hand-authored synthetic captures. Their comments
  explain every header and packet field that matters to the test;
- `upstream/*.hex` are exact bytes from small public upstream captures, rendered
  as lowercase hexadecimal so reviews and diffs remain textual.

`upstream/corpus-v0.json` is the admission ledger. Each entry pins the upstream
repository revision, source path, Git blob ID, decoded SHA-256 digest, license,
curation purpose, stable normalization expectations, and typed conversation
reduction expectations. The non-ignored corpus test checks the ledger, unique
content identities and immutable origin coordinates, and exact bytes without
requiring Wireshark. The ignored smoke test additionally normalizes every
admitted artifact twice with installed `capinfos` and `tshark`, round-trips both
the occurrence-bearing and deterministic JSONL projections through
`netbraid-replay`, and checks byte-stable deterministic records, receipt-bound
digests, replayed evidence equality, and conservative conversation grouping.

The corpus is intentionally small. It spans capture and link-layer boundaries
that have changed adapter behavior:

| Fixture | Boundary exercised |
| --- | --- |
| libpcap radiotap | Classic PCAP, 802.11 radiotap, management/control frames |
| libpcap Nokia mobile join | Classic PCAP, raw 802.11 management/control/data frames without radio metadata |
| libpcap WPA2 link-up | 5 GHz radiotap, WPA2 EAPOL handshake, protected data, wildcard SSID |
| libpcap RARP | PCAPNG, Ethernet, non-IP frames |
| libpcap PPPoE | Classic PCAP, PPPoE discovery, conservative conversation exclusion |
| libpcap VXLAN | Nested Ethernet/IPv4 dissection plus conservative exclusion from flat conversation reduction |
| libpcap IPv6 extension headers | Deep repeated extension-header stack plus one complete UDP conversation |
| rust-pcap snaplen pair | The same ICMP frame at snaplen 20 and 65535: truncated network evidence versus complete non-TCP/UDP evidence |
| pcap-parser NTP | Real bidirectional UDP conversations over an 83-second span |
| pcap-parser big-endian | Big-endian PCAPNG, section/interface IDs, file provenance |

## Admission and rejection

An admitted fixture must have a redistribution license, an immutable upstream
revision and path, a verified blob ID and decoded SHA-256 digest, bounded size,
and a distinct behavior it protects. Raw household captures and mutable sample
links are not eligible for this public corpus.

Candidates inspected but not admitted:

| Candidate | Result |
| --- | --- |
| Wireshark SampleCaptures wiki assets | Useful discovery index, but the first corpus does not admit an asset until its per-file license and immutable source URL are verified. |
| `courvoif/pcap-file` `tests/pcap/big_endian.pcap` at `d5e458f17561b149c224bb5f059b2b7252284246` | The raw URL returned a 128-byte Git LFS pointer, not the declared 252-byte capture. Rejected rather than silently testing pointer text. |
| Large IDS/security corpora | Deferred: too large and semantically broad for an adapter boundary suite; future evaluation datasets belong in an external, purpose-specific corpus. |

## Running

The integrity/provenance test runs in the normal Rust suite. To exercise the
installed Wireshark tools and end-to-end normalize/replay/reduce contract too:

```sh
just pcap-smoke
```

The fixture bytes are observations from their named upstream projects, not
Netbraid-generated evidence. Their inclusion does not assert how, where, or under
which acquisition policy the original traffic was captured.
