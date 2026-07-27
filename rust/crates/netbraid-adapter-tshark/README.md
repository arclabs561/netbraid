# netbraid-adapter-tshark

`netbraid-adapter-tshark` is a bounded, shell-free process boundary around
TShark and Capinfos for immutable PCAP and PCAPNG artifacts. It disables name
resolution, selects an explicit field registry, preserves invalid rows as
quarantines, and emits provenance-bearing `netbraid-evidence` records plus a
successful-run receipt.

TShark and Capinfos remain runtime dependencies and are not bundled. The
adapter normalizes saved artifacts; it does not perform live capture or infer
capture-wide network, channel, observer, or acquisition-policy coverage.

Version 0.2 and later emit the producer identity `netbraid-adapter-tshark`.
Historical records that name `netmon-adapter-tshark` remain valid input. The
separate `netmon.*.v0` wire identifiers remain stable.

```toml
[dependencies]
netbraid-adapter-tshark = "0.2"
```

License: MIT OR Unlicense.
