# Experiment 0040 — Which echo connection was it?

Zeek's regression suite contains a capture of 500 TCP echo connections from one client to one server. All 500 connections have different source ports. The first SYNs arrive within 131 ms. This lets us ask what the counter signal adds when we deliberately hide the port distinction between two neighboring connections.

## Results

Each row covers all 500 queries. The middle columns count queries with zero, one or two admitted records. Correct, wrong and tied counts include only queries with at least one candidate. Both methods rank the same candidates. A single true candidate counts as correct for both.

| Ports | Packet observation | Zero / one / two candidates | Rust correct / wrong / tied | Nearest midpoint correct / wrong / tied |
| --- | --- | --- | --- | --- |
| Distinct | Complete | 0 / 500 / 0 | 500 / 0 / 0 | 500 / 0 / 0 |
| Distinct | Every fourth frame omitted | 1 / 499 / 0 | 499 / 0 / 0 | 499 / 0 / 0 |
| Paired | Complete | 0 / 0 / 500 | 362 / 0 / 138 | 500 / 0 / 0 |
| Paired | Every fourth frame omitted | 1 / 2 / 497 | 2 / 0 / 497 | 488 / 11 / 0 |

With missing packets and two admitted records, the default Rust scorer tied on all 497 queries. Midpoint distance chose the right record on 486 and the wrong one on 11. The two single-candidate queries account for both Rust wins in the last row. The remaining query lost the evidence needed to orient the flow.

In the complete paired treatment, 69 pairs had identical directional counters, accounting for all 138 ties. With the default omission schedule, each of the 497 ambiguous queries differs from *both* records by more than the default 5% tolerance on *all four* counters. The heuristic gives those discrepancies the same weight.

After the primary run, we shifted the omissions through the three other phases of the four-frame cycle. In phases one, two and three respectively, all 496, 493 and 496 two-candidate queries tied under the Rust scorer. Nearest midpoint made 6, 8 and 6 wrong choices. These are repeat measurements on the same connections. Pass `--omit-phase 1`, `2` or `3` to the projector to reproduce them.

These are retrieval ranks, separate from the model's binary marginal dispositions. On complete observations the two views share both counters and timestamps by construction. The all-correct midpoint control shows what one shared clock can do. Independent exporters, different clocks and naturally reused ports remain untested.

## What if one clock is ahead?

Keep the same 250 pairs and the same missing frames. Add a constant to both ends of each thinned interval before calling the Rust example. At +100 ms the midpoint chooses the wrong record 129 times, up from 11. At +1 s it makes 250 correct choices and 249 wrong ones. Negative offsets give a similar curve.

| Query clock minus record clock | Zero / one / two candidates | Midpoint correct / wrong |
| ---: | ---: | ---: |
| −1,000 ms | 1 / 0 / 499 | 258 / 241 |
| −100 ms | 1 / 2 / 497 | 369 / 130 |
| −10 ms | 1 / 2 / 497 | 466 / 33 |
| −1 ms | 1 / 2 / 497 | 485 / 14 |
| 0 ms | 1 / 2 / 497 | 488 / 11 |
| +1 ms | 1 / 2 / 497 | 485 / 14 |
| +10 ms | 1 / 2 / 497 | 467 / 32 |
| +100 ms | 1 / 3 / 496 | 370 / 129 |
| +1,000 ms | 1 / 3 / 496 | 250 / 249 |

Each row covers the same 500 queries. One query always lacks a candidate. The midpoint has no ties. The Rust scorer ties on every two-candidate query at every offset, and every sole candidate is correct. Between −10 and +10 ms even the candidate counts stay fixed. Translating both clocks together by one second reproduces the original output byte for byte.

These are injected offsets in one capture. They do not measure how often real exporters differ by any of these amounts. Choosing a default needs a paired capture with independently measured timing and session labels.

## Construction

Start with the 82,582 captured frames. Use the original port to partition the known connections before masking. For each full connection the client SYN sequence number agrees with the server SYN-ACK acknowledgment minus one, including retransmissions. All 500 resulting labels are distinct. Independently derive the label of a thinned query from the handshake packets still visible. A query lacking those packets has no independently recovered label or usable orientation in this fixture. No sequence number, acknowledgment value, frame number, payload or label reaches either ranking method.

Pair neighboring connections in first-frame order, yielding 250 disjoint pairs. Query each member once against the two complete records. Preserve source-port equality in the distinct control. Assign both members the same source port in the paired treatment. Actual ports and addresses may be replaced with fixture-local aliases because the model only tests their equality here. This experiment assumes prepartitioned sessions even in the masked treatment.

Each summary uses the first and last observed timestamps, directional packet counts, and IPv4 total lengths in octets (headers included). All timestamps are converted to integer nanoseconds. The thinned observation drops every fourth frame in capture order, starting with frame four, before aggregating. This fixed schedule removes 20,645 packets. Its results describe this omission pattern in this workload.

Each query is passed alone with its two records to the default production correspondence scorer. Rank its eligible records by their correspondence belief. On those same edges the baseline ranks by absolute distance between interval midpoints. Neither method breaks ties by input order. These are 250 paired comparisons per query direction from one capture, with no fitted parameters.

## Reproduce

The [fixture](https://github.com/zeek/zeek/blob/e392402c64972c1aa4701e3fd7a8fe6621c61d73/testing/btest/Traces/echo-connections.pcap.gz) was [added to Zeek's test suite in April 2022](https://github.com/zeek/zeek/commit/445903f80879993b61b2f6c11cf526f1b7ecf981). The projector checks the compressed SHA-256 before calling TShark. The capture and per-connection measurements stay local.

From the repository root with TShark, Python 3.10+ and the locked Cargo dependencies available:

```sh
curl -fL -o /tmp/echo-connections.pcap.gz \
  https://raw.githubusercontent.com/zeek/zeek/e392402c64972c1aa4701e3fd7a8fe6621c61d73/testing/btest/Traces/echo-connections.pcap.gz
python3 eval/project-zeek-echo.py /tmp/echo-connections.pcap.gz > /tmp/echo-pairs.jsonl
cargo run --quiet --offline --locked --manifest-path rust/Cargo.toml \
  --example recorded_echo_identity < /tmp/echo-pairs.jsonl > /tmp/echo-results.tsv
sha256sum /tmp/echo-results.tsv
```

Expected output digest: `a2013e8470493e8e6d5df056a3067cf65eebcb76e9ee3b43d5c6559693c5e159`.


To reproduce one clock row, pass the offset in milliseconds. Use the same projected pairs and Rust example as above. Read the `paired thinned` output row.

```sh
python3 - 100 /tmp/echo-pairs.jsonl <<'PYTHON' | cargo run --quiet --offline --locked --manifest-path rust/Cargo.toml --example recorded_echo_identity
import json
import sys

offset_ns = int(sys.argv[1]) * 1_000_000
with open(sys.argv[2]) as pairs:
    for line in pairs:
        pair = json.loads(line)
        for query in pair["thinned"]:
            query["first"] += offset_ns
            query["last"] += offset_ns
        print(json.dumps(pair))
PYTHON
```
