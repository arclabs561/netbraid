"""Project one pinned Zeek test trace into per-connection observations for the Rust example."""
import csv
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import subprocess
import sys

DIGEST = "381cdf0c0aa8e2ac1c72296a32e05b28afe935b55c567d368cdabd118bda8c5d"
FIELDS = ("frame.number", "frame.time_epoch", "ip.len", "tcp.srcport",
          "tcp.dstport", "tcp.flags", "tcp.seq_raw", "tcp.ack_raw")


def summarize(frames):
    first = frames[0]
    counters = [0, 0, 0, 0]
    syn, ack = set(), set()
    fin = rst = False
    for _, _, octets, outgoing, flags, seq, ack_seq in frames:
        offset = 0 if outgoing else 2
        counters[offset] += 1
        counters[offset + 1] += octets
        if outgoing and flags & 0x12 == 0x02:
            syn.add(seq)
        if not outgoing and flags & 0x12 == 0x12:
            ack.add((ack_seq - 1) % 2**32)
        fin |= bool(flags & 1)
        rst |= bool(flags & 4)
    labels = syn | ack
    assert len(labels) <= 1
    initial_synack = not first[3] and first[4] & 0x12 == 0x12
    basis = "syn" if syn else "synack" if initial_synack else "unknown"
    return {
        "label": next(iter(labels), None), "basis": basis,
        "end": "rst" if rst else "fin" if fin else "boundary",
        "first": min(f[1] for f in frames), "last": max(f[1] for f in frames),
        "counters": counters,
    }, bool(syn and ack)


def project(lines):
    connections = {}
    for index, row in enumerate(csv.reader(lines, delimiter="\t"), 1):
        number, epoch, ip_len, sport, dport, flags, seq, ack = row
        outgoing = dport == "7000"
        assert outgoing != (sport == "7000") and int(number) == index
        client_port = sport if outgoing else dport
        record = (index, int(Decimal(epoch) * 10**9), int(ip_len), outgoing,
                  int(flags, 16), int(seq), int(ack))
        connections.setdefault(client_port, []).append(record)
    assert index == 82582 and len(connections) == 500
    # Dict order pairs neighbors by their first captured frame.
    labels = set()
    ordered = iter(connections.values())
    for pair in zip(ordered, ordered, strict=True):
        complete, thinned = [], []
        for frames in pair:
            full, verified_both_directions = summarize(frames)
            assert verified_both_directions and full["label"] not in labels
            labels.add(full["label"])
            partial, _ = summarize([f for f in frames if f[0] % 4 != 0])
            if partial["label"] is not None:
                assert partial["label"] == full["label"]
            complete.append(full)
            thinned.append(partial)
        # Only a pair-local label and elapsed times leave the projection.
        tags = {key: index for index, key in enumerate(sorted(f["label"] for f in complete))}
        start = min(f["first"] for f in complete)
        for view in complete + thinned:
            view["label"] = tags.get(view["label"])
            view["first"] -= start
            view["last"] -= start
        yield {"complete": complete, "thinned": thinned}


def main():
    path = Path(sys.argv[1])
    if hashlib.sha256(path.read_bytes()).hexdigest() != DIGEST:
        sys.exit("expected the pinned Zeek echo capture")
    cmd = ["tshark", "-n", "-r", str(path), "-T", "fields"]
    for field in FIELDS:
        cmd.extend(["-e", field])
    lines = subprocess.run(cmd, text=True, capture_output=True, check=True).stdout.splitlines()
    for pair in project(lines):
        print(json.dumps(pair))


if __name__ == "__main__":
    main()
