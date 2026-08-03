# Experiment 0010: XRF55 multimodal alignment feasibility v0

## Hypothesis

The pinned XRF55 processed archives contain a complete, deterministic
Wi-Fi/RFID/mmWave event grid under the publisher's scene-scoped
subject/action/repetition grammar, while raw-to-processed alignment cannot be
established from exact member paths alone.

## Method

The bounded profiler is reproduced with:

```sh
just xrf55-layout-profile
```

It validates exact archive sizes and local receipt metadata, bounds each ZIP64
central directory before Python materializes its entries, and rejects unsafe,
duplicate, encrypted, non-regular, or unsupported members. It never opens a
member payload. Processed NPY names are interpreted only through the grammar
documented by the publisher: subject, action, and repetition. Scene is retained
as a namespace because the first archive spans four scenes. Every processed
event must have exactly one Wi-Fi, one RFID, and one mmWave member.

The publisher's first-14/last-6 repetition policy is measured but not treated
as a leakage-safe identity split. Exact member-path and stem-path intersections
across archives are counted from domain-separated hashes; neither hashes nor
paths enter the report.

## Data provenance

The corpus is XRF55 under CC BY-NC 4.0. The
[publisher project page](https://aiotgroup.github.io/XRF55/) documents 39
participants, 55 actions, 20 repetitions, four scenes, synchronized RF
modalities, and the 14/6 repetition split. The
[publisher Q&A](https://github.com/aiotgroup/XRF55-repo/blob/main/XRF55-QA.md)
documents the subject/action/repetition filename grammar. The three ignored
archives and receipts are acquired by `data/fetch/fetch-xrf55.py`.

## Results

The real profile completed twice with byte-identical reports in approximately
12 seconds. It inspected 300,310 ZIP members and 30,737,686 central-directory
bytes while reading zero member payload bytes.

The two processed archives contained 128,700 NPY members forming 42,900
complete tri-modal events. Part 1 contained 20 scene-scoped performer groups,
55 actions, 20 repetitions, and four scenes: 15,400 publisher-train and 6,600
publisher-test events. Part 2 contained 19 performer groups in scene 1 with
14,630 train and 6,270 test events. The parts had zero performer-group and event
intersections.

The raw archive contained 171,610 members: 42,910 CSV, 125,400 DAT, and 3,300
MAT files. No archive pair had an exact member-path or stem-path intersection.
That negative result blocks a raw-to-processed join based only on path equality.

The run validated receipt structure and declared sizes but intentionally did
not freshly hash the 195,896,168,944 archive bytes. All three receipts remain in
their legacy adjacent locations pending one full verification and migration
after the OSU LoRa download releases the heavy-I/O lane.

## Conclusion

XRF55 supports an exact synchronized-event oracle across three RF modalities
and a publisher-scoped performer grouping. It does not establish RF-device or
physical-source identity, malicious intent, tamper, or raw-to-processed
lineage. The next evaluator can compile same-event and same/different-actor
frames from the processed grid, but the hypothesis schema needs an explicit
actor relation rather than overloading physical device or source.
