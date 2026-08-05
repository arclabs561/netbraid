# Experiment 0037: RoboLoc-G structural alignment profile v0

## Hypothesis

The train, calibration, and validation takes can be profiled with strict,
bounded CSV readers while preserving the locked-test non-open gate and
retaining only enough aggregate evidence to refine the preregistered blockers.
This refinement of experiment 0036 was fixed before the payload run.

## Method

From baseline commit `fa2190b`, with this uncommitted profiler tranche applied,
run:

```text
python3 eval/test-profile-robolocg-structural-alignment.py
python3 eval/profile-robolocg-structural-alignment.py
```

The profiler authenticates the canonical digest of curated manifest record
`15989282`, exact local receipt sources and integrity fields, and each raw
archive's byte count, MD5, and SHA-256 before opening a ZIP. It validates the
complete central-directory grammar, then streams bounded rows only for the six
non-locked takes. Integer-nanosecond and decimal-second clocks use the exact
parsers from `eval/robolocg_policy.py`; clocks are never parsed as floats.

The hermetic test uses synthetic ZIPs and checks manifest, receipt, and raw-byte
tamper; symlink and unsafe member paths; row and field bounds; wrong headers;
locked-test read attempts; deterministic rendering; and metadata-only private
publication.

## Data provenance

The source is curated manifest record `15989282` and its local mode-0600
receipts. The payload inputs are the sensor CSV, processed ground-truth, and
raw gantry-measurement archives. The four zigzag takes are train, still is
calibration, and circle is validation. Random takes remain locked test and no
payload member from that role is opened. Processed ground truth is the sole
oracle; raw gantry measurements are dependent consistency evidence only.

## Result placeholder

The canonical local run filled this placeholder with a deterministic
mode-0600 report at
`data/derived/eval/robolocg-structural-alignment-v0/report.json`:

- authenticated archives: 3; authenticated receipts: 3;
- locked-test payload members opened: 0;
- radar-scan rows: 1,014,462; radar-point-cloud rows: 809,951;
- FTM rows: 10,475; IMU rows: 1,800; UWB rows: 8,295;
- ground-truth rows: 4,805 per reference frame; gantry rows: 4,805;
- outer-versus-header clock diagnostics: complete for radar scan, radar point
  cloud, and IMU in every profiled role;
- UWB observations: all 8,295 values are at least 1,000 in the source's
  unresolved unit; and
- profiled FTM anchor sets are equal across the six open takes, while the
  external anchor mapping remains unresolved.

The outer-versus-header diagnostic blocker closed. The UWB-unit, FTM external
mapping, radar association/extrinsics, and interpolation-tolerance blockers
remain open, so both fusion and scoring remain false. No localization score was
computed.

## Performance profile

The canonical open-role workload contains 1,859,398 data rows. A three-run
`hyperfine` baseline took 22.272 s (standard deviation 0.138 s). `cProfile`
attributed almost all of the work to per-row CSV and field validation; archive
authentication, ZIP decompression, and file reads were minor. Three changes
were retained and measured after a warmup:

| Change | Mean time | Change from prior |
| --- | ---: | ---: |
| Validate discarded decimals without constructing `Decimal` values | 20.797 s | -6.6% |
| Compile header column indexes once per member | 20.072 s | -3.5% |
| Replace the field-size generator with an explicit short-circuiting loop | 19.394 s | -3.4% |

The final result is 12.9% below baseline. An ASCII-only field-size fast path and
a single-row CSV iterator change were rejected because each improved the full
run by less than 1%. Generated reports were byte-identical to the baseline.

The measured path is CPU-bound, so memory mapping the archives would not address
the current limit. Dataset selection, split construction, and metric analysis
remain Python because they change frequently and use the scientific Python
stack. If this profiler becomes a repeated ingestion boundary, the next
language experiment should move archive authentication, bounded CSV parsing,
and aggregate construction together into one Rust process. A per-row language
boundary would add overhead without removing the Python loop.

## Conclusion

The hypothesis held for structural profiling: the permitted payload can be
measured deterministically without crossing the locked-test boundary or
retaining row-level data. This tranche does not support fusion or localization
claims. The next work must resolve units and external anchor semantics from
independent evidence before touching radar association or interpolation.
