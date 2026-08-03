# Experiment 0018: RUFF-UWB cross-campaign transfer v0

## Hypothesis

A publisher-aligned common magnitude projection may preserve more physical-
device information than uniform chance when prototype rules are fit on the
one-meter campaign and evaluated once on the two-meter campaign, despite the
combined distance, day, room-position, and stored-representation shift.

Balanced accuracy at or below the 1/13 uniform-chance baseline would falsify
that prediction for this projection and protocol.

## Method

Status: completed. The real target was evaluated exactly once at implementation
checkpoint `9fb8504`; implementation baseline before this experiment was
`cf40d57`.

The source campaign retains experiment 0006's seeded 80/10/10 location
assignment. Prototype candidates are fit only on its 40-location train role and
selected only on its five-location validation role. The previously observed
five-location one-meter test role is quarantined: it has zero feature rows and
is never predicted or scored. Every two-meter location is assigned to the sole
target-test role before bounded row sampling.

The common projection converts each row to magnitude, aligns the maximum
positive magnitude gradient to sample 40, crops a common 200-sample prefix,
then mean-centers and L2-normalizes four deterministic 128-sample windows. This
explicitly reconciles the publisher archives' complex-250 and real-200 stored
representations; it does not establish that those representations are
semantically equivalent.

The canonical commands are:

```sh
just ruff-uwb-cross-campaign-check
just ruff-uwb-row-sampling-benchmark
just ruff-uwb-two-meter-row-adapter
just ruff-uwb-cross-campaign-transfer
```

## Data provenance

- Source: pinned RUFF-UWB one-meter NPY archive and central fetch receipt.
- Target: pinned RUFF-UWB two-meter NPY archive and central fetch receipt.
- Publisher design: the same 13 transmitting boards and receiver were used;
  the campaigns were recorded on different days, at different positions in the
  same room, and at relative distances of one and two meters.
- Source rows: 771,232 across 50 locations; source test locations remain
  assigned but unused.
- Target rows: 1,152,491 across 100 locations, all assigned to target test
  before bounded sampling.
- Stored arrays: source `<c16` with 250 samples per row; target `<f8` with 200
  samples per row.
- Retention: archives, standalone arrays, row adapters, and generated reports
  remain ignored. The checked-in code retains only public immutable metadata.

The evaluator requires exact equality of source-to-device opaque alias maps
across adapters. This assumes the publisher's shared numeric labels identify
the same physical boards across campaigns; no serial-number evidence is
available in the corpus.

## Results

The 11-test synthetic suite passes. It covers exact production-binding
projection from the compiler registry, deterministic transfer with overlapping
collection-local row indices, source-test non-use, target perturbation
isolation, pre-I/O identity and adapter-alias rejection, pre-I/O feature-memory
rejection, read-only mmap, path-free output, byte-identical reports from compact
and expanded adapters, and exact SHA-256 top-k parity when one atomic group is
split across non-adjacent spans.

Metadata load, location partitioning, and bounded source-row sampling were
measured three times per mode on the complete 771,232-row one-meter adapter:

```sh
/usr/bin/time -l uv run --script eval/benchmark-ruff-uwb-row-sampling.py --mode expanded
/usr/bin/time -l uv run --script eval/benchmark-ruff-uwb-row-sampling.py --mode compact
```

| Mode | Median internal time | Median maximum RSS | Sampled rows |
| --- | ---: | ---: | ---: |
| Expanded reference | 6.906741 s | 353,140,736 bytes | 5,160 |
| Compact production | 1.938099 s | 29,147,136 bytes | 5,160 |

All six runs emitted the same sampled-row receipt,
`1210d9d2cb955f51263e3537f28fb69da43ffe89dd5fd5fd405189f940f12678`.
The compact path is 3.56 times as fast for this boundary and reduces median
maximum RSS by 91.7%. The benchmark excludes waveform hashing and projection;
it isolates the metadata cost changed here.

The two-meter adapter compiled 1,152,491 rows into 1,145 validated compact
spans. The frozen centroid rule was selected on 520 one-meter validation rows,
then evaluated on 9,160 bounded rows spanning all 100 target locations and all
13 devices. The quarantined one-meter test role retained 77,738 assigned rows
but zero sampled, feature, prediction, or metric rows.

| Target metric | Result |
| --- | ---: |
| Balanced accuracy | 0.131830153973 |
| Macro-F1 | 0.128241021412 |
| Uniform-chance balanced accuracy | 0.076923076923 |

```json
{
  "leakage_checks": {
    "all_checks_passed": true,
    "source_test_feature_rows": 0,
    "source_test_target_row_overlap": 0,
    "source_train_validation_row_overlap": 0,
    "target_configuration_candidates": 0
  },
  "privacy": {
    "corpus_rows_retained": 0,
    "input_paths_retained": 0,
    "raw_source_identifiers_retained": 0
  },
  "roles": {
    "source_test_unused": {
      "atomic_groups": 65,
      "feature_rows": 0,
      "locations": 5,
      "sampled_rows": 0,
      "source_rows": 77738
    },
    "source_train": {
      "atomic_groups": 515,
      "feature_rows": 4120,
      "locations": 40,
      "sampled_rows": 4120,
      "source_rows": 615745
    },
    "source_validation": {
      "atomic_groups": 65,
      "feature_rows": 520,
      "locations": 5,
      "sampled_rows": 520,
      "source_rows": 77749
    },
    "target_test": {
      "atomic_groups": 1145,
      "feature_rows": 9160,
      "locations": 100,
      "sampled_rows": 9160,
      "source_rows": 1152491
    }
  },
  "schema": "netbraid.ruff_uwb_cross_campaign_result_summary.v0",
  "selected_prototype_mode": "centroid",
  "status": "pass",
  "target_metrics": {
    "balanced_accuracy": 0.131830153973,
    "evaluated_rows": 9160,
    "macro_f1": 0.128241021412,
    "per_device_recall": {
      "device-001": 0.335,
      "device-002": 0.08125,
      "device-003": 0.145408163265,
      "device-004": 0.1075,
      "device-005": 0.05303030303,
      "device-006": 0.0175,
      "device-007": 0.165,
      "device-008": 0.115,
      "device-009": 0.193181818182,
      "device-010": 0.0825,
      "device-011": 0.19375,
      "device-012": 0.092171717172,
      "device-013": 0.1325
    },
    "uniform_chance_balanced_accuracy": 0.076923076923
  },
  "validation_candidates": {
    "centroid": {
      "balanced_accuracy": 0.142307692308,
      "evaluated_rows": 520,
      "macro_f1": 0.116368441841
    },
    "template": {
      "balanced_accuracy": 0.132692307692,
      "evaluated_rows": 520,
      "macro_f1": 0.104677781465
    }
  }
}
```

Per-device recall ranged from 0.0175 to 0.335, so the aggregate lift is uneven
and does not imply reliable transfer for every board. All recorded leakage
checks passed: source train/validation overlap was zero, source-test feature
rows were zero, target configuration candidates were zero, and cross-adapter
row identity was source-qualified.

The complete command took 9.77 seconds wall time with maximum RSS of
375,209,984 bytes, including full source-integrity hashing and feature/model
work. The 5,159-byte report was written mode 0600 under the ignored derived-data
root and retained no paths or raw source identifiers.

## Conclusion

The point estimate exceeds the preregistered 1/13 falsification boundary, so
the narrow hypothesis is not falsified and the projection retains some
cross-campaign device information. This is not an isolated distance effect:
distance, day, room position, and stored representation all change together,
and no cluster-aware uncertainty interval or population-level claim is made.

The production cross-campaign path now retains compact validated spans and
materializes only bounded sampled rows. Source verification still hashes
approximately 4.93 GB before opening the two arrays by read-only mmap; the
completed runtime above includes that integrity cost.
