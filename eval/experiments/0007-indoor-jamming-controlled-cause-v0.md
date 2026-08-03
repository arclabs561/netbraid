# Indoor jamming controlled-cause smoke evaluation v0

## Hypothesis

A fixed train-only standardized nearest-centroid baseline can distinguish the
publisher-controlled `silent`, `sine`, and `gaussian` causes at assigned
relative jamming power 0.5 and distance 10 m on one validation jammer setup,
with coverage at least two thirds and balanced accuracy above one third when
abstentions count as errors.

## Method

The preregistered policy is
`eval/fixtures/indoor-jamming-controlled-cause-v0.json`. The evaluator is
`eval/evaluate-indoor-jamming-controlled-cause.py`; both are versioned with
this experiment record.

The canonical recipe first regenerates the full-digest indoor-jamming oracle,
then runs the evaluator:

```sh
just indoor-jamming-controlled-cause-eval
```

The admitted slice must contain exactly 24 observations in eight complete
three-cause file triplets. Jammer-setup repetition counts must be exactly
`1,1,1,2,3`: the three singleton setups form train, the setup repeated twice
forms validation, and the setup repeated three times forms the one-shot test.
Assigned-jammer, file-session, paired-condition, and combined-setup groups are
atomic and disjoint across roles. Tx/Rx, power, and distance are conditioning
constants, not model features or transfer axes.

Every observation uses the same four interior 65,536-column windows computed
from the minimum admitted extent. The six model inputs are anonymous-row mean,
RMS, and zero rate, averaged across the four windows. Train alone determines
feature means, nonzero scales, class centroids, and maximum within-class support
radii. Validation does not tune the model. Test is read and scored once only
after the validation gate passes.

## Data provenance

The source is Zenodo record 7119040, DOI `10.5281/zenodo.7119040`, under the
publisher-recorded CC BY 4.0 license. The checked artifact manifest binds one
publisher workbook and 31 MATLAB 7.3/HDF5 files. A real evaluation requires the
ignored full-digest oracle
`netbraid.indoor_jamming_observation_oracles.v0`, whose compiler maps workbook
groups to the exact `Nojamming`, `Sine`, and `Gaussian` datasets while retaining
no paths or dataset names in the oracle.

The planned slice is assigned power 0.5 and distance 10 m: 24 observations,
eight file triplets, and five opaque jammer setups. The minimum expected extent
is 145,920,978 columns. The campaign plans 96 bounded one-MiB selections, or 96
MiB of logical selected data. Local paths and dataset bindings are reconstructed
in memory and are not persisted in the report.

## Results

The canonical recipe completed against the full local MD5/SHA-256 rehash and
exact fetch receipts. It reconstructed all 24 admitted observations and read
the 36 train plus 24 validation windows: 60 attempted and completed bounded
reads with 60 MiB of verified selected payload. The validation gate failed, so
none of the 36 planned test windows was read or scored.

Validation covered 1 of 6 observations (`0.166666666667`) and abstained on the
other five because they lay outside the selected class's train support radius.
Balanced accuracy was `0.166666666667`, macro-F1 was `0.222222222222`, and zero
of the two complete validation triplets was classified correctly throughout.
Both preregistered requirements—coverage at least two thirds and balanced
accuracy strictly above one third—failed. The ignored canonical report retains
the confusion counts, per-class support, path-free split receipts, model
receipt, and execution counts.

The canonical recipe verifies this tracked result summary against that report:

```json
{
  "attempted_reads": 60,
  "completed_reads": 60,
  "failed_reader_calls": 0,
  "schema": "netbraid.indoor_jamming_controlled_cause_result_summary.v0",
  "status": "validation_failed",
  "test_evaluated": false,
  "validation": {
    "abstentions": 5,
    "balanced_accuracy": 0.166666666667,
    "complete_triplets_succeeded": 0,
    "coverage_denominator": 6,
    "coverage_numerator": 1,
    "macro_f1": 0.222222222222,
    "observations": 6
  },
  "verified_selected_windows": 60,
  "verified_completed_selected_bytes": 62914560
}
```

## Conclusion

The fixed anonymous-row aggregate nearest-centroid baseline did not distinguish
the three controlled causes on its held-out validation jammer setup. This is a
valid negative result and validation-gate exercise; the untouched test split
remains available for a separately preregistered representation. The result
does not establish population-level jammer-setup generalization, transfer
across Tx/Rx, power, or distance, physical identity, tamper, actor, malicious
intent, spectral behavior, timing, or detection latency. Distinct metadata
extents do not prove payload-level deduplication.
