# mmWave jamming layout attribution v0

## Hypothesis

The 20 combined-layout mismatches from experiment 0025 are caused by MAT
variable-name differences, while array shape/class remains invariant in all 40
matched cells.

## Method

This hypothesis was written before adding the decomposed counters or rerunning
the corpus. The Git basis is `52e175b`; the exact decomposed producer commit is
`e3e9dab`.

The follow-up keeps the original combined signature and all storage-extent
gates. It adds two pairwise diagnostics computed from the same already-admitted
metadata:

- variable-name signature only; and
- array shape/class multiset only.

Run:

```sh
just mmwave-jamming-layout-profile
```

The interpretation is fixed before the run. A 40/40 array-layout match permits
later payload work only after an extractor proves it excludes names, paths,
storage encoding, and byte extent. It does not clear the existing metadata
blocker. Any array-layout mismatch instead requires an explicit shape
normalization or paired-window policy before payload evaluation.

## Data provenance

The same 80 pinned artifacts and 40 matched cells from Zenodo record 6516954,
DOI `10.5281/zenodo.6516954`. No split, detector, or identity oracle is added.

## Results

The canonical recipe completed twice with byte-identical 1,632-byte reports,
both mode 0600. The decomposed pair counts were:

| Pairwise diagnostic | Matching | Mismatching |
|---|---:|---:|
| combined named layout | 20 | 20 |
| variable-name signature | 40 | 0 |
| array shape/class multiset | 20 | 20 |
| exact file extent | 0 | 40 |
| one-MiB extent class | 16 | 24 |

Every artifact contains one rank-three double array. No array values were
materialized. The report remains path-free and label-free.

## Conclusion

The hypothesis did not hold. Variable names are invariant; array geometry is
not. Half of the matched cells therefore require an explicit common-window or
shape-normalization policy before payload features can be compared. File extent
also remains disallowed in every later feature contract.

The next useful step is not a classifier. It is a bounded, pair-aligned payload
adapter that derives its window from train-independent shape policy, writes a
content-bound feature cache, and proves that paths, names, storage encoding,
and source byte counts cannot reach the model matrix.
