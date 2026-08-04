# mmWave jamming paired grid cache v0

## Hypothesis

Every matched jammer-present and jammer-absent pair has enough common ADC
sample, chirp, and frame extent to produce the same fixed 16 by 16 by 8
stratified content grid, and all selected values are finite. The resulting
float32 real/imaginary cache will be byte-identical across repeated runs and
will retain no source shape, name, path, storage, extent, or condition field.

## Method

This hypothesis was written before inspecting payload values or recording the
corpus's concrete shape distribution. The Git basis is `62eb40c`.

The producer will first run the existing exact size/MD5/SHA-256/local-receipt
admission and reconstruct the 40 opaque matched pairs. For each pair, it will
inspect the one rank-three numeric array in each MAT v5 artifact, take the
elementwise minimum shape, and derive one shared set of evenly spaced integer
indices along the publisher-defined ADC-sample, chirp, and frame axes. Both
members of the pair will use those exact indices. The fixed output grid is
16 by 16 by 8 with a final real/imaginary component axis of length two.

Only one bounded source array may be materialized at a time. Rows will be
written directly into a temporary NumPy NPY memmap, atomically installed, then
reopened read-only and fully digested. A separate adapter will map matrix rows
to opaque observation identifiers. It may retain the fixed output contract and
aggregate provenance, but not source geometry or other prohibited metadata.

The canonical recipe will run the producer twice and require byte-identical
matrix and adapter outputs. Hermetic tests will cover mismatched source shapes,
shared pair indices, metadata erasure, nonfinite rejection, deterministic
output, output hazards, and read-only mmap consumption.

## Data provenance

Zenodo record 6516954, DOI `10.5281/zenodo.6516954`: the same 80 pinned MAT v5
artifacts and 40 receiver/regime/target matched condition pairs admitted by the
observation oracle. The publisher describes each receiver array as ADC samples
by chirps by frames. Jammer presence remains a controlled cause only; no event,
session, device, identity, variant, actor, tamper, authorization, or malicious
intent label is introduced.

## Results

The canonical recipe completed twice over all 80 admitted artifacts and 40
matched pairs. Both runs produced byte-identical outputs:

- matrix shape: 80 by 16 by 16 by 8 by 2;
- matrix dtype: little-endian float32;
- values per observation: 4,096;
- matrix extent: 1,310,848 bytes;
- matrix SHA-256:
  `3491379a2355f6ab47136a899c8a93b287b0d24384a19231a54a929f33692981`;
- adapter extent: 11,216 bytes; and
- output mode: 0600 for both matrices and both adapters.

All selected values remained finite after the float32 real/imaginary
projection. The adapter has 80 contiguous opaque row bindings and records no
condition label, pair-group identifier, source shape, filename, path, URL,
variable name, storage encoding, byte count, or source digest.

## Conclusion

The hypothesis held. A fixed pair-aligned content cache can be compiled from
the full corpus without exposing the condition-associated shape and storage
metadata found in experiments 0025 and 0026. The matrix is small enough for
read-only mmap and preserves a coarse three-axis grid rather than committing
to detector-specific moments.

This establishes an input boundary, not predictive utility. A later
preregistered evaluation must join opaque rows to the separate oracle, assign
group-safe train/calibration/validation/test roles, fit only on training data,
and compare simple content baselines before any larger model is justified.
