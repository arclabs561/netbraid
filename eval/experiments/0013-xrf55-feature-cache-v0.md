# Experiment 0013: XRF55 feature cache v0

## Hypothesis

A fixed geometry-aware summary can compile the preregistered XRF55 campaign of
eight performer/action groups and 20 repetitions into byte-deterministic private
feature matrices while reading less than 1 GiB of logical NPY payload and
retaining no raw scene, performer, action, member, archive, or local-path value.

## Method

Pre-implementation base revision: `a5ade67`.

The real campaign is reproduced twice with:

```sh
just xrf55-feature-cache
```

The compiler first reruns the complete metadata-only processed-layout checks.
It hash-ranks complete `(scene, performer, action)` groups, selects eight, and
keeps all 20 publisher repetitions for each group. Repetitions 1–14 retain the
publisher train role and repetitions 15–20 retain the publisher test role. Raw
group components are used only in memory; the adapter stores domain-separated
opaque group and event digests.

The feature policy follows the input geometry in the publisher implementation
at revision
[`6cf9582`](https://github.com/airslab2020/XRF55-repo/tree/6cf95821e45277ee97c55e9c68d67bc7e33962ad):

- [Wi-Fi](https://github.com/airslab2020/XRF55-repo/blob/6cf95821e45277ee97c55e9c68d67bc7e33962ad/model/resnet1d.py)
  enters a one-dimensional model as 270 channels over a sequence axis.
- [RFID](https://github.com/airslab2020/XRF55-repo/blob/6cf95821e45277ee97c55e9c68d67bc7e33962ad/model/resnet1d_rfid.py)
  enters a one-dimensional model as 23 channels over a sequence axis.
- [mmWave](https://github.com/airslab2020/XRF55-repo/blob/6cf95821e45277ee97c55e9c68d67bc7e33962ad/model/resnet2d.py)
  removes its singleton dimension and enters a two-dimensional model as 17
  channels over a 256 by 128 grid.

Wi-Fi and RFID therefore use 16 sequence bins and eight channel bins. mmWave
uses a 4 by 4 spatial grid and eight channel bins. Every region contributes
mean, standard deviation, mean absolute value, and root mean square, yielding
96 float64 values per modality. No label or metadata value is a feature.

Each selected NPY member is bounded at 8 MiB, fully decompressed through the ZIP
reader, parsed with pickle disabled, checked against its exact dtype, order, and
shape contract, reduced, and discarded before the next member is opened. The
three matrices and path-free adapter are written through 0600 temporary files;
the adapter is replaced last and carries the matrix byte sizes and SHA-256
digests. The repeat outputs must compare byte-for-byte equal.

## Data provenance

The inputs are the two ignored XRF55 processed archives and local fetch
receipts. The [publisher project page](https://aiotgroup.github.io/XRF55/)
documents 42,900 synchronized multimodal samples, 39 subjects, 55 actions, 20
repetitions, four scenes, and the first-14/last-6 split. Experiment 0012 measured
4,415,840 NPY bytes per complete tri-modal event, so this fixed 160-event
campaign has a 706,534,400-byte logical payload bound before ZIP overhead.

## Results

The hermetic compiler suite passes six tests covering official-shape and
hand-computed feature moments, exact shape/order/nonfinite rejection,
input-order-invariant campaign selection, byte-identical cache emission,
read-only mmap reuse, 0600 output modes, privacy-field absence, and symlink
rejection.

The real 160-event cache has not yet been compiled. The concurrent Oregon State
LoRa fetch remains the sole heavy-I/O lane, so real payload results and artifact
digests are not recorded yet.

## Conclusion

Pending the real campaign. A pass requires exactly 160 events, eight opaque
groups, 96 features for each of three modalities, byte-identical repeat
artifacts, and zero retained raw identifier/path fields. Any nonfinite input,
shape/order drift, missing modality, output-path hazard, or repeat mismatch
falsifies the operational hypothesis rather than being skipped.
