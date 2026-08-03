# Experiment 0012: XRF55 feature-cache feasibility v0

## Hypothesis

The XRF55 processed archives use a small bounded set of fixed numeric array
shapes, and one complete Wi-Fi/RFID/mmWave event is at most 64 MiB
uncompressed, making a deterministic bounded feature cache practical without
extracting the corpus.

## Method

Pre-implementation base revision: `0ed7a7d`.

The bounded header profiler is reproduced with:

```sh
just xrf55-npy-shape-profile
```

For each processed archive, it first runs the complete metadata-only layout
validation from experiment 0010. It groups every NPY member by modality and
uncompressed member size, permits at most 16 size classes per modality, and
selects one deterministic representative per class. It opens only the NPY
header of each representative, rejects unsupported or object-bearing dtypes,
validates shape-derived byte extents, and reads no array elements. The two
reports must be byte-identical.

The profiler is a precondition for a later cross-modal retrieval campaign, not
the retrieval evaluation itself. That campaign will fit on publisher-train
repetitions 1–14 and test exact event matching among repetitions 15–20 while
holding performer and action constant. This candidate-set construction is
intended to falsify the shortcut that a model can succeed by recognizing only
the performer or action.

## Data provenance

The input is the two ignored XRF55 processed archives and local fetch receipts.
The [publisher project page](https://aiotgroup.github.io/XRF55/) documents
42,900 synchronized multimodal samples, 39 subjects, 55 actions, 20
repetitions, four scenes, and the first-14/last-6 split. Local archive payloads,
member names, observation identifiers, and paths are not retained in the
report.

## Results

The real profiler completed in approximately four seconds. Both archives had
exactly one member-size class per modality, and the six deterministic class
representatives had matching headers across parts. Those header reads returned
768 bytes total; zero array elements were deserialized.

The fixed classes were:

| Modality | Dtype/order | Shape | NPY bytes per event |
| --- | --- | --- | ---: |
| Wi-Fi | float64, C order | 270 × 1000 | 2,160,128 |
| RFID | float64, C order | 23 × 148 | 27,360 |
| mmWave | float32, Fortran order | 1 × 17 × 256 × 128 | 2,228,352 |

A complete tri-modal event is therefore exactly 4,415,840 NPY bytes. A bounded
campaign over eight performer/action groups and all 20 repetitions would read
160 events, or 706,534,400 logical NPY bytes, before writing a much smaller
fixed-width feature matrix suitable for read-only mmap reuse.

Receipt metadata and exact archive sizes were validated, but this run did not
freshly rehash the complete archives. Header-class representatives establish
the observed shape for each distinct member-size class; they are not proof
that every same-sized member has an identical header under an adversarial ZIP.

## Conclusion

The hypothesis held with substantial margin. The next implementation should
stream only the preregistered 160 events, reduce each modality to a fixed-width
temporal feature vector, write private 0600 NPY matrices plus a path-free
adapter, and have the evaluator reopen those matrices with `mmap_mode="r"`.
The first scored baseline should report retrieval rank per modality direction
and per performer/action group rather than one aggregate accuracy.
