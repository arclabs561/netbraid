# Experiment 0036: RoboLoc-G structural alignment v0

## Problem

Preregister the first RoboLoc-G policy tranche before any payload profiling,
feature construction, model fitting, fusion, or scoring. The hermetic contract
is checked with `just robolocg-policy-check`.

## Non-goals

This tranche does not read corpus rows, associate radar returns, interpolate
tracks, fit localization models, select features, tune thresholds, create a
derived artifact, or make a performance claim. A paired-row transform test is
deferred to the payload profiler; the policy test instead checks the published
origin mapping within 0.005 mm.

## Roles

Each complete take is one session. The `zigzag1` through `zigzag4` family is
train, `still` is calibration, `circle` is validation, and the `random1` and
`random2` family is locked test. Each trajectory family is one domain and may
not cross roles. Publisher CNC and OptiTrack calibration are frozen
configuration that may cross roles; `still` remains an observation take.

## Oracle and dependent evidence

The processed ground truth is the sole scoring oracle. Raw gantry measurements
are dependent consistency evidence and may be neither a second oracle nor a
model input. Sensor CSVs are observations. The outer CSV timestamp is the
cross-modal clock; embedded ROS header-clock deltas are diagnostics only.

The OptiTrack-to-gantry transform translates by
`(-2647.33, 2226.40, -2462.04)` mm, then applies active column-vector rotations
`Rz(-94.6088) Ry(-0.2091) Rx(+0.6730)`.

## Blockers

Fusion and scoring remain blocked by the UWB unit conflict, FTM anchor-ID
mismatch, unresolved outer-versus-header clock deltas, absent radar
association/extrinsics, and an unfixed interpolation/no-extrapolation
tolerance. Ground-truth interpolation may not extrapolate.

## Gates

The archive counts, member kinds, exact CSV headers, role atomicity, integer
clock parsing, transform convention, and deterministic opaque policy IDs must
pass hermetic tests. `fusion_capable` and scoring remain false until a later
profiler explicitly closes every blocker; partial closure has no effect on
either gate.

