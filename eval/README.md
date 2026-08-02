# Evaluation

This directory contains executable measurements of Netbraid behavior.

- `fixtures/` contains bounded synthetic or reviewed public-safe inputs.
- `experiments/` records aggregate methods, provenance, results, and limits.
- `evaluate-*.py` implements dataset-backed evaluators.
- `profile-*.py` inspects bounded corpus structure without promoting it to a
  production contract.
- `test-*.py` provides exact hermetic oracles for the harnesses.

`counter_capture_campaign.py` evaluates a bounded campaign containing only
identifier-free traffic windows. Collection paths, addresses, interfaces, and
deployment-selected runs remain outside this repository.

Evaluators read ignored artifacts from `data/raw/` and write ignored results to
`data/derived/eval/`. A dataset result is not a unit test and is not part of the
default CI gate unless its oracle is exact and corpus-independent.
