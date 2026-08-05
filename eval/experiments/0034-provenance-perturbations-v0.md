# Experiment 0034: provenance perturbations v0

Hypothesis: a provenance-aware oracle will preserve event chronology and
dependence-aware evidence under bounded delay, reorder, duplicate, and copied
evidence, while explicit supersession or withdrawal alone changes the active
annotation set. Any remaining active-label conflict will produce abstention.

Method: from repository state `e76895b`, run
`python3 eval/test-provenance-perturbations.py`. The fixture generator uses seed
`3405`, one opaque observation, two conflicting organic annotations, and seven
independently evaluated perturbations. The assertions lock event-time order,
arrival-time order, active annotation IDs, declared lineage roots,
dependence-group counts, and decisions.

Data provenance: the fixture is source-agnostic synthetic evaluation data. It
contains only documentation-safe opaque IDs, integer clock ticks, explicit
source versions, declared parent links, and dependence groups. No corpus rows,
paths, network identifiers, people, devices, or deployment values are inputs.

Scope: this tests the difficulty-5 conflicting/delayed-source contract and the
named naive failure modes. Non-goals are source reliability estimation,
probability calibration, majority voting, identity or intent inference,
attribution, independence inferred from missing ancestry, and production
revision storage.

Results: preregistered before execution. The scoped command passed 12/12 tests
in 0.096 seconds. Scoped `ruff check` passed, and scoped
`ruff format --check` reported both Python files already formatted.
