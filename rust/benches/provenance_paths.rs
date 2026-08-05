use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use netbraid::infer::{
    assess_content_relation_v0, ContentDigestEvidenceV0, ContentSha256V0, FiniteHypothesisClaimV0,
    FiniteHypothesisCompositionV0, ProjectFiniteHypothesisClaimV0, ProvenanceActivityKindV0,
    ProvenanceActivityV0, ProvenanceArtifactRefV0, ProvenanceGraphV0, ProvenanceLineageRelationV0,
    ProvenanceProducerKindV0, ProvenanceProducerV0,
    ProvenanceQualifiedFiniteHypothesisCompositionV0, ProvenanceRecordV0,
};

fn digest(index: usize) -> ContentSha256V0 {
    ContentSha256V0::try_new(format!("{index:064x}")).unwrap()
}

fn graph_artifact(index: usize) -> ProvenanceArtifactRefV0 {
    ProvenanceArtifactRefV0::try_new(
        "netbraid.bench.graph_artifact.v0",
        format!("graph:{index}"),
        digest(index + 1),
    )
    .unwrap()
}

fn chain_records(count: usize) -> Vec<ProvenanceRecordV0> {
    (0..count)
        .map(|index| {
            let inputs = index
                .checked_sub(1)
                .map(graph_artifact)
                .into_iter()
                .collect::<Vec<_>>();
            let activity_kind = if inputs.is_empty() {
                ProvenanceActivityKindV0::DirectObservation
            } else {
                ProvenanceActivityKindV0::DeterministicDerivation
            };
            ProvenanceRecordV0::try_new(
                graph_artifact(index),
                ProvenanceProducerV0::try_new(
                    format!("producer:{index}"),
                    ProvenanceProducerKindV0::Software,
                )
                .unwrap(),
                ProvenanceActivityV0::try_new(format!("activity:{index}"), activity_kind).unwrap(),
                inputs,
            )
            .unwrap()
        })
        .collect()
}

fn external_artifact(index: usize) -> ProvenanceArtifactRefV0 {
    ProvenanceArtifactRefV0::try_new(
        "netbraid.bench.external_artifact.v0",
        format!("external:{index}"),
        digest(10_000 + index),
    )
    .unwrap()
}

fn claim_evidence(index: usize) -> ContentDigestEvidenceV0 {
    ContentDigestEvidenceV0::observed(
        format!("evidence:{index}"),
        "netbraid.bench.subject.v0",
        format!("subject:{index}"),
        digest(20_000 + index),
    )
    .unwrap()
}

fn claim(claim_index: usize) -> FiniteHypothesisClaimV0 {
    let left = claim_evidence(claim_index * 2);
    let right = claim_evidence(claim_index * 2 + 1);
    assess_content_relation_v0(&left, &right)
        .unwrap()
        .project_finite_hypothesis_claim_v0((&left, &right))
        .unwrap()
}

fn claims(claim_count: usize) -> Vec<FiniteHypothesisClaimV0> {
    (0..claim_count).map(claim).collect()
}

fn benchmark_graph_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("provenance_graph_build");
    for count in [4, 64, 1_024] {
        let records = chain_records(count);
        assert_eq!(records.len(), count);
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &records,
            |b, records| {
                b.iter_batched(
                    || records.clone(),
                    |records| black_box(ProvenanceGraphV0::try_new(records).unwrap()),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn benchmark_graph_compare(c: &mut Criterion) {
    let graph = ProvenanceGraphV0::try_new(chain_records(1_024)).unwrap();
    let same = graph_artifact(1_023);
    let first = graph_artifact(0);
    let last = graph_artifact(1_023);
    let external_left = external_artifact(0);
    let external_right = external_artifact(1);

    assert_eq!(
        graph.compare(&same, &same).lineage(),
        ProvenanceLineageRelationV0::SameReference
    );
    assert_eq!(
        graph.compare(&last, &first).lineage(),
        ProvenanceLineageRelationV0::LeftDescendsFromRight
    );

    let mut group = c.benchmark_group("provenance_graph_compare");
    group.bench_function("same_reference_1024_records", |b| {
        b.iter(|| black_box(graph.compare(black_box(&same), black_box(&same))));
    });
    group.bench_function("deep_chain_1024_records", |b| {
        b.iter(|| black_box(graph.compare(black_box(&last), black_box(&first))));
    });
    group.bench_function("external_disjoint_1024_records", |b| {
        b.iter(|| black_box(graph.compare(black_box(&external_left), black_box(&external_right))));
    });
    group.finish();
}

fn benchmark_composition(c: &mut Criterion) {
    let mut composition_group = c.benchmark_group("finite_composition_only");
    for claim_count in [2, 8, 16] {
        let source_claims = claims(claim_count);
        composition_group.bench_with_input(
            BenchmarkId::new("two_inputs", claim_count),
            &source_claims,
            |b, source_claims| {
                b.iter_batched(
                    || source_claims.clone(),
                    |claims| black_box(FiniteHypothesisCompositionV0::try_new(claims).unwrap()),
                    BatchSize::SmallInput,
                );
            },
        );
    }
    composition_group.finish();

    let empty_graph = ProvenanceGraphV0::try_new(vec![]).unwrap();
    let padded_graph = ProvenanceGraphV0::try_new(chain_records(1_024)).unwrap();
    let mut qualification_group = c.benchmark_group("provenance_qualified_composition");
    for claim_count in [2, 8, 16] {
        let composition = FiniteHypothesisCompositionV0::try_new(claims(claim_count)).unwrap();
        let expected_pairs = claim_count * (claim_count - 1) / 2;

        let qualified = ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
            composition.clone(),
            empty_graph.clone(),
        )
        .unwrap();
        assert_eq!(qualified.claim_lineage_pairs().len(), expected_pairs);

        qualification_group.bench_with_input(
            BenchmarkId::new("empty_graph_two_inputs", claim_count),
            &composition,
            |b, composition| {
                b.iter_batched(
                    || (composition.clone(), empty_graph.clone()),
                    |(composition, graph)| {
                        black_box(
                            ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
                                composition,
                                graph,
                            )
                            .unwrap(),
                        )
                    },
                    BatchSize::SmallInput,
                );
            },
        );
        qualification_group.bench_with_input(
            BenchmarkId::new("unrelated_1024_records_two_inputs", claim_count),
            &composition,
            |b, composition| {
                b.iter_batched(
                    || (composition.clone(), padded_graph.clone()),
                    |(composition, graph)| {
                        black_box(
                            ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
                                composition,
                                graph,
                            )
                            .unwrap(),
                        )
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    qualification_group.finish();
}

criterion_group!(
    benches,
    benchmark_graph_build,
    benchmark_graph_compare,
    benchmark_composition
);
criterion_main!(benches);
