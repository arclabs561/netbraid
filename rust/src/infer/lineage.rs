use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::{
    CalibratedEventRelationObservationRefV0, ContentSha256ParseErrorV0, ContentSha256V0,
    FiniteHypothesisInputRefV0,
};

pub const PROVENANCE_RECORD_SCHEMA_V0: &str = "netbraid.provenance_record.v0";
pub const PROVENANCE_GRAPH_SCHEMA_V0: &str = "netbraid.provenance_graph.v0";
pub const PROVENANCE_GRAPH_MAX_RECORDS_V0: usize = 1_024;
pub const PROVENANCE_RECORD_MAX_INPUTS_V0: usize = 64;

const MAX_IDENTIFIER_LEN: usize = 512;

/// A content-bound artifact named by the schema that defines it.
///
/// The digest binds bytes; it does not authenticate the producer or establish
/// that two differently encoded artifacts describe different real-world
/// events, entities, or sources.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[non_exhaustive]
pub struct ProvenanceArtifactRefV0 {
    source_schema: String,
    source_id: String,
    content_sha256: ContentSha256V0,
}

/// Source-neutral name for a schema-defined, content-bound evidence reference.
///
/// This is the same wire and validation contract used by provenance artifacts;
/// it does not imply that unlike evidence families share a payload schema.
pub type ContentBoundEvidenceRefV0 = ProvenanceArtifactRefV0;

impl ProvenanceArtifactRefV0 {
    pub fn try_new(
        source_schema: impl Into<String>,
        source_id: impl Into<String>,
        content_sha256: ContentSha256V0,
    ) -> Result<Self, ProvenanceArtifactRefErrorV0> {
        let source_schema = source_schema.into();
        if !valid_identifier(&source_schema) {
            return Err(ProvenanceArtifactRefErrorV0::InvalidSourceSchema);
        }
        let source_id = source_id.into();
        if !valid_opaque_id(&source_id) {
            return Err(ProvenanceArtifactRefErrorV0::InvalidSourceId);
        }
        Ok(Self {
            source_schema,
            source_id,
            content_sha256,
        })
    }

    pub fn source_schema(&self) -> &str {
        &self.source_schema
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn content_sha256(&self) -> &ContentSha256V0 {
        &self.content_sha256
    }
}

impl TryFrom<&FiniteHypothesisInputRefV0> for ProvenanceArtifactRefV0 {
    type Error = ProvenanceArtifactRefErrorV0;

    fn try_from(value: &FiniteHypothesisInputRefV0) -> Result<Self, Self::Error> {
        let digest = ContentSha256V0::try_new(value.content_sha256())
            .map_err(ProvenanceArtifactRefErrorV0::InvalidContentSha256)?;
        Self::try_new(value.source_schema(), value.source_id(), digest)
    }
}

impl TryFrom<&CalibratedEventRelationObservationRefV0> for ProvenanceArtifactRefV0 {
    type Error = ProvenanceArtifactRefErrorV0;

    fn try_from(value: &CalibratedEventRelationObservationRefV0) -> Result<Self, Self::Error> {
        let digest = ContentSha256V0::try_new(value.content_sha256())
            .map_err(ProvenanceArtifactRefErrorV0::InvalidContentSha256)?;
        Self::try_new(value.source_schema(), value.source_id(), digest)
    }
}

/// Failure to construct a content-bound provenance artifact reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvenanceArtifactRefErrorV0 {
    InvalidSourceSchema,
    InvalidSourceId,
    InvalidContentSha256(ContentSha256ParseErrorV0),
}

impl std::fmt::Display for ProvenanceArtifactRefErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSourceSchema => "invalid provenance artifact source schema",
            Self::InvalidSourceId => "invalid provenance artifact source id",
            Self::InvalidContentSha256(_) => "invalid provenance artifact content digest",
        })
    }
}

impl std::error::Error for ProvenanceArtifactRefErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidContentSha256(source) => Some(source),
            Self::InvalidSourceSchema | Self::InvalidSourceId => None,
        }
    }
}

/// Descriptive producer category, separate from any trust or merit judgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceProducerKindV0 {
    Sensor,
    Software,
    Model,
    Human,
    Organization,
    Unknown,
}

/// The agent that emitted a provenance record.
///
/// A producer identifier records attribution only. It is not a credential,
/// reputation score, authorization decision, or assertion of truth.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ProvenanceProducerV0 {
    producer_id: String,
    kind: ProvenanceProducerKindV0,
}

impl ProvenanceProducerV0 {
    pub fn try_new(
        producer_id: impl Into<String>,
        kind: ProvenanceProducerKindV0,
    ) -> Result<Self, ProvenanceRecordErrorV0> {
        let producer_id = producer_id.into();
        if !valid_opaque_id(&producer_id) {
            return Err(ProvenanceRecordErrorV0::InvalidProducerId);
        }
        Ok(Self { producer_id, kind })
    }

    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    pub fn kind(&self) -> ProvenanceProducerKindV0 {
        self.kind
    }
}

/// How an output came to exist relative to its cited inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceActivityKindV0 {
    DirectObservation,
    AuthoredAssertion,
    DeterministicDerivation,
    StatisticalInference,
    HumanAnnotation,
    ModelAnnotation,
    Quotation,
    Repetition,
}

/// One named generation activity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ProvenanceActivityV0 {
    activity_id: String,
    kind: ProvenanceActivityKindV0,
}

impl ProvenanceActivityV0 {
    pub fn try_new(
        activity_id: impl Into<String>,
        kind: ProvenanceActivityKindV0,
    ) -> Result<Self, ProvenanceRecordErrorV0> {
        let activity_id = activity_id.into();
        if !valid_opaque_id(&activity_id) {
            return Err(ProvenanceRecordErrorV0::InvalidActivityId);
        }
        Ok(Self { activity_id, kind })
    }

    pub fn activity_id(&self) -> &str {
        &self.activity_id
    }

    pub fn kind(&self) -> ProvenanceActivityKindV0 {
        self.kind
    }
}

/// One output and the activity and inputs that generated it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ProvenanceRecordV0 {
    schema: String,
    output: ProvenanceArtifactRefV0,
    producer: ProvenanceProducerV0,
    activity: ProvenanceActivityV0,
    inputs: Box<[ProvenanceArtifactRefV0]>,
}

impl ProvenanceRecordV0 {
    pub fn try_new(
        output: ProvenanceArtifactRefV0,
        producer: ProvenanceProducerV0,
        activity: ProvenanceActivityV0,
        mut inputs: Vec<ProvenanceArtifactRefV0>,
    ) -> Result<Self, ProvenanceRecordErrorV0> {
        if inputs.len() > PROVENANCE_RECORD_MAX_INPUTS_V0 {
            return Err(ProvenanceRecordErrorV0::InputLimitExceeded);
        }
        inputs.sort();
        if inputs.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProvenanceRecordErrorV0::DuplicateInput);
        }
        if inputs.iter().any(|input| input == &output) {
            return Err(ProvenanceRecordErrorV0::OutputCitesItself);
        }
        match activity.kind {
            ProvenanceActivityKindV0::DirectObservation
            | ProvenanceActivityKindV0::AuthoredAssertion
                if !inputs.is_empty() =>
            {
                return Err(ProvenanceRecordErrorV0::RootActivityHasInputs)
            }
            ProvenanceActivityKindV0::Quotation | ProvenanceActivityKindV0::Repetition
                if inputs.len() != 1 =>
            {
                return Err(ProvenanceRecordErrorV0::UnaryActivityInputCount)
            }
            ProvenanceActivityKindV0::DeterministicDerivation
            | ProvenanceActivityKindV0::StatisticalInference
            | ProvenanceActivityKindV0::HumanAnnotation
            | ProvenanceActivityKindV0::ModelAnnotation
                if inputs.is_empty() =>
            {
                return Err(ProvenanceRecordErrorV0::DerivedActivityLacksInput)
            }
            _ => {}
        }
        Ok(Self {
            schema: PROVENANCE_RECORD_SCHEMA_V0.to_owned(),
            output,
            producer,
            activity,
            inputs: inputs.into_boxed_slice(),
        })
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn output(&self) -> &ProvenanceArtifactRefV0 {
        &self.output
    }

    pub fn producer(&self) -> &ProvenanceProducerV0 {
        &self.producer
    }

    pub fn activity(&self) -> &ProvenanceActivityV0 {
        &self.activity
    }

    pub fn inputs(&self) -> &[ProvenanceArtifactRefV0] {
        &self.inputs
    }
}

/// Failure to construct one provenance generation record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvenanceRecordErrorV0 {
    InvalidProducerId,
    InvalidActivityId,
    InputLimitExceeded,
    DuplicateInput,
    OutputCitesItself,
    RootActivityHasInputs,
    UnaryActivityInputCount,
    DerivedActivityLacksInput,
}

impl std::fmt::Display for ProvenanceRecordErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProducerId => "invalid provenance producer id",
            Self::InvalidActivityId => "invalid provenance activity id",
            Self::InputLimitExceeded => "provenance record input limit exceeded",
            Self::DuplicateInput => "provenance record cites one input more than once",
            Self::OutputCitesItself => "provenance record output cites itself",
            Self::RootActivityHasInputs => "root provenance activity cannot cite inputs",
            Self::UnaryActivityInputCount => {
                "quotation or repetition provenance activity requires exactly one input"
            }
            Self::DerivedActivityLacksInput => {
                "derived provenance activity requires at least one input"
            }
        })
    }
}

impl std::error::Error for ProvenanceRecordErrorV0 {}

/// Byte-level relation between two artifact references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceContentRelationV0 {
    SameReference,
    MatchingContentDigest,
    DifferentContentDigest,
}

/// Relation found in the declared lineage graph.
///
/// `NoSharedAncestryFound` is intentionally not named `Independent`: an
/// omitted edge, duplicated upstream feed, or unknown prehistory may still
/// make the artifacts dependent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceLineageRelationV0 {
    SameReference,
    LeftDescendsFromRight,
    RightDescendsFromLeft,
    SharedAncestor,
    NoSharedAncestryFound,
}

/// Orthogonal content and declared-lineage comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ProvenanceComparisonV0 {
    content: ProvenanceContentRelationV0,
    lineage: ProvenanceLineageRelationV0,
}

impl ProvenanceComparisonV0 {
    pub fn content(&self) -> ProvenanceContentRelationV0 {
        self.content
    }

    pub fn lineage(&self) -> ProvenanceLineageRelationV0 {
        self.lineage
    }
}

/// A bounded acyclic set of generation records.
///
/// Inputs may refer to artifacts whose generating record is outside this
/// graph. Such references remain ancestry leaves; their unknown prehistory is
/// why a disjoint comparison never establishes independence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ProvenanceGraphV0 {
    schema: String,
    records: Box<[ProvenanceRecordV0]>,
}

impl ProvenanceGraphV0 {
    pub fn try_new(mut records: Vec<ProvenanceRecordV0>) -> Result<Self, ProvenanceGraphErrorV0> {
        if records.len() > PROVENANCE_GRAPH_MAX_RECORDS_V0 {
            return Err(ProvenanceGraphErrorV0::RecordLimitExceeded);
        }
        records.sort_by(|left, right| left.output.cmp(&right.output));
        for pair in records.windows(2) {
            if pair[0].output == pair[1].output {
                return Err(ProvenanceGraphErrorV0::DuplicateOutput);
            }
        }
        ensure_acyclic(&records)?;
        Ok(Self {
            schema: PROVENANCE_GRAPH_SCHEMA_V0.to_owned(),
            records: records.into_boxed_slice(),
        })
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn records(&self) -> &[ProvenanceRecordV0] {
        &self.records
    }

    pub fn compare(
        &self,
        left: &ProvenanceArtifactRefV0,
        right: &ProvenanceArtifactRefV0,
    ) -> ProvenanceComparisonV0 {
        let content = if left == right {
            ProvenanceContentRelationV0::SameReference
        } else if left.content_sha256 == right.content_sha256 {
            ProvenanceContentRelationV0::MatchingContentDigest
        } else {
            ProvenanceContentRelationV0::DifferentContentDigest
        };

        let lineage = if left == right {
            ProvenanceLineageRelationV0::SameReference
        } else {
            let left_ancestors = self.ancestors(left);
            let right_ancestors = self.ancestors(right);
            if left_ancestors.contains(right) {
                ProvenanceLineageRelationV0::LeftDescendsFromRight
            } else if right_ancestors.contains(left) {
                ProvenanceLineageRelationV0::RightDescendsFromLeft
            } else if left_ancestors
                .intersection(&right_ancestors)
                .next()
                .is_some()
            {
                ProvenanceLineageRelationV0::SharedAncestor
            } else {
                ProvenanceLineageRelationV0::NoSharedAncestryFound
            }
        };

        ProvenanceComparisonV0 { content, lineage }
    }

    fn ancestors(&self, artifact: &ProvenanceArtifactRefV0) -> BTreeSet<ProvenanceArtifactRefV0> {
        let by_output: BTreeMap<_, _> = self
            .records
            .iter()
            .map(|record| (&record.output, record))
            .collect();
        let mut ancestors = BTreeSet::new();
        let mut pending = vec![artifact.clone()];
        while let Some(current) = pending.pop() {
            if !ancestors.insert(current.clone()) {
                continue;
            }
            if let Some(record) = by_output.get(&current) {
                pending.extend(record.inputs.iter().cloned());
            }
        }
        ancestors
    }
}

/// Failure to construct a bounded provenance graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvenanceGraphErrorV0 {
    RecordLimitExceeded,
    DuplicateOutput,
    Cycle,
}

impl std::fmt::Display for ProvenanceGraphErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::RecordLimitExceeded => "provenance graph record limit exceeded",
            Self::DuplicateOutput => "provenance graph contains duplicate output records",
            Self::Cycle => "provenance graph contains a derivation cycle",
        })
    }
}

impl std::error::Error for ProvenanceGraphErrorV0 {}

fn ensure_acyclic(records: &[ProvenanceRecordV0]) -> Result<(), ProvenanceGraphErrorV0> {
    let by_output: BTreeMap<_, _> = records
        .iter()
        .enumerate()
        .map(|(index, record)| (&record.output, index))
        .collect();
    let mut state = vec![0_u8; records.len()];
    for index in 0..records.len() {
        visit(index, records, &by_output, &mut state)?;
    }
    Ok(())
}

fn visit(
    index: usize,
    records: &[ProvenanceRecordV0],
    by_output: &BTreeMap<&ProvenanceArtifactRefV0, usize>,
    state: &mut [u8],
) -> Result<(), ProvenanceGraphErrorV0> {
    match state[index] {
        1 => return Err(ProvenanceGraphErrorV0::Cycle),
        2 => return Ok(()),
        _ => {}
    }
    state[index] = 1;
    for input in &records[index].inputs {
        if let Some(input_index) = by_output.get(input) {
            visit(*input_index, records, by_output, state)?;
        }
    }
    state[index] = 2;
    Ok(())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_opaque_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTIFIER_LEN && !value.chars().any(char::is_control)
}
