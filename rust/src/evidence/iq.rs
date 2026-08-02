use serde::Serialize;

pub const IQ_WINDOW_EVIDENCE_SCHEMA_V0: &str = "netbraid.iq_window_evidence.v0";
pub const IQ_WINDOW_LINKABILITY_NOTICE_V0: &str =
    "Exact aggregates are linkable signal observations, not anonymous identity evidence.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IqDialectV0 {
    SigmfCore,
    OsuLoraV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IqComponentTypeV0 {
    ComplexFloat32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IqByteOrderStateV0 {
    Little,
    Big,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IqByteOrderProvenanceV0 {
    SigmfDatatype,
    CallerOverride,
    SigmfDatatypeConfirmedByCaller,
    Undeclared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct IqByteOrderV0 {
    state: IqByteOrderStateV0,
    provenance: IqByteOrderProvenanceV0,
}

impl IqByteOrderV0 {
    pub(crate) const fn new(
        state: IqByteOrderStateV0,
        provenance: IqByteOrderProvenanceV0,
    ) -> Self {
        Self { state, provenance }
    }

    pub const fn state(&self) -> IqByteOrderStateV0 {
        self.state
    }

    pub const fn provenance(&self) -> IqByteOrderProvenanceV0 {
        self.provenance
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct IqSampleIntervalV0 {
    first_sample: u64,
    sample_count: u64,
}

impl IqSampleIntervalV0 {
    pub(crate) const fn new(first_sample: u64, sample_count: u64) -> Self {
        Self {
            first_sample,
            sample_count,
        }
    }

    pub const fn first_sample(&self) -> u64 {
        self.first_sample
    }

    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IqWindowCompletenessV0 {
    Complete,
    Truncated,
    UndecodableUnknownByteOrder,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct IqValueCountsV0 {
    finite_components: u64,
    nonfinite_components: u64,
    zero_components: u64,
}

impl IqValueCountsV0 {
    pub(crate) const fn new(
        finite_components: u64,
        nonfinite_components: u64,
        zero_components: u64,
    ) -> Self {
        Self {
            finite_components,
            nonfinite_components,
            zero_components,
        }
    }

    pub const fn finite_components(&self) -> u64 {
        self.finite_components
    }

    pub const fn nonfinite_components(&self) -> u64 {
        self.nonfinite_components
    }

    pub const fn zero_components(&self) -> u64 {
        self.zero_components
    }
}

/// Exact component summaries that avoid target-dependent floating-point reduction.
///
/// Minimum and maximum values are serialized as their IEEE-754 binary32 bit
/// patterns. Counts and bit patterns are stable integers; no unconstrained
/// floating-point sum is performed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct IqComponentAggregateV0 {
    positive_finite: u64,
    negative_finite: u64,
    subnormal: u64,
    minimum_finite_bits: Option<u32>,
    maximum_finite_bits: Option<u32>,
}

impl IqComponentAggregateV0 {
    pub(crate) const fn new(
        positive_finite: u64,
        negative_finite: u64,
        subnormal: u64,
        minimum_finite_bits: Option<u32>,
        maximum_finite_bits: Option<u32>,
    ) -> Self {
        Self {
            positive_finite,
            negative_finite,
            subnormal,
            minimum_finite_bits,
            maximum_finite_bits,
        }
    }

    pub const fn positive_finite(&self) -> u64 {
        self.positive_finite
    }

    pub const fn negative_finite(&self) -> u64 {
        self.negative_finite
    }

    pub const fn subnormal(&self) -> u64 {
        self.subnormal
    }

    pub const fn minimum_finite_bits(&self) -> Option<u32> {
        self.minimum_finite_bits
    }

    pub const fn maximum_finite_bits(&self) -> Option<u32> {
        self.maximum_finite_bits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct IqDeterministicAggregatesV0 {
    in_phase: IqComponentAggregateV0,
    quadrature: IqComponentAggregateV0,
}

impl IqDeterministicAggregatesV0 {
    pub(crate) const fn new(
        in_phase: IqComponentAggregateV0,
        quadrature: IqComponentAggregateV0,
    ) -> Self {
        Self {
            in_phase,
            quadrature,
        }
    }

    pub const fn in_phase(&self) -> IqComponentAggregateV0 {
        self.in_phase
    }

    pub const fn quadrature(&self) -> IqComponentAggregateV0 {
        self.quadrature
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IqWindowEvidenceV0 {
    schema: &'static str,
    dialect: IqDialectV0,
    component_type: IqComponentTypeV0,
    byte_order: IqByteOrderV0,
    channel_count: u32,
    sample_rate_hz: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    center_frequency_hz: Option<u64>,
    requested_interval: IqSampleIntervalV0,
    observed_interval: IqSampleIntervalV0,
    completeness: IqWindowCompletenessV0,
    counts: IqValueCountsV0,
    #[serde(skip_serializing_if = "Option::is_none")]
    aggregates: Option<IqDeterministicAggregatesV0>,
    interpretation: &'static str,
}

impl IqWindowEvidenceV0 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn decoded(
        dialect: IqDialectV0,
        byte_order: IqByteOrderV0,
        sample_rate_hz: u64,
        center_frequency_hz: Option<u64>,
        requested_interval: IqSampleIntervalV0,
        observed_interval: IqSampleIntervalV0,
        completeness: IqWindowCompletenessV0,
        counts: IqValueCountsV0,
        aggregates: IqDeterministicAggregatesV0,
    ) -> Self {
        Self {
            schema: IQ_WINDOW_EVIDENCE_SCHEMA_V0,
            dialect,
            component_type: IqComponentTypeV0::ComplexFloat32,
            byte_order,
            channel_count: 1,
            sample_rate_hz,
            center_frequency_hz,
            requested_interval,
            observed_interval,
            completeness,
            counts,
            aggregates: Some(aggregates),
            interpretation: IQ_WINDOW_LINKABILITY_NOTICE_V0,
        }
    }

    pub(crate) const fn undecodable(
        dialect: IqDialectV0,
        sample_rate_hz: u64,
        center_frequency_hz: Option<u64>,
        requested_interval: IqSampleIntervalV0,
    ) -> Self {
        Self {
            schema: IQ_WINDOW_EVIDENCE_SCHEMA_V0,
            dialect,
            component_type: IqComponentTypeV0::ComplexFloat32,
            byte_order: IqByteOrderV0::new(
                IqByteOrderStateV0::Unknown,
                IqByteOrderProvenanceV0::Undeclared,
            ),
            channel_count: 1,
            sample_rate_hz,
            center_frequency_hz,
            requested_interval,
            observed_interval: IqSampleIntervalV0::new(requested_interval.first_sample, 0),
            completeness: IqWindowCompletenessV0::UndecodableUnknownByteOrder,
            counts: IqValueCountsV0::new(0, 0, 0),
            aggregates: None,
            interpretation: IQ_WINDOW_LINKABILITY_NOTICE_V0,
        }
    }

    pub const fn schema(&self) -> &'static str {
        self.schema
    }

    pub const fn dialect(&self) -> IqDialectV0 {
        self.dialect
    }

    pub const fn component_type(&self) -> IqComponentTypeV0 {
        self.component_type
    }

    pub const fn byte_order(&self) -> IqByteOrderV0 {
        self.byte_order
    }

    pub const fn channel_count(&self) -> u32 {
        self.channel_count
    }

    pub const fn sample_rate_hz(&self) -> u64 {
        self.sample_rate_hz
    }

    pub const fn center_frequency_hz(&self) -> Option<u64> {
        self.center_frequency_hz
    }

    pub const fn requested_interval(&self) -> IqSampleIntervalV0 {
        self.requested_interval
    }

    pub const fn observed_interval(&self) -> IqSampleIntervalV0 {
        self.observed_interval
    }

    pub const fn completeness(&self) -> IqWindowCompletenessV0 {
        self.completeness
    }

    pub const fn counts(&self) -> IqValueCountsV0 {
        self.counts
    }

    pub const fn aggregates(&self) -> Option<IqDeterministicAggregatesV0> {
        self.aggregates
    }
}
