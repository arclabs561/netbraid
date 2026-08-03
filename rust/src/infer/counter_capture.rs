use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PPB: u128 = 1_000_000_000;
pub const COUNTER_CAPTURE_SCALE_FLOOR_PPB_V0: u128 = 50_000_000;
pub const TRAFFIC_WINDOW_SCHEMA_V0: &str = "netmon.traffic_window.v0";
pub const COUNTER_CAPTURE_PROFILE_SCHEMA_V0: &str = "netmon.counter_capture_profile.v0";
pub const COUNTER_CAPTURE_HYPOTHESIS_SET_SCHEMA_V0: &str =
    "netmon.counter_capture_hypothesis_set.v0";
pub const COUNTER_CAPTURE_REDUCER_V0: &str = "netbraid.counter_capture.exact_rational_ppb.v0";

const LIMITATIONS: &[&str] = &[
    "traffic windows contain no source, interface, address, device, owner, person, place, application, or path identity",
    "the result describes counter/capture correspondence only and makes no physical-source, event-identity, intent, replay, impersonation, evasion, or integrity claim",
    "evidence and profile digests bind cited bytes but do not authenticate their source or establish the analytical claim",
    "thresholds and scales are supplied by an explicit external calibration profile; v0 has no default profile",
    "declared_complete is a caller assertion bound into the evidence digest; the reducer does not independently verify normalization completeness",
    "incomplete, unavailable, arithmetically unrepresentable, or sparsely incompatible evidence is never forced into support or contradiction",
];

/// One bounded, source-neutral traffic window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct TrafficWindowV0 {
    pub duration_ms: u64,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
    pub received_packets: u64,
    pub transmitted_packets: u64,
}

impl TrafficWindowV0 {
    pub fn new(
        duration_ms: u64,
        received_bytes: u64,
        transmitted_bytes: u64,
        received_packets: u64,
        transmitted_packets: u64,
    ) -> Result<Self, TrafficWindowValidationErrorV0> {
        let window = Self {
            duration_ms,
            received_bytes,
            transmitted_bytes,
            received_packets,
            transmitted_packets,
        };
        window.validate()?;
        Ok(window)
    }

    pub fn validate(&self) -> Result<(), TrafficWindowValidationErrorV0> {
        if self.duration_ms == 0 {
            return Err(TrafficWindowValidationErrorV0::ZeroDuration);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrafficWindowValidationErrorV0 {
    ZeroDuration,
}

impl std::fmt::Display for TrafficWindowValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("traffic window duration must be positive")
    }
}

impl std::error::Error for TrafficWindowValidationErrorV0 {}

/// Caller-declared coverage of traffic represented by a source window.
///
/// The reducer binds this assertion into the evidence digest but cannot verify
/// normalization completeness independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum TrafficWindowCoverageV0 {
    DeclaredComplete,
    Incomplete,
    Unavailable,
}

/// Content to be scored and bound into an immutable evidence reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct TrafficWindowEvidenceV0 {
    pub schema: String,
    pub record_id: String,
    pub coverage: TrafficWindowCoverageV0,
    pub window: Option<TrafficWindowV0>,
}

impl TrafficWindowEvidenceV0 {
    pub fn declared_complete(record_id: impl Into<String>, window: TrafficWindowV0) -> Self {
        Self {
            schema: TRAFFIC_WINDOW_SCHEMA_V0.to_owned(),
            record_id: record_id.into(),
            coverage: TrafficWindowCoverageV0::DeclaredComplete,
            window: Some(window),
        }
    }

    pub fn incomplete(record_id: impl Into<String>) -> Self {
        Self {
            schema: TRAFFIC_WINDOW_SCHEMA_V0.to_owned(),
            record_id: record_id.into(),
            coverage: TrafficWindowCoverageV0::Incomplete,
            window: None,
        }
    }

    pub fn unavailable(record_id: impl Into<String>) -> Self {
        Self {
            schema: TRAFFIC_WINDOW_SCHEMA_V0.to_owned(),
            record_id: record_id.into(),
            coverage: TrafficWindowCoverageV0::Unavailable,
            window: None,
        }
    }

    pub fn validate(&self) -> Result<(), TrafficWindowEvidenceValidationErrorV0> {
        if self.schema != TRAFFIC_WINDOW_SCHEMA_V0 {
            return Err(TrafficWindowEvidenceValidationErrorV0::UnsupportedSchema);
        }
        if self.record_id.is_empty() {
            return Err(TrafficWindowEvidenceValidationErrorV0::EmptyRecordId);
        }
        match (self.coverage, self.window) {
            (TrafficWindowCoverageV0::DeclaredComplete, Some(window)) => window
                .validate()
                .map_err(TrafficWindowEvidenceValidationErrorV0::InvalidWindow),
            (TrafficWindowCoverageV0::DeclaredComplete, None) => {
                Err(TrafficWindowEvidenceValidationErrorV0::MissingCompleteWindow)
            }
            (TrafficWindowCoverageV0::Incomplete | TrafficWindowCoverageV0::Unavailable, None) => {
                Ok(())
            }
            (
                TrafficWindowCoverageV0::Incomplete | TrafficWindowCoverageV0::Unavailable,
                Some(_),
            ) => Err(TrafficWindowEvidenceValidationErrorV0::UnexpectedGatedWindow),
        }
    }

    /// SHA-256 of the deterministic serde JSON representation of this evidence.
    pub fn canonical_sha256(&self) -> Result<String, serde_json::Error> {
        canonical_sha256(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrafficWindowEvidenceValidationErrorV0 {
    UnsupportedSchema,
    EmptyRecordId,
    MissingCompleteWindow,
    UnexpectedGatedWindow,
    InvalidWindow(TrafficWindowValidationErrorV0),
}

impl std::fmt::Display for TrafficWindowEvidenceValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSchema => "unsupported traffic-window evidence schema",
            Self::EmptyRecordId => "traffic-window evidence record id is empty",
            Self::MissingCompleteWindow => "complete traffic-window evidence has no window",
            Self::UnexpectedGatedWindow => {
                "incomplete or unavailable traffic-window evidence contains a window"
            }
            Self::InvalidWindow(_) => "traffic-window evidence contains an invalid window",
        })
    }
}

impl std::error::Error for TrafficWindowEvidenceValidationErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidWindow(source) => Some(source),
            _ => None,
        }
    }
}

/// The ten features retained from the Python counter/capture evaluator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum CounterCaptureFeatureV0 {
    ReceivedBytes,
    TransmittedBytes,
    ReceivedPackets,
    TransmittedPackets,
    ReceivedShare,
    TransmittedShare,
    MeanReceivedPacketBytes,
    MeanTransmittedPacketBytes,
    MeanReceivedBitsPerSecond,
    MeanTransmittedBitsPerSecond,
}

const FEATURES: [CounterCaptureFeatureV0; 10] = [
    CounterCaptureFeatureV0::ReceivedBytes,
    CounterCaptureFeatureV0::TransmittedBytes,
    CounterCaptureFeatureV0::ReceivedPackets,
    CounterCaptureFeatureV0::TransmittedPackets,
    CounterCaptureFeatureV0::ReceivedShare,
    CounterCaptureFeatureV0::TransmittedShare,
    CounterCaptureFeatureV0::MeanReceivedPacketBytes,
    CounterCaptureFeatureV0::MeanTransmittedPacketBytes,
    CounterCaptureFeatureV0::MeanReceivedBitsPerSecond,
    CounterCaptureFeatureV0::MeanTransmittedBitsPerSecond,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExactRatio {
    numerator: u128,
    denominator: u128,
}

impl ExactRatio {
    fn new(numerator: u128, denominator: u128) -> Result<Self, CounterCaptureScoringErrorV0> {
        if denominator == 0 {
            return Err(CounterCaptureScoringErrorV0::ArithmeticOverflow);
        }
        if numerator == 0 {
            return Ok(Self {
                numerator: 0,
                denominator: 1,
            });
        }
        let divisor = gcd(numerator, denominator);
        Ok(Self {
            numerator: numerator / divisor,
            denominator: denominator / divisor,
        })
    }

    fn integer(value: u64) -> Self {
        Self {
            numerator: u128::from(value),
            denominator: 1,
        }
    }

    fn one() -> Self {
        Self {
            numerator: 1,
            denominator: 1,
        }
    }

    fn checked_abs_diff(self, other: Self) -> Result<Self, CounterCaptureScoringErrorV0> {
        if self == other {
            return Self::new(0, 1);
        }
        if self.numerator == 0 {
            return Ok(other);
        }
        if other.numerator == 0 {
            return Ok(self);
        }

        let common = gcd(self.denominator, other.denominator);
        let self_factor = other.denominator / common;
        let other_factor = self.denominator / common;
        let self_numerator = self
            .numerator
            .checked_mul(self_factor)
            .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
        let other_numerator = other
            .numerator
            .checked_mul(other_factor)
            .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
        let denominator = self
            .denominator
            .checked_mul(self_factor)
            .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
        Self::new(self_numerator.abs_diff(other_numerator), denominator)
    }

    fn checked_mul(self, other: Self) -> Result<Self, CounterCaptureScoringErrorV0> {
        if self.numerator == 0 || other.numerator == 0 {
            return Self::new(0, 1);
        }
        let left_cancel = gcd(self.numerator, other.denominator);
        let right_cancel = gcd(other.numerator, self.denominator);
        let numerator = (self.numerator / left_cancel)
            .checked_mul(other.numerator / right_cancel)
            .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
        let denominator = (self.denominator / right_cancel)
            .checked_mul(other.denominator / left_cancel)
            .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
        Self::new(numerator, denominator)
    }

    fn checked_div(self, other: Self) -> Result<Self, CounterCaptureScoringErrorV0> {
        if other.numerator == 0 {
            return Err(CounterCaptureScoringErrorV0::ArithmeticOverflow);
        }
        self.checked_mul(Self {
            numerator: other.denominator,
            denominator: other.numerator,
        })
    }

    fn checked_add(self, other: Self) -> Result<Self, CounterCaptureScoringErrorV0> {
        if self.numerator == 0 {
            return Ok(other);
        }
        if other.numerator == 0 {
            return Ok(self);
        }
        let common = gcd(self.denominator, other.denominator);
        let self_factor = other.denominator / common;
        let other_factor = self.denominator / common;
        let numerator = self
            .numerator
            .checked_mul(self_factor)
            .and_then(|left| {
                other
                    .numerator
                    .checked_mul(other_factor)
                    .and_then(|right| left.checked_add(right))
            })
            .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
        let denominator = self
            .denominator
            .checked_mul(self_factor)
            .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
        Self::new(numerator, denominator)
    }

    fn floor_scaled(self, scale: u128) -> Result<u128, CounterCaptureScoringErrorV0> {
        checked_mul_div_floor(self.numerator, scale, self.denominator)
    }
}

/// Ten feature values in parts per billion; sparse ratios are explicit nulls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct CounterCaptureFeatureVectorPpbV0 {
    pub received_bytes: Option<u128>,
    pub transmitted_bytes: Option<u128>,
    pub received_packets: Option<u128>,
    pub transmitted_packets: Option<u128>,
    pub received_share: Option<u128>,
    pub transmitted_share: Option<u128>,
    pub mean_received_packet_bytes: Option<u128>,
    pub mean_transmitted_packet_bytes: Option<u128>,
    pub mean_received_bits_per_second: Option<u128>,
    pub mean_transmitted_bits_per_second: Option<u128>,
}

impl CounterCaptureFeatureVectorPpbV0 {
    fn from_values(values: [Option<u128>; 10]) -> Self {
        let [received_bytes, transmitted_bytes, received_packets, transmitted_packets, received_share, transmitted_share, mean_received_packet_bytes, mean_transmitted_packet_bytes, mean_received_bits_per_second, mean_transmitted_bits_per_second] =
            values;
        Self {
            received_bytes,
            transmitted_bytes,
            received_packets,
            transmitted_packets,
            received_share,
            transmitted_share,
            mean_received_packet_bytes,
            mean_transmitted_packet_bytes,
            mean_received_bits_per_second,
            mean_transmitted_bits_per_second,
        }
    }

    fn values(&self) -> [Option<u128>; 10] {
        [
            self.received_bytes,
            self.transmitted_bytes,
            self.received_packets,
            self.transmitted_packets,
            self.received_share,
            self.transmitted_share,
            self.mean_received_packet_bytes,
            self.mean_transmitted_packet_bytes,
            self.mean_received_bits_per_second,
            self.mean_transmitted_bits_per_second,
        ]
    }
}

/// Positive PPB scales from one explicit calibration profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct CounterCaptureScaleVectorPpbV0 {
    pub received_bytes: u128,
    pub transmitted_bytes: u128,
    pub received_packets: u128,
    pub transmitted_packets: u128,
    pub received_share: u128,
    pub transmitted_share: u128,
    pub mean_received_packet_bytes: u128,
    pub mean_transmitted_packet_bytes: u128,
    pub mean_received_bits_per_second: u128,
    pub mean_transmitted_bits_per_second: u128,
}

impl CounterCaptureScaleVectorPpbV0 {
    pub fn from_values(values: [u128; 10]) -> Self {
        let [received_bytes, transmitted_bytes, received_packets, transmitted_packets, received_share, transmitted_share, mean_received_packet_bytes, mean_transmitted_packet_bytes, mean_received_bits_per_second, mean_transmitted_bits_per_second] =
            values;
        Self {
            received_bytes,
            transmitted_bytes,
            received_packets,
            transmitted_packets,
            received_share,
            transmitted_share,
            mean_received_packet_bytes,
            mean_transmitted_packet_bytes,
            mean_received_bits_per_second,
            mean_transmitted_bits_per_second,
        }
    }

    fn values(&self) -> [u128; 10] {
        [
            self.received_bytes,
            self.transmitted_bytes,
            self.received_packets,
            self.transmitted_packets,
            self.received_share,
            self.transmitted_share,
            self.mean_received_packet_bytes,
            self.mean_transmitted_packet_bytes,
            self.mean_received_bits_per_second,
            self.mean_transmitted_bits_per_second,
        ]
    }

    fn all_at_least_floor(&self) -> bool {
        self.values()
            .into_iter()
            .all(|value| value >= COUNTER_CAPTURE_SCALE_FLOOR_PPB_V0)
    }
}

/// Ten normalized residuals in PPB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct CounterCaptureResidualVectorPpbV0 {
    pub received_bytes: u128,
    pub transmitted_bytes: u128,
    pub received_packets: u128,
    pub transmitted_packets: u128,
    pub received_share: u128,
    pub transmitted_share: u128,
    pub mean_received_packet_bytes: u128,
    pub mean_transmitted_packet_bytes: u128,
    pub mean_received_bits_per_second: u128,
    pub mean_transmitted_bits_per_second: u128,
}

impl CounterCaptureResidualVectorPpbV0 {
    fn from_values(values: [u128; 10]) -> Self {
        let [received_bytes, transmitted_bytes, received_packets, transmitted_packets, received_share, transmitted_share, mean_received_packet_bytes, mean_transmitted_packet_bytes, mean_received_bits_per_second, mean_transmitted_bits_per_second] =
            values;
        Self {
            received_bytes,
            transmitted_bytes,
            received_packets,
            transmitted_packets,
            received_share,
            transmitted_share,
            mean_received_packet_bytes,
            mean_transmitted_packet_bytes,
            mean_received_bits_per_second,
            mean_transmitted_bits_per_second,
        }
    }
}

/// Explicit calibration content. No default profile exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct CounterCaptureProfileV0 {
    pub schema: String,
    pub profile_id: String,
    pub scales_ppb: CounterCaptureScaleVectorPpbV0,
    pub support_threshold_ppb: u128,
    pub contradiction_threshold_ppb: u128,
}

impl CounterCaptureProfileV0 {
    pub fn new(
        profile_id: impl Into<String>,
        scales_ppb: CounterCaptureScaleVectorPpbV0,
        support_threshold_ppb: u128,
        contradiction_threshold_ppb: u128,
    ) -> Result<Self, CounterCaptureProfileValidationErrorV0> {
        let profile = Self {
            schema: COUNTER_CAPTURE_PROFILE_SCHEMA_V0.to_owned(),
            profile_id: profile_id.into(),
            scales_ppb,
            support_threshold_ppb,
            contradiction_threshold_ppb,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), CounterCaptureProfileValidationErrorV0> {
        if self.schema != COUNTER_CAPTURE_PROFILE_SCHEMA_V0 {
            return Err(CounterCaptureProfileValidationErrorV0::UnsupportedSchema);
        }
        if self.profile_id.is_empty() {
            return Err(CounterCaptureProfileValidationErrorV0::EmptyProfileId);
        }
        if !self.scales_ppb.all_at_least_floor() {
            return Err(CounterCaptureProfileValidationErrorV0::ScaleBelowFloor);
        }
        if self.support_threshold_ppb >= self.contradiction_threshold_ppb {
            return Err(CounterCaptureProfileValidationErrorV0::InvalidThresholdOrder);
        }
        Ok(())
    }

    /// SHA-256 of the deterministic serde JSON representation of this profile.
    pub fn canonical_sha256(&self) -> Result<String, serde_json::Error> {
        canonical_sha256(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CounterCaptureProfileValidationErrorV0 {
    UnsupportedSchema,
    EmptyProfileId,
    ScaleBelowFloor,
    InvalidThresholdOrder,
}

impl std::fmt::Display for CounterCaptureProfileValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSchema => "unsupported counter/capture profile schema",
            Self::EmptyProfileId => "counter/capture profile id is empty",
            Self::ScaleBelowFloor => {
                "counter/capture feature scales must respect the v0 calibration floor"
            }
            Self::InvalidThresholdOrder => {
                "support threshold must be lower than contradiction threshold"
            }
        })
    }
}

impl std::error::Error for CounterCaptureProfileValidationErrorV0 {}

/// A fully computed reusable feature/residual score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct CounterCaptureScoreV0 {
    pub counter_features_ppb: CounterCaptureFeatureVectorPpbV0,
    pub capture_features_ppb: CounterCaptureFeatureVectorPpbV0,
    pub residuals_ppb: CounterCaptureResidualVectorPpbV0,
    pub scaled_residual_sum_ppb: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CounterCaptureScoringErrorV0 {
    InvalidWindow(TrafficWindowValidationErrorV0),
    ScaleBelowFloor,
    ArithmeticOverflow,
    IncompatibleEvidence { feature: CounterCaptureFeatureV0 },
}

impl std::fmt::Display for CounterCaptureScoringErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidWindow(_) => formatter.write_str("invalid traffic window"),
            Self::ScaleBelowFloor => formatter
                .write_str("counter/capture feature scale is below the v0 calibration floor"),
            Self::ArithmeticOverflow => {
                formatter.write_str("counter/capture fixed-point arithmetic overflow")
            }
            Self::IncompatibleEvidence { feature } => {
                write!(
                    formatter,
                    "counter/capture sparse feature is incompatible: {feature:?}"
                )
            }
        }
    }
}

impl std::error::Error for CounterCaptureScoringErrorV0 {}

/// Compute the ten feature definitions and serialize each as
/// `floor(exact_feature * 1_000_000_000)`.
pub fn derive_traffic_window_features_ppb_v0(
    window: &TrafficWindowV0,
) -> Result<CounterCaptureFeatureVectorPpbV0, CounterCaptureScoringErrorV0> {
    serialize_features_ppb(&derive_exact_features(window)?)
}

/// Score two compatible complete windows using one explicit scale vector.
///
/// Features, residuals, and scaled contributions remain reduced exact
/// rationals internally. Auditable fields are independently floored to PPB;
/// the final score is `floor(sum(exact_residual / exact_scale) * PPB)`, not a
/// sum over already-rounded serialized fields.
pub fn score_counter_capture_windows_v0(
    counter: &TrafficWindowV0,
    capture: &TrafficWindowV0,
    scales_ppb: &CounterCaptureScaleVectorPpbV0,
) -> Result<CounterCaptureScoreV0, CounterCaptureScoringErrorV0> {
    let counter_features = derive_exact_features(counter)?;
    let capture_features = derive_exact_features(capture)?;
    let residuals = exact_residuals(&counter_features, &capture_features)?;
    let counter_features_ppb = serialize_features_ppb(&counter_features)?;
    let capture_features_ppb = serialize_features_ppb(&capture_features)?;
    let residuals_ppb = serialize_residuals_ppb(&residuals)?;
    let scaled_residual_sum_ppb = exact_scaled_residual_sum_ppb(&residuals, scales_ppb)?;
    Ok(CounterCaptureScoreV0 {
        counter_features_ppb,
        capture_features_ppb,
        residuals_ppb,
        scaled_residual_sum_ppb,
    })
}

/// Disposition of one retained counter/capture alternative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum CounterCaptureDispositionV0 {
    Supported,
    Contradicted,
    Underdetermined,
}

/// Why v0 must retain and select the explicit unknown alternative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum CounterCaptureUnknownReasonV0 {
    CounterEvidenceIncomplete,
    CounterEvidenceUnavailable,
    CaptureEvidenceIncomplete,
    CaptureEvidenceUnavailable,
    IncompatibleEvidence { feature: CounterCaptureFeatureV0 },
    ArithmeticUnrepresentable,
    ScoreBetweenThresholds,
}

/// Deterministic selected answer while all alternatives remain present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "hypothesis", rename_all = "snake_case", deny_unknown_fields)]
pub enum CounterCaptureReferenceV0 {
    CaptureAccountsForWindow,
    CaptureDoesNotAccountForWindow,
    Unknown {
        reason: CounterCaptureUnknownReasonV0,
    },
}

/// Content-bound reference to one traffic-window evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct CounterCaptureEvidenceRefV0 {
    pub source_schema: String,
    pub record_id: String,
    pub content_sha256: String,
}

/// Content-bound reference to the supplied calibration profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct CounterCaptureProfileRefV0 {
    pub source_schema: String,
    pub profile_id: String,
    pub content_sha256: String,
}

/// Auditable fixed-point decision basis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct CounterCaptureBasisV0 {
    pub counter_coverage: TrafficWindowCoverageV0,
    pub capture_coverage: TrafficWindowCoverageV0,
    pub counter_features_ppb: Option<CounterCaptureFeatureVectorPpbV0>,
    pub capture_features_ppb: Option<CounterCaptureFeatureVectorPpbV0>,
    pub residuals_ppb: Option<CounterCaptureResidualVectorPpbV0>,
    pub scales_ppb: CounterCaptureScaleVectorPpbV0,
    pub scaled_residual_sum_ppb: Option<u128>,
    pub support_threshold_ppb: u128,
    pub contradiction_threshold_ppb: u128,
}

/// Typed counter/capture correspondence alternatives over two evidence records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct CounterCaptureHypothesisSetV0 {
    pub schema: String,
    pub reducer: String,
    pub counter: CounterCaptureEvidenceRefV0,
    pub capture: CounterCaptureEvidenceRefV0,
    pub profile: CounterCaptureProfileRefV0,
    pub basis: CounterCaptureBasisV0,
    pub capture_accounts_for_window: CounterCaptureDispositionV0,
    pub capture_does_not_account_for_window: CounterCaptureDispositionV0,
    pub unknown: CounterCaptureDispositionV0,
    pub reference: CounterCaptureReferenceV0,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CounterCaptureValidationErrorV0 {
    UnsupportedSchema,
    UnsupportedReducer,
    InvalidEvidenceReference,
    InvalidProfileReference,
    InvalidBasis,
    IncoherentDisposition,
    UnexpectedLimitations,
    ResolvedContentMismatch,
}

impl std::fmt::Display for CounterCaptureValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSchema => "unsupported counter/capture hypothesis-set schema",
            Self::UnsupportedReducer => "unsupported counter/capture reducer",
            Self::InvalidEvidenceReference => "invalid counter/capture evidence reference",
            Self::InvalidProfileReference => "invalid counter/capture profile reference",
            Self::InvalidBasis => "counter/capture decision basis is incoherent",
            Self::IncoherentDisposition => {
                "counter/capture dispositions contradict the selected reference"
            }
            Self::UnexpectedLimitations => {
                "counter/capture limitations differ from the v0 contract"
            }
            Self::ResolvedContentMismatch => {
                "counter/capture assessment differs from the resolved evidence or profile"
            }
        })
    }
}

impl std::error::Error for CounterCaptureValidationErrorV0 {}

impl CounterCaptureHypothesisSetV0 {
    /// Validate only the serialized assessment's shape and internal disposition.
    ///
    /// This cannot bind content references to evidence that is not supplied.
    /// Use [`Self::validate_against`] when the cited inputs are available.
    pub fn validate_structure(&self) -> Result<(), CounterCaptureValidationErrorV0> {
        if self.schema != COUNTER_CAPTURE_HYPOTHESIS_SET_SCHEMA_V0 {
            return Err(CounterCaptureValidationErrorV0::UnsupportedSchema);
        }
        if self.reducer != COUNTER_CAPTURE_REDUCER_V0 {
            return Err(CounterCaptureValidationErrorV0::UnsupportedReducer);
        }
        if !valid_evidence_ref(&self.counter) || !valid_evidence_ref(&self.capture) {
            return Err(CounterCaptureValidationErrorV0::InvalidEvidenceReference);
        }
        if !valid_profile_ref(&self.profile) {
            return Err(CounterCaptureValidationErrorV0::InvalidProfileReference);
        }
        if !self.basis.scales_ppb.all_at_least_floor()
            || self.basis.support_threshold_ppb >= self.basis.contradiction_threshold_ppb
        {
            return Err(CounterCaptureValidationErrorV0::InvalidBasis);
        }
        if self
            .limitations
            .iter()
            .map(String::as_str)
            .ne(LIMITATIONS.iter().copied())
        {
            return Err(CounterCaptureValidationErrorV0::UnexpectedLimitations);
        }

        let basis_valid = match self.reference {
            CounterCaptureReferenceV0::Unknown { reason } => self.unknown_basis_valid(reason),
            CounterCaptureReferenceV0::CaptureAccountsForWindow => self
                .complete_score()
                .is_some_and(|score| score <= self.basis.support_threshold_ppb),
            CounterCaptureReferenceV0::CaptureDoesNotAccountForWindow => self
                .complete_score()
                .is_some_and(|score| score >= self.basis.contradiction_threshold_ppb),
        };
        if !basis_valid {
            return Err(CounterCaptureValidationErrorV0::InvalidBasis);
        }

        let dispositions_valid = match self.reference {
            CounterCaptureReferenceV0::CaptureAccountsForWindow => {
                self.capture_accounts_for_window == CounterCaptureDispositionV0::Supported
                    && self.capture_does_not_account_for_window
                        == CounterCaptureDispositionV0::Contradicted
                    && self.unknown == CounterCaptureDispositionV0::Contradicted
            }
            CounterCaptureReferenceV0::CaptureDoesNotAccountForWindow => {
                self.capture_accounts_for_window == CounterCaptureDispositionV0::Contradicted
                    && self.capture_does_not_account_for_window
                        == CounterCaptureDispositionV0::Supported
                    && self.unknown == CounterCaptureDispositionV0::Contradicted
            }
            CounterCaptureReferenceV0::Unknown { .. } => {
                self.capture_accounts_for_window == CounterCaptureDispositionV0::Underdetermined
                    && self.capture_does_not_account_for_window
                        == CounterCaptureDispositionV0::Underdetermined
                    && self.unknown == CounterCaptureDispositionV0::Supported
            }
        };
        if !dispositions_valid {
            return Err(CounterCaptureValidationErrorV0::IncoherentDisposition);
        }
        Ok(())
    }

    /// Resolve content references and recompute the complete assessment.
    pub fn validate_against(
        &self,
        counter: &TrafficWindowEvidenceV0,
        capture: &TrafficWindowEvidenceV0,
        profile: &CounterCaptureProfileV0,
    ) -> Result<(), CounterCaptureErrorV0> {
        self.validate_structure()
            .map_err(CounterCaptureErrorV0::InternalInvariant)?;
        let expected = assess_counter_capture_v0(counter, capture, profile)?;
        if self != &expected {
            return Err(CounterCaptureErrorV0::InternalInvariant(
                CounterCaptureValidationErrorV0::ResolvedContentMismatch,
            ));
        }
        Ok(())
    }

    fn complete_score(&self) -> Option<u128> {
        self.basis.counter_features_ppb.as_ref()?;
        self.basis.capture_features_ppb.as_ref()?;
        self.basis.residuals_ppb.as_ref()?;
        let score = self.basis.scaled_residual_sum_ppb?;
        if self.basis.counter_coverage != TrafficWindowCoverageV0::DeclaredComplete
            || self.basis.capture_coverage != TrafficWindowCoverageV0::DeclaredComplete
        {
            return None;
        }
        Some(score)
    }

    fn unknown_basis_valid(&self, reason: CounterCaptureUnknownReasonV0) -> bool {
        match reason {
            CounterCaptureUnknownReasonV0::CounterEvidenceIncomplete => {
                self.basis.counter_coverage == TrafficWindowCoverageV0::Incomplete
                    && self.empty_score_basis()
            }
            CounterCaptureUnknownReasonV0::CounterEvidenceUnavailable => {
                self.basis.counter_coverage == TrafficWindowCoverageV0::Unavailable
                    && self.empty_score_basis()
            }
            CounterCaptureUnknownReasonV0::CaptureEvidenceIncomplete => {
                self.basis.counter_coverage == TrafficWindowCoverageV0::DeclaredComplete
                    && self.basis.capture_coverage == TrafficWindowCoverageV0::Incomplete
                    && self.empty_score_basis()
            }
            CounterCaptureUnknownReasonV0::CaptureEvidenceUnavailable => {
                self.basis.counter_coverage == TrafficWindowCoverageV0::DeclaredComplete
                    && self.basis.capture_coverage == TrafficWindowCoverageV0::Unavailable
                    && self.empty_score_basis()
            }
            CounterCaptureUnknownReasonV0::IncompatibleEvidence { feature } => {
                self.incompatible_basis_feature() == Some(feature)
            }
            CounterCaptureUnknownReasonV0::ArithmeticUnrepresentable => {
                self.basis.counter_coverage == TrafficWindowCoverageV0::DeclaredComplete
                    && self.basis.capture_coverage == TrafficWindowCoverageV0::DeclaredComplete
                    && self.empty_score_basis()
            }
            CounterCaptureUnknownReasonV0::ScoreBetweenThresholds => {
                self.complete_score().is_some_and(|score| {
                    score > self.basis.support_threshold_ppb
                        && score < self.basis.contradiction_threshold_ppb
                })
            }
        }
    }

    fn empty_score_basis(&self) -> bool {
        self.basis.counter_features_ppb.is_none()
            && self.basis.capture_features_ppb.is_none()
            && self.basis.residuals_ppb.is_none()
            && self.basis.scaled_residual_sum_ppb.is_none()
    }

    fn incompatible_basis_feature(&self) -> Option<CounterCaptureFeatureV0> {
        if self.basis.counter_coverage != TrafficWindowCoverageV0::DeclaredComplete
            || self.basis.capture_coverage != TrafficWindowCoverageV0::DeclaredComplete
            || self.basis.residuals_ppb.is_some()
            || self.basis.scaled_residual_sum_ppb.is_some()
        {
            return None;
        }
        let counter = self.basis.counter_features_ppb.as_ref()?;
        let capture = self.basis.capture_features_ppb.as_ref()?;
        counter
            .values()
            .into_iter()
            .zip(capture.values())
            .zip(FEATURES)
            .find_map(|((expected, observed), feature)| {
                (expected.is_some() != observed.is_some()).then_some(feature)
            })
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum CounterCaptureErrorV0 {
    CounterInvalid(TrafficWindowEvidenceValidationErrorV0),
    CaptureInvalid(TrafficWindowEvidenceValidationErrorV0),
    ProfileInvalid(CounterCaptureProfileValidationErrorV0),
    EvidenceSerialization(serde_json::Error),
    ProfileSerialization(serde_json::Error),
    Scoring(CounterCaptureScoringErrorV0),
    InternalInvariant(CounterCaptureValidationErrorV0),
}

impl std::fmt::Display for CounterCaptureErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CounterInvalid(source) => write!(formatter, "invalid counter evidence: {source}"),
            Self::CaptureInvalid(source) => write!(formatter, "invalid capture evidence: {source}"),
            Self::ProfileInvalid(source) => write!(formatter, "invalid profile: {source}"),
            Self::EvidenceSerialization(source) => {
                write!(formatter, "serialize evidence: {source}")
            }
            Self::ProfileSerialization(source) => write!(formatter, "serialize profile: {source}"),
            Self::Scoring(source) => write!(formatter, "score counter/capture evidence: {source}"),
            Self::InternalInvariant(source) => write!(formatter, "validate assessment: {source}"),
        }
    }
}

impl std::error::Error for CounterCaptureErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CounterInvalid(source) => Some(source),
            Self::CaptureInvalid(source) => Some(source),
            Self::ProfileInvalid(source) => Some(source),
            Self::EvidenceSerialization(source) | Self::ProfileSerialization(source) => {
                Some(source)
            }
            Self::Scoring(source) => Some(source),
            Self::InternalInvariant(source) => Some(source),
        }
    }
}

/// Assess whether one capture accounts for one counter window.
pub fn assess_counter_capture_v0(
    counter: &TrafficWindowEvidenceV0,
    capture: &TrafficWindowEvidenceV0,
    profile: &CounterCaptureProfileV0,
) -> Result<CounterCaptureHypothesisSetV0, CounterCaptureErrorV0> {
    counter
        .validate()
        .map_err(CounterCaptureErrorV0::CounterInvalid)?;
    capture
        .validate()
        .map_err(CounterCaptureErrorV0::CaptureInvalid)?;
    profile
        .validate()
        .map_err(CounterCaptureErrorV0::ProfileInvalid)?;

    let counter_ref =
        evidence_ref(counter).map_err(CounterCaptureErrorV0::EvidenceSerialization)?;
    let capture_ref =
        evidence_ref(capture).map_err(CounterCaptureErrorV0::EvidenceSerialization)?;
    let profile_ref = profile_ref(profile).map_err(CounterCaptureErrorV0::ProfileSerialization)?;

    let mut basis = CounterCaptureBasisV0 {
        counter_coverage: counter.coverage,
        capture_coverage: capture.coverage,
        counter_features_ppb: None,
        capture_features_ppb: None,
        residuals_ppb: None,
        scales_ppb: profile.scales_ppb.clone(),
        scaled_residual_sum_ppb: None,
        support_threshold_ppb: profile.support_threshold_ppb,
        contradiction_threshold_ppb: profile.contradiction_threshold_ppb,
    };

    let reference = if let Some(reason) = coverage_gate(counter.coverage, capture.coverage) {
        CounterCaptureReferenceV0::Unknown { reason }
    } else {
        let (Some(counter_window), Some(capture_window)) =
            (counter.window.as_ref(), capture.window.as_ref())
        else {
            return Err(CounterCaptureErrorV0::InternalInvariant(
                CounterCaptureValidationErrorV0::InvalidBasis,
            ));
        };
        let exact_counter = match derive_exact_features(counter_window) {
            Ok(features) => features,
            Err(CounterCaptureScoringErrorV0::ArithmeticOverflow) => {
                return finish_assessment(
                    counter_ref,
                    capture_ref,
                    profile_ref,
                    basis,
                    CounterCaptureReferenceV0::Unknown {
                        reason: CounterCaptureUnknownReasonV0::ArithmeticUnrepresentable,
                    },
                );
            }
            Err(source) => return Err(CounterCaptureErrorV0::Scoring(source)),
        };
        let exact_capture = match derive_exact_features(capture_window) {
            Ok(features) => features,
            Err(CounterCaptureScoringErrorV0::ArithmeticOverflow) => {
                return finish_assessment(
                    counter_ref,
                    capture_ref,
                    profile_ref,
                    basis,
                    CounterCaptureReferenceV0::Unknown {
                        reason: CounterCaptureUnknownReasonV0::ArithmeticUnrepresentable,
                    },
                );
            }
            Err(source) => return Err(CounterCaptureErrorV0::Scoring(source)),
        };
        let counter_features = match serialize_features_ppb(&exact_counter) {
            Ok(features) => features,
            Err(CounterCaptureScoringErrorV0::ArithmeticOverflow) => {
                return finish_assessment(
                    counter_ref,
                    capture_ref,
                    profile_ref,
                    basis,
                    CounterCaptureReferenceV0::Unknown {
                        reason: CounterCaptureUnknownReasonV0::ArithmeticUnrepresentable,
                    },
                );
            }
            Err(source) => return Err(CounterCaptureErrorV0::Scoring(source)),
        };
        let capture_features = match serialize_features_ppb(&exact_capture) {
            Ok(features) => features,
            Err(CounterCaptureScoringErrorV0::ArithmeticOverflow) => {
                return finish_assessment(
                    counter_ref,
                    capture_ref,
                    profile_ref,
                    basis,
                    CounterCaptureReferenceV0::Unknown {
                        reason: CounterCaptureUnknownReasonV0::ArithmeticUnrepresentable,
                    },
                );
            }
            Err(source) => return Err(CounterCaptureErrorV0::Scoring(source)),
        };
        basis.counter_features_ppb = Some(counter_features);
        basis.capture_features_ppb = Some(capture_features);

        match exact_residuals(&exact_counter, &exact_capture) {
            Err(CounterCaptureScoringErrorV0::IncompatibleEvidence { feature }) => {
                CounterCaptureReferenceV0::Unknown {
                    reason: CounterCaptureUnknownReasonV0::IncompatibleEvidence { feature },
                }
            }
            Err(CounterCaptureScoringErrorV0::ArithmeticOverflow) => {
                basis.counter_features_ppb = None;
                basis.capture_features_ppb = None;
                CounterCaptureReferenceV0::Unknown {
                    reason: CounterCaptureUnknownReasonV0::ArithmeticUnrepresentable,
                }
            }
            Err(source) => return Err(CounterCaptureErrorV0::Scoring(source)),
            Ok(residuals) => {
                let residuals_ppb = match serialize_residuals_ppb(&residuals) {
                    Ok(values) => values,
                    Err(CounterCaptureScoringErrorV0::ArithmeticOverflow) => {
                        basis.counter_features_ppb = None;
                        basis.capture_features_ppb = None;
                        return finish_assessment(
                            counter_ref,
                            capture_ref,
                            profile_ref,
                            basis,
                            CounterCaptureReferenceV0::Unknown {
                                reason: CounterCaptureUnknownReasonV0::ArithmeticUnrepresentable,
                            },
                        );
                    }
                    Err(source) => return Err(CounterCaptureErrorV0::Scoring(source)),
                };
                let score = match exact_scaled_residual_sum_ppb(&residuals, &profile.scales_ppb) {
                    Ok(value) => value,
                    Err(CounterCaptureScoringErrorV0::ArithmeticOverflow) => {
                        basis.counter_features_ppb = None;
                        basis.capture_features_ppb = None;
                        return finish_assessment(
                            counter_ref,
                            capture_ref,
                            profile_ref,
                            basis,
                            CounterCaptureReferenceV0::Unknown {
                                reason: CounterCaptureUnknownReasonV0::ArithmeticUnrepresentable,
                            },
                        );
                    }
                    Err(source) => return Err(CounterCaptureErrorV0::Scoring(source)),
                };
                basis.residuals_ppb = Some(residuals_ppb);
                basis.scaled_residual_sum_ppb = Some(score);
                if score <= profile.support_threshold_ppb {
                    CounterCaptureReferenceV0::CaptureAccountsForWindow
                } else if score >= profile.contradiction_threshold_ppb {
                    CounterCaptureReferenceV0::CaptureDoesNotAccountForWindow
                } else {
                    CounterCaptureReferenceV0::Unknown {
                        reason: CounterCaptureUnknownReasonV0::ScoreBetweenThresholds,
                    }
                }
            }
        }
    };

    finish_assessment(counter_ref, capture_ref, profile_ref, basis, reference)
}

fn finish_assessment(
    counter: CounterCaptureEvidenceRefV0,
    capture: CounterCaptureEvidenceRefV0,
    profile: CounterCaptureProfileRefV0,
    basis: CounterCaptureBasisV0,
    reference: CounterCaptureReferenceV0,
) -> Result<CounterCaptureHypothesisSetV0, CounterCaptureErrorV0> {
    let (capture_accounts_for_window, capture_does_not_account_for_window, unknown) =
        match reference {
            CounterCaptureReferenceV0::CaptureAccountsForWindow => (
                CounterCaptureDispositionV0::Supported,
                CounterCaptureDispositionV0::Contradicted,
                CounterCaptureDispositionV0::Contradicted,
            ),
            CounterCaptureReferenceV0::CaptureDoesNotAccountForWindow => (
                CounterCaptureDispositionV0::Contradicted,
                CounterCaptureDispositionV0::Supported,
                CounterCaptureDispositionV0::Contradicted,
            ),
            CounterCaptureReferenceV0::Unknown { .. } => (
                CounterCaptureDispositionV0::Underdetermined,
                CounterCaptureDispositionV0::Underdetermined,
                CounterCaptureDispositionV0::Supported,
            ),
        };

    let assessment = CounterCaptureHypothesisSetV0 {
        schema: COUNTER_CAPTURE_HYPOTHESIS_SET_SCHEMA_V0.to_owned(),
        reducer: COUNTER_CAPTURE_REDUCER_V0.to_owned(),
        counter,
        capture,
        profile,
        basis,
        capture_accounts_for_window,
        capture_does_not_account_for_window,
        unknown,
        reference,
        limitations: LIMITATIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    };
    assessment
        .validate_structure()
        .map_err(CounterCaptureErrorV0::InternalInvariant)?;
    Ok(assessment)
}

fn coverage_gate(
    counter: TrafficWindowCoverageV0,
    capture: TrafficWindowCoverageV0,
) -> Option<CounterCaptureUnknownReasonV0> {
    match (counter, capture) {
        (TrafficWindowCoverageV0::Incomplete, _) => {
            Some(CounterCaptureUnknownReasonV0::CounterEvidenceIncomplete)
        }
        (TrafficWindowCoverageV0::Unavailable, _) => {
            Some(CounterCaptureUnknownReasonV0::CounterEvidenceUnavailable)
        }
        (TrafficWindowCoverageV0::DeclaredComplete, TrafficWindowCoverageV0::Incomplete) => {
            Some(CounterCaptureUnknownReasonV0::CaptureEvidenceIncomplete)
        }
        (TrafficWindowCoverageV0::DeclaredComplete, TrafficWindowCoverageV0::Unavailable) => {
            Some(CounterCaptureUnknownReasonV0::CaptureEvidenceUnavailable)
        }
        (TrafficWindowCoverageV0::DeclaredComplete, TrafficWindowCoverageV0::DeclaredComplete) => {
            None
        }
    }
}

fn derive_exact_features(
    window: &TrafficWindowV0,
) -> Result<[Option<ExactRatio>; 10], CounterCaptureScoringErrorV0> {
    window
        .validate()
        .map_err(CounterCaptureScoringErrorV0::InvalidWindow)?;
    let packet_total = u128::from(window.received_packets)
        .checked_add(u128::from(window.transmitted_packets))
        .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
    let received_rate = u128::from(window.received_bytes)
        .checked_mul(8_000)
        .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
    let transmitted_rate = u128::from(window.transmitted_bytes)
        .checked_mul(8_000)
        .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
    Ok([
        Some(ExactRatio::integer(window.received_bytes)),
        Some(ExactRatio::integer(window.transmitted_bytes)),
        Some(ExactRatio::integer(window.received_packets)),
        Some(ExactRatio::integer(window.transmitted_packets)),
        optional_ratio(u128::from(window.received_packets), packet_total)?,
        optional_ratio(u128::from(window.transmitted_packets), packet_total)?,
        optional_ratio(
            u128::from(window.received_bytes),
            u128::from(window.received_packets),
        )?,
        optional_ratio(
            u128::from(window.transmitted_bytes),
            u128::from(window.transmitted_packets),
        )?,
        Some(ExactRatio::new(
            received_rate,
            u128::from(window.duration_ms),
        )?),
        Some(ExactRatio::new(
            transmitted_rate,
            u128::from(window.duration_ms),
        )?),
    ])
}

fn optional_ratio(
    numerator: u128,
    denominator: u128,
) -> Result<Option<ExactRatio>, CounterCaptureScoringErrorV0> {
    if denominator == 0 {
        Ok(None)
    } else {
        ExactRatio::new(numerator, denominator).map(Some)
    }
}

fn serialize_features_ppb(
    features: &[Option<ExactRatio>; 10],
) -> Result<CounterCaptureFeatureVectorPpbV0, CounterCaptureScoringErrorV0> {
    let mut values = [None; 10];
    for (index, feature) in features.iter().enumerate() {
        values[index] = feature.map(|value| value.floor_scaled(PPB)).transpose()?;
    }
    Ok(CounterCaptureFeatureVectorPpbV0::from_values(values))
}

fn exact_residuals(
    counter: &[Option<ExactRatio>; 10],
    capture: &[Option<ExactRatio>; 10],
) -> Result<[ExactRatio; 10], CounterCaptureScoringErrorV0> {
    let mut values = [ExactRatio::new(0, 1)?; 10];
    for index in 0..10 {
        values[index] = match (counter[index], capture[index]) {
            (None, None) => ExactRatio::new(0, 1)?,
            (Some(expected), Some(observed)) => {
                let difference = expected.checked_abs_diff(observed)?;
                let normalization = if expected.numerator >= expected.denominator {
                    expected
                } else {
                    ExactRatio::one()
                };
                difference.checked_div(normalization)?
            }
            _ => {
                return Err(CounterCaptureScoringErrorV0::IncompatibleEvidence {
                    feature: FEATURES[index],
                })
            }
        };
    }
    Ok(values)
}

fn serialize_residuals_ppb(
    residuals: &[ExactRatio; 10],
) -> Result<CounterCaptureResidualVectorPpbV0, CounterCaptureScoringErrorV0> {
    let mut values = [0; 10];
    for (index, residual) in residuals.iter().enumerate() {
        values[index] = residual.floor_scaled(PPB)?;
    }
    Ok(CounterCaptureResidualVectorPpbV0::from_values(values))
}

fn exact_scaled_residual_sum_ppb(
    residuals: &[ExactRatio; 10],
    scales: &CounterCaptureScaleVectorPpbV0,
) -> Result<u128, CounterCaptureScoringErrorV0> {
    if !scales.all_at_least_floor() {
        return Err(CounterCaptureScoringErrorV0::ScaleBelowFloor);
    }
    let mut sum = ExactRatio::new(0, 1)?;
    for (residual, scale) in residuals.iter().zip(scales.values()) {
        let exact_scale = ExactRatio::new(scale, PPB)?;
        sum = sum.checked_add(residual.checked_div(exact_scale)?)?;
    }
    sum.floor_scaled(PPB)
}

fn checked_mul_div_floor(
    multiplicand: u128,
    multiplier: u128,
    divisor: u128,
) -> Result<u128, CounterCaptureScoringErrorV0> {
    if divisor == 0 {
        return Err(CounterCaptureScoringErrorV0::ArithmeticOverflow);
    }
    let add_quotient = multiplicand / divisor;
    let add_remainder = multiplicand % divisor;
    let mut quotient = 0u128;
    let mut remainder = 0u128;

    for bit in (0..128).rev() {
        quotient = quotient
            .checked_mul(2)
            .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
        let (next_remainder, carry) = add_remainders_mod(remainder, remainder, divisor);
        remainder = next_remainder;
        quotient = quotient
            .checked_add(carry)
            .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;

        if multiplier & (1u128 << bit) != 0 {
            quotient = quotient
                .checked_add(add_quotient)
                .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
            let (next_remainder, carry) = add_remainders_mod(remainder, add_remainder, divisor);
            remainder = next_remainder;
            quotient = quotient
                .checked_add(carry)
                .ok_or(CounterCaptureScoringErrorV0::ArithmeticOverflow)?;
        }
    }
    Ok(quotient)
}

fn add_remainders_mod(left: u128, right: u128, modulus: u128) -> (u128, u128) {
    if left >= modulus - right {
        (left - (modulus - right), 1)
    } else {
        (left + right, 0)
    }
}

fn gcd(mut left: u128, mut right: u128) -> u128 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

fn evidence_ref(
    evidence: &TrafficWindowEvidenceV0,
) -> Result<CounterCaptureEvidenceRefV0, serde_json::Error> {
    Ok(CounterCaptureEvidenceRefV0 {
        source_schema: evidence.schema.clone(),
        record_id: evidence.record_id.clone(),
        content_sha256: evidence.canonical_sha256()?,
    })
}

fn profile_ref(
    profile: &CounterCaptureProfileV0,
) -> Result<CounterCaptureProfileRefV0, serde_json::Error> {
    Ok(CounterCaptureProfileRefV0 {
        source_schema: profile.schema.clone(),
        profile_id: profile.profile_id.clone(),
        content_sha256: profile.canonical_sha256()?,
    })
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let encoded = serde_json::to_vec(value)?;
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn valid_evidence_ref(reference: &CounterCaptureEvidenceRefV0) -> bool {
    reference.source_schema == TRAFFIC_WINDOW_SCHEMA_V0
        && !reference.record_id.is_empty()
        && valid_sha256(&reference.content_sha256)
}

fn valid_profile_ref(reference: &CounterCaptureProfileRefV0) -> bool {
    reference.source_schema == COUNTER_CAPTURE_PROFILE_SCHEMA_V0
        && !reference.profile_id.is_empty()
        && valid_sha256(&reference.content_sha256)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[cfg(test)]
mod tests {
    use super::checked_mul_div_floor;

    #[test]
    fn overflow_avoiding_mul_div_matches_safe_naive_products() {
        let values = [0, 1, 2, u32::MAX.into(), u64::MAX.into()];
        for multiplicand in values {
            for multiplier in values {
                for divisor in values.into_iter().skip(1) {
                    assert_eq!(
                        checked_mul_div_floor(multiplicand, multiplier, divisor).unwrap(),
                        multiplicand * multiplier / divisor
                    );
                }
            }
        }
    }
}
