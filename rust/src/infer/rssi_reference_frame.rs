use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub const RSSI_REFERENCE_FRAME_PROFILE_SCHEMA_V0: &str = "netmon.rssi_reference_frame_profile.v0";
pub const RSSI_REFERENCE_FRAME_ASSESSMENT_SCHEMA_V0: &str =
    "netmon.rssi_reference_frame_assessment.v0";
pub const RSSI_REFERENCE_FRAME_REDUCER_V0: &str = "netbraid.rssi_reference_frame.fixed_point.v0";
pub const RSSI_REFERENCE_FRAME_PPB_V0: u64 = 1_000_000_000;
pub const RSSI_REFERENCE_FRAME_MAX_LINK_EVIDENCE_V0: usize = 5;

/// One received-signal-strength value in fixed-point milli-dB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RssiMilliDbV0(i32);

impl RssiMilliDbV0 {
    pub const fn new(milli_db: i32) -> Self {
        Self(milli_db)
    }

    pub const fn milli_db(self) -> i32 {
        self.0
    }
}

/// One observer/source link with baseline samples and an optional recent sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct RssiReferenceFrameLinkV0 {
    observer_id: String,
    source_id: String,
    baseline_rssi_milli_db: Vec<RssiMilliDbV0>,
    recent_rssi_milli_db: Option<RssiMilliDbV0>,
}

impl RssiReferenceFrameLinkV0 {
    pub fn new(
        observer_id: impl Into<String>,
        source_id: impl Into<String>,
        mut baseline_rssi_milli_db: Vec<RssiMilliDbV0>,
        recent_rssi_milli_db: Option<RssiMilliDbV0>,
    ) -> Result<Self, RssiReferenceFrameLinkValidationErrorV0> {
        baseline_rssi_milli_db.sort_unstable();
        let link = Self {
            observer_id: observer_id.into(),
            source_id: source_id.into(),
            baseline_rssi_milli_db,
            recent_rssi_milli_db,
        };
        link.validate()?;
        Ok(link)
    }

    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn baseline_rssi_milli_db(&self) -> &[RssiMilliDbV0] {
        &self.baseline_rssi_milli_db
    }

    pub const fn recent_rssi_milli_db(&self) -> Option<RssiMilliDbV0> {
        self.recent_rssi_milli_db
    }

    pub fn validate(&self) -> Result<(), RssiReferenceFrameLinkValidationErrorV0> {
        if self.observer_id.is_empty() {
            return Err(RssiReferenceFrameLinkValidationErrorV0::EmptyObserverId);
        }
        if self.source_id.is_empty() {
            return Err(RssiReferenceFrameLinkValidationErrorV0::EmptySourceId);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RssiReferenceFrameLinkValidationErrorV0 {
    EmptyObserverId,
    EmptySourceId,
}

impl std::fmt::Display for RssiReferenceFrameLinkValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::EmptyObserverId => "RSSI reference-frame observer id is empty",
            Self::EmptySourceId => "RSSI reference-frame source id is empty",
        })
    }
}

impl std::error::Error for RssiReferenceFrameLinkValidationErrorV0 {}

/// Explicit fixed-point calibration for the v0 reducer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct RssiReferenceFrameProfileV0 {
    schema: String,
    profile_id: String,
    minimum_baseline_readings: u32,
    minimum_absolute_shift_milli_db: u32,
    mad_multiplier_ppb: u64,
    minimum_steady_links: u32,
    minimum_shifted_fraction_ppb: u64,
}

impl RssiReferenceFrameProfileV0 {
    pub fn new(
        profile_id: impl Into<String>,
        minimum_baseline_readings: u32,
        minimum_absolute_shift_milli_db: u32,
        mad_multiplier_ppb: u64,
        minimum_steady_links: u32,
        minimum_shifted_fraction_ppb: u64,
    ) -> Result<Self, RssiReferenceFrameProfileValidationErrorV0> {
        let profile = Self {
            schema: RSSI_REFERENCE_FRAME_PROFILE_SCHEMA_V0.to_owned(),
            profile_id: profile_id.into(),
            minimum_baseline_readings,
            minimum_absolute_shift_milli_db,
            mad_multiplier_ppb,
            minimum_steady_links,
            minimum_shifted_fraction_ppb,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub const fn minimum_baseline_readings(&self) -> u32 {
        self.minimum_baseline_readings
    }

    pub const fn minimum_absolute_shift_milli_db(&self) -> u32 {
        self.minimum_absolute_shift_milli_db
    }

    pub const fn mad_multiplier_ppb(&self) -> u64 {
        self.mad_multiplier_ppb
    }

    pub const fn minimum_steady_links(&self) -> u32 {
        self.minimum_steady_links
    }

    pub const fn minimum_shifted_fraction_ppb(&self) -> u64 {
        self.minimum_shifted_fraction_ppb
    }

    pub fn validate(&self) -> Result<(), RssiReferenceFrameProfileValidationErrorV0> {
        if self.schema != RSSI_REFERENCE_FRAME_PROFILE_SCHEMA_V0 {
            return Err(RssiReferenceFrameProfileValidationErrorV0::UnsupportedSchema);
        }
        if self.profile_id.is_empty() {
            return Err(RssiReferenceFrameProfileValidationErrorV0::EmptyProfileId);
        }
        if self.minimum_baseline_readings == 0 {
            return Err(RssiReferenceFrameProfileValidationErrorV0::ZeroMinimumBaselineReadings);
        }
        if self.minimum_absolute_shift_milli_db == 0 {
            return Err(RssiReferenceFrameProfileValidationErrorV0::ZeroMinimumAbsoluteShift);
        }
        if self.mad_multiplier_ppb == 0 {
            return Err(RssiReferenceFrameProfileValidationErrorV0::ZeroMadMultiplier);
        }
        if self.minimum_steady_links == 0 {
            return Err(RssiReferenceFrameProfileValidationErrorV0::ZeroMinimumSteadyLinks);
        }
        if !(1..=RSSI_REFERENCE_FRAME_PPB_V0).contains(&self.minimum_shifted_fraction_ppb) {
            return Err(RssiReferenceFrameProfileValidationErrorV0::InvalidMinimumShiftedFraction);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RssiReferenceFrameProfileValidationErrorV0 {
    UnsupportedSchema,
    EmptyProfileId,
    ZeroMinimumBaselineReadings,
    ZeroMinimumAbsoluteShift,
    ZeroMadMultiplier,
    ZeroMinimumSteadyLinks,
    InvalidMinimumShiftedFraction,
}

impl std::fmt::Display for RssiReferenceFrameProfileValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSchema => "unsupported RSSI reference-frame profile schema",
            Self::EmptyProfileId => "RSSI reference-frame profile id is empty",
            Self::ZeroMinimumBaselineReadings => "minimum baseline reading count must be positive",
            Self::ZeroMinimumAbsoluteShift => "minimum absolute shift must be positive",
            Self::ZeroMadMultiplier => "MAD multiplier must be positive",
            Self::ZeroMinimumSteadyLinks => "minimum steady link count must be positive",
            Self::InvalidMinimumShiftedFraction => {
                "minimum shifted fraction must be within one PPB and one whole"
            }
        })
    }
}

impl std::error::Error for RssiReferenceFrameProfileValidationErrorV0 {}

/// Fixed-point evidence retained for one shifted or vanished steady link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct RssiLinkShiftEvidenceV0 {
    source_id: String,
    kind: RssiLinkShiftKindV0,
}

impl RssiLinkShiftEvidenceV0 {
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub const fn kind(&self) -> RssiLinkShiftKindV0 {
        self.kind
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RssiLinkShiftKindV0 {
    Shifted { delta_milli_db: i64 },
    Vanished,
}

/// Observer-scoped evidence after source-wide candidates have been excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct RssiObserverEvidenceV0 {
    observer_id: String,
    observer_shift_candidate: bool,
    steady_link_count: u32,
    shifted_link_count: u32,
    median_shift_milli_db: Option<i64>,
    link_evidence: Vec<RssiLinkShiftEvidenceV0>,
}

impl RssiObserverEvidenceV0 {
    pub fn observer_id(&self) -> &str {
        &self.observer_id
    }

    pub const fn observer_shift_candidate(&self) -> bool {
        self.observer_shift_candidate
    }

    pub const fn steady_link_count(&self) -> u32 {
        self.steady_link_count
    }

    pub const fn shifted_link_count(&self) -> u32 {
        self.shifted_link_count
    }

    pub const fn median_shift_milli_db(&self) -> Option<i64> {
        self.median_shift_milli_db
    }

    pub fn link_evidence(&self) -> &[RssiLinkShiftEvidenceV0] {
        &self.link_evidence
    }
}

/// A source whose steady links all shifted or vanished at two or more observers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct RssiSourceWideShiftCandidateV0 {
    source_id: String,
    observer_ids: Vec<String>,
}

impl RssiSourceWideShiftCandidateV0 {
    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn observer_ids(&self) -> &[String] {
        &self.observer_ids
    }
}

/// Deterministic fixed-point RSSI reference-frame evidence and candidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct RssiReferenceFrameAssessmentV0 {
    schema: String,
    reducer: String,
    profile_id: String,
    observer_evidence: Vec<RssiObserverEvidenceV0>,
    source_wide_shift_candidates: Vec<RssiSourceWideShiftCandidateV0>,
}

impl RssiReferenceFrameAssessmentV0 {
    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn reducer(&self) -> &str {
        &self.reducer
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn observer_evidence(&self) -> &[RssiObserverEvidenceV0] {
        &self.observer_evidence
    }

    pub fn source_wide_shift_candidates(&self) -> &[RssiSourceWideShiftCandidateV0] {
        &self.source_wide_shift_candidates
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum RssiReferenceFrameErrorV0 {
    InvalidLink {
        index: usize,
        source: RssiReferenceFrameLinkValidationErrorV0,
    },
    InvalidProfile(RssiReferenceFrameProfileValidationErrorV0),
    ConflictingObserverSourceLink {
        observer_id: String,
        source_id: String,
    },
}

impl std::fmt::Display for RssiReferenceFrameErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLink { index, source } => {
                write!(formatter, "invalid RSSI reference-frame link at index {index}: {source}")
            }
            Self::InvalidProfile(source) => {
                write!(formatter, "invalid RSSI reference-frame profile: {source}")
            }
            Self::ConflictingObserverSourceLink {
                observer_id,
                source_id,
            } => write!(
                formatter,
                "conflicting RSSI reference-frame link for observer {observer_id:?} and source {source_id:?}"
            ),
        }
    }
}

impl std::error::Error for RssiReferenceFrameErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidLink { source, .. } => Some(source),
            Self::InvalidProfile(source) => Some(source),
            Self::ConflictingObserverSourceLink { .. } => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalLink {
    baseline_rssi_milli_db: Vec<i32>,
    recent_rssi_milli_db: Option<i32>,
}

impl From<&RssiReferenceFrameLinkV0> for CanonicalLink {
    fn from(link: &RssiReferenceFrameLinkV0) -> Self {
        let mut baseline_rssi_milli_db = link
            .baseline_rssi_milli_db
            .iter()
            .map(|value| value.milli_db())
            .collect::<Vec<_>>();
        baseline_rssi_milli_db.sort_unstable();
        Self {
            baseline_rssi_milli_db,
            recent_rssi_milli_db: link.recent_rssi_milli_db.map(RssiMilliDbV0::milli_db),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinkAssessment {
    shifted: bool,
    delta_quarter_milli_db: Option<i64>,
}

/// Reduce baseline and recent RSSI links into stable evidence and candidate lists.
pub fn assess_rssi_reference_frame_v0(
    links: &[RssiReferenceFrameLinkV0],
    profile: &RssiReferenceFrameProfileV0,
) -> Result<RssiReferenceFrameAssessmentV0, RssiReferenceFrameErrorV0> {
    profile
        .validate()
        .map_err(RssiReferenceFrameErrorV0::InvalidProfile)?;

    let mut canonical = BTreeMap::new();
    for (index, link) in links.iter().enumerate() {
        link.validate()
            .map_err(|source| RssiReferenceFrameErrorV0::InvalidLink { index, source })?;
        let key = (link.observer_id.clone(), link.source_id.clone());
        let value = CanonicalLink::from(link);
        if let Some(existing) = canonical.get(&key) {
            if existing != &value {
                return Err(RssiReferenceFrameErrorV0::ConflictingObserverSourceLink {
                    observer_id: key.0,
                    source_id: key.1,
                });
            }
        } else {
            canonical.insert(key, value);
        }
    }

    let alive_observers = canonical
        .iter()
        .filter_map(|((observer_id, _), link)| {
            link.recent_rssi_milli_db
                .is_some()
                .then_some(observer_id.clone())
        })
        .collect::<BTreeSet<_>>();
    let minimum_baseline_readings =
        usize::try_from(profile.minimum_baseline_readings).unwrap_or(usize::MAX);
    let mut link_assessments = BTreeMap::new();

    for ((observer_id, source_id), link) in &canonical {
        if link.baseline_rssi_milli_db.len() < minimum_baseline_readings {
            continue;
        }
        let assessment = match link.recent_rssi_milli_db {
            Some(recent) => {
                let baseline_median = median_quarter_milli_db(&link.baseline_rssi_milli_db);
                let delta = i64::from(recent) * 4 - baseline_median;
                let mad = mad_quarter_milli_db(&link.baseline_rssi_milli_db, baseline_median);
                LinkAssessment {
                    shifted: exceeds_shift_threshold(delta, mad, profile),
                    delta_quarter_milli_db: Some(delta),
                }
            }
            None if alive_observers.contains(observer_id) => LinkAssessment {
                shifted: true,
                delta_quarter_milli_db: None,
            },
            None => continue,
        };
        link_assessments.insert((observer_id.clone(), source_id.clone()), assessment);
    }

    let mut assessments_by_source: BTreeMap<&str, Vec<(&str, LinkAssessment)>> = BTreeMap::new();
    for ((observer_id, source_id), assessment) in &link_assessments {
        assessments_by_source
            .entry(source_id)
            .or_default()
            .push((observer_id, *assessment));
    }
    let source_wide_shift_candidates = assessments_by_source
        .into_iter()
        .filter_map(|(source_id, assessments)| {
            (assessments.len() >= 2 && assessments.iter().all(|(_, value)| value.shifted)).then(
                || RssiSourceWideShiftCandidateV0 {
                    source_id: source_id.to_owned(),
                    observer_ids: assessments
                        .into_iter()
                        .map(|(observer_id, _)| observer_id.to_owned())
                        .collect(),
                },
            )
        })
        .collect::<Vec<_>>();
    let source_wide_ids = source_wide_shift_candidates
        .iter()
        .map(|candidate| candidate.source_id.as_str())
        .collect::<BTreeSet<_>>();

    let observer_ids = link_assessments
        .keys()
        .map(|(observer_id, _)| observer_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut observer_evidence = Vec::with_capacity(observer_ids.len());
    for observer_id in observer_ids {
        let retained = link_assessments
            .iter()
            .filter(|((candidate_observer_id, source_id), _)| {
                candidate_observer_id == observer_id
                    && !source_wide_ids.contains(source_id.as_str())
            })
            .collect::<Vec<_>>();
        let steady_link_count = u32::try_from(retained.len()).unwrap_or(u32::MAX);
        let mut shifted_deltas = Vec::new();
        let mut link_evidence = retained
            .into_iter()
            .filter(|(_, assessment)| assessment.shifted)
            .map(|((_, source_id), assessment)| {
                let kind = match assessment.delta_quarter_milli_db {
                    Some(delta) => {
                        let delta_milli_db = round_quarter_milli_db(delta);
                        shifted_deltas.push(delta_milli_db);
                        RssiLinkShiftKindV0::Shifted { delta_milli_db }
                    }
                    None => RssiLinkShiftKindV0::Vanished,
                };
                RssiLinkShiftEvidenceV0 {
                    source_id: source_id.clone(),
                    kind,
                }
            })
            .collect::<Vec<_>>();
        let shifted_link_count = u32::try_from(link_evidence.len()).unwrap_or(u32::MAX);
        let observer_shift_candidate = steady_link_count >= profile.minimum_steady_links
            && u128::from(shifted_link_count) * u128::from(RSSI_REFERENCE_FRAME_PPB_V0)
                >= u128::from(profile.minimum_shifted_fraction_ppb) * u128::from(steady_link_count);
        link_evidence.sort_by(compare_link_evidence);
        link_evidence.truncate(RSSI_REFERENCE_FRAME_MAX_LINK_EVIDENCE_V0);
        observer_evidence.push(RssiObserverEvidenceV0 {
            observer_id: observer_id.to_owned(),
            observer_shift_candidate,
            steady_link_count,
            shifted_link_count,
            median_shift_milli_db: median_i64(&mut shifted_deltas),
            link_evidence,
        });
    }

    Ok(RssiReferenceFrameAssessmentV0 {
        schema: RSSI_REFERENCE_FRAME_ASSESSMENT_SCHEMA_V0.to_owned(),
        reducer: RSSI_REFERENCE_FRAME_REDUCER_V0.to_owned(),
        profile_id: profile.profile_id.clone(),
        observer_evidence,
        source_wide_shift_candidates,
    })
}

fn median_quarter_milli_db(sorted_milli_db: &[i32]) -> i64 {
    let middle = sorted_milli_db.len() / 2;
    if sorted_milli_db.len() % 2 == 1 {
        i64::from(sorted_milli_db[middle]) * 4
    } else {
        (i64::from(sorted_milli_db[middle - 1]) + i64::from(sorted_milli_db[middle])) * 2
    }
}

fn mad_quarter_milli_db(sorted_milli_db: &[i32], median_quarter_milli_db: i64) -> u64 {
    let mut deviations = sorted_milli_db
        .iter()
        .map(|value| (i64::from(*value) * 4 - median_quarter_milli_db).unsigned_abs())
        .collect::<Vec<_>>();
    deviations.sort_unstable();
    let middle = deviations.len() / 2;
    if deviations.len() % 2 == 1 {
        deviations[middle]
    } else {
        (deviations[middle - 1] + deviations[middle]) / 2
    }
}

fn exceeds_shift_threshold(
    delta_quarter_milli_db: i64,
    mad_quarter_milli_db: u64,
    profile: &RssiReferenceFrameProfileV0,
) -> bool {
    let absolute_delta = delta_quarter_milli_db.unsigned_abs();
    absolute_delta >= u64::from(profile.minimum_absolute_shift_milli_db) * 4
        && u128::from(absolute_delta) * u128::from(RSSI_REFERENCE_FRAME_PPB_V0)
            >= u128::from(mad_quarter_milli_db) * u128::from(profile.mad_multiplier_ppb)
}

fn round_quarter_milli_db(value: i64) -> i64 {
    if value >= 0 {
        (value + 2) / 4
    } else {
        -((-value + 2) / 4)
    }
}

fn median_i64(values: &mut [i64]) -> Option<i64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let middle = values.len() / 2;
    if values.len() % 2 == 1 {
        Some(values[middle])
    } else {
        Some(round_half_away_from_zero(
            values[middle - 1] + values[middle],
        ))
    }
}

fn round_half_away_from_zero(numerator: i64) -> i64 {
    if numerator >= 0 {
        (numerator + 1) / 2
    } else {
        -((-numerator + 1) / 2)
    }
}

fn compare_link_evidence(
    left: &RssiLinkShiftEvidenceV0,
    right: &RssiLinkShiftEvidenceV0,
) -> Ordering {
    match (left.kind, right.kind) {
        (
            RssiLinkShiftKindV0::Shifted {
                delta_milli_db: left_delta,
            },
            RssiLinkShiftKindV0::Shifted {
                delta_milli_db: right_delta,
            },
        ) => right_delta
            .unsigned_abs()
            .cmp(&left_delta.unsigned_abs())
            .then_with(|| left.source_id.cmp(&right.source_id)),
        (RssiLinkShiftKindV0::Shifted { .. }, RssiLinkShiftKindV0::Vanished) => Ordering::Less,
        (RssiLinkShiftKindV0::Vanished, RssiLinkShiftKindV0::Shifted { .. }) => Ordering::Greater,
        (RssiLinkShiftKindV0::Vanished, RssiLinkShiftKindV0::Vanished) => {
            left.source_id.cmp(&right.source_id)
        }
    }
}
