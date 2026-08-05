#!/usr/bin/env python3
"""Preregister the structural RoboLoc-G evaluation policy.

This module contains no corpus reader, payload profiler, feature builder, model,
or scorer. It fixes the observation split, archive evidence roles, tabular
headers, clocks, coordinate transform, and blockers that a later profiler must
close before fusion or scoring is allowed.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Optional, Sequence, Tuple


NANOSECONDS_PER_SECOND = 1_000_000_000
_INTEGER_NS = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_DECIMAL_SECONDS = re.compile(r"(0|[1-9][0-9]*)\.([0-9]{1,9})\Z")
_OPAQUE_ID_DOMAIN = b"netbraid.robolocg-policy.v0\x00"


class RoboLocGPolicyError(ValueError):
    """Stable fail-closed reason for an invalid policy operation."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class Role(Enum):
    TRAIN = "train"
    CALIBRATION = "calibration"
    VALIDATION = "validation"
    LOCKED_TEST = "locked_test"


class Take(Enum):
    ZIGZAG1 = "zigzag1"
    ZIGZAG2 = "zigzag2"
    ZIGZAG3 = "zigzag3"
    ZIGZAG4 = "zigzag4"
    STILL = "still"
    CIRCLE = "circle"
    RANDOM1 = "random1"
    RANDOM2 = "random2"


class Family(Enum):
    ZIGZAG = "zigzag"
    STILL = "still"
    CIRCLE = "circle"
    RANDOM = "random"


class ArchiveUse(Enum):
    OBSERVATION = "observation"
    ORACLE = "oracle"
    DEPENDENT_CONSISTENCY = "dependent_consistency"
    CONFIGURATION = "configuration"


class Blocker(Enum):
    UWB_UNIT_CONFLICT = "uwb_unit_conflict"
    FTM_ANCHOR_ID_MISMATCH = "ftm_anchor_id_mismatch"
    OUTER_VS_HEADER_DELTAS_DIAGNOSTIC = "outer_vs_header_deltas_diagnostic"
    RADAR_ASSOCIATION_EXTRINSICS_ABSENT = "radar_association_extrinsics_absent"
    INTERPOLATION_NO_EXTRAPOLATION_TOLERANCE_UNFIXED = (
        "interpolation_no_extrapolation_tolerance_unfixed"
    )


@dataclass(frozen=True)
class TakeAssignment:
    take: Take
    family: Family
    role: Role
    session_id: str
    domain_id: str
    configuration_id: str


@dataclass(frozen=True)
class CsvHeaderContract:
    columns: Tuple[str, ...]
    outer_clock_column: str
    embedded_clock_columns: Tuple[str, ...] = ()


@dataclass(frozen=True)
class MemberContract:
    kind: str
    count: int
    header: Optional[CsvHeaderContract] = None


@dataclass(frozen=True)
class ArchiveContract:
    kind: str
    use: ArchiveUse
    file_count: int
    entry_count: Optional[int]
    members: Tuple[MemberContract, ...]

    @property
    def model_input_allowed(self) -> bool:
        return self.use is ArchiveUse.OBSERVATION

    @property
    def scoring_oracle(self) -> bool:
        return self.use is ArchiveUse.ORACLE


@dataclass(frozen=True)
class GateState:
    closed_blockers: Tuple[Blocker, ...]
    open_blockers: Tuple[Blocker, ...]
    fusion_capable: bool
    scoring_allowed: bool


TAKE_ORDER = tuple(Take)
BLOCKER_ORDER = tuple(Blocker)

_TAKE_POLICY = {
    Take.ZIGZAG1: (Family.ZIGZAG, Role.TRAIN),
    Take.ZIGZAG2: (Family.ZIGZAG, Role.TRAIN),
    Take.ZIGZAG3: (Family.ZIGZAG, Role.TRAIN),
    Take.ZIGZAG4: (Family.ZIGZAG, Role.TRAIN),
    Take.STILL: (Family.STILL, Role.CALIBRATION),
    Take.CIRCLE: (Family.CIRCLE, Role.VALIDATION),
    Take.RANDOM1: (Family.RANDOM, Role.LOCKED_TEST),
    Take.RANDOM2: (Family.RANDOM, Role.LOCKED_TEST),
}


def opaque_id(namespace: str, canonical_token: str) -> str:
    """Return a deterministic domain-separated identifier for policy labels."""

    if not namespace or not canonical_token:
        raise RoboLocGPolicyError("empty_opaque_id_input")
    digest = hashlib.sha256(_OPAQUE_ID_DOMAIN)
    digest.update(namespace.encode("ascii"))
    digest.update(b"\x00")
    digest.update(canonical_token.encode("ascii"))
    return digest.hexdigest()


FROZEN_CONFIGURATION_ID = opaque_id("configuration", "publisher-v0")


def _assignment(take: Take) -> TakeAssignment:
    family, role = _TAKE_POLICY[take]
    return TakeAssignment(
        take=take,
        family=family,
        role=role,
        session_id=opaque_id("session", take.value),
        domain_id=opaque_id("domain", family.value),
        configuration_id=FROZEN_CONFIGURATION_ID,
    )


TAKE_ASSIGNMENTS = tuple(_assignment(take) for take in TAKE_ORDER)


def build_take_assignments(
    takes: Iterable[Take] = TAKE_ORDER,
) -> Tuple[TakeAssignment, ...]:
    """Build the exact assignment in publisher order, independent of input order."""

    supplied = tuple(takes)
    if any(not isinstance(take, Take) for take in supplied):
        raise RoboLocGPolicyError("invalid_take")
    if len(supplied) != len(TAKE_ORDER) or set(supplied) != set(TAKE_ORDER):
        raise RoboLocGPolicyError("take_set_mismatch")
    return tuple(_assignment(take) for take in TAKE_ORDER)


def audit_take_assignments(assignments: Sequence[TakeAssignment]) -> None:
    """Require session-atomic takes and domain-atomic trajectory families."""

    if any(not isinstance(item, TakeAssignment) for item in assignments):
        raise RoboLocGPolicyError("invalid_take_assignment")

    session_roles = {}
    domain_roles = {}
    for item in assignments:
        session_roles.setdefault(item.session_id, set()).add(item.role)
        domain_roles.setdefault(item.domain_id, set()).add(item.role)
    if any(len(roles) != 1 for roles in session_roles.values()):
        raise RoboLocGPolicyError("session_crosses_roles")
    if any(len(roles) != 1 for roles in domain_roles.values()):
        raise RoboLocGPolicyError("family_domain_crosses_roles")

    by_take = {item.take: item for item in assignments}
    if len(assignments) != len(TAKE_ORDER) or set(by_take) != set(TAKE_ORDER):
        raise RoboLocGPolicyError("take_set_mismatch")
    for expected in TAKE_ASSIGNMENTS:
        if by_take[expected.take] != expected:
            raise RoboLocGPolicyError("take_assignment_mismatch")


RADAR_HEADER = CsvHeaderContract(
    columns=(
        "timestamp",
        "array_index",
        "header.frame_id",
        "header.stamp.nanosec",
        "header.stamp.sec",
        "returns.amplitude",
        "returns.azimuth",
        "returns.doppler_velocity",
        "returns.elevation",
        "returns.range",
    ),
    outer_clock_column="timestamp",
    embedded_clock_columns=("header.stamp.sec", "header.stamp.nanosec"),
)

POINT_CLOUD_HEADER = CsvHeaderContract(
    columns=(
        "timestamp",
        "doppler",
        "header.frame_id",
        "header.seq",
        "header.stamp.nanosec",
        "header.stamp.sec",
        "height",
        "is_bigendian",
        "is_dense",
        "point_step",
        "row_step",
        "snr",
        "width",
        "x",
        "y",
        "z",
    ),
    outer_clock_column="timestamp",
    embedded_clock_columns=("header.stamp.sec", "header.stamp.nanosec"),
)

FTM_HEADER = CsvHeaderContract(
    columns=(
        "timestamp",
        "anchor_id",
        "array_index",
        "dist_est",
        "frames.rssi",
        "frames.rtt",
        "frames.t1",
        "frames.t2",
        "frames.t3",
        "frames.t4",
        "num_frames",
        "rtt_est",
        "rtt_raw",
    ),
    outer_clock_column="timestamp",
)

IMU_HEADER = CsvHeaderContract(
    columns=(
        "timestamp",
        "angular_velocity.x",
        "angular_velocity.y",
        "angular_velocity.z",
        *(f"angular_velocity_covariance[{index}]" for index in range(9)),
        "header.frame_id",
        "header.stamp.nanosec",
        "header.stamp.sec",
        "linear_acceleration.x",
        "linear_acceleration.y",
        "linear_acceleration.z",
        *(f"linear_acceleration_covariance[{index}]" for index in range(9)),
        "orientation.w",
        "orientation.x",
        "orientation.y",
        "orientation.z",
        *(f"orientation_covariance[{index}]" for index in range(9)),
    ),
    outer_clock_column="timestamp",
    embedded_clock_columns=("header.stamp.sec", "header.stamp.nanosec"),
)

UWB_HEADER = CsvHeaderContract(
    columns=(
        "timestamp",
        "anchor_id",
        "error_estimation",
        "range",
        "rss",
        "seq",
        "tag_id",
    ),
    outer_clock_column="timestamp",
)

GROUND_TRUTH_HEADER = CsvHeaderContract(
    columns=(
        "time",
        "Grua.X",
        "Grua.Y",
        "Grua.Z",
        "UWB_tag.X",
        "UWB_tag.Y",
        "UWB_tag.Z",
        "FTM_tag.X",
        "FTM_tag.Y",
        "FTM_tag.Z",
        "Feet.X",
        "Feet.Y",
        "Feet.Z",
    ),
    outer_clock_column="time",
)

GANTRY_MEASUREMENT_HEADER = CsvHeaderContract(
    columns=("time", "x", "y", "z"),
    outer_clock_column="time",
)

ARCHIVE_CONTRACTS = (
    ArchiveContract(
        kind="sensor_measurements_csv",
        use=ArchiveUse.OBSERVATION,
        file_count=64,
        entry_count=101,
        members=(
            MemberContract("radar_scan_csv", 24, RADAR_HEADER),
            MemberContract("radar_point_cloud_csv", 16, POINT_CLOUD_HEADER),
            MemberContract("ftm_csv", 8, FTM_HEADER),
            MemberContract("imu_csv", 8, IMU_HEADER),
            MemberContract("uwb_ranging_csv", 8, UWB_HEADER),
        ),
    ),
    ArchiveContract(
        kind="ground_truth",
        use=ArchiveUse.ORACLE,
        file_count=16,
        entry_count=None,
        members=(
            MemberContract("gantry_frame_ground_truth_csv", 8, GROUND_TRUTH_HEADER),
            MemberContract("optitrack_frame_ground_truth_csv", 8, GROUND_TRUTH_HEADER),
        ),
    ),
    ArchiveContract(
        kind="gantry_measurements",
        use=ArchiveUse.DEPENDENT_CONSISTENCY,
        file_count=8,
        entry_count=None,
        members=(
            MemberContract("raw_gantry_measurement_csv", 8, GANTRY_MEASUREMENT_HEADER),
        ),
    ),
    ArchiveContract(
        kind="gantry_cnc",
        use=ArchiveUse.CONFIGURATION,
        file_count=8,
        entry_count=None,
        members=(
            MemberContract("trajectory_gcode", 7),
            MemberContract("still_position_text", 1),
        ),
    ),
    ArchiveContract(
        kind="optitrack_calibration",
        use=ArchiveUse.CONFIGURATION,
        file_count=12,
        entry_count=None,
        members=(
            MemberContract("camera_node_json", 10),
            MemberContract("extracted_calibration_json", 1),
            MemberContract("native_calibration_binary", 1),
        ),
    ),
)


def parse_integer_nanoseconds(value: str) -> int:
    """Parse an unsigned integer-nanosecond clock without binary floating point."""

    if not isinstance(value, str) or _INTEGER_NS.fullmatch(value) is None:
        raise RoboLocGPolicyError("invalid_integer_nanoseconds")
    return int(value)


def parse_decimal_seconds_nanoseconds(value: str) -> int:
    """Parse exact decimal seconds into integer nanoseconds without rounding."""

    if not isinstance(value, str):
        raise RoboLocGPolicyError("invalid_decimal_seconds")
    matched = _DECIMAL_SECONDS.fullmatch(value)
    if matched is None:
        raise RoboLocGPolicyError("invalid_decimal_seconds")
    seconds, fraction = matched.groups()
    return int(seconds) * NANOSECONDS_PER_SECOND + int(fraction.ljust(9, "0"))


TRANSLATION_MM = (-2647.33, 2226.40, -2462.04)
ROTATION_DEGREES_XYZ = (0.6730, -0.2091, -94.6088)

Matrix3 = Tuple[Tuple[float, float, float], ...]
Vector3 = Tuple[float, float, float]


def _matrix_multiply(left: Matrix3, right: Matrix3) -> Matrix3:
    return tuple(
        tuple(
            sum(left[row][inner] * right[inner][column] for inner in range(3))
            for column in range(3)
        )
        for row in range(3)
    )


def active_axis_rotation(axis: str, degrees: float) -> Matrix3:
    """Build a right-handed active rotation for a column vector."""

    radians = math.radians(degrees)
    cosine = math.cos(radians)
    sine = math.sin(radians)
    if axis == "x":
        return ((1.0, 0.0, 0.0), (0.0, cosine, -sine), (0.0, sine, cosine))
    if axis == "y":
        return ((cosine, 0.0, sine), (0.0, 1.0, 0.0), (-sine, 0.0, cosine))
    if axis == "z":
        return ((cosine, -sine, 0.0), (sine, cosine, 0.0), (0.0, 0.0, 1.0))
    raise RoboLocGPolicyError("invalid_rotation_axis")


def compose_rotation_matrix() -> Matrix3:
    """Compose active column-vector rotations as Rz @ Ry @ Rx."""

    x_degrees, y_degrees, z_degrees = ROTATION_DEGREES_XYZ
    return _matrix_multiply(
        active_axis_rotation("z", z_degrees),
        _matrix_multiply(
            active_axis_rotation("y", y_degrees),
            active_axis_rotation("x", x_degrees),
        ),
    )


# Frozen from compose_rotation_matrix(); tests guard both the values and order.
ROTATION_MATRIX = (
    (-0.08035148253494716, 0.9967012322165939, -0.011414593832425707),
    (-0.9967599112042966, -0.08030374721779358, 0.0045812224114574135),
    (0.0036494753648449807, 0.01174571754742469, 0.9999243568634867),
)


def transform_optitrack_to_gantry_mm(point_mm: Sequence[float]) -> Vector3:
    """Translate first, then apply the frozen active Rz @ Ry @ Rx rotation."""

    if len(point_mm) != 3 or any(not math.isfinite(value) for value in point_mm):
        raise RoboLocGPolicyError("invalid_point")
    translated = tuple(point_mm[index] + TRANSLATION_MM[index] for index in range(3))
    return tuple(
        sum(ROTATION_MATRIX[row][column] * translated[column] for column in range(3))
        for row in range(3)
    )


def evaluate_gate(closed_blockers: Iterable[Blocker] = ()) -> GateState:
    """Open fusion and scoring only after every preregistered blocker closes."""

    supplied = tuple(closed_blockers)
    if any(not isinstance(blocker, Blocker) for blocker in supplied):
        raise RoboLocGPolicyError("invalid_blocker_closure")
    if len(supplied) != len(set(supplied)):
        raise RoboLocGPolicyError("duplicate_blocker_closure")
    closed = tuple(blocker for blocker in BLOCKER_ORDER if blocker in supplied)
    opened = tuple(blocker for blocker in BLOCKER_ORDER if blocker not in supplied)
    capable = not opened
    return GateState(
        closed_blockers=closed,
        open_blockers=opened,
        fusion_capable=capable,
        scoring_allowed=capable,
    )


audit_take_assignments(TAKE_ASSIGNMENTS)
