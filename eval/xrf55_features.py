"""Shared deterministic feature and campaign policy for XRF55 evaluation."""

from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

SCHEMA = "netbraid.xrf55_feature_cache.v0"
ID_REVISION = "xrf55-feature-cache-v0"
MODALITIES = ("wifi", "rfid", "mmwave")
FEATURES_PER_REGION = 4
SEQUENCE_BINS = 16
CHANNEL_BINS = 8
SPATIAL_BINS = (4, 4)
FEATURE_COUNT = 96
DEFAULT_GROUP_COUNT = 8
PUBLISHER_REPETITIONS = tuple(range(1, 21))
TRAIN_REPETITIONS = frozenset(range(1, 15))
TEST_REPETITIONS = frozenset(range(15, 21))

ObservationKey = tuple[int, int, int, int]
GroupKey = tuple[int, int, int]


class Xrf55FeatureError(RuntimeError):
    """Stable failure at the XRF55 feature-cache boundary."""


@dataclass(frozen=True)
class ArrayLayout:
    dtype: str
    fortran_order: bool
    shape: tuple[int, ...]


OFFICIAL_LAYOUTS = {
    "wifi": ArrayLayout("<f8", False, (270, 1000)),
    "rfid": ArrayLayout("<f8", False, (23, 148)),
    "mmwave": ArrayLayout("<f4", True, (1, 17, 256, 128)),
}


@dataclass(frozen=True)
class CampaignEvent:
    event_id: str
    group_id: str
    observation: ObservationKey
    repetition: int
    row: int
    split: str


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")


def _digest(namespace: str, value: Any) -> str:
    return hashlib.sha256(
        ID_REVISION.encode("ascii")
        + b"\0"
        + namespace.encode("ascii")
        + b"\0"
        + _canonical(value)
    ).hexdigest()


def _ranked(namespace: str, values: Iterable[Any]) -> list[Any]:
    return sorted(values, key=lambda value: (_digest(namespace, value), value))


def _validate_observation(value: ObservationKey) -> None:
    if (
        not isinstance(value, tuple)
        or len(value) != 4
        or any(type(item) is not int or item <= 0 for item in value)
    ):
        raise Xrf55FeatureError("invalid_observation_key")


def select_campaign(
    observations: Iterable[ObservationKey],
    *,
    group_count: int = DEFAULT_GROUP_COUNT,
    repetitions: Sequence[int] = PUBLISHER_REPETITIONS,
) -> tuple[CampaignEvent, ...]:
    """Select complete performer/action groups without exposing their labels."""

    if type(group_count) is not int or group_count <= 0:
        raise Xrf55FeatureError("invalid_group_count")
    expected_repetitions = tuple(repetitions)
    if (
        not expected_repetitions
        or len(set(expected_repetitions)) != len(expected_repetitions)
        or any(type(value) is not int or value <= 0 for value in expected_repetitions)
    ):
        raise Xrf55FeatureError("invalid_repetition_policy")

    by_group: defaultdict[GroupKey, set[int]] = defaultdict(set)
    for observation in set(observations):
        _validate_observation(observation)
        scene, subject, action, repetition = observation
        by_group[(scene, subject, action)].add(repetition)

    expected = set(expected_repetitions)
    complete_groups = [
        group for group, observed in by_group.items() if observed == expected
    ]
    if len(complete_groups) < group_count:
        raise Xrf55FeatureError("insufficient_complete_groups")

    selected_groups = _ranked("group-selection", complete_groups)[:group_count]
    events = []
    for group in selected_groups:
        group_id = _digest("group-id", group)
        for repetition in expected_repetitions:
            observation = (*group, repetition)
            split = "train" if repetition in TRAIN_REPETITIONS else "test"
            if repetition not in TRAIN_REPETITIONS | TEST_REPETITIONS:
                split = "other"
            events.append(
                CampaignEvent(
                    event_id=_digest("event-id", observation),
                    group_id=group_id,
                    observation=observation,
                    repetition=repetition,
                    row=len(events),
                    split=split,
                )
            )
    return tuple(events)


def _moments(values: np.ndarray) -> tuple[float, float, float, float]:
    region = np.asarray(values, dtype=np.float64)
    if region.size == 0:
        raise Xrf55FeatureError("empty_feature_region")
    mean = float(np.mean(region, dtype=np.float64))
    centered = region - mean
    standard_deviation = math.sqrt(
        float(np.mean(centered * centered, dtype=np.float64))
    )
    mean_absolute = float(np.mean(np.abs(region), dtype=np.float64))
    root_mean_square = math.sqrt(float(np.mean(region * region, dtype=np.float64)))
    values_out = (mean, standard_deviation, mean_absolute, root_mean_square)
    if not all(math.isfinite(value) for value in values_out):
        raise Xrf55FeatureError("nonfinite_feature")
    return values_out


def _axis_regions(array: np.ndarray, axis: int, bins: int) -> list[np.ndarray]:
    if array.shape[axis] < bins:
        raise Xrf55FeatureError("feature_axis_too_short")
    return list(np.array_split(array, bins, axis=axis))


def _grid_regions(
    array: np.ndarray, first_axis: int, second_axis: int
) -> list[np.ndarray]:
    rows, columns = SPATIAL_BINS
    if array.shape[first_axis] < rows or array.shape[second_axis] < columns:
        raise Xrf55FeatureError("feature_axis_too_short")
    regions = []
    for row in np.array_split(array, rows, axis=first_axis):
        regions.extend(np.array_split(row, columns, axis=second_axis))
    return regions


def feature_vector(
    modality: str,
    array: np.ndarray,
    *,
    layouts: Mapping[str, ArrayLayout] = OFFICIAL_LAYOUTS,
) -> np.ndarray:
    """Reduce one publisher-shaped array to a geometry-aware 96-value vector."""

    if modality not in MODALITIES or modality not in layouts:
        raise Xrf55FeatureError("unsupported_modality")
    if not isinstance(array, np.ndarray):
        raise Xrf55FeatureError("feature_input_not_array")
    layout = layouts[modality]
    if array.shape != layout.shape:
        raise Xrf55FeatureError("feature_shape_mismatch")
    if array.dtype.str != layout.dtype:
        raise Xrf55FeatureError("feature_dtype_mismatch")
    if layout.fortran_order:
        if not array.flags.f_contiguous:
            raise Xrf55FeatureError("feature_order_mismatch")
    elif not array.flags.c_contiguous:
        raise Xrf55FeatureError("feature_order_mismatch")
    if not bool(np.isfinite(array).all()):
        raise Xrf55FeatureError("nonfinite_feature_input")

    if modality in {"wifi", "rfid"}:
        regions = _axis_regions(array, 1, SEQUENCE_BINS)
        regions.extend(_axis_regions(array, 0, CHANNEL_BINS))
    else:
        reduced = array[0]
        regions = _grid_regions(reduced, 1, 2)
        regions.extend(_axis_regions(reduced, 0, CHANNEL_BINS))

    result = np.asarray(
        [value for region in regions for value in _moments(region)],
        dtype="<f8",
    )
    if result.shape != (FEATURE_COUNT,):
        raise Xrf55FeatureError("feature_width_mismatch")
    return result


def feature_policy_document() -> dict[str, Any]:
    return {
        "feature_count": FEATURE_COUNT,
        "labels_used_as_features": False,
        "moments": ["mean", "standard_deviation", "mean_absolute", "rms"],
        "mmwave": {
            "channel_bins": CHANNEL_BINS,
            "publisher_model_geometry": "channels_by_spatial_grid",
            "spatial_bins": list(SPATIAL_BINS),
        },
        "rfid": {
            "channel_bins": CHANNEL_BINS,
            "publisher_model_geometry": "channels_by_sequence",
            "sequence_bins": SEQUENCE_BINS,
        },
        "wifi": {
            "channel_bins": CHANNEL_BINS,
            "publisher_model_geometry": "channels_by_sequence",
            "sequence_bins": SEQUENCE_BINS,
        },
    }


def campaign_document(events: Sequence[CampaignEvent]) -> list[dict[str, Any]]:
    documents = []
    for event in events:
        documents.append(
            {
                "event_id": event.event_id,
                "group_id": event.group_id,
                "repetition": event.repetition,
                "row": event.row,
                "split": event.split,
            }
        )
    return documents
