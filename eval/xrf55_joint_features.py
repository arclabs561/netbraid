"""Deterministic joint-grid feature and role policy for XRF55 evaluation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

import numpy as np

import xrf55_features as FEATURES

FEATURE_COUNT = 512
ROLE_ORDER = ("train", "calibration", "validation")
ROLE_GROUP_RANKS = {
    "train": (1, 8),
    "calibration": (17, 18),
    "validation": (19, 20),
}
QUARANTINED_GROUP_RANKS = (9, 16)
RANKED_GROUP_COUNT = 20
ROLE_EVENT_COUNTS = {
    role: (last - first + 1) * len(FEATURES.PUBLISHER_REPETITIONS)
    for role, (first, last) in ROLE_GROUP_RANKS.items()
}


def _joint_regions(modality: str, array: np.ndarray) -> list[np.ndarray]:
    if modality in {"wifi", "rfid"}:
        return [
            sequence_region
            for channel_region in FEATURES._axis_regions(  # noqa: SLF001
                array, 0, FEATURES.CHANNEL_BINS
            )
            for sequence_region in FEATURES._axis_regions(  # noqa: SLF001
                channel_region, 1, FEATURES.SEQUENCE_BINS
            )
        ]

    reduced = array[0]
    return [
        spatial_region
        for channel_region in FEATURES._axis_regions(  # noqa: SLF001
            reduced, 0, FEATURES.CHANNEL_BINS
        )
        for spatial_region in FEATURES._grid_regions(  # noqa: SLF001
            channel_region, 1, 2
        )
    ]


def feature_vector(
    modality: str,
    array: np.ndarray,
    *,
    layouts: Mapping[str, FEATURES.ArrayLayout] = FEATURES.OFFICIAL_LAYOUTS,
) -> np.ndarray:
    """Reduce one validated publisher array to a 512-value joint-grid vector."""

    FEATURES._validate_feature_input(modality, array, layouts=layouts)  # noqa: SLF001
    result = np.asarray(
        [
            value
            for region in _joint_regions(modality, array)
            for value in FEATURES._moments(region)  # noqa: SLF001
        ],
        dtype="<f8",
    )
    if result.shape != (FEATURE_COUNT,):
        raise FEATURES.Xrf55FeatureError("feature_width_mismatch")
    return result


def feature_policy_document() -> dict[str, Any]:
    """Return the path-free joint representation contract."""

    marginal_policy = FEATURES.feature_policy_document()
    return {
        "feature_count": FEATURE_COUNT,
        "labels_used_as_features": marginal_policy["labels_used_as_features"],
        "moments": list(marginal_policy["moments"]),
        "representation": "joint_grid",
        "mmwave": {
            "bin_order": "channel_major_then_spatial_row_major",
            "channel_bins": FEATURES.CHANNEL_BINS,
            "spatial_bins": list(FEATURES.SPATIAL_BINS),
        },
        "rfid": {
            "bin_order": "channel_major_then_sequence",
            "channel_bins": FEATURES.CHANNEL_BINS,
            "sequence_bins": FEATURES.SEQUENCE_BINS,
        },
        "wifi": {
            "bin_order": "channel_major_then_sequence",
            "channel_bins": FEATURES.CHANNEL_BINS,
            "sequence_bins": FEATURES.SEQUENCE_BINS,
        },
    }


def role_policy_document() -> dict[str, Any]:
    """Return the fixed opaque-group rank partition."""

    return {
        "assignment": "complete_opaque_performer_action_group_rank",
        "quarantined_group_ranks": list(QUARANTINED_GROUP_RANKS),
        "ranked_group_count": RANKED_GROUP_COUNT,
        "roles": {role: list(ROLE_GROUP_RANKS[role]) for role in ROLE_ORDER},
    }


def select_role_events(
    observations: Iterable[FEATURES.ObservationKey],
) -> dict[str, tuple[FEATURES.CampaignEvent, ...]]:
    """Select fixed disjoint roles while omitting quarantined group ranks."""

    campaign = FEATURES.select_campaign(
        observations,
        group_count=RANKED_GROUP_COUNT,
        repetitions=FEATURES.PUBLISHER_REPETITIONS,
    )
    ranked_group_ids = tuple(dict.fromkeys(event.group_id for event in campaign))
    if len(ranked_group_ids) != RANKED_GROUP_COUNT:
        raise FEATURES.Xrf55FeatureError("role_group_count_mismatch")

    role_by_group = {
        group_id: role
        for role, (first, last) in ROLE_GROUP_RANKS.items()
        for group_id in ranked_group_ids[first - 1 : last]
    }
    partitioned: dict[str, list[FEATURES.CampaignEvent]] = {
        role: [] for role in ROLE_ORDER
    }
    for event in campaign:
        role = role_by_group.get(event.group_id)
        if role is None:
            continue
        role_events = partitioned[role]
        role_events.append(
            FEATURES.CampaignEvent(
                event_id=event.event_id,
                group_id=event.group_id,
                observation=event.observation,
                repetition=event.repetition,
                row=len(role_events),
                split=role,
            )
        )

    result = {role: tuple(partitioned[role]) for role in ROLE_ORDER}
    if any(len(result[role]) != ROLE_EVENT_COUNTS[role] for role in ROLE_ORDER):
        raise FEATURES.Xrf55FeatureError("role_event_count_mismatch")
    return result
