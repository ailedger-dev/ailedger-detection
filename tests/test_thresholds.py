"""Tests for the standard-anchored threshold registry + anti-theater guard."""

from __future__ import annotations

import pytest

from ailedger_detection.thresholds import (
    TightenDirection,
    enforce_tighten_only,
    get_standard,
    rejected_thresholds_for,
)


class TestRegistry:
    def test_known_standards_resolve(self) -> None:
        assert get_standard("disparate_impact_ratio").baseline == 0.80
        assert get_standard("statistical_parity_difference").baseline == 0.10
        assert get_standard("model_drift.action").baseline == 0.25

    def test_unknown_name_raises(self) -> None:
        with pytest.raises(KeyError, match="No registered threshold"):
            get_standard("nope")


class TestEnforceRaiseToTighten:
    # disparate_impact_ratio: raising the bar tightens.
    def test_baseline_passes(self) -> None:
        assert enforce_tighten_only("disparate_impact_ratio", 0.80) == 0.80

    def test_tighter_passes(self) -> None:
        assert enforce_tighten_only("disparate_impact_ratio", 0.95) == 0.95

    def test_looser_refused(self) -> None:
        with pytest.raises(ValueError, match="LOOSENS"):
            enforce_tighten_only("disparate_impact_ratio", 0.70)

    def test_out_of_range_refused(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            enforce_tighten_only("disparate_impact_ratio", 1.5)


class TestEnforceLowerToTighten:
    # statistical_parity_difference: lowering the bar tightens.
    def test_baseline_passes(self) -> None:
        assert enforce_tighten_only("statistical_parity_difference", 0.10) == 0.10

    def test_tighter_passes(self) -> None:
        assert enforce_tighten_only("statistical_parity_difference", 0.05) == 0.05

    def test_looser_refused(self) -> None:
        with pytest.raises(ValueError, match="LOOSENS"):
            enforce_tighten_only("statistical_parity_difference", 0.25)


class TestDirectionMetadata:
    def test_directions_are_correct(self) -> None:
        assert get_standard("disparate_impact_ratio").direction is TightenDirection.RAISE_TO_TIGHTEN
        assert (
            get_standard("statistical_parity_difference").direction
            is TightenDirection.LOWER_TO_TIGHTEN
        )


class TestRejectedThresholds:
    def test_raise_direction_rejects_below(self) -> None:
        rejected = rejected_thresholds_for("disparate_impact_ratio", 0.80)
        assert rejected[0].value == "< 0.8"
        assert "four-fifths" in rejected[0].reason

    def test_lower_direction_rejects_above(self) -> None:
        rejected = rejected_thresholds_for("statistical_parity_difference", 0.10)
        assert rejected[0].value == "> 0.1"
        assert "Charter" in rejected[0].reason
