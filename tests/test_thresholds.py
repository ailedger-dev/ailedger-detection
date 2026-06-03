"""Tests for the standard-anchored threshold registry + anti-theater guard."""

from __future__ import annotations

import pytest

from ailedger_detection import thresholds as th
from ailedger_detection.thresholds import (
    CANONICAL_REGISTRY_DIGEST,
    ThresholdStandard,
    TightenDirection,
    enforce_tighten_only,
    get_standard,
    registry_digest,
    rejected_thresholds_for,
    verify_registry_integrity,
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


class TestRegistryIsStructurallyImmutable:
    """F1 — the tighten-only guard must not rest on a mutable module global."""

    def test_registry_rejects_item_assignment(self) -> None:
        # The red-team's one-line monkeypatch (`_REGISTRY["x"] = loosened`) must
        # now raise: the registry is a read-only view, not a plain dict.
        with pytest.raises(TypeError):
            th._REGISTRY["disparate_impact_ratio"] = ThresholdStandard(  # type: ignore[index]
                name="disparate_impact_ratio",
                baseline=0.10,
                direction=TightenDirection.RAISE_TO_TIGHTEN,
                standard="loosened",
            )

    def test_standard_entries_are_frozen(self) -> None:
        # Frozen dataclass: assignment raises FrozenInstanceError (an AttributeError).
        with pytest.raises(AttributeError):
            get_standard("disparate_impact_ratio").baseline = 0.1  # type: ignore[misc]

    def test_clean_registry_verifies(self) -> None:
        assert verify_registry_integrity() is True
        assert registry_digest() == CANONICAL_REGISTRY_DIGEST

    def test_enforce_refuses_when_registry_baseline_swapped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Even reaching past the read-only type (rebinding the module global to a
        # plain dict with a loosened baseline) cannot weaken enforce: it validates
        # against the SEALED canonical baseline and refuses as an integrity
        # violation instead of detecting under the loosened bar.
        loosened = {
            "disparate_impact_ratio": ThresholdStandard(
                name="disparate_impact_ratio",
                baseline=0.10,
                direction=TightenDirection.RAISE_TO_TIGHTEN,
                standard="loosened",
            )
        }
        monkeypatch.setattr(th, "_REGISTRY", loosened)
        assert verify_registry_integrity() is False
        with pytest.raises(ValueError, match="integrity violation"):
            enforce_tighten_only("disparate_impact_ratio", 0.2)


class TestFloatBoundary:
    """F10 — a baseline reached by float arithmetic must not be spuriously refused."""

    def test_baseline_via_arithmetic_is_accepted(self) -> None:
        # 0.1 + 0.7 == 0.7999999999999999, the disparate-impact baseline (0.8).
        value = 0.1 + 0.7
        assert value < 0.8  # genuinely below in raw float terms
        assert enforce_tighten_only("disparate_impact_ratio", value) == value

    def test_genuine_loosening_still_refused(self) -> None:
        with pytest.raises(ValueError, match="LOOSENS"):
            enforce_tighten_only("disparate_impact_ratio", 0.70)
