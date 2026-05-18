"""Tests for disparate impact ratio primitive."""

from __future__ import annotations

import pytest

from ailedger_detection.disparate_impact import (
    FOUR_FIFTHS_BASELINE,
    disparate_impact_ratio,
)


def _event(race: str, hire: bool) -> dict:
    return {
        "protected_class_context": {"race": race},
        "output": {"decision": "hire" if hire else "no"},
    }


def _hire_predicate(event: dict) -> bool:
    return event["output"]["decision"] == "hire"


class TestDisparateImpactRatio:
    def test_baseline_threshold_is_four_fifths(self) -> None:
        assert FOUR_FIFTHS_BASELINE == 0.8

    def test_perfect_parity_yields_ratio_one(self) -> None:
        events = [
            _event("A", True),
            _event("A", False),
            _event("B", True),
            _event("B", False),
        ]
        result = disparate_impact_ratio(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
        )
        assert result.ratio == 1.0
        assert result.flagged is False

    def test_adverse_impact_is_flagged_at_baseline(self) -> None:
        # Group A: 8/10 = 0.80 hire rate
        # Group B: 5/10 = 0.50 hire rate
        # Ratio: 0.50 / 0.80 = 0.625 < 0.8 → flagged
        events = [_event("A", True) for _ in range(8)] + [_event("A", False) for _ in range(2)]
        events += [_event("B", True) for _ in range(5)] + [_event("B", False) for _ in range(5)]
        result = disparate_impact_ratio(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
        )
        assert pytest.approx(result.ratio, abs=1e-6) == 0.625
        assert result.flagged is True
        assert result.high_group == "A"
        assert result.low_group == "B"

    def test_borderline_at_four_fifths(self) -> None:
        # Group A: 10/10 hire rate. Group B: 8/10 hire rate. Ratio: 0.8.
        # Ratio NOT < 0.8, so NOT flagged. Strict-less-than semantics.
        events = [_event("A", True) for _ in range(10)]
        events += [_event("B", True) for _ in range(8)] + [_event("B", False) for _ in range(2)]
        result = disparate_impact_ratio(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
        )
        assert pytest.approx(result.ratio, abs=1e-6) == 0.8
        assert result.flagged is False  # 0.8 is not < 0.8

    def test_custom_threshold_tighter(self) -> None:
        # Customers tighten, never loosen.
        events = [_event("A", True) for _ in range(10)]
        events += [_event("B", True) for _ in range(8)] + [_event("B", False) for _ in range(2)]
        result = disparate_impact_ratio(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
            threshold=0.9,  # tighter than baseline
        )
        assert result.flagged is True  # 0.8 < 0.9

    def test_zero_total_in_one_group_raises(self) -> None:
        # A has events, B has no events at this protected_class_key
        events = [_event("A", True), _event("A", False)]
        with pytest.raises(ValueError, match="At least two distinct"):
            disparate_impact_ratio(
                events,
                protected_class_key="race",
                positive_outcome_predicate=_hire_predicate,
            )

    def test_no_positive_outcomes_anywhere_yields_ratio_one(self) -> None:
        events = [_event("A", False), _event("B", False)]
        result = disparate_impact_ratio(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
        )
        assert result.ratio == 1.0
        assert result.flagged is False

    def test_invalid_threshold_raises(self) -> None:
        events = [_event("A", True), _event("B", False)]
        with pytest.raises(ValueError, match="threshold must be in"):
            disparate_impact_ratio(
                events,
                protected_class_key="race",
                positive_outcome_predicate=_hire_predicate,
                threshold=0,
            )
        with pytest.raises(ValueError, match="threshold must be in"):
            disparate_impact_ratio(
                events,
                protected_class_key="race",
                positive_outcome_predicate=_hire_predicate,
                threshold=1.5,
            )

    def test_group_stats_inspectable(self) -> None:
        events = [
            _event("A", True),
            _event("A", True),
            _event("A", False),
            _event("B", False),
            _event("B", False),
        ]
        result = disparate_impact_ratio(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
        )
        assert result.group_stats == {"A": (2, 3), "B": (0, 2)}
