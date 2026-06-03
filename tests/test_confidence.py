"""Tests for confidence-stratified outcome analysis primitive."""

from __future__ import annotations

import pytest

from ailedger_detection.confidence import (
    FOUR_FIFTHS_BASELINE,
    confidence_stratified_outcome_analysis,
)


def _event(race: str, hire: bool, confidence: float) -> dict:
    return {
        "protected_class_context": {"race": race},
        "output": {"decision": "hire" if hire else "no"},
        "confidence": confidence,
    }


def _hire_predicate(event: dict) -> bool:
    return event["output"]["decision"] == "hire"


class TestConfidenceStratified:
    def test_baseline_is_four_fifths(self) -> None:
        assert FOUR_FIFTHS_BASELINE == 0.8

    def test_high_confidence_bucket_flags_concentrated_adverse_impact(self) -> None:
        # Low-confidence bucket [0.5,0.7): perfect parity (1/2 each).
        # High-confidence bucket [0.95,1.0]: A=4/4 (1.0), B=1/4 (0.25), ratio 0.25.
        events = [
            _event("A", True, 0.6),
            _event("A", False, 0.6),
            _event("B", True, 0.6),
            _event("B", False, 0.6),
        ]
        events += [_event("A", True, 0.97) for _ in range(4)]
        events += [_event("B", True, 0.97)] + [_event("B", False, 0.97) for _ in range(3)]

        result = confidence_stratified_outcome_analysis(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
        )
        assert result.flagged is True
        top = result.buckets[-1]
        assert top.label == "[0.95, 1.0]"
        assert top.ratio is not None
        assert pytest.approx(top.ratio, abs=1e-6) == 0.25
        assert top.flagged is True

        # The low-confidence bucket should not be flagged (perfect parity).
        low_bucket = next(b for b in result.buckets if b.label == "[0.5, 0.7)")
        assert low_bucket.ratio == 1.0
        assert low_bucket.flagged is False

    def test_aggregate_clean_but_stratified_flags(self) -> None:
        # Aggregate ratio clears four-fifths, but a single bucket does not.
        events = [
            # bucket [0.7,0.85): A=2/2, B=0/2 -> ratio 0.0, flagged
            _event("A", True, 0.8),
            _event("A", True, 0.8),
            _event("B", False, 0.8),
            _event("B", False, 0.8),
            # bucket [0.5,0.7): A=0/2, B=2/2 -> ratio 0.0, flagged the other way
            _event("A", False, 0.6),
            _event("A", False, 0.6),
            _event("B", True, 0.6),
            _event("B", True, 0.6),
        ]
        result = confidence_stratified_outcome_analysis(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
        )
        assert result.flagged is True

    def test_single_group_bucket_has_none_ratio(self) -> None:
        events = [_event("A", True, 0.6), _event("A", False, 0.6)]
        result = confidence_stratified_outcome_analysis(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
        )
        bucket = next(b for b in result.buckets if b.total > 0)
        assert bucket.ratio is None
        assert bucket.flagged is False
        assert result.flagged is False

    def test_confidence_one_lands_in_top_bucket(self) -> None:
        events = [_event("A", True, 1.0), _event("B", False, 1.0)]
        result = confidence_stratified_outcome_analysis(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
        )
        top = result.buckets[-1]
        assert top.total == 2
        assert top.upper == 1.0

    def test_skips_missing_confidence_and_class(self) -> None:
        events = [
            {"protected_class_context": {"race": "A"}, "output": {"decision": "hire"}},  # no conf
            {"confidence": 0.9, "output": {"decision": "hire"}},  # no class
            {"confidence": "high", "protected_class_context": {"race": "A"}},  # bad conf
            {"confidence": True, "protected_class_context": {"race": "A"}},  # bool, not numeric
        ]
        result = confidence_stratified_outcome_analysis(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
        )
        assert result.skipped_no_confidence == 3
        assert result.skipped_no_class == 1

    def test_out_of_range_confidence_skipped(self) -> None:
        events = [
            _event("A", True, 1.5),
            _event("B", False, -0.1),
        ]
        result = confidence_stratified_outcome_analysis(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
        )
        assert result.skipped_no_confidence == 2

    def test_custom_threshold_tighter(self) -> None:
        # bucket ratio 0.8 — not flagged at baseline, flagged at 0.9.
        events = [_event("A", True, 0.9) for _ in range(10)]
        events += [_event("B", True, 0.9) for _ in range(8)]
        events += [_event("B", False, 0.9) for _ in range(2)]
        baseline = confidence_stratified_outcome_analysis(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
        )
        assert baseline.flagged is False
        tighter = confidence_stratified_outcome_analysis(
            events,
            protected_class_key="race",
            positive_outcome_predicate=_hire_predicate,
            threshold=0.9,
        )
        assert tighter.flagged is True

    def test_invalid_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="threshold must be in"):
            confidence_stratified_outcome_analysis(
                [],
                protected_class_key="race",
                positive_outcome_predicate=_hire_predicate,
                threshold=0,
            )

    def test_non_increasing_boundaries_raise(self) -> None:
        with pytest.raises(ValueError, match="strictly increasing"):
            confidence_stratified_outcome_analysis(
                [],
                protected_class_key="race",
                positive_outcome_predicate=_hire_predicate,
                bucket_boundaries=(0.7, 0.7),
            )

    def test_out_of_unit_interval_boundaries_raise(self) -> None:
        with pytest.raises(ValueError, match="in \\(0, 1\\)"):
            confidence_stratified_outcome_analysis(
                [],
                protected_class_key="race",
                positive_outcome_predicate=_hire_predicate,
                bucket_boundaries=(0.5, 1.0),
            )

    def test_empty_boundaries_raise(self) -> None:
        with pytest.raises(ValueError, match="at least one cut point"):
            confidence_stratified_outcome_analysis(
                [],
                protected_class_key="race",
                positive_outcome_predicate=_hire_predicate,
                bucket_boundaries=(),
            )

    def test_custom_confidence_extractor(self) -> None:
        events = [
            {"protected_class_context": {"race": "A"}, "p": 0.97, "ok": True},
            {"protected_class_context": {"race": "B"}, "p": 0.97, "ok": False},
        ]
        result = confidence_stratified_outcome_analysis(
            events,
            protected_class_key="race",
            positive_outcome_predicate=lambda e: bool(e["ok"]),
            confidence_extractor=lambda e: e.get("p"),
        )
        top = result.buckets[-1]
        assert top.total == 2
        assert top.ratio == 0.0
