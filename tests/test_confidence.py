"""Tests for confidence-stratified outcome analysis."""

from __future__ import annotations

import pytest

from ailedger_detection.confidence import confidence_stratified_outcome_analysis


def _event(race: str, hire: bool, conf: float | None) -> dict:
    e: dict = {
        "protected_class_context": {"race": race},
        "output": {"decision": "hire" if hire else "no"},
    }
    if conf is not None:
        e["confidence"] = conf
    return e


def _hire(e: dict) -> bool:
    return e["output"]["decision"] == "hire"


def _analyze(events: list[dict], **kw: object):
    return confidence_stratified_outcome_analysis(
        events,
        protected_class_key="race",
        positive_outcome_predicate=_hire,
        **kw,  # type: ignore[arg-type]
    )


class TestConfidenceStratified:
    def test_flags_disparate_impact_in_top_stratum(self) -> None:
        # Top stratum [0.95,1.0]: A 10/10 hired, B 0/10 hired -> ratio 0 -> flag.
        events = [_event("A", True, 0.97) for _ in range(10)]
        events += [_event("B", False, 0.97) for _ in range(10)]
        # Low stratum [0.5,0.7): perfect parity.
        events += [_event("A", i < 5, 0.6) for i in range(10)]
        events += [_event("B", i < 5, 0.6) for i in range(10)]

        result = _analyze(events)
        assert result.flagged is True
        flagged = [b.label for b in result.buckets if b.flagged]
        assert flagged == ["[0.95,1.00]"]

    def test_no_flag_when_parity_in_all_strata(self) -> None:
        events = [_event("A", i < 5, 0.97) for i in range(10)]
        events += [_event("B", i < 5, 0.97) for i in range(10)]
        result = _analyze(events)
        assert result.flagged is False

    def test_single_group_stratum_is_not_evaluable(self) -> None:
        events = [_event("A", True, 0.97) for _ in range(5)]
        result = _analyze(events)
        top = next(b for b in result.buckets if b.label == "[0.95,1.00]")
        assert top.evaluable is False
        assert top.ratio is None
        assert result.flagged is False

    def test_skips_events_without_confidence(self) -> None:
        events = [_event("A", True, None), _event("B", False, None)]
        result = _analyze(events)
        assert result.skipped_no_confidence == 2

    def test_skips_events_without_group(self) -> None:
        events = [
            {"output": {"decision": "hire"}, "confidence": 0.9},
            {"output": {"decision": "no"}, "confidence": 0.9},
        ]
        result = _analyze(events)
        assert result.skipped_no_group == 2

    def test_min_group_size_excludes_small_groups(self) -> None:
        # B has only 1 event in the top stratum; min_group_size=2 drops it.
        events = [_event("A", True, 0.97) for _ in range(5)]
        events += [_event("B", False, 0.97)]
        result = _analyze(events, min_group_size=2)
        top = next(b for b in result.buckets if b.label == "[0.95,1.00]")
        assert top.evaluable is False

    def test_invalid_boundaries_raise(self) -> None:
        with pytest.raises(ValueError, match="ascending"):
            _analyze([], bucket_boundaries=(0.7, 0.5))
        with pytest.raises(ValueError, match="in \\(0, 1\\)"):
            _analyze([], bucket_boundaries=(0.0, 0.5))

    def test_confidence_out_of_range_raises(self) -> None:
        with pytest.raises(ValueError, match="outside"):
            _analyze([_event("A", True, 1.5)])

    def test_looser_threshold_refused(self) -> None:
        with pytest.raises(ValueError, match="LOOSENS"):
            _analyze([], threshold=0.5)

    def test_to_warrant_records_flagged_strata(self) -> None:
        events = [_event("A", True, 0.97) for _ in range(10)]
        events += [_event("B", False, 0.97) for _ in range(10)]
        warrant = _analyze(events).to_warrant(created_at="2026-06-03T00:00:00+00:00")
        assert warrant.flagged is True
        assert "[0.95,1.00]" in warrant.result["flagged_strata"]
        assert warrant.verify_digest() is True
