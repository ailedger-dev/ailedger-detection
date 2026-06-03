"""Tests for unresolved-flag accumulation."""

from __future__ import annotations

import pytest

from ailedger_detection.unresolved_flags import unresolved_flag_accumulation


def _event(
    event_id: str,
    flags: list[str],
    required: list[str],
    taken: list[str],
    subject: str = "s1",
) -> dict:
    return {
        "event_id": event_id,
        "flags_raised": flags,
        "required_actions": required,
        "actions_taken": taken,
        "subject_id": subject,
    }


class TestUnresolvedFlagAccumulation:
    def test_flags_when_required_action_not_taken(self) -> None:
        events = [_event("e1", ["low_conf"], ["review"], [])]
        result = unresolved_flag_accumulation(events)
        assert result.flagged is True
        assert result.rate == 1.0
        assert result.unresolved_event_count == 1
        assert result.unresolved_by_flag == {"low_conf": 1}

    def test_resolved_event_does_not_accumulate(self) -> None:
        events = [_event("e1", ["low_conf"], ["review"], ["review"])]
        result = unresolved_flag_accumulation(events)
        assert result.flagged is False
        assert result.rate == 0.0
        assert result.unresolved_event_count == 0

    def test_events_without_flags_excluded_from_denominator(self) -> None:
        # 1 flagged-unresolved, 1 flagged-resolved, 1 unflagged -> rate 1/2.
        events = [
            _event("e1", ["f"], ["review"], []),
            _event("e2", ["f"], ["review"], ["review"]),
            _event("e3", [], ["review"], []),
        ]
        result = unresolved_flag_accumulation(events)
        assert result.total_events == 3
        assert result.flagged_event_count == 2
        assert result.rate == 0.5

    def test_rate_zero_when_no_flags(self) -> None:
        events = [_event("e1", [], [], [])]
        result = unresolved_flag_accumulation(events)
        assert result.rate == 0.0
        assert result.flagged is False

    def test_group_by_reports_per_entity(self) -> None:
        events = [
            _event("e1", ["f"], ["review"], [], subject="alice"),
            _event("e2", ["f"], ["review"], [], subject="alice"),
            _event("e3", ["f"], ["review"], [], subject="bob"),
        ]
        result = unresolved_flag_accumulation(events, group_by_extractor=lambda e: e["subject_id"])
        assert result.unresolved_by_group == {"alice": 2, "bob": 1}

    def test_per_event_detail_is_sorted_and_stable(self) -> None:
        events = [_event("e1", ["z_flag", "a_flag"], ["b", "a"], ["a"])]
        result = unresolved_flag_accumulation(events)
        assert result.per_event_unresolved == [("e1", ("b",), ("a_flag", "z_flag"))]

    def test_looser_threshold_refused(self) -> None:
        with pytest.raises(ValueError, match="LOOSENS"):
            unresolved_flag_accumulation([], threshold=0.5)

    def test_to_warrant_memorializes_rate(self) -> None:
        events = [_event("e1", ["low_conf"], ["review"], [])]
        warrant = unresolved_flag_accumulation(events).to_warrant(
            created_at="2026-06-03T00:00:00+00:00"
        )
        assert warrant.flagged is True
        assert warrant.result["value"] == 1.0
        assert warrant.verify_digest() is True
