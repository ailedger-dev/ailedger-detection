"""Tests for unresolved-flag accumulation primitive."""

from __future__ import annotations

import pytest

from ailedger_detection.unresolved_flags import (
    DEFAULT_MIN_ACCUMULATION,
    unresolved_flag_accumulation,
)


def _event(
    event_id: str,
    *,
    subject: str,
    required: list[str],
    taken: list[str],
) -> dict:
    return {
        "event_id": event_id,
        "subject_id": subject,
        "required_actions": required,
        "actions_taken": taken,
    }


class TestUnresolvedFlagAccumulation:
    def test_default_min_accumulation_is_two(self) -> None:
        assert DEFAULT_MIN_ACCUMULATION == 2

    def test_all_resolved_yields_no_flag(self) -> None:
        events = [
            _event("e1", subject="s1", required=["review"], taken=["review"]),
            _event("e2", subject="s1", required=["review"], taken=["review", "log"]),
        ]
        result = unresolved_flag_accumulation(events)
        assert result.flagged is False
        assert result.unresolved_event_count == 0
        assert result.rate == 0.0
        assert result.accumulating_groups == ()

    def test_accumulation_on_one_subject_flags(self) -> None:
        events = [
            _event("e1", subject="s1", required=["review"], taken=[]),
            _event("e2", subject="s1", required=["review"], taken=[]),
            _event("e3", subject="s2", required=["review"], taken=["review"]),
        ]
        result = unresolved_flag_accumulation(events)
        assert result.flagged is True
        assert result.accumulating_groups == ("s1",)
        assert result.accumulation_by_group == {"s1": 2}
        assert result.unresolved_event_count == 2
        assert pytest.approx(result.rate, abs=1e-6) == 2 / 3

    def test_single_unresolved_event_not_flagged_at_baseline(self) -> None:
        events = [
            _event("e1", subject="s1", required=["review"], taken=[]),
            _event("e2", subject="s2", required=["review"], taken=["review"]),
        ]
        result = unresolved_flag_accumulation(events)
        assert result.flagged is False
        assert result.accumulation_by_group == {"s1": 1}
        assert result.accumulating_groups == ()

    def test_tighten_to_one_flags_single_unresolved(self) -> None:
        events = [_event("e1", subject="s1", required=["review"], taken=[])]
        result = unresolved_flag_accumulation(events, min_accumulation=1)
        assert result.flagged is True
        assert result.accumulating_groups == ("s1",)

    def test_loosening_above_baseline_refused(self) -> None:
        with pytest.raises(ValueError, match="loosens detection"):
            unresolved_flag_accumulation([], min_accumulation=3)

    def test_min_accumulation_below_one_refused(self) -> None:
        with pytest.raises(ValueError, match="must be >= 1"):
            unresolved_flag_accumulation([], min_accumulation=0)

    def test_per_action_and_per_event_detail(self) -> None:
        events = [
            _event("e1", subject="s1", required=["review", "notify"], taken=["notify"]),
            _event("e2", subject="s1", required=["review"], taken=[]),
        ]
        result = unresolved_flag_accumulation(events)
        assert result.unresolved_by_action == {"review": 2}
        assert ("e1", ("review",)) in result.per_event_unresolved
        assert ("e2", ("review",)) in result.per_event_unresolved

    def test_group_falls_back_to_tenant_then_ungrouped(self) -> None:
        events = [
            {"event_id": "e1", "tenant_id": "t1", "required_actions": ["r"], "actions_taken": []},
            {"event_id": "e2", "tenant_id": "t1", "required_actions": ["r"], "actions_taken": []},
            {"event_id": "e3", "required_actions": ["r"], "actions_taken": []},
        ]
        result = unresolved_flag_accumulation(events)
        assert result.accumulation_by_group == {"t1": 2, "__ungrouped__": 1}
        assert result.accumulating_groups == ("t1",)

    def test_missing_fields_treated_as_empty(self) -> None:
        events = [{"event_id": "e1", "subject_id": "s1", "required_actions": ["r"]}]
        result = unresolved_flag_accumulation(events)
        assert result.unresolved_event_count == 1

    def test_empty_population_is_not_a_failure(self) -> None:
        result = unresolved_flag_accumulation([])
        assert result.flagged is False
        assert result.total_events == 0
        assert result.rate == 0.0
