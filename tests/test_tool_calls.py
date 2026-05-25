"""Tests for tool-call unauthorized-action-rate primitive."""

from __future__ import annotations

import pytest

from ailedger_detection.tool_calls import (
    UNAUTHORIZED_ACTION_BASELINE,
    UnauthorizedToolCallResult,
    tool_call_unauthorized_action_rate,
)


def _event(
    event_id: str,
    required: list[str] | None = None,
    taken: list[str] | None = None,
) -> dict:
    return {
        "event_id": event_id,
        "required_actions": required if required is not None else [],
        "actions_taken": taken if taken is not None else [],
    }


class TestToolCallUnauthorizedActionRate:
    def test_baseline_threshold_is_zero(self) -> None:
        assert UNAUTHORIZED_ACTION_BASELINE == 0.0

    def test_all_authorized_actions_yield_rate_zero(self) -> None:
        events = [
            _event("e1", required=["tool.play_media", "tool.pause_media"], taken=["tool.play_media"]),
            _event("e2", required=["tool.play_media"], taken=["tool.play_media"]),
        ]
        result = tool_call_unauthorized_action_rate(events)
        assert result.rate == 0.0
        assert result.flagged is False
        assert result.total_events == 2
        assert result.unauthorized_event_count == 0
        assert result.unauthorized_actions_by_tool == {}
        assert result.per_event_unauthorized == []

    def test_any_unauthorized_action_flags_at_baseline(self) -> None:
        events = [
            _event("e1", required=["tool.play_media"], taken=["tool.play_media"]),
            _event(
                "e2",
                required=["tool.play_media"],
                taken=["tool.play_media", "tool.unlock_door"],
            ),
        ]
        result = tool_call_unauthorized_action_rate(events)
        assert result.rate == 0.5
        assert result.flagged is True
        assert result.unauthorized_event_count == 1
        assert result.unauthorized_actions_by_tool == {"tool.unlock_door": 1}
        assert result.per_event_unauthorized == [("e2", ("tool.unlock_door",))]

    def test_multiple_unauthorized_actions_in_one_event(self) -> None:
        events = [
            _event(
                "e1",
                required=["tool.play_media"],
                taken=["tool.play_media", "tool.unlock_door", "tool.transfer_funds"],
            ),
        ]
        result = tool_call_unauthorized_action_rate(events)
        assert result.rate == 1.0
        assert result.flagged is True
        assert result.unauthorized_event_count == 1
        assert result.unauthorized_actions_by_tool == {
            "tool.unlock_door": 1,
            "tool.transfer_funds": 1,
        }
        # Per-event detail is sorted for stability.
        assert result.per_event_unauthorized == [
            ("e1", ("tool.transfer_funds", "tool.unlock_door"))
        ]

    def test_empty_required_means_everything_unauthorized(self) -> None:
        # If required_actions is empty (no policy declared), any taken action
        # is by definition outside the empty-set envelope.
        events = [_event("e1", required=[], taken=["tool.play_media"])]
        result = tool_call_unauthorized_action_rate(events)
        assert result.rate == 1.0
        assert result.flagged is True
        assert result.unauthorized_actions_by_tool == {"tool.play_media": 1}

    def test_missing_required_actions_treated_as_empty(self) -> None:
        # Real-world events from the Decision Events schema may omit
        # required_actions entirely; the default extractor treats None as [].
        events = [
            {
                "event_id": "e1",
                "actions_taken": ["tool.play_media"],
                # required_actions omitted
            }
        ]
        result = tool_call_unauthorized_action_rate(events)
        assert result.unauthorized_event_count == 1
        assert result.flagged is True

    def test_missing_actions_taken_treated_as_empty(self) -> None:
        # If the model declined to act (no actions_taken), there are by
        # definition no unauthorized actions.
        events = [
            {
                "event_id": "e1",
                "required_actions": ["tool.play_media"],
                # actions_taken omitted
            }
        ]
        result = tool_call_unauthorized_action_rate(events)
        assert result.rate == 0.0
        assert result.flagged is False
        assert result.unauthorized_event_count == 0

    def test_empty_event_stream_returns_rate_zero(self) -> None:
        result = tool_call_unauthorized_action_rate([])
        assert result.total_events == 0
        assert result.rate == 0.0
        assert result.flagged is False
        assert result.unauthorized_actions_by_tool == {}
        assert result.per_event_unauthorized == []

    def test_custom_extractors_for_non_canonical_schema(self) -> None:
        # Caller may want to compute on a nested schema (e.g. inside `output`).
        events = [
            {
                "id": "e1",
                "policy": {"allowed_tools": ["tool.play_media"]},
                "audit": {"invoked": ["tool.play_media", "tool.unlock_door"]},
            }
        ]
        result = tool_call_unauthorized_action_rate(
            events,
            required_actions_extractor=lambda e: e["policy"]["allowed_tools"],
            actions_taken_extractor=lambda e: e["audit"]["invoked"],
            event_id_extractor=lambda e: e["id"],
        )
        assert result.unauthorized_event_count == 1
        assert result.per_event_unauthorized == [("e1", ("tool.unlock_door",))]

    def test_threshold_above_default_loosens_detection(self) -> None:
        # Customers SHOULD NOT do this in production (per Charter), but the
        # primitive accepts a tunable threshold for API symmetry. Validate that
        # raising it does mathematically what's expected.
        events = [
            _event("e1", required=["tool.play_media"], taken=["tool.play_media"]),
            _event("e2", required=["tool.play_media"], taken=["tool.unlock_door"]),
        ]
        # rate = 0.5
        result_strict = tool_call_unauthorized_action_rate(events)  # threshold=0.0
        assert result_strict.flagged is True

        result_loose = tool_call_unauthorized_action_rate(events, threshold=0.5)
        # rate (0.5) is not > threshold (0.5); strict-greater-than semantics
        assert result_loose.flagged is False

    def test_invalid_threshold_raises(self) -> None:
        events = [_event("e1", required=[], taken=["tool.x"])]
        with pytest.raises(ValueError, match="threshold must be in"):
            tool_call_unauthorized_action_rate(events, threshold=-0.1)
        with pytest.raises(ValueError, match="threshold must be in"):
            tool_call_unauthorized_action_rate(events, threshold=1.1)

    def test_result_is_frozen_dataclass(self) -> None:
        # Match the convention of other primitives (DisparateImpactResult etc.)
        result = tool_call_unauthorized_action_rate([])
        assert isinstance(result, UnauthorizedToolCallResult)
        with pytest.raises((AttributeError, TypeError)):
            result.rate = 1.0  # type: ignore[misc]

    def test_unauthorized_by_tool_counts_multiple_events(self) -> None:
        # Same tool invoked unauthorized across multiple events is summed.
        events = [
            _event("e1", required=[], taken=["tool.bad"]),
            _event("e2", required=[], taken=["tool.bad"]),
            _event("e3", required=[], taken=["tool.bad", "tool.also_bad"]),
        ]
        result = tool_call_unauthorized_action_rate(events)
        assert result.unauthorized_event_count == 3
        assert result.unauthorized_actions_by_tool == {
            "tool.bad": 3,
            "tool.also_bad": 1,
        }
