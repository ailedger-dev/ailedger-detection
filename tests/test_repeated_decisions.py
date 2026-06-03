"""Tests for subject-level repeated-decision pattern detection."""

from __future__ import annotations

import pytest

from ailedger_detection.repeated_decisions import subject_repeated_decision_patterns


def _event(subject: str | None, adverse: bool) -> dict:
    e: dict = {"output": {"decision": "deny" if adverse else "approve"}}
    if subject is not None:
        e["subject_id"] = subject
    return e


def _adverse(e: dict) -> bool:
    return e["output"]["decision"] == "deny"


def _detect(events: list[dict], **kw: object):
    return subject_repeated_decision_patterns(
        events,
        adverse_outcome_predicate=_adverse,
        **kw,  # type: ignore[arg-type]
    )


class TestRepeatedDecisionPatterns:
    def test_flags_subject_at_threshold(self) -> None:
        events = [_event("alice", True) for _ in range(3)]
        result = _detect(events)
        assert result.flagged is True
        assert result.flagged_subjects == ("alice",)
        assert result.subject_patterns["alice"].adverse_count == 3

    def test_below_threshold_not_flagged(self) -> None:
        events = [_event("alice", True) for _ in range(2)]
        result = _detect(events)
        assert result.flagged is False
        assert result.flagged_subjects == ()

    def test_favorable_decisions_do_not_count(self) -> None:
        events = [_event("alice", True), _event("alice", False), _event("alice", True)]
        result = _detect(events)
        p = result.subject_patterns["alice"]
        assert p.adverse_count == 2
        assert p.total_count == 3
        assert result.flagged is False

    def test_flagged_subjects_sorted_most_adverse_first(self) -> None:
        events = [_event("alice", True) for _ in range(3)]
        events += [_event("bob", True) for _ in range(5)]
        result = _detect(events)
        assert result.flagged_subjects == ("bob", "alice")

    def test_skips_events_without_subject(self) -> None:
        events = [_event(None, True), _event(None, True)]
        result = _detect(events)
        assert result.skipped_no_subject == 2
        assert result.total_subjects == 0

    def test_tighter_threshold_catches_shorter_patterns(self) -> None:
        events = [_event("alice", True) for _ in range(2)]
        result = _detect(events, threshold=2)
        assert result.flagged is True

    def test_looser_threshold_refused(self) -> None:
        with pytest.raises(ValueError, match="LOOSENS"):
            _detect([], threshold=5)

    def test_below_minimum_threshold_refused(self) -> None:
        with pytest.raises(ValueError, match="out of range"):
            _detect([], threshold=0)

    def test_to_warrant_lists_flagged_subjects(self) -> None:
        events = [_event("alice", True) for _ in range(3)]
        warrant = _detect(events).to_warrant(created_at="2026-06-03T00:00:00+00:00")
        assert warrant.flagged is True
        assert warrant.result["flagged_subjects"] == ["alice"]
        assert warrant.verify_digest() is True
