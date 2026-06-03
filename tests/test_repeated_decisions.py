"""Tests for subject-level repeated-decision pattern primitive."""

from __future__ import annotations

import pytest

from ailedger_detection.repeated_decisions import (
    DEFAULT_MIN_REPETITIONS,
    subject_repeated_decision_patterns,
)


def _event(event_id: str, subject: str, *, rejected: bool) -> dict:
    return {
        "event_id": event_id,
        "subject_id": subject,
        "output": {"decision": "reject" if rejected else "approve"},
    }


def _rejected(event: dict) -> bool:
    return event["output"]["decision"] == "reject"


class TestRepeatedDecisionPatterns:
    def test_default_min_repetitions_is_three(self) -> None:
        assert DEFAULT_MIN_REPETITIONS == 3

    def test_three_rejections_flag_subject(self) -> None:
        events = [
            _event("e1", "s1", rejected=True),
            _event("e2", "s1", rejected=True),
            _event("e3", "s1", rejected=True),
            _event("e4", "s2", rejected=True),  # only once
        ]
        result = subject_repeated_decision_patterns(
            events, adverse_outcome_predicate=_rejected
        )
        assert result.flagged is True
        assert len(result.flagged_subjects) == 1
        pattern = result.flagged_subjects[0]
        assert pattern.subject_id == "s1"
        assert pattern.adverse_decisions == 3
        assert pattern.total_decisions == 3
        assert pattern.event_ids == ("e1", "e2", "e3")

    def test_two_rejections_not_flagged_at_baseline(self) -> None:
        events = [
            _event("e1", "s1", rejected=True),
            _event("e2", "s1", rejected=True),
        ]
        result = subject_repeated_decision_patterns(
            events, adverse_outcome_predicate=_rejected
        )
        assert result.flagged is False
        assert result.flagged_subjects == ()
        assert result.subjects_examined == 1

    def test_mixed_outcomes_count_only_adverse(self) -> None:
        events = [
            _event("e1", "s1", rejected=True),
            _event("e2", "s1", rejected=False),
            _event("e3", "s1", rejected=True),
            _event("e4", "s1", rejected=True),
        ]
        result = subject_repeated_decision_patterns(
            events, adverse_outcome_predicate=_rejected
        )
        assert result.flagged is True
        pattern = result.flagged_subjects[0]
        assert pattern.adverse_decisions == 3
        assert pattern.total_decisions == 4
        assert pattern.event_ids == ("e1", "e3", "e4")

    def test_tighten_to_two_flags_sooner(self) -> None:
        events = [
            _event("e1", "s1", rejected=True),
            _event("e2", "s1", rejected=True),
        ]
        result = subject_repeated_decision_patterns(
            events, adverse_outcome_predicate=_rejected, min_repetitions=2
        )
        assert result.flagged is True

    def test_loosening_above_baseline_refused(self) -> None:
        with pytest.raises(ValueError, match="loosens detection"):
            subject_repeated_decision_patterns(
                [], adverse_outcome_predicate=_rejected, min_repetitions=4
            )

    def test_min_repetitions_below_two_refused(self) -> None:
        with pytest.raises(ValueError, match="must be >= 2"):
            subject_repeated_decision_patterns(
                [], adverse_outcome_predicate=_rejected, min_repetitions=1
            )

    def test_subjects_sorted_by_adverse_count_desc(self) -> None:
        events = []
        for i in range(3):
            events.append(_event(f"a{i}", "low", rejected=True))
        for i in range(5):
            events.append(_event(f"b{i}", "high", rejected=True))
        result = subject_repeated_decision_patterns(
            events, adverse_outcome_predicate=_rejected
        )
        assert [p.subject_id for p in result.flagged_subjects] == ["high", "low"]

    def test_missing_subject_skipped(self) -> None:
        events = [
            {"event_id": "e1", "output": {"decision": "reject"}},
            {"event_id": "e2", "subject_id": "", "output": {"decision": "reject"}},
            _event("e3", "s1", rejected=True),
        ]
        result = subject_repeated_decision_patterns(
            events, adverse_outcome_predicate=_rejected
        )
        assert result.skipped_no_subject == 2
        assert result.subjects_examined == 1

    def test_custom_subject_extractor(self) -> None:
        events = [
            {"id": "e1", "pseudonym": "p1", "adverse": True},
            {"id": "e2", "pseudonym": "p1", "adverse": True},
        ]
        result = subject_repeated_decision_patterns(
            events,
            adverse_outcome_predicate=lambda e: bool(e["adverse"]),
            subject_id_extractor=lambda e: e.get("pseudonym"),
            event_id_extractor=lambda e: str(e["id"]),
            min_repetitions=2,
        )
        assert result.flagged is True
        assert result.flagged_subjects[0].event_ids == ("e1", "e2")
