"""Tests for the Detection engine + structural anti-theater enforcement."""

from __future__ import annotations

import pytest

from ailedger_detection.disparate_impact import disparate_impact_ratio
from ailedger_detection.engine import (
    DetectionEngine,
    DetectionSpec,
    DetectionSuppressionError,
    refuse_suppression,
)
from ailedger_detection.tool_calls import tool_call_unauthorized_action_rate
from ailedger_detection.unresolved_flags import unresolved_flag_accumulation

_TS = "2026-06-03T00:00:00+00:00"


def _di_event(race: str, hire: bool) -> dict:
    return {
        "protected_class_context": {"race": race},
        "output": {"decision": "hire" if hire else "no"},
    }


def _di_spec() -> DetectionSpec:
    return DetectionSpec(
        name="disparate_impact",
        fn=disparate_impact_ratio,
        kwargs={
            "protected_class_key": "race",
            "positive_outcome_predicate": lambda e: e["output"]["decision"] == "hire",
        },
    )


class TestAntiTheater:
    @pytest.mark.parametrize(
        "key",
        ["disable", "compliance_mode", "bypass", "suppress", "skip_detection", "off"],
    )
    def test_suppression_keys_refused(self, key: str) -> None:
        with pytest.raises(DetectionSuppressionError):
            refuse_suppression({key: True})

    def test_spec_refuses_suppression_kwargs(self) -> None:
        with pytest.raises(DetectionSuppressionError):
            DetectionSpec(name="x", fn=disparate_impact_ratio, kwargs={"compliance_mode": True})

    def test_legitimate_kwargs_allowed(self) -> None:
        # No false positives on normal config.
        refuse_suppression({"threshold": 0.9, "protected_class_key": "race"})


class TestDetectionEngine:
    def test_run_produces_one_warrant_per_spec(self) -> None:
        engine = DetectionEngine([_di_spec()])
        events = [_di_event("A", True), _di_event("B", False)]
        run = engine.run(events, created_at=_TS)
        assert len(run.warrants) == 1
        assert run.warrants[0].primitive == "disparate_impact_ratio"

    def test_run_flagged_when_any_warrant_flags(self) -> None:
        engine = DetectionEngine([_di_spec()])
        # B has 0 hire rate vs A 1.0 -> flagged.
        events = [_di_event("A", True), _di_event("A", True), _di_event("B", False)]
        run = engine.run(events, created_at=_TS)
        assert run.flagged is True
        assert len(run.flagged_warrants()) == 1

    def test_run_digest_is_deterministic(self) -> None:
        engine = DetectionEngine([_di_spec()])
        events = [_di_event("A", True), _di_event("B", False)]
        a = engine.run(events, created_at=_TS)
        b = engine.run(events, created_at="2027-01-01T00:00:00+00:00")
        # Digest chains warrant content, which excludes timestamps.
        assert a.run_digest == b.run_digest

    def test_multiple_specs_share_one_cohort(self) -> None:
        events = [
            {
                "event_id": "e1",
                "protected_class_context": {"race": "A"},
                "output": {"decision": "hire"},
                "flags_raised": ["low_conf"],
                "required_actions": ["review"],
                "actions_taken": [],
            },
            {
                "event_id": "e2",
                "protected_class_context": {"race": "B"},
                "output": {"decision": "no"},
                "required_actions": [],
                "actions_taken": ["tool.unlock"],
            },
        ]
        engine = DetectionEngine(
            [
                _di_spec(),
                DetectionSpec("unresolved", unresolved_flag_accumulation),
                DetectionSpec("tool_calls", tool_call_unauthorized_action_rate),
            ]
        )
        run = engine.run(events, created_at=_TS)
        assert {w.primitive for w in run.warrants} == {
            "disparate_impact_ratio",
            "unresolved_flag_accumulation",
            "tool_call_unauthorized_action_rate",
        }

    def test_duplicate_spec_names_rejected(self) -> None:
        with pytest.raises(ValueError, match="Duplicate"):
            DetectionEngine([_di_spec(), _di_spec()])

    def test_with_spec_appends_immutably(self) -> None:
        base = DetectionEngine([_di_spec()])
        extended = base.with_spec(DetectionSpec("uf", unresolved_flag_accumulation))
        assert len(base.specs) == 1
        assert len(extended.specs) == 2

    def test_to_dict_is_serializable(self) -> None:
        import json

        engine = DetectionEngine([_di_spec()])
        events = [_di_event("A", True), _di_event("B", False)]
        run = engine.run(events, created_at=_TS)
        # Must round-trip through JSON (audit-ledger record).
        dumped = json.dumps(run.to_dict())
        assert "run_digest" in dumped
