"""Tests for the warranted-Decision (LARP) layer."""

from __future__ import annotations

import dataclasses

import pytest

from ailedger_detection import (
    disparate_impact_ratio,
    model_drift_between_versions,
)
from ailedger_detection.warrant import (
    Warrant,
    WarrantedDecision,
    warrant_detection_result,
)


def _di_result(flagged: bool):
    # Group A 1/1, group B 0/1 -> ratio 0.0 -> flagged; both positive -> ratio 1.0.
    events = [
        {"protected_class_context": {"race": "A"}, "hire": True},
        {"protected_class_context": {"race": "B"}, "hire": flagged is False},
    ]
    return disparate_impact_ratio(
        events,
        protected_class_key="race",
        positive_outcome_predicate=lambda e: bool(e["hire"]),
    )


class TestWarrantDetectionResult:
    def test_wraps_flagged_result_with_standard_and_value(self) -> None:
        result = _di_result(flagged=True)
        assert result.flagged is True
        decision = warrant_detection_result(
            result,
            decision_id="dec-1",
            rejected_alternatives=("statistical parity: rejected, ratio is load-bearing here",),
        )
        assert isinstance(decision, WarrantedDecision)
        assert decision.decision_id == "dec-1"
        assert decision.primitive == "DisparateImpactResult"
        assert decision.warrant.flagged is True
        assert "four-fifths" in decision.warrant.standard
        assert decision.warrant.observed_value == result.ratio
        assert decision.warrant.threshold == result.threshold
        assert len(decision.warrant.rejected_alternatives) == 1

    def test_clean_result_yields_clean_warrant(self) -> None:
        result = _di_result(flagged=False)
        assert result.flagged is False
        decision = warrant_detection_result(result, decision_id="dec-2")
        assert decision.warrant.flagged is False

    def test_ladder_result_has_no_threshold_but_has_value(self) -> None:
        ref = [{"decision_type": "approve"} for _ in range(10)]
        cur = [{"decision_type": "deny"} for _ in range(10)]
        result = model_drift_between_versions(ref, cur)
        decision = warrant_detection_result(result, decision_id="dec-3")
        assert decision.warrant.observed_value == result.psi
        # ModelDriftResult exposes no single `threshold` attribute.
        assert decision.warrant.threshold is None

    def test_unknown_result_type_refused(self) -> None:
        with pytest.raises(TypeError, match="not a recognized detection result"):
            warrant_detection_result({"flagged": True}, decision_id="x")

    def test_default_charter_clause_present(self) -> None:
        decision = warrant_detection_result(_di_result(flagged=True), decision_id="d")
        assert "Charter v1.1" in decision.warrant.charter_clause


class TestAntiTheaterInvariant:
    def test_cannot_construct_decision_that_suppresses_a_flag(self) -> None:
        result = _di_result(flagged=True)
        lying_warrant = Warrant(
            standard="EEOC four-fifths",
            observed_value=result.ratio,
            threshold=result.threshold,
            flagged=False,  # contradicts the flagged result
            rejected_alternatives=(),
            charter_clause="(none)",
        )
        with pytest.raises(ValueError, match="refused at the schema level"):
            WarrantedDecision(
                decision_id="bad",
                primitive="DisparateImpactResult",
                result=result,
                warrant=lying_warrant,
            )

    def test_warrant_helper_never_emits_contradiction(self) -> None:
        # Mutating the produced warrant requires building a new (frozen) one,
        # and re-binding it through WarrantedDecision is what re-checks the
        # invariant — so suppression cannot slip through the helper either.
        result = _di_result(flagged=True)
        decision = warrant_detection_result(result, decision_id="d")
        suppressed = dataclasses.replace(decision.warrant, flagged=False)
        with pytest.raises(ValueError, match="refused at the schema level"):
            dataclasses.replace(decision, warrant=suppressed)

    def test_non_detection_result_refused(self) -> None:
        class NotAResult:
            pass

        bogus = Warrant(
            standard="x",
            observed_value=None,
            threshold=None,
            flagged=False,
            rejected_alternatives=(),
            charter_clause="x",
        )
        with pytest.raises(TypeError, match="no boolean 'flagged'"):
            WarrantedDecision(
                decision_id="d",
                primitive="NotAResult",
                result=NotAResult(),
                warrant=bogus,
            )
