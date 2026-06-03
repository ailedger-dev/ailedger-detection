"""
Structural anti-theater regression tests.

Each test pins a red-team thesis-breaker CLOSED: the "anti-theater is structural,
not convention" claim is enforced by these guarantees, not merely documented.
The repro in each docstring is the attack these tests refute.
"""

from __future__ import annotations

from types import MappingProxyType

import pytest

from ailedger_detection import thresholds as _thresholds
from ailedger_detection.disparate_impact import disparate_impact_ratio
from ailedger_detection.engine import DetectionEngine, DetectionSpec
from ailedger_detection.parity import statistical_parity_difference
from ailedger_detection.thresholds import (
    RegistryIntegrityError,
    ThresholdStandard,
    TightenDirection,
    enforce_tighten_only,
    registry_digest,
)
from ailedger_detection.warrant import Warrant

_TS = "2026-06-03T00:00:00+00:00"


def _di_spec() -> DetectionSpec:
    return DetectionSpec(
        name="di",
        fn=disparate_impact_ratio,
        kwargs={"protected_class_key": "race", "positive_outcome_predicate": lambda e: e["hire"]},
    )


class TestF1RegistrySeal:
    """F1 — the tighten-only guard must not rest on a mutable module global."""

    def test_registry_is_read_only(self) -> None:
        # Direct item assignment to the registry is refused by the type.
        with pytest.raises(TypeError):
            _thresholds._REGISTRY["disparate_impact_ratio"] = ThresholdStandard(  # type: ignore[index]
                name="disparate_impact_ratio",
                baseline=0.10,
                direction=TightenDirection.RAISE_TO_TIGHTEN,
                standard="loosened",
            )

    def test_rebinding_global_fails_closed(self) -> None:
        # Even reaching past the proxy to rebind the global is caught: the
        # integrity self-check refuses to validate on a tampered registry.
        saved = _thresholds._REGISTRY
        try:
            _thresholds._REGISTRY = MappingProxyType(
                {
                    **dict(saved),
                    "disparate_impact_ratio": ThresholdStandard(
                        name="disparate_impact_ratio",
                        baseline=0.10,
                        direction=TightenDirection.RAISE_TO_TIGHTEN,
                        standard="loosened",
                    ),
                }
            )
            with pytest.raises(RegistryIntegrityError):
                enforce_tighten_only("disparate_impact_ratio", 0.2)
        finally:
            _thresholds._REGISTRY = saved

    def test_registry_digest_recorded_in_warrant(self) -> None:
        events = [{"race": "A", "hire": True}, {"race": "B", "hire": False}]
        w = disparate_impact_ratio(
            events, protected_class_key="race", positive_outcome_predicate=lambda e: e["hire"]
        ).to_warrant(created_at=_TS)
        assert w.registry_digest == registry_digest()
        assert w.registry_digest != ""


class TestF2UnguardedPredicate:
    """F2 — dropped/unlabeled events counted + recorded; identity memorialized."""

    def test_stripped_labels_are_counted_not_silent(self) -> None:
        events = [
            {"protected_class_context": {"race": "A"}, "hire": True},
            {"protected_class_context": {"race": "A"}, "hire": True},
            {"protected_class_context": {"race": "B"}, "hire": True},
            {"hire": False},  # label stripped
            {"hire": False},
            {"hire": False},
        ]
        r = disparate_impact_ratio(
            events, protected_class_key="race", positive_outcome_predicate=lambda e: e["hire"]
        )
        assert r.skipped_no_group == 3
        assert r.total_events == 6
        assert r.coverage == pytest.approx(0.5)
        w = r.to_warrant(created_at=_TS)
        assert w.evidence["skipped_no_group"] == 3
        assert w.evidence["coverage"] == pytest.approx(0.5)
        assert w.evidence["protected_class_key"] == "race"
        assert w.evidence["predicate_identity"]  # non-empty identity recorded

    def test_min_coverage_guard_flags_thin_cohort(self) -> None:
        events = [
            {"protected_class_context": {"race": "A"}, "hire": True},
            {"protected_class_context": {"race": "B"}, "hire": False},
            {"hire": False},
            {"hire": False},
        ]
        r = disparate_impact_ratio(
            events,
            protected_class_key="race",
            positive_outcome_predicate=lambda e: e["hire"],
            min_coverage=0.9,
        )
        assert r.coverage_flagged is True
        assert r.to_warrant(created_at=_TS).result["coverage_flagged"] is True

    def test_parity_also_counts_drops(self) -> None:
        events = [
            {"protected_class_context": {"g": "A"}, "ok": True},
            {"protected_class_context": {"g": "B"}, "ok": False},
            {"ok": True},
        ]
        r = statistical_parity_difference(
            events, protected_class_key="g", positive_outcome_predicate=lambda e: e["ok"]
        )
        assert r.skipped_no_group == 1
        assert r.predicate_identity


class TestF3WarrantSoundness:
    """F3 — an empty-standard, empty-rejected warrant must be unrepresentable."""

    def test_empty_justification_refused(self) -> None:
        with pytest.raises(ValueError, match="standard"):
            Warrant.build(
                primitive="x",
                result={"flagged": False},
                evidence={},
                standard="",
                threshold=0.0,
                rejected_thresholds=(),
                created_at=_TS,
            )

    def test_empty_rejected_requires_sentinel(self) -> None:
        with pytest.raises(ValueError, match="looser"):
            Warrant.build(
                primitive="x",
                result={"flagged": False},
                evidence={},
                standard="STD",
                threshold=0.0,
                rejected_thresholds=(),
                created_at=_TS,
            )

    def test_no_looser_alternative_sentinel_is_sound(self) -> None:
        w = Warrant.build(
            primitive="x",
            result={"flagged": False},
            evidence={},
            standard="STD",
            threshold=0.0,
            rejected_thresholds=(),
            no_looser_alternative=True,
            created_at=_TS,
        )
        assert w.no_looser_alternative is True
        assert w.verify_digest() is True


class TestF4DigestKeying:
    """F4 — unkeyed digest is consistency, not tamper-evidence; HMAC + chaining."""

    def _sound(self, **kw: object) -> Warrant:
        base: dict[str, object] = {
            "primitive": "x",
            "result": {"flagged": True},
            "evidence": {"n": 1},
            "standard": "STD",
            "threshold": 0.8,
            "no_looser_alternative": True,
            "created_at": _TS,
        }
        base.update(kw)
        return Warrant.build(**base)  # type: ignore[arg-type]

    def test_unkeyed_is_not_keyed(self) -> None:
        assert self._sound().keyed is False

    def test_hmac_round_trip(self) -> None:
        key = b"secret"
        w = self._sound(signing_key=key)
        assert w.keyed is True
        assert w.verify_digest(signing_key=key) is True
        assert w.verify_digest(signing_key=b"wrong") is False
        # Scheme mismatch is rejected both ways.
        assert w.verify_digest() is False
        assert self._sound().verify_digest(signing_key=key) is False

    def test_run_digest_chains_prev(self) -> None:
        engine = DetectionEngine([_di_spec()])
        events = [{"race": "A", "hire": True}, {"race": "B", "hire": False}]
        run1 = engine.run(events, created_at=_TS)
        run2 = engine.run(events, created_at=_TS, prev_digest=run1.run_digest)
        assert run2.prev_digest == run1.run_digest
        # Chaining changes the run digest: a run is bound to its predecessor.
        assert run2.run_digest != run1.run_digest
        assert "prev_digest" in run2.to_dict()


class TestF5FailClosed:
    """F5 — a result with no recorded decision must fail closed, not read False."""

    def test_missing_flagged_refused_at_build(self) -> None:
        with pytest.raises(ValueError, match="flagged"):
            Warrant.build(
                primitive="x",
                result={"metric": "m"},
                evidence={},
                standard="STD",
                threshold=0.8,
                no_looser_alternative=True,
                created_at=_TS,
            )

    def test_flagged_property_does_not_default(self) -> None:
        bad = Warrant(
            primitive="x",
            result={"metric": "m"},  # no flagged cell
            evidence={},
            standard="STD",
            threshold=0.8,
            rejected_thresholds=(),
            warrant_digest="deadbeef",
            created_at=_TS,
        )
        with pytest.raises(KeyError):
            _ = bad.flagged


class TestF6MinSample:
    """F6 — trivially small samples must not manufacture flags."""

    def test_n2_not_evaluable_with_gate(self) -> None:
        r = disparate_impact_ratio(
            [{"r": "A", "h": True}, {"r": "B", "h": False}],
            protected_class_key="r",
            positive_outcome_predicate=lambda e: e["h"],
            min_group_size=2,
        )
        assert r.evaluable is False
        assert r.flagged is False
        assert r.skipped_small_group == 2

    def test_parity_n2_not_evaluable_with_gate(self) -> None:
        r = statistical_parity_difference(
            [{"r": "A", "h": True}, {"r": "B", "h": False}],
            protected_class_key="r",
            positive_outcome_predicate=lambda e: e["h"],
            min_group_size=2,
        )
        assert r.evaluable is False
        assert r.flagged is False

    def test_adequate_sample_still_evaluates(self) -> None:
        events = [{"r": "A", "h": True}] * 3 + [{"r": "B", "h": False}] * 3
        r = disparate_impact_ratio(
            events,
            protected_class_key="r",
            positive_outcome_predicate=lambda e: e["h"],
            min_group_size=2,
        )
        assert r.evaluable is True
        assert r.flagged is True  # 0/3 vs 3/3 → real disparity


class TestF10BaselineBoundary:
    """F10 — the baseline value reached by float arithmetic is not 'loosening'."""

    def test_float_baseline_accepted(self) -> None:
        val = 0.1 + 0.7  # 0.7999999999999999
        assert val < 0.8  # the float trap
        assert enforce_tighten_only("disparate_impact_ratio", val) == val
