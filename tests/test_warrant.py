"""Tests for the LARP warrant core (audit spine)."""

from __future__ import annotations

from ailedger_detection.warrant import RejectedThreshold, Warrant

_TS = "2026-06-03T00:00:00+00:00"


def _warrant(**overrides: object) -> Warrant:
    kwargs: dict[str, object] = {
        "primitive": "p",
        "result": {"flagged": True, "metric": "m", "value": 0.5},
        "evidence": {"n": 10},
        "standard": "STD",
        "threshold": 0.8,
        "rejected_thresholds": (RejectedThreshold("< 0.8", "refused"),),
        "created_at": _TS,
    }
    kwargs.update(overrides)
    return Warrant.build(**kwargs)  # type: ignore[arg-type]


class TestWarrant:
    def test_flagged_reads_result_cell(self) -> None:
        assert _warrant().flagged is True
        assert _warrant(result={"flagged": False}).flagged is False

    def test_digest_is_deterministic_across_timestamp(self) -> None:
        # Same content, different created_at -> same digest (created_at excluded).
        a = _warrant(created_at="2026-06-03T00:00:00+00:00")
        b = _warrant(created_at="2027-01-01T12:00:00+00:00")
        assert a.warrant_digest == b.warrant_digest

    def test_digest_changes_when_content_changes(self) -> None:
        a = _warrant()
        b = _warrant(result={"flagged": False, "metric": "m", "value": 0.5})
        assert a.warrant_digest != b.warrant_digest

    def test_verify_digest_passes_for_minted_warrant(self) -> None:
        assert _warrant().verify_digest() is True

    def test_verify_digest_fails_when_tampered(self) -> None:
        w = _warrant()
        tampered = Warrant(
            primitive=w.primitive,
            result={"flagged": False},  # altered
            evidence=w.evidence,
            standard=w.standard,
            threshold=w.threshold,
            rejected_thresholds=w.rejected_thresholds,
            warrant_digest=w.warrant_digest,  # stale digest
            created_at=w.created_at,
        )
        assert tampered.verify_digest() is False

    def test_to_dict_round_trips_rejected_thresholds(self) -> None:
        d = _warrant().to_dict()
        assert d["rejected_thresholds"] == [{"value": "< 0.8", "reason": "refused"}]
        assert d["warrant_digest"] == _warrant().warrant_digest
        assert d["standard"] == "STD"

    def test_created_at_defaults_to_now_when_omitted(self) -> None:
        w = _warrant(created_at=None)
        # RFC3339-ish, non-empty.
        assert "T" in w.created_at and w.created_at.endswith("+00:00")
