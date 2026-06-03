"""Tests for the LARP warrant core (audit spine)."""

from __future__ import annotations

import pytest

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


class TestWarrantSoundness:
    """F3 — an empty-standard / empty-rejected 2-cell must be unrepresentable."""

    def test_empty_standard_refused(self) -> None:
        with pytest.raises(ValueError, match="non-empty `standard`"):
            _warrant(standard="")

    def test_empty_rejected_and_no_sentinel_refused(self) -> None:
        with pytest.raises(ValueError, match="rejected"):
            _warrant(rejected_thresholds=())

    def test_no_looser_alternative_sentinel_accepted(self) -> None:
        # An explicit, recorded sentinel stands in for the rejected set when the
        # chosen value is already the strictest representable.
        w = _warrant(rejected_thresholds=(), no_looser_alternative=True)
        assert w.no_looser_alternative is True
        assert w.verify_digest() is True
        assert w.to_dict()["no_looser_alternative"] is True


class TestFailClosed:
    """F5 — a missing decision cell must not fail open (read as not-flagged)."""

    def test_build_requires_flagged_cell(self) -> None:
        with pytest.raises(ValueError, match="flagged"):
            _warrant(result={"metric": "m", "value": 0.5})

    def test_flagged_property_defaults_closed(self) -> None:
        # Defence-in-depth: a warrant somehow lacking the cell reads as flagged.
        w = _warrant()
        bare = Warrant(
            primitive=w.primitive,
            result={},  # no 'flagged'
            evidence=w.evidence,
            standard=w.standard,
            threshold=w.threshold,
            rejected_thresholds=w.rejected_thresholds,
            warrant_digest=w.warrant_digest,
            created_at=w.created_at,
        )
        assert bare.flagged is True


class TestKeyedSignature:
    """F4 — tamper-evidence is the keyed signature's job, not the unkeyed digest."""

    def test_unsigned_warrant_has_no_signature(self) -> None:
        w = _warrant()
        assert w.signature is None
        assert w.verify_signature(b"any-key") is False

    def test_signed_warrant_verifies_with_key(self) -> None:
        w = _warrant(signing_key=b"s3cret")
        assert w.signature is not None
        assert w.verify_signature(b"s3cret") is True

    def test_signature_rejects_wrong_key(self) -> None:
        w = _warrant(signing_key=b"s3cret")
        assert w.verify_signature(b"wrong") is False

    def test_signature_binds_content(self) -> None:
        # Recomputing the public digest over altered content passes verify_digest
        # (consistency) but a forger without the key cannot produce a matching
        # signature for the altered payload.
        a = _warrant(signing_key=b"s3cret")
        b = _warrant(result={"flagged": False}, signing_key=b"s3cret")
        assert a.signature != b.signature
