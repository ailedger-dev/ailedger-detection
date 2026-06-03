"""
LARP warrant — the audit spine of the Detection layer.

LARP is the accountable-reckoning principle: *every decision is memorialized
with its warrant.* In the Detection layer that principle is structural — every
detection run produces a WARRANTED result, not a bare boolean.

Why a warrant, not a bare flag:

- The detection **result** is the decision itself ("flagged" / "not flagged" at
  this metric value) — directed and non-invertible; you cannot un-detect.
- The **warrant** records that decision *together with* the reasoning it was
  chosen over the alternatives. Concretely it carries two things:
    1. the **evidence** that grounds the result (the per-group stats, the PSI
       bucket contributions, the per-event diffs — whatever the primitive
       computed), and
    2. the **rejected thresholds** — the looser thresholds that were refused,
       each annotated with *why* (the standard that anchors the chosen value).
  "Chose this result rather than that one, because…" is exactly what the
  warrant captures.

Recording the bare flag alone is strictly weaker than recording the warrant
(flag + evidence + rejected alternatives). A bare flag memorializes only the
outcome; a warrant memorializes the decision behind it. Auditability is
completeness — the recorded warrant identifies the detection. The warrant is
what makes the Detection layer auditable by customers, regulators, and
adversarial reviewers, and it is the artifact the Grafana LARP monitor consumes.

The `warrant_digest` is a content hash over the substantive cells (result +
evidence + rejected thresholds + standard + threshold), deliberately excluding
the wall-clock `created_at`. Two runs of the same detection over the same
evidence therefore produce the same digest: a verifier can re-run a detection
and confirm the warrant's content without trusting the timestamp. This is the
hook for chaining warrants into the append-only audit ledger.

This module is a pure leaf: it has no dependency on any primitive. Result
classes import `Warrant`/`RejectedThreshold` and expose a `to_warrant()`; the
threshold registry imports `RejectedThreshold` to describe what each standard
refuses.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class RejectedThreshold:
    """
    A looser threshold that the Charter refuses, with its reason.

    This is part of the warrant's reasoning: the chosen threshold was chosen
    *rather than* this rejected one, and `reason` records why (the anchoring
    standard). Per Charter v1.1, customers tighten, never loosen — so the
    rejected set is always the loosening direction relative to the baseline.
    """

    value: str
    """Description of the rejected threshold region, e.g. "< 0.80" or "> 0.10"."""

    reason: str
    """Why it is refused — the standard it would fall below / drift past."""

    def to_dict(self) -> dict[str, str]:
        return {"value": self.value, "reason": self.reason}


@dataclass(frozen=True)
class Warrant:
    """
    A memorialized detection decision: the decision plus its grounding evidence
    and the looser thresholds it refused.

    Construct via `Warrant.build(...)` so the digest is computed consistently.
    """

    primitive: str
    """The detection primitive that produced this warrant."""

    result: dict[str, Any]
    """The decision. Always carries at least `flagged` and the metric name +
    value; primitives may add domain fields (severity, groups)."""

    evidence: dict[str, Any]
    """The grounding stats supporting the decision."""

    standard: str
    """The published standard anchoring the chosen threshold (e.g. EEOC 29 CFR
    1607). Empty string only for primitives with no external anchor."""

    threshold: float
    """The chosen threshold value the decision was made against."""

    rejected_thresholds: tuple[RejectedThreshold, ...]
    """The looser thresholds refused, with reasons."""

    warrant_digest: str
    """SHA-256 over the substantive cells (excludes created_at). Deterministic."""

    created_at: str
    """RFC3339 UTC timestamp the warrant was minted. Metadata, not hashed."""

    spec_version: int = field(default=1)
    """Warrant schema version, for forward compatibility of the audit ledger."""

    @staticmethod
    def _digest(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def build(
        cls,
        *,
        primitive: str,
        result: dict[str, Any],
        evidence: dict[str, Any],
        standard: str,
        threshold: float,
        rejected_thresholds: tuple[RejectedThreshold, ...] = (),
        created_at: str | None = None,
        spec_version: int = 1,
    ) -> Warrant:
        """
        Mint a warrant, computing its content digest.

        Args:
            primitive: Name of the detection primitive.
            result: The decision dict (must be JSON-serializable).
            evidence: The grounding evidence dict (must be JSON-serializable).
            standard: Anchoring standard citation.
            threshold: The threshold the decision was made against.
            rejected_thresholds: Looser thresholds refused, with reasons.
            created_at: RFC3339 UTC timestamp. Defaults to now(UTC). Pass an
                explicit value for deterministic tests / replay.
            spec_version: Warrant schema version.

        Returns:
            A frozen Warrant with `warrant_digest` populated.
        """
        if created_at is None:
            created_at = datetime.now(timezone.utc).isoformat()

        digest_payload = {
            "primitive": primitive,
            "result": result,
            "evidence": evidence,
            "standard": standard,
            "threshold": threshold,
            "rejected_thresholds": [r.to_dict() for r in rejected_thresholds],
            "spec_version": spec_version,
        }
        return cls(
            primitive=primitive,
            result=result,
            evidence=evidence,
            standard=standard,
            threshold=threshold,
            rejected_thresholds=tuple(rejected_thresholds),
            warrant_digest=cls._digest(digest_payload),
            created_at=created_at,
            spec_version=spec_version,
        )

    @property
    def flagged(self) -> bool:
        """Convenience: did the underlying decision flag?"""
        return bool(self.result.get("flagged", False))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict (the audit-ledger record shape)."""
        return {
            "primitive": self.primitive,
            "result": self.result,
            "evidence": self.evidence,
            "standard": self.standard,
            "threshold": self.threshold,
            "rejected_thresholds": [r.to_dict() for r in self.rejected_thresholds],
            "warrant_digest": self.warrant_digest,
            "created_at": self.created_at,
            "spec_version": self.spec_version,
        }

    def verify_digest(self) -> bool:
        """
        Recompute the content digest and confirm it matches `warrant_digest`.

        A consumer of the audit ledger calls this to confirm the warrant's
        substantive cells have not been altered since minting.
        """
        recomputed = self._digest(
            {
                "primitive": self.primitive,
                "result": self.result,
                "evidence": self.evidence,
                "standard": self.standard,
                "threshold": self.threshold,
                "rejected_thresholds": [r.to_dict() for r in self.rejected_thresholds],
                "spec_version": self.spec_version,
            }
        )
        return recomputed == self.warrant_digest
