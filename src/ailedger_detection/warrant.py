"""
Warrant — the audit spine of the Detection layer.

The warrant embodies the accountable-reckoning principle: *every decision is
memorialized with its warrant.* In the Detection layer that principle is
structural — every detection run produces a WARRANTED result, not a bare boolean.

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
adversarial reviewers, and it is the artifact the Grafana monitor consumes.

Soundness is enforced, not assumed. `Warrant.build` refuses to mint a warrant
that does not actually justify its decision: a detection warrant must carry a
non-empty `standard` and at least one `rejected_thresholds` entry, or it must
explicitly record `no_looser_alternative=True`. An empty justification is
unrepresentable, not merely discouraged. The decision cell (`flagged`) is also
required: a warrant with no recorded decision fails closed at build time rather
than reading as "not flagged".

What the digest is — and is NOT. The `warrant_digest` is a *content* hash over
the substantive cells (result + evidence + rejected thresholds + standard +
threshold + registry digest), deliberately excluding the wall-clock
`created_at`. Its job is DETERMINISM: two runs of the same detection over the
same evidence produce the same digest, so a verifier can re-run a detection and
re-derive the identical digest. By default it is unkeyed (`hashlib.sha256`),
which makes it a CONSISTENCY check, not tamper-evidence: anyone can recompute an
unkeyed digest. Tamper-evidence is the job of the append-only DB hash-chain that
consumes these warrants (and of `prev_digest` run-chaining in `engine.py`). For
standalone tamper-evidence, pass a `signing_key` to `build()` / `verify_digest()`
to key the digest with HMAC-SHA256.

This module is a pure leaf: it has no dependency on any primitive. Result
classes import `Warrant`/`RejectedThreshold` and expose a `to_warrant()`; the
threshold registry imports `RejectedThreshold` to describe what each standard
refuses, and passes its sealed `registry_digest` into each warrant.
"""

from __future__ import annotations

import hashlib
import hmac
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
    """Content hash over the substantive cells (excludes created_at).
    Deterministic. HMAC-keyed iff `keyed` is True; otherwise a consistency
    check, not tamper-evidence (see module docstring)."""

    created_at: str
    """RFC3339 UTC timestamp the warrant was minted. Metadata, not hashed."""

    registry_digest: str = field(default="")
    """Digest of the threshold registry baselines the run was evaluated against
    (from thresholds.registry_digest()). Lets an auditor confirm the sealed
    baselines were in force; a divergent value flags a tampered registry."""

    no_looser_alternative: bool = field(default=False)
    """Explicit, recorded sentinel: this decision had no looser alternative to
    refuse (so an empty `rejected_thresholds` is sound, not an empty
    justification). Required when `rejected_thresholds` is empty."""

    keyed: bool = field(default=False)
    """True iff `warrant_digest` is an HMAC keyed with a signing key (genuine
    tamper-evidence). False = unkeyed SHA-256 (consistency check only)."""

    spec_version: int = field(default=1)
    """Warrant schema version, for forward compatibility of the audit ledger."""

    @staticmethod
    def _canonical(payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def _digest(cls, payload: dict[str, Any], *, signing_key: bytes | None = None) -> str:
        canonical = cls._canonical(payload)
        if signing_key is not None:
            return hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
        return hashlib.sha256(canonical).hexdigest()

    def _digest_payload(self) -> dict[str, Any]:
        """The substantive cells the digest commits to (excludes created_at)."""
        return {
            "primitive": self.primitive,
            "result": self.result,
            "evidence": self.evidence,
            "standard": self.standard,
            "threshold": self.threshold,
            "rejected_thresholds": [r.to_dict() for r in self.rejected_thresholds],
            "registry_digest": self.registry_digest,
            "no_looser_alternative": self.no_looser_alternative,
            "keyed": self.keyed,
            "spec_version": self.spec_version,
        }

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
        registry_digest: str = "",
        no_looser_alternative: bool = False,
        signing_key: bytes | None = None,
        spec_version: int = 1,
    ) -> Warrant:
        """
        Mint a warrant, computing its content digest.

        Soundness is enforced here (F3/F5): the warrant must record a decision
        and must actually justify it.

        Args:
            primitive: Name of the detection primitive.
            result: The decision dict (must be JSON-serializable). MUST contain
                a `flagged` key — a warrant with no recorded decision is refused
                (fail-closed), never read as "not flagged".
            evidence: The grounding evidence dict (must be JSON-serializable).
            standard: Anchoring standard citation. Must be non-empty for a sound
                detection warrant.
            threshold: The threshold the decision was made against.
            rejected_thresholds: Looser thresholds refused, with reasons. Must be
                non-empty unless `no_looser_alternative` is True.
            created_at: RFC3339 UTC timestamp. Defaults to now(UTC). Pass an
                explicit value for deterministic tests / replay.
            registry_digest: Sealed threshold-registry digest in force for the run.
            no_looser_alternative: Set True (and recorded) only when the decision
                genuinely has no looser alternative to refuse, making an empty
                `rejected_thresholds` sound rather than empty justification.
            signing_key: If provided, key the digest with HMAC-SHA256 for genuine
                tamper-evidence. If None, the digest is an unkeyed consistency
                check (see module docstring).
            spec_version: Warrant schema version.

        Returns:
            A frozen Warrant with `warrant_digest` populated.

        Raises:
            ValueError: If `result` lacks a `flagged` cell, or the warrant is not
                sound (empty `standard`, or empty `rejected_thresholds` without
                the `no_looser_alternative` sentinel).
        """
        if "flagged" not in result:
            raise ValueError(
                f"{primitive}: warrant result must record a 'flagged' decision "
                f"(fail-closed); got keys {sorted(result)}"
            )
        if not standard:
            raise ValueError(
                f"{primitive}: a detection warrant must cite a non-empty standard "
                f"(an empty justification is not a sound warrant)"
            )
        if not rejected_thresholds and not no_looser_alternative:
            raise ValueError(
                f"{primitive}: a detection warrant must refuse at least one looser "
                f"threshold, or explicitly record no_looser_alternative=True "
                f"(an empty 2-sided justification is not a sound warrant)"
            )

        if created_at is None:
            created_at = datetime.now(timezone.utc).isoformat()

        digest_payload = {
            "primitive": primitive,
            "result": result,
            "evidence": evidence,
            "standard": standard,
            "threshold": threshold,
            "rejected_thresholds": [r.to_dict() for r in rejected_thresholds],
            "registry_digest": registry_digest,
            "no_looser_alternative": no_looser_alternative,
            "keyed": signing_key is not None,
            "spec_version": spec_version,
        }
        return cls(
            primitive=primitive,
            result=result,
            evidence=evidence,
            standard=standard,
            threshold=threshold,
            rejected_thresholds=tuple(rejected_thresholds),
            warrant_digest=cls._digest(digest_payload, signing_key=signing_key),
            created_at=created_at,
            registry_digest=registry_digest,
            no_looser_alternative=no_looser_alternative,
            keyed=signing_key is not None,
            spec_version=spec_version,
        )

    @property
    def flagged(self) -> bool:
        """
        Did the underlying decision flag?

        Reads the decision cell directly (fail-closed): a warrant minted via
        `build` always has it, and a malformed warrant raises `KeyError` rather
        than silently reading as "not flagged".
        """
        return bool(self.result["flagged"])

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
            "registry_digest": self.registry_digest,
            "no_looser_alternative": self.no_looser_alternative,
            "keyed": self.keyed,
            "spec_version": self.spec_version,
        }

    def verify_digest(self, *, signing_key: bytes | None = None) -> bool:
        """
        Recompute the content digest and confirm it matches `warrant_digest`.

        This is a CONSISTENCY check: it confirms the substantive cells are
        internally consistent with the recorded digest. For an unkeyed warrant
        (`keyed` False) that is not tamper-evidence — an adversary who alters a
        cell can recompute the unkeyed digest the same public way. Genuine
        tamper-evidence requires the HMAC path: mint with a `signing_key` and
        verify with the same key (and `keyed` must be True).

        Args:
            signing_key: HMAC key for a keyed warrant. Required iff `keyed` is
                True; rejected if `keyed` is False (the schemes must match).

        Returns:
            True iff the digest recomputes to the recorded value under the
            matching scheme.
        """
        if self.keyed and signing_key is None:
            return False
        if not self.keyed and signing_key is not None:
            return False
        recomputed = self._digest(self._digest_payload(), signing_key=signing_key)
        return hmac.compare_digest(recomputed, self.warrant_digest)
