"""
LARP warrant — the audit spine of the Detection layer.

LARP is the Lodestar Accountable Reckoning Principle: *every decision is
memorialized with its warrant.* GUPP says GO; LARP says KNOW. In the Detection
layer that principle is structural — every detection run produces a WARRANTED
result, not a bare boolean.

The (∞,1)-category reading (see docs/n-category-memorialization-formalization):

- The detection **result** is a **1-cell**: a directed, non-invertible decision
  ("flagged" / "not flagged" at this metric value). You cannot un-detect.
- The **warrant** is a **2-cell**: the morphism between the chosen decision and
  the alternatives it was chosen *rather than*. Concretely the 2-cell carries
  two things:
    1. the **evidence** that grounds the 1-cell (the per-group stats, the PSI
       bucket contributions, the per-event diffs — whatever the primitive
       computed), and
    2. the **rejected thresholds** — the looser thresholds that were refused,
       each annotated with *why* (the standard that anchors the chosen value).
  "Chose this 1-cell rather than that one, because…" is exactly a 2-cell.

Recording the 1-cell alone (the bare flag) is strictly weaker than recording
the 2-cell (flag + evidence + rejected alternatives): they live in different
dimensions. A bare flag is topology-memorialization; a warrant is
decision-memorialization. Auditability is completeness — the recorded cells
identify the detection. The warrant is what makes the Detection layer auditable
by customers, regulators, and adversarial reviewers, and it is the artifact the
Interchange (fleet-level federation) and the Grafana LARP monitor consume.

The `warrant_digest` is a content hash over the substantive cells (result +
evidence + rejected thresholds + standard + threshold), deliberately excluding
the wall-clock `created_at`. Two runs of the same detection over the same
evidence therefore produce the same digest: a verifier can re-run a detection
and confirm the warrant's content without trusting the timestamp. This is the
hook for chaining warrants into the append-only audit ledger.

Integrity boundary (read this before relying on the digest for tamper-evidence)
-------------------------------------------------------------------------------
`warrant_digest` is an **unkeyed content hash**: it proves *consistency*
(re-running the same detection yields the same digest, and a field cannot be
mutated without recomputing the digest), but it is **not, by itself,
tamper-evidence against a motivated adversary** — anyone can recompute the
public hash over altered content. Tamper-evidence is delivered by one of two
keyed/chained layers, never by the bare digest:

  1. The append-only DB hash-chain (`hash_chain_prev` / `hash_chain_self` on the
     persisted Detection Event / run), which links record N to record N-1; and
  2. For standalone use, an optional HMAC **signature** over the digest payload
     (`Warrant.build(..., signing_key=...)`), verified with
     `verify_signature(key)`. Without the secret an adversary cannot forge it.

`verify_digest()` is therefore named for what it does — a *consistency* check —
and the docstring no longer claims the unkeyed digest detects motivated tampering.

This module is a pure leaf: it has no dependency on any primitive. Result
classes import `Warrant`/`RejectedThreshold` and expose a `to_warrant()`; the
threshold registry imports `RejectedThreshold` to describe what each standard
refuses.
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

    This is one edge of the warrant's 2-cell: the chosen threshold was chosen
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
    A memorialized detection decision: the 1-cell plus its 2-cell.

    Construct via `Warrant.build(...)` so the digest is computed consistently.
    """

    primitive: str
    """The detection primitive that produced this warrant."""

    result: dict[str, Any]
    """The 1-cell: the decision. Always carries at least `flagged` and the
    metric name + value; primitives may add domain fields (severity, groups)."""

    evidence: dict[str, Any]
    """The 2-cell (grounding half): the stats supporting the 1-cell."""

    standard: str
    """The published standard anchoring the chosen threshold (e.g. EEOC 29 CFR
    1607). Empty string only for primitives with no external anchor."""

    threshold: float
    """The chosen threshold value the decision was made against."""

    rejected_thresholds: tuple[RejectedThreshold, ...]
    """The 2-cell (rejected half): looser thresholds refused, with reasons."""

    warrant_digest: str
    """SHA-256 over the substantive cells (excludes created_at). Deterministic.
    A *consistency* digest, not keyed tamper-evidence — see module docstring."""

    created_at: str
    """RFC3339 UTC timestamp the warrant was minted. Metadata, not hashed."""

    spec_version: int = field(default=1)
    """Warrant schema version, for forward compatibility of the audit ledger."""

    no_looser_alternative: bool = field(default=False)
    """Soundness sentinel: True when the chosen threshold is already the
    strictest representable value, so there is no looser alternative to reject.
    A sound warrant carries either ≥1 rejected threshold OR this sentinel."""

    signature: str | None = field(default=None)
    """Optional HMAC-SHA256 over the digest payload, keyed by a caller secret.
    Present only when `build(..., signing_key=...)` was used. This — not the
    unkeyed `warrant_digest` — is what binds the warrant against forgery."""

    @staticmethod
    def _digest(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _sign(payload: dict[str, Any], key: bytes) -> str:
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

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
        no_looser_alternative: bool = False,
        signing_key: bytes | None = None,
    ) -> Warrant:
        """
        Mint a warrant, enforcing soundness and computing its content digest.

        Soundness (the (∞,1) 2-cell must be non-trivial, not merely present):

        - The `result` MUST carry the `flagged` decision cell. A warrant whose
          decision is absent would *fail open* (read as not-flagged) — the wrong
          default for a safety spine — so it is refused at build time.
        - A detection warrant MUST carry a non-empty `standard` AND either ≥1
          `rejected_thresholds` entry or `no_looser_alternative=True`. An
          empty-standard / empty-rejected "warrant" is an unsound 2-cell (a bare
          flag dressed as a justification) and is unrepresentable, not merely
          discouraged.

        Args:
            primitive: Name of the detection primitive.
            result: The 1-cell decision dict (must be JSON-serializable, must
                contain `flagged`).
            evidence: The grounding evidence dict (must be JSON-serializable).
            standard: Anchoring standard citation (must be non-empty).
            threshold: The threshold the decision was made against.
            rejected_thresholds: Looser thresholds refused, with reasons.
            created_at: RFC3339 UTC timestamp. Defaults to now(UTC). Pass an
                explicit value for deterministic tests / replay.
            spec_version: Warrant schema version.
            no_looser_alternative: Set True to attest the chosen threshold is the
                strictest representable value (an explicit, recorded soundness
                sentinel in lieu of a rejected set).
            signing_key: Optional secret. When provided, an HMAC-SHA256
                `signature` over the digest payload is attached so the warrant is
                forgery-resistant for standalone (non-DB-chained) use.

        Returns:
            A frozen Warrant with `warrant_digest` (and `signature`, if keyed)
            populated.

        Raises:
            ValueError: If the result omits `flagged`, or the warrant is unsound
                (empty standard, or no rejected threshold and no sentinel).
        """
        if "flagged" not in result:
            raise ValueError(
                f"{primitive}: warrant result must record the 'flagged' decision "
                f"cell. A missing decision fails OPEN (reads as not-flagged), the "
                f"wrong default for a safety-critical audit spine. Set it explicitly."
            )
        if not standard:
            raise ValueError(
                f"{primitive}: unsound warrant — a detection warrant must cite a "
                f"non-empty `standard` (the grounds the decision was made against). "
                f"An empty 2-cell is a bare flag dressed as a justification."
            )
        if not rejected_thresholds and not no_looser_alternative:
            raise ValueError(
                f"{primitive}: unsound warrant — a detection warrant must record at "
                f"least one rejected (looser) threshold, or set "
                f"no_looser_alternative=True to attest the chosen value is already "
                f"the strictest representable. 'Chose this rather than that, "
                f"because…' requires a 'that'."
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
            "spec_version": spec_version,
            "no_looser_alternative": no_looser_alternative,
        }
        signature = cls._sign(digest_payload, signing_key) if signing_key is not None else None
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
            no_looser_alternative=no_looser_alternative,
            signature=signature,
        )

    @property
    def flagged(self) -> bool:
        """
        Did the underlying 1-cell flag?

        Reads the `flagged` cell, which `build()` guarantees is present. The
        `.get(..., True)` default is fail-closed defence-in-depth: a warrant
        somehow constructed without the cell reads as flagged, never silently safe.
        """
        return bool(self.result.get("flagged", True))

    def _digest_payload(self) -> dict[str, Any]:
        return {
            "primitive": self.primitive,
            "result": self.result,
            "evidence": self.evidence,
            "standard": self.standard,
            "threshold": self.threshold,
            "rejected_thresholds": [r.to_dict() for r in self.rejected_thresholds],
            "spec_version": self.spec_version,
            "no_looser_alternative": self.no_looser_alternative,
        }

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
            "no_looser_alternative": self.no_looser_alternative,
            "signature": self.signature,
        }

    def verify_digest(self) -> bool:
        """
        Recompute the content digest and confirm it matches `warrant_digest`.

        This is a **consistency** check: it confirms the substantive cells have
        not been altered *without recomputing the digest* (accidental corruption,
        a dropped field, a replay mismatch). It is NOT tamper-evidence against a
        motivated adversary, who can recompute the public unkeyed hash over
        altered content — for that, use `verify_signature` (keyed) or the DB
        hash-chain. See the module docstring's integrity boundary.
        """
        return self._digest(self._digest_payload()) == self.warrant_digest

    def verify_signature(self, key: bytes) -> bool:
        """
        Verify the HMAC `signature` against `key` in constant time.

        Returns False if the warrant was not signed, or if the signature does
        not match the digest payload under `key`. This is the keyed, forgery-
        resistant check: without the secret an adversary cannot mint a matching
        signature over altered content.
        """
        if self.signature is None:
            return False
        expected = self._sign(self._digest_payload(), key)
        return hmac.compare_digest(expected, self.signature)
