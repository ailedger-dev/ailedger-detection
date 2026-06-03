"""
Warranted Decisions — the LARP audit-spine layer over detection results.

AILedger's product is not the answer; it is the *warranted* answer. Every
detection result is wrapped as a Decision that carries its own justification:
the published standard it was judged against, the observed value, the outcome,
and the alternatives that were considered and rejected. The log of warranted
Decisions is the artifact a regulator or Federal Rule 707 expert audits.

Categorically (the (∞,1) framing in the AILedger posture): a Decision is a
1-cell and the warrant — standard, observed value, and rejected alternatives —
is the 2-cell that justifies the morphism. A bare result without its warrant is
a 1-cell with no 2-cell: not auditable, not admissible.

Anti-theater (Charter v1.1), enforced structurally:

- A warrant's `flagged` is read directly off the underlying detection result.
  There is no parameter to override it, so a warrant can never claim "clean"
  over a result that flagged. `WarrantedDecision.__post_init__` re-checks this
  invariant and refuses to construct an inconsistent record.
- Wrapping is the only way to emit a Decision; you cannot drop a flagged result
  on the floor and still produce a warranted log entry.

This module composes over every detection primitive's `*Result` dataclass; it
adds no new statistics, only the justification scaffold that makes the existing
results audit-grade.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Default Charter clause cited by a warrant when the caller does not supply one.
DEFAULT_CHARTER_CLAUSE: str = (
    "AILedger Charter v1.1 — detection thresholds anchored to published "
    "standards; customers tighten, never loosen; detection disablement refused."
)

# Maps a detection *Result class name to (published standard, observed-value
# attribute). A None value attribute means the result has no single scalar
# headline value (it reports per-bucket / per-subject detail instead).
_STANDARD_REGISTRY: dict[str, tuple[str, str | None]] = {
    "DisparateImpactResult": (
        "EEOC Uniform Guidelines four-fifths rule (29 CFR 1607)",
        "ratio",
    ),
    "StatisticalParityResult": (
        "Statistical parity difference (Caton & Haas 2024; EU AI Act Art. 26)",
        "spd",
    ),
    "ModelDriftResult": (
        "Population Stability Index ladder (FDIC SR 11-7 / OCC 2011-12)",
        "psi",
    ),
    "UnauthorizedToolCallResult": (
        "Model-outside-scope (FDIC SR 11-7) / human oversight (EU AI Act Art. 14)",
        "rate",
    ),
    "ConfidenceStratifiedResult": (
        "EEOC four-fifths rule, confidence-stratified (29 CFR 1607)",
        None,
    ),
    "UnresolvedFlagResult": (
        "Unresolved required-action gap (EU AI Act Art. 14 human oversight)",
        "rate",
    ),
    "RepeatedDecisionResult": (
        "Subject repeated-decision pattern (disparate treatment; Fed. R. Evid. 707)",
        None,
    ),
}


@dataclass(frozen=True)
class Warrant:
    """The 2-cell justifying a detection Decision.

    A warrant cites the standard the result was judged against, the value that
    was observed, the outcome, and the alternatives that were considered and
    rejected. It is the audit-grade rationale, not the statistic itself.
    """

    standard: str
    """The published standard the detection threshold derives from."""

    observed_value: float | None
    """The headline scalar observed (e.g. disparate impact ratio, PSI). None
    for primitives whose signal is per-bucket / per-subject rather than scalar."""

    threshold: float | None
    """The threshold the observed value was compared against, when the result
    exposes a single one. None for ladder/count-based results."""

    flagged: bool
    """Outcome, copied verbatim from the underlying result. Never overridable."""

    rejected_alternatives: tuple[str, ...]
    """The alternatives considered and why they were rejected (the 2-cell
    content). Empty is allowed but discouraged — an empty tuple is an
    unjustified morphism."""

    charter_clause: str
    """The Charter clause this Decision was screened against."""


@dataclass(frozen=True)
class WarrantedDecision:
    """A detection Decision (1-cell) bound to its warrant (2-cell).

    Constructing one is the only sanctioned way to emit a Decision from a
    detection result. The post-init invariant refuses any record whose warrant
    contradicts the result it wraps — suppression is impossible by construction.
    """

    decision_id: str
    primitive: str
    """Name of the detection primitive's result class (the 1-cell's type)."""

    result: Any
    """The underlying detection *Result dataclass instance."""

    warrant: Warrant

    def __post_init__(self) -> None:
        result_flagged = getattr(self.result, "flagged", None)
        if not isinstance(result_flagged, bool):
            raise TypeError(
                f"result of type {type(self.result).__name__} has no boolean "
                f"'flagged' attribute; cannot warrant a non-detection result"
            )
        if self.warrant.flagged != result_flagged:
            raise ValueError(
                "warrant.flagged contradicts result.flagged "
                f"({self.warrant.flagged} != {result_flagged}); suppressing a "
                "flagged Decision is refused at the schema level (Charter v1.1)"
            )


def warrant_detection_result(
    result: Any,
    *,
    decision_id: str,
    rejected_alternatives: tuple[str, ...] = (),
    charter_clause: str = DEFAULT_CHARTER_CLAUSE,
) -> WarrantedDecision:
    """
    Wrap a detection result as a warranted Decision.

    The outcome (`flagged`), observed value, and threshold are read directly off
    the result — the caller supplies only the justification context (the
    rejected alternatives and, optionally, the Charter clause). There is
    deliberately no way to override the outcome: a flagged result always
    produces a flagged Decision.

    Args:
        result: A detection *Result dataclass instance (e.g.
            DisparateImpactResult). Must expose a boolean `flagged`.
        decision_id: Stable identifier for this Decision (the 1-cell id).
        rejected_alternatives: Alternatives considered and rejected, with their
            reasons (the 2-cell content). Strongly recommended for audit value.
        charter_clause: The Charter clause screened against. Defaults to the
            v1.1 anti-theater clause.

    Returns:
        A WarrantedDecision binding the result to its warrant.

    Raises:
        TypeError: If `result` is not a recognized detection result type, or
            lacks a boolean `flagged` attribute.
    """
    name = type(result).__name__
    if name not in _STANDARD_REGISTRY:
        raise TypeError(
            f"{name} is not a recognized detection result type; "
            f"known types: {sorted(_STANDARD_REGISTRY)}"
        )

    standard, value_attr = _STANDARD_REGISTRY[name]
    observed_value = getattr(result, value_attr) if value_attr is not None else None
    threshold = getattr(result, "threshold", None)

    flagged = getattr(result, "flagged", None)
    if not isinstance(flagged, bool):
        raise TypeError(
            f"result of type {name} has no boolean 'flagged' attribute"
        )

    warrant = Warrant(
        standard=standard,
        observed_value=observed_value,
        threshold=threshold,
        flagged=flagged,
        rejected_alternatives=tuple(rejected_alternatives),
        charter_clause=charter_clause,
    )
    return WarrantedDecision(
        decision_id=decision_id,
        primitive=name,
        result=result,
        warrant=warrant,
    )
