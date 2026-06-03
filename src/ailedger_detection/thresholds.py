"""
Standard-anchored threshold registry + anti-theater enforcement.

Every detection threshold in this package is anchored to a published standard
and ships with a baseline value. Per the AILedger Charter v1.1 anti-theater
commitments, a customer may TIGHTEN a threshold (move it toward stricter
detection) but may never LOOSEN it (move it toward suppressing detection). That
commitment is enforced HERE, structurally, not as per-primitive policy: a call
site that passes a looser threshold receives a `ValueError`. The refusal is a
property of the type, not a configuration knob.

This module is the single source of truth for:
  - the baseline value of each threshold,
  - the standard that anchors it,
  - which direction counts as "tighter",
  - and `enforce_tighten_only(...)`, the guard every primitive calls.

It also constructs the `RejectedThreshold` set for a chosen value, so the
warrant (see warrant.py) can memorialize exactly which looser thresholds were
refused and why.

Direction semantics
-------------------
A threshold is either:
  - RAISE_TO_TIGHTEN: a higher value flags more cases. Loosening = going lower.
    (disparate impact ratio: flag when ratio < threshold; raising the bar to
    1.0 catches more disparity.)
  - LOWER_TO_TIGHTEN: a lower value flags more cases. Loosening = going higher.
    (parity difference, PSI drift, unauthorized-action rate: flag when metric
    exceeds the threshold; lowering the bar catches more.)
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from ailedger_detection.warrant import RejectedThreshold

# Float comparisons against a baseline use this relative tolerance so a caller
# who arrives at the baseline by float arithmetic (e.g. 0.1 + 0.7) is not
# spuriously refused for "loosening" the baseline value itself.
_BASELINE_REL_TOL = 1e-9


class TightenDirection(Enum):
    """Which way a threshold must move to detect *more*."""

    RAISE_TO_TIGHTEN = "raise_to_tighten"
    LOWER_TO_TIGHTEN = "lower_to_tighten"


@dataclass(frozen=True)
class ThresholdStandard:
    """A threshold's baseline, anchoring standard, and tighten direction."""

    name: str
    baseline: float
    direction: TightenDirection
    standard: str
    """Published-standard citation that anchors the baseline."""

    lower_bound: float = 0.0
    upper_bound: float = 1.0
    """Absolute range the metric/threshold can occupy (inclusive)."""


# --- The registry: single source of truth for every shipped threshold. -------

DISPARATE_IMPACT = ThresholdStandard(
    name="disparate_impact_ratio",
    baseline=0.80,
    direction=TightenDirection.RAISE_TO_TIGHTEN,
    standard="EEOC Uniform Guidelines four-fifths rule (29 CFR 1607)",
)

STATISTICAL_PARITY = ThresholdStandard(
    name="statistical_parity_difference",
    baseline=0.10,
    direction=TightenDirection.LOWER_TO_TIGHTEN,
    standard="AILedger default (complements EU AI Act Art. 26 deployer obligations)",
)

DRIFT_NO_DRIFT = ThresholdStandard(
    name="model_drift.no_drift",
    baseline=0.10,
    direction=TightenDirection.LOWER_TO_TIGHTEN,
    standard="FDIC SR 11-7 / OCC 2011-12 PSI ladder",
)

DRIFT_ACTION = ThresholdStandard(
    name="model_drift.action",
    baseline=0.25,
    direction=TightenDirection.LOWER_TO_TIGHTEN,
    standard="FDIC SR 11-7 / OCC 2011-12 PSI ladder",
)

UNAUTHORIZED_ACTION = ThresholdStandard(
    name="tool_call_unauthorized_action_rate",
    baseline=0.0,
    direction=TightenDirection.LOWER_TO_TIGHTEN,
    standard="FDIC SR 11-7 / OCC 2011-12 model-outside-scope; EU AI Act Art. 14",
)

CONFIDENCE_STRATIFIED = ThresholdStandard(
    name="confidence_stratified_outcome_analysis",
    baseline=0.80,
    direction=TightenDirection.RAISE_TO_TIGHTEN,
    standard="EEOC four-fifths rule (29 CFR 1607), applied per confidence stratum",
)

UNRESOLVED_FLAGS = ThresholdStandard(
    name="unresolved_flag_accumulation",
    baseline=0.0,
    direction=TightenDirection.LOWER_TO_TIGHTEN,
    standard="EU AI Act Art. 14 human oversight; NIST AI RMF GOVERN-1.5",
)

REPEATED_DECISIONS = ThresholdStandard(
    name="subject_repeated_decision_patterns",
    baseline=3.0,
    direction=TightenDirection.LOWER_TO_TIGHTEN,
    standard="AILedger default (pattern-of-practice, cf. Federal Rule 707)",
    lower_bound=1.0,
    upper_bound=float("inf"),
)


# The canonical standards, sourced from the module-level frozen constants above.
# These constants are the single source of truth; the baseline of every shipped
# threshold is fixed here at import and nowhere else.
_CANONICAL_STANDARDS: tuple[ThresholdStandard, ...] = (
    DISPARATE_IMPACT,
    STATISTICAL_PARITY,
    DRIFT_NO_DRIFT,
    DRIFT_ACTION,
    UNAUTHORIZED_ACTION,
    CONFIDENCE_STRATIFIED,
    UNRESOLVED_FLAGS,
    REPEATED_DECISIONS,
)

# Sealed registry. `MappingProxyType` makes it read-only: `_REGISTRY[k] = ...`
# raises `TypeError`, so the F1 "monkeypatch the baseline" attack cannot mutate
# an entry in place. The baselines live in the frozen `ThresholdStandard`
# constants above, which cannot be rebound to loosen a value.
_REGISTRY: MappingProxyType[str, ThresholdStandard] = MappingProxyType(
    {s.name: s for s in _CANONICAL_STANDARDS}
)


class RegistryIntegrityError(RuntimeError):
    """
    Raised when the live threshold registry no longer matches the baseline set
    sealed at import.

    This fails detection CLOSED: if anyone reaches past the read-only proxy to
    rebind the module-level `_REGISTRY` (or otherwise alter the baseline set),
    no threshold can be validated and no warrant can be minted on the tampered
    registry — the tamper surfaces as an error instead of a silently loosened
    detection.
    """


def _digest_of(standards: tuple[ThresholdStandard, ...]) -> str:
    """Stable content digest over the substantive fields of a standard set."""
    payload = json.dumps(
        sorted(
            [
                {
                    "name": s.name,
                    "baseline": s.baseline,
                    "direction": s.direction.value,
                    "standard": s.standard,
                    "lower_bound": s.lower_bound,
                    "upper_bound": s.upper_bound,
                }
                for s in standards
            ],
            key=lambda d: d["name"],
        ),
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# The baseline integrity digest, sealed at import from the canonical constants.
# `registry_digest()` recomputes over the *live* registry; a mismatch means the
# registry has been tampered with.
_SEALED_DIGEST: str = _digest_of(_CANONICAL_STANDARDS)


def registry_digest() -> str:
    """
    Content digest over the live threshold registry's baseline set.

    Every warrant records this so an auditor can confirm the run was evaluated
    against the sealed baselines. A value other than the sealed digest means the
    registry was altered after import.
    """
    return _digest_of(tuple(_REGISTRY.values()))


def _verify_integrity() -> None:
    """Fail closed if the live registry diverges from the sealed baseline set."""
    if registry_digest() != _SEALED_DIGEST:
        raise RegistryIntegrityError(
            "Threshold registry integrity check failed: the live baseline set "
            "does not match the values sealed at import. Detection is refused "
            "on a tampered registry (fail-closed). Per AILedger Charter v1.1, "
            "baselines are tighten-only and structurally immutable."
        )


def get_standard(name: str) -> ThresholdStandard:
    """Look up a registered threshold standard by name (integrity-checked)."""
    _verify_integrity()
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(
            f"No registered threshold standard '{name}'. Known: {sorted(_REGISTRY)}"
        ) from None


def _loosens(std: ThresholdStandard, value: float) -> bool:
    """
    True if `value` is looser than the baseline (the refused direction).

    The baseline value itself is never treated as loosening, even when the
    caller computes it via float arithmetic (F10): an `isclose` band around the
    baseline counts as "at the baseline", not below/above it.
    """
    if math.isclose(value, std.baseline, rel_tol=_BASELINE_REL_TOL):
        return False
    if std.direction is TightenDirection.RAISE_TO_TIGHTEN:
        return value < std.baseline
    return value > std.baseline


def enforce_tighten_only(name: str, value: float) -> float:
    """
    Validate a caller-supplied threshold against the Charter tighten-only rule.

    Returns the value unchanged if it is in range AND not looser than the
    standard baseline. Raises `ValueError` otherwise. This is the structural
    anti-theater guard: there is no flag, mode, or per-customer setting that
    bypasses it.

    Args:
        name: Registered threshold name.
        value: Caller-supplied threshold.

    Returns:
        `value`, validated.

    Raises:
        ValueError: If `value` is out of the standard's absolute range, or if it
            loosens detection relative to the baseline.
        RegistryIntegrityError: If the registry was tampered with after import.
    """
    std = get_standard(name)  # integrity-checked

    if not (std.lower_bound <= value <= std.upper_bound):
        raise ValueError(
            f"{name}: threshold {value} out of range [{std.lower_bound}, {std.upper_bound}]"
        )

    if _loosens(std, value):
        direction = (
            "at or above" if std.direction is TightenDirection.RAISE_TO_TIGHTEN else "at or below"
        )
        raise ValueError(
            f"{name}: threshold {value} LOOSENS detection below the "
            f"{std.standard} baseline of {std.baseline}. Per AILedger Charter "
            f"v1.1, customers tighten ({direction} {std.baseline}), never "
            f"loosen. This refusal is structural, not policy."
        )

    return value


def rejected_thresholds_for(name: str, chosen: float) -> tuple[RejectedThreshold, ...]:
    """
    Build the RejectedThreshold set memorialized in a warrant.

    Describes the looser-than-chosen region the Charter refuses, anchored to the
    standard — the "chose this rather than that, because…" half of the warrant.

    Args:
        name: Registered threshold name.
        chosen: The threshold actually used for the run.

    Returns:
        A tuple of RejectedThreshold (one entry describing the refused region).
    """
    std = get_standard(name)
    if std.direction is TightenDirection.RAISE_TO_TIGHTEN:
        region = f"< {chosen}"
    else:
        region = f"> {chosen}"
    return (
        RejectedThreshold(
            value=region,
            reason=(
                f"would loosen detection past the {std.standard} "
                f"baseline ({std.baseline}); refused per Charter v1.1 "
                f"(tighten, never loosen)"
            ),
        ),
    )
