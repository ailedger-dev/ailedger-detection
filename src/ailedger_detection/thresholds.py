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

from dataclasses import dataclass
from enum import Enum

from ailedger_detection.warrant import RejectedThreshold


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


_REGISTRY: dict[str, ThresholdStandard] = {
    s.name: s
    for s in (
        DISPARATE_IMPACT,
        STATISTICAL_PARITY,
        DRIFT_NO_DRIFT,
        DRIFT_ACTION,
        UNAUTHORIZED_ACTION,
        CONFIDENCE_STRATIFIED,
        UNRESOLVED_FLAGS,
        REPEATED_DECISIONS,
    )
}


def get_standard(name: str) -> ThresholdStandard:
    """Look up a registered threshold standard by name."""
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(
            f"No registered threshold standard '{name}'. Known: {sorted(_REGISTRY)}"
        ) from None


def _loosens(std: ThresholdStandard, value: float) -> bool:
    """True if `value` is looser than the baseline (the refused direction)."""
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
    """
    std = get_standard(name)

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
    Build the RejectedThreshold set memorialized in a warrant's 2-cell.

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
