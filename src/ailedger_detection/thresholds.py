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
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

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


# The canonical standards, in registration order. This tuple is the sealed
# source of truth: the immutability the tighten-only guarantee needs is enforced
# here, not asserted in a docstring.
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

# The registry is a read-only view: `_REGISTRY["x"] = ...` raises TypeError, so
# the documented one-line monkeypatch that loosened every primitive is gone. The
# entries are frozen dataclasses, so their fields cannot be rebound either.
_REGISTRY: Mapping[str, ThresholdStandard] = MappingProxyType(
    {s.name: s for s in _CANONICAL_STANDARDS}
)


def _fingerprint(standards: Iterable[ThresholdStandard]) -> str:
    """Stable content hash over a set of standards' load-bearing fields."""
    payload = sorted(
        [s.name, s.baseline, s.direction.value, s.standard, s.lower_bound, s.upper_bound]
        for s in standards
    )
    canonical = json.dumps(payload, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# An independent witness of the canonical baselines, computed once at import from
# the constant tuple (NOT read back through `_REGISTRY`). A run records the live
# registry digest against this; any drift is visible in the audit record even if
# someone reaches past the mapping's read-only type to rebind the module global.
CANONICAL_REGISTRY_DIGEST: str = _fingerprint(_CANONICAL_STANDARDS)

# Sealed per-standard baselines captured at import as plain immutable tuples,
# unreachable through `_REGISTRY`. `enforce_tighten_only` validates against THIS,
# so the guarantee holds even if the registry mapping is swapped out wholesale.
_SEALED_BASELINES: Mapping[str, tuple[float, str, float, float]] = MappingProxyType(
    {
        s.name: (s.baseline, s.direction.value, s.lower_bound, s.upper_bound)
        for s in _CANONICAL_STANDARDS
    }
)


# --- Sealed anti-theater floors (not caller-tunable; see F2/F6 hardening). ----

MIN_EVALUABLE_GROUP_SIZE: int = 5
"""Minimum per-group sample below which a fairness ratio/difference is recorded
as ``evaluable=False`` rather than ``flagged``. Sealed, not a caller parameter:
*raising* a sample floor suppresses detection (a loosening surface), so the floor
is fixed structurally. EEOC Uniform Guidelines caution the four-fifths rule
against small samples; this is the minimal floor that refuses N=1/N=2 theater
while leaving real cohorts evaluable. Callers wanting stricter detection tighten
the threshold, not this floor."""

MIN_LABEL_COVERAGE: float = 0.80
"""Minimum fraction of a cohort that must carry the protected-class label for a
fairness result to be considered well-covered. Below this the warrant records a
``low_coverage`` warning and the dropped count — the missing labels are counted
and surfaced, never silently dropped (F2). Sealed for the same reason as above."""


def registry_digest() -> str:
    """Content digest of the *live* registry — recorded in each run for audit."""
    return _fingerprint(_REGISTRY.values())


def verify_registry_integrity() -> bool:
    """True if the live registry still matches the sealed canonical baselines."""
    return registry_digest() == CANONICAL_REGISTRY_DIGEST


def get_standard(name: str) -> ThresholdStandard:
    """Look up a registered threshold standard by name."""
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(
            f"No registered threshold standard '{name}'. Known: {sorted(_REGISTRY)}"
        ) from None


def _loosens(std: ThresholdStandard, value: float) -> bool:
    """True if `value` is looser than the baseline (the refused direction).

    A value equal to the baseline within float tolerance is NOT loosening: a
    caller who computes the baseline by arithmetic (e.g. ``0.1 + 0.7`` →
    ``0.7999999999999999``) means the baseline and must not be spuriously refused
    for floating-point error (F10).
    """
    if math.isclose(value, std.baseline, rel_tol=1e-9, abs_tol=1e-12):
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

    The guard validates against the *sealed* canonical baseline, not the live
    registry entry, so loosening the registry (even by reaching past its
    read-only type) cannot weaken the check — it is refused as an integrity
    violation instead.

    Args:
        name: Registered threshold name.
        value: Caller-supplied threshold.

    Returns:
        `value`, validated.

    Raises:
        ValueError: If `value` is out of the standard's absolute range, if it
            loosens detection relative to the baseline, or if the registry's
            baseline for `name` has been altered from the sealed canonical value.
    """
    std = get_standard(name)

    sealed = _SEALED_BASELINES.get(name)
    live = (std.baseline, std.direction.value, std.lower_bound, std.upper_bound)
    if sealed is None or live != sealed:
        raise ValueError(
            f"{name}: threshold registry integrity violation — the standard's "
            f"baseline/direction has been altered from its sealed canonical value. "
            f"The tighten-only guarantee is enforced against the sealed standard, "
            f"not a mutated registry; refusing rather than detecting under a "
            f"loosened baseline. This refusal is structural, not policy."
        )

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
