"""
Disparate impact ratio — four-fifths-rule baseline detection primitive.

The four-fifths rule (also known as the 80% rule) is a U.S. EEOC Uniform
Guidelines (29 CFR 1607) heuristic: a selection rate for any race, sex, or
ethnic group that is less than four-fifths (4/5 = 0.8) of the rate for the
group with the highest rate is generally regarded as evidence of adverse impact.

This module computes the disparate impact ratio over a population of Detection
Events filtered by a positive-outcome predicate, partitioned by a
protected-class label, and returns the minimum cross-group ratio plus the
group pair that yielded it.

Threshold convention: AILedger ships with the EEOC four-fifths-rule threshold
of 0.8 as the default. Per Charter v1.1, customers tighten (raise the threshold
toward 1.0), never loosen.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from ailedger_detection.thresholds import (
    enforce_tighten_only,
    get_standard,
    registry_digest,
    rejected_thresholds_for,
)
from ailedger_detection.warrant import Warrant

# EEOC Uniform Guidelines four-fifths-rule baseline. Customers tighten, never loosen.
FOUR_FIFTHS_BASELINE: float = 0.8

_PRIMITIVE = "disparate_impact_ratio"


def _predicate_identity(fn: Callable[[dict[str, Any]], bool]) -> str:
    """A stable, recordable identity for a caller-supplied predicate."""
    name = getattr(fn, "__qualname__", None) or getattr(fn, "__name__", None)
    module = getattr(fn, "__module__", None)
    if name:
        return f"{module}.{name}" if module else name
    return repr(fn)


@dataclass(frozen=True)
class DisparateImpactResult:
    """Result of a disparate-impact-ratio calculation."""

    ratio: float
    """Minimum cross-group ratio (group_low_rate / group_high_rate). 0 to 1."""

    threshold: float
    """Threshold below which adverse impact is flagged. Default FOUR_FIFTHS_BASELINE."""

    flagged: bool
    """True if evaluable and ratio < threshold (adverse impact indicated)."""

    evaluable: bool
    """True if ≥2 groups met `min_group_size` so a ratio is defined. When False
    the sample was too small to evaluate and `flagged` is False (not a
    false-positive on a trivial sample)."""

    high_group: str
    """Protected-class label with the highest positive-outcome rate."""

    high_rate: float
    """Positive-outcome rate for high_group."""

    low_group: str
    """Protected-class label with the lowest positive-outcome rate."""

    low_rate: float
    """Positive-outcome rate for low_group."""

    group_stats: dict[str, tuple[int, int]]
    """Per-group (positive_count, total_count) for full inspectability."""

    total_events: int
    """Total events seen in the cohort."""

    skipped_no_group: int
    """Events dropped because they carried no protected-class label. Counted and
    recorded — never silently suppressed (the F2 loosening surface)."""

    skipped_small_group: int
    """Groups excluded from the ratio because they fell below `min_group_size`."""

    coverage: float
    """Fraction of the cohort that carried a usable protected-class label."""

    coverage_flagged: bool
    """True if `coverage` fell below the caller's `min_coverage` guard — a
    recorded signal that detection ran on a thinly-labeled cohort."""

    protected_class_key: str
    """The class key the cohort was partitioned on (recorded so an auditor sees
    *which definition* produced the number)."""

    predicate_identity: str
    """Identity of the positive-outcome predicate (recorded for the same reason
    — the predicate is the real loosening surface, not the threshold)."""

    def to_warrant(self, *, created_at: str | None = None) -> Warrant:
        """Memorialize this result as a warrant."""
        std = get_standard(_PRIMITIVE)
        return Warrant.build(
            primitive=_PRIMITIVE,
            result={
                "flagged": self.flagged,
                "metric": "disparate_impact_ratio",
                "value": self.ratio,
                "evaluable": self.evaluable,
                "coverage_flagged": self.coverage_flagged,
                "high_group": self.high_group,
                "low_group": self.low_group,
            },
            evidence={
                "high_rate": self.high_rate,
                "low_rate": self.low_rate,
                "group_stats": {k: list(v) for k, v in self.group_stats.items()},
                "total_events": self.total_events,
                "skipped_no_group": self.skipped_no_group,
                "skipped_small_group": self.skipped_small_group,
                "coverage": self.coverage,
                "protected_class_key": self.protected_class_key,
                "predicate_identity": self.predicate_identity,
            },
            standard=std.standard,
            threshold=self.threshold,
            rejected_thresholds=rejected_thresholds_for(_PRIMITIVE, self.threshold),
            registry_digest=registry_digest(),
            created_at=created_at,
        )


def disparate_impact_ratio(
    events: Iterable[dict[str, Any]],
    *,
    protected_class_key: str,
    positive_outcome_predicate: Callable[[dict[str, Any]], bool],
    threshold: float = FOUR_FIFTHS_BASELINE,
    min_group_size: int = 1,
    min_coverage: float = 0.0,
) -> DisparateImpactResult:
    """
    Compute the disparate impact ratio across protected-class groups.

    The caller-supplied `positive_outcome_predicate` and `protected_class_key`
    are the real loosening surface (F2): an event missing the class label is not
    silently dropped — it is COUNTED (`skipped_no_group`), the coverage is
    recorded, and the predicate/key identity is memorialized in the warrant, so
    an auditor can see *what definition* produced the number and how much of the
    cohort it silently excluded.

    Args:
        events: An iterable of Detection Event records (dicts). Each record
            must carry a protected-class label at the key specified by
            protected_class_key.
        protected_class_key: The key inside each event used to extract the
            protected-class label. Typically a key inside the
            `protected_class_context` JSONB (e.g. "race", "sex", "ancestry").
        positive_outcome_predicate: A callable that, given an event, returns
            True if the event represents a positive outcome (e.g. hired,
            approved, diagnosed positive). The predicate is the
            decision-domain-specific positive-outcome definition.
        threshold: Threshold below which adverse impact is flagged. Default
            is the four-fifths-rule baseline (0.8). Customers tighten, never
            loosen.
        min_group_size: Minimum per-group event count for a group to enter the
            ratio (F6). Groups below it are excluded and counted in
            `skipped_small_group`; if fewer than two groups remain the result is
            `evaluable=False` (not a false-positive on a trivial sample).
        min_coverage: If > 0, the fraction of the cohort that must carry the
            class label; below it the result records `coverage_flagged=True`
            (the under-coverage is surfaced, not silently dropped).

    Returns:
        A DisparateImpactResult with the minimum cross-group ratio, the
        high-rate and low-rate groups, full per-group stats, and the
        drop/coverage accounting.

    Raises:
        ValueError: If the event stream contains fewer than two distinct
            protected-class groups (a single-group ratio is undefined).
        ValueError: If threshold is out of range or LOOSENS detection below the
            four-fifths baseline (0.8). Per Charter v1.1 the refusal is
            structural: customers tighten (raise toward 1.0), never loosen.

    Example:
        >>> events = [
        ...     {"protected_class_context": {"race": "A"}, "output": {"decision": "hire"}},
        ...     {"protected_class_context": {"race": "A"}, "output": {"decision": "no"}},
        ...     {"protected_class_context": {"race": "B"}, "output": {"decision": "no"}},
        ...     {"protected_class_context": {"race": "B"}, "output": {"decision": "no"}},
        ... ]
        >>> result = disparate_impact_ratio(
        ...     events,
        ...     protected_class_key="race",
        ...     positive_outcome_predicate=lambda e: e["output"]["decision"] == "hire",
        ... )
        >>> result.flagged  # 0/2 < 0.8 * 1/2 → adverse impact flagged
        True
    """
    threshold = enforce_tighten_only(_PRIMITIVE, threshold)

    group_stats: dict[str, list[int]] = {}
    total_events = 0
    skipped_no_group = 0

    for event in events:
        total_events += 1
        # Extract the protected-class label. Look inside protected_class_context
        # first (typical AILedger Detection Event shape), then fall back to
        # top-level (allows the primitive to work with arbitrary dict shapes).
        ctx = event.get("protected_class_context")
        if isinstance(ctx, dict) and protected_class_key in ctx:
            label = ctx[protected_class_key]
        elif protected_class_key in event:
            label = event[protected_class_key]
        else:
            # No label for this dimension: count it, never silently suppress.
            skipped_no_group += 1
            continue

        label_str = str(label)
        if label_str not in group_stats:
            group_stats[label_str] = [0, 0]
        if positive_outcome_predicate(event):
            group_stats[label_str][0] += 1
        group_stats[label_str][1] += 1

    if len(group_stats) < 2:
        raise ValueError(
            f"At least two distinct protected-class groups required for "
            f"disparate impact analysis; found {len(group_stats)} "
            f"({list(group_stats.keys()) if group_stats else 'none'})"
        )

    labeled = total_events - skipped_no_group
    coverage = (labeled / total_events) if total_events else 1.0
    coverage_flagged = min_coverage > 0.0 and coverage < min_coverage

    # F6 min-sample gate: only groups meeting min_group_size enter the ratio.
    rates: dict[str, float] = {}
    skipped_small_group = 0
    for label, (positive, total) in group_stats.items():
        if total < min_group_size:
            skipped_small_group += 1
            continue
        rates[label] = positive / total

    evaluable = len(rates) >= 2
    if not evaluable:
        # Too small to evaluate: do not manufacture a flag from a trivial sample.
        return DisparateImpactResult(
            ratio=1.0,
            threshold=threshold,
            flagged=False,
            evaluable=False,
            high_group="",
            high_rate=0.0,
            low_group="",
            low_rate=0.0,
            group_stats={k: (v[0], v[1]) for k, v in group_stats.items()},
            total_events=total_events,
            skipped_no_group=skipped_no_group,
            skipped_small_group=skipped_small_group,
            coverage=coverage,
            coverage_flagged=coverage_flagged,
            protected_class_key=protected_class_key,
            predicate_identity=_predicate_identity(positive_outcome_predicate),
        )

    high_group = max(rates, key=lambda k: rates[k])
    low_group = min(rates, key=lambda k: rates[k])
    high_rate = rates[high_group]
    low_rate = rates[low_group]

    # If the highest rate is zero, every group has zero positive outcomes.
    # Define ratio as 1.0 (no disparity) in that degenerate case.
    if high_rate == 0:
        ratio = 1.0
    else:
        ratio = low_rate / high_rate

    return DisparateImpactResult(
        ratio=ratio,
        threshold=threshold,
        flagged=ratio < threshold,
        evaluable=True,
        high_group=high_group,
        high_rate=high_rate,
        low_group=low_group,
        low_rate=low_rate,
        group_stats={k: (v[0], v[1]) for k, v in group_stats.items()},
        total_events=total_events,
        skipped_no_group=skipped_no_group,
        skipped_small_group=skipped_small_group,
        coverage=coverage,
        coverage_flagged=coverage_flagged,
        protected_class_key=protected_class_key,
        predicate_identity=_predicate_identity(positive_outcome_predicate),
    )
