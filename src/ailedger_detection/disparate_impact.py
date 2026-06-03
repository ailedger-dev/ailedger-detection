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

from ailedger_detection._coverage import callable_identity, extract_label
from ailedger_detection.thresholds import (
    MIN_EVALUABLE_GROUP_SIZE,
    MIN_LABEL_COVERAGE,
    enforce_tighten_only,
    get_standard,
    rejected_thresholds_for,
)
from ailedger_detection.warrant import Warrant

# EEOC Uniform Guidelines four-fifths-rule baseline. Customers tighten, never loosen.
FOUR_FIFTHS_BASELINE: float = 0.8

_PRIMITIVE = "disparate_impact_ratio"


@dataclass(frozen=True)
class DisparateImpactResult:
    """Result of a disparate-impact-ratio calculation."""

    ratio: float | None
    """Minimum cross-group ratio (group_low_rate / group_high_rate), 0 to 1, over
    the groups that met the minimum sample size. None when not `evaluable`."""

    threshold: float
    """Threshold below which adverse impact is flagged. Default FOUR_FIFTHS_BASELINE."""

    flagged: bool
    """True if `evaluable` and ratio < threshold (adverse impact indicated)."""

    evaluable: bool
    """True if ≥2 groups met the sealed minimum sample size, so a ratio is
    defined. A trivially small cohort is recorded `evaluable=False` rather than
    flagged — no four-fifths false-positive theater on N=1/N=2 (F6)."""

    high_group: str
    """Protected-class label with the highest positive-outcome rate ("" if not evaluable)."""

    high_rate: float
    """Positive-outcome rate for high_group (0.0 if not evaluable)."""

    low_group: str
    """Protected-class label with the lowest positive-outcome rate ("" if not evaluable)."""

    low_rate: float
    """Positive-outcome rate for low_group (0.0 if not evaluable)."""

    group_stats: dict[str, tuple[int, int]]
    """Per-group (positive_count, total_count) for full inspectability. Carries
    every labeled group, including those below the minimum sample size."""

    total_events: int
    """Every event seen, labeled or not."""

    labeled_events: int
    """Events that carried a protected-class label for this dimension."""

    skipped_no_label: int
    """Events dropped because they carried no protected-class label. Counted and
    recorded, never silently `continue`d past (F2)."""

    coverage: float
    """labeled_events / total_events (1.0 on empty input)."""

    low_coverage: bool
    """True if `coverage` fell below the sealed MIN_LABEL_COVERAGE floor — a loud
    audit warning that the caller's class-key left much of the cohort unlabeled."""

    min_group_size: int
    """The sealed minimum per-group sample applied (audit provenance)."""

    protected_class_key: str
    """The class-key the caller used — recorded so the warrant memorializes *what
    definition* produced the number (F2)."""

    predicate_id: str
    """Module-qualified identity of the positive-outcome predicate (F2)."""

    def to_warrant(self, *, created_at: str | None = None) -> Warrant:
        """Memorialize this result as a LARP warrant (1-cell + 2-cell)."""
        std = get_standard(_PRIMITIVE)
        return Warrant.build(
            primitive=_PRIMITIVE,
            result={
                "flagged": self.flagged,
                "evaluable": self.evaluable,
                "metric": "disparate_impact_ratio",
                "value": self.ratio,
                "high_group": self.high_group,
                "low_group": self.low_group,
            },
            evidence={
                "high_rate": self.high_rate,
                "low_rate": self.low_rate,
                "group_stats": {k: list(v) for k, v in self.group_stats.items()},
                "total_events": self.total_events,
                "labeled_events": self.labeled_events,
                "skipped_no_label": self.skipped_no_label,
                "coverage": self.coverage,
                "low_coverage": self.low_coverage,
                "min_group_size": self.min_group_size,
                "protected_class_key": self.protected_class_key,
                "predicate_id": self.predicate_id,
            },
            standard=std.standard,
            threshold=self.threshold,
            rejected_thresholds=rejected_thresholds_for(_PRIMITIVE, self.threshold),
            created_at=created_at,
        )


def disparate_impact_ratio(
    events: Iterable[dict[str, Any]],
    *,
    protected_class_key: str,
    positive_outcome_predicate: Callable[[dict[str, Any]], bool],
    threshold: float = FOUR_FIFTHS_BASELINE,
) -> DisparateImpactResult:
    """
    Compute the disparate impact ratio across protected-class groups.

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

    Returns:
        A DisparateImpactResult with the minimum cross-group ratio, the
        high-rate and low-rate groups, and full per-group stats.

    Raises:
        ValueError: If the event stream contains fewer than two distinct
            protected-class groups (a single-group ratio is undefined).
        ValueError: If threshold is out of range or LOOSENS detection below the
            four-fifths baseline (0.8). Per Charter v1.1 the refusal is
            structural: customers tighten (raise toward 1.0), never loosen.

    Note:
        A ratio is only computed — and adverse impact only flagged — over groups
        meeting the sealed minimum sample size (MIN_EVALUABLE_GROUP_SIZE). A
        cohort too small to evaluate is returned `evaluable=False, flagged=False`
        rather than declaring "adverse impact" on a handful of data points (F6).
        Events lacking the protected-class label are counted in `skipped_no_label`
        and surfaced in the warrant, never silently dropped (F2).

    Example:
        >>> events = [
        ...     {"protected_class_context": {"race": "A"}, "output": {"decision": "hire"}}
        ...     for _ in range(6)
        ... ] + [
        ...     {"protected_class_context": {"race": "B"}, "output": {"decision": "no"}}
        ...     for _ in range(6)
        ... ]
        >>> result = disparate_impact_ratio(
        ...     events,
        ...     protected_class_key="race",
        ...     positive_outcome_predicate=lambda e: e["output"]["decision"] == "hire",
        ... )
        >>> result.evaluable and result.flagged  # A 6/6 vs B 0/6 → ratio 0 → flagged
        True
    """
    threshold = enforce_tighten_only(_PRIMITIVE, threshold)

    group_stats: dict[str, list[int]] = {}
    total_events = 0
    skipped_no_label = 0

    for event in events:
        total_events += 1
        label_str = extract_label(event, protected_class_key)
        if label_str is None:
            # Dropped events are COUNTED, not silently skipped (F2): a caller
            # cannot make adverse rows vanish from the denominator invisibly.
            skipped_no_label += 1
            continue

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

    labeled_events = sum(total for _, total in group_stats.values())
    coverage = labeled_events / total_events if total_events > 0 else 1.0
    low_coverage = coverage < MIN_LABEL_COVERAGE

    # Only groups meeting the minimum sample size are eligible to define the
    # ratio or raise a flag — the small-sample false-positive gate (F6).
    rates: dict[str, float] = {
        label: positive / total
        for label, (positive, total) in group_stats.items()
        if total >= MIN_EVALUABLE_GROUP_SIZE
    }
    evaluable = len(rates) >= 2

    ratio: float | None = None
    flagged = False
    high_group = ""
    low_group = ""
    high_rate = 0.0
    low_rate = 0.0

    if evaluable:
        high_group = max(rates, key=lambda k: rates[k])
        low_group = min(rates, key=lambda k: rates[k])
        high_rate = rates[high_group]
        low_rate = rates[low_group]
        # If the highest rate is zero, every evaluable group has zero positive
        # outcomes. Define ratio as 1.0 (no disparity) in that degenerate case.
        ratio = 1.0 if high_rate == 0 else low_rate / high_rate
        flagged = ratio < threshold

    return DisparateImpactResult(
        ratio=ratio,
        threshold=threshold,
        flagged=flagged,
        evaluable=evaluable,
        high_group=high_group,
        high_rate=high_rate,
        low_group=low_group,
        low_rate=low_rate,
        group_stats={k: (v[0], v[1]) for k, v in group_stats.items()},
        total_events=total_events,
        labeled_events=labeled_events,
        skipped_no_label=skipped_no_label,
        coverage=coverage,
        low_coverage=low_coverage,
        min_group_size=MIN_EVALUABLE_GROUP_SIZE,
        protected_class_key=protected_class_key,
        predicate_id=callable_identity(positive_outcome_predicate),
    )
