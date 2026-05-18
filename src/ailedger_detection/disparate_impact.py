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

# EEOC Uniform Guidelines four-fifths-rule baseline. Customers tighten, never loosen.
FOUR_FIFTHS_BASELINE: float = 0.8


@dataclass(frozen=True)
class DisparateImpactResult:
    """Result of a disparate-impact-ratio calculation."""

    ratio: float
    """Minimum cross-group ratio (group_low_rate / group_high_rate). 0 to 1."""

    threshold: float
    """Threshold below which adverse impact is flagged. Default FOUR_FIFTHS_BASELINE."""

    flagged: bool
    """True if ratio < threshold (adverse impact indicated)."""

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
        ValueError: If any group has zero total events (rate is undefined).
        ValueError: If threshold is not in (0, 1].

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
    if not 0 < threshold <= 1:
        raise ValueError(f"threshold must be in (0, 1]; got {threshold}")

    group_stats: dict[str, list[int]] = {}

    for event in events:
        # Extract the protected-class label. Look inside protected_class_context
        # first (typical AILedger Detection Event shape), then fall back to
        # top-level (allows the primitive to work with arbitrary dict shapes).
        ctx = event.get("protected_class_context")
        if isinstance(ctx, dict) and protected_class_key in ctx:
            label = ctx[protected_class_key]
        elif protected_class_key in event:
            label = event[protected_class_key]
        else:
            # Skip events without a protected-class label for this dimension.
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

    rates: dict[str, float] = {}
    for label, (positive, total) in group_stats.items():
        if total == 0:
            raise ValueError(f"Group '{label}' has zero events; rate undefined")
        rates[label] = positive / total

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
        high_group=high_group,
        high_rate=high_rate,
        low_group=low_group,
        low_rate=low_rate,
        group_stats={k: (v[0], v[1]) for k, v in group_stats.items()},
    )
