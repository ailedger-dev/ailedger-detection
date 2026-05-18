"""
Statistical parity difference — bias detection primitive.

Statistical parity difference (SPD) measures the absolute difference in
positive-outcome rates between two protected-class groups. Where disparate
impact ratio is a ratio (low/high), SPD is a difference (high − low).

Per Caton & Haas 2024 survey of fairness measures, SPD complements disparate
impact ratio by giving an absolute-difference view that does not collapse
when one group has very low rates (where the ratio metric becomes unstable).

Threshold convention: SPD above 0.1 (10 percentage points absolute difference)
is the AILedger default flag threshold. Customers tighten, never loosen.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

# Default flag threshold for statistical parity difference. Customers tighten.
DEFAULT_SPD_THRESHOLD: float = 0.10


@dataclass(frozen=True)
class StatisticalParityResult:
    """Result of a statistical-parity-difference calculation."""

    spd: float
    """Statistical parity difference = high_rate − low_rate. Range [0, 1]."""

    threshold: float
    """Threshold above which parity violation is flagged."""

    flagged: bool
    """True if spd > threshold."""

    high_group: str
    high_rate: float
    low_group: str
    low_rate: float
    group_stats: dict[str, tuple[int, int]]


def statistical_parity_difference(
    events: Iterable[dict[str, Any]],
    *,
    protected_class_key: str,
    positive_outcome_predicate: Callable[[dict[str, Any]], bool],
    threshold: float = DEFAULT_SPD_THRESHOLD,
) -> StatisticalParityResult:
    """
    Compute statistical parity difference across protected-class groups.

    SPD = max_group_rate − min_group_rate.

    Args:
        events: Detection Event records.
        protected_class_key: Key inside protected_class_context for the dimension.
        positive_outcome_predicate: Predicate that determines positive outcome.
        threshold: Flag threshold. Default 0.10 (10 percentage points).

    Returns:
        StatisticalParityResult with SPD value, threshold, and per-group rates.

    Raises:
        ValueError: If fewer than two groups present.
        ValueError: If any group has zero total events.
        ValueError: If threshold is not in [0, 1].
    """
    if not 0 <= threshold <= 1:
        raise ValueError(f"threshold must be in [0, 1]; got {threshold}")

    group_stats: dict[str, list[int]] = {}

    for event in events:
        ctx = event.get("protected_class_context")
        if isinstance(ctx, dict) and protected_class_key in ctx:
            label = ctx[protected_class_key]
        elif protected_class_key in event:
            label = event[protected_class_key]
        else:
            continue

        label_str = str(label)
        if label_str not in group_stats:
            group_stats[label_str] = [0, 0]
        if positive_outcome_predicate(event):
            group_stats[label_str][0] += 1
        group_stats[label_str][1] += 1

    if len(group_stats) < 2:
        raise ValueError(
            f"At least two distinct protected-class groups required; "
            f"found {len(group_stats)}"
        )

    rates: dict[str, float] = {}
    for label, (positive, total) in group_stats.items():
        if total == 0:
            raise ValueError(f"Group '{label}' has zero events; rate undefined")
        rates[label] = positive / total

    high_group = max(rates, key=lambda k: rates[k])
    low_group = min(rates, key=lambda k: rates[k])
    spd = rates[high_group] - rates[low_group]

    return StatisticalParityResult(
        spd=spd,
        threshold=threshold,
        flagged=spd > threshold,
        high_group=high_group,
        high_rate=rates[high_group],
        low_group=low_group,
        low_rate=rates[low_group],
        group_stats={k: (v[0], v[1]) for k, v in group_stats.items()},
    )
