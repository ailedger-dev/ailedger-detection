"""
Statistical parity difference — bias detection primitive.

Statistical parity difference (SPD) measures the absolute difference in
positive-outcome rates between two protected-class groups. Where disparate
impact ratio is a ratio (low/high), SPD is a difference (high - low).

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

from ailedger_detection._coverage import callable_identity, extract_label
from ailedger_detection.thresholds import (
    MIN_EVALUABLE_GROUP_SIZE,
    MIN_LABEL_COVERAGE,
    enforce_tighten_only,
    get_standard,
    rejected_thresholds_for,
)
from ailedger_detection.warrant import Warrant

# Default flag threshold for statistical parity difference. Customers tighten.
DEFAULT_SPD_THRESHOLD: float = 0.10

_PRIMITIVE = "statistical_parity_difference"


@dataclass(frozen=True)
class StatisticalParityResult:
    """Result of a statistical-parity-difference calculation."""

    spd: float | None
    """Statistical parity difference = high_rate - low_rate, range [0, 1], over
    the groups that met the minimum sample size. None when not `evaluable`."""

    threshold: float
    """Threshold above which parity violation is flagged."""

    flagged: bool
    """True if `evaluable` and spd > threshold."""

    evaluable: bool
    """True if ≥2 groups met the sealed minimum sample size (F6)."""

    high_group: str
    high_rate: float
    low_group: str
    low_rate: float
    group_stats: dict[str, tuple[int, int]]
    """Per-group (positive_count, total_count); carries every labeled group."""

    total_events: int
    """Every event seen, labeled or not."""

    labeled_events: int
    """Events that carried a protected-class label for this dimension."""

    skipped_no_label: int
    """Events dropped because they carried no protected-class label (F2)."""

    coverage: float
    """labeled_events / total_events (1.0 on empty input)."""

    low_coverage: bool
    """True if coverage fell below the sealed MIN_LABEL_COVERAGE floor (F2)."""

    min_group_size: int
    """The sealed minimum per-group sample applied (audit provenance)."""

    protected_class_key: str
    """The class-key the caller used — recorded in the warrant (F2)."""

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
                "metric": "statistical_parity_difference",
                "value": self.spd,
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


def statistical_parity_difference(
    events: Iterable[dict[str, Any]],
    *,
    protected_class_key: str,
    positive_outcome_predicate: Callable[[dict[str, Any]], bool],
    threshold: float = DEFAULT_SPD_THRESHOLD,
) -> StatisticalParityResult:
    """
    Compute statistical parity difference across protected-class groups.

    SPD = max_group_rate - min_group_rate.

    Args:
        events: Detection Event records.
        protected_class_key: Key inside protected_class_context for the dimension.
        positive_outcome_predicate: Predicate that determines positive outcome.
        threshold: Flag threshold. Default 0.10 (10 percentage points).

    Returns:
        StatisticalParityResult with SPD value, threshold, and per-group rates.

    Raises:
        ValueError: If fewer than two groups present.
        ValueError: If threshold is out of range or LOOSENS detection above the
            0.10 baseline. Per Charter v1.1 the refusal is structural: customers
            tighten (lower toward 0), never loosen.

    Note:
        SPD is only computed — and a parity violation only flagged — over groups
        meeting the sealed minimum sample size (MIN_EVALUABLE_GROUP_SIZE); a
        cohort too small is `evaluable=False, flagged=False` (F6). Unlabeled
        events are counted in `skipped_no_label` and surfaced in the warrant (F2).
    """
    threshold = enforce_tighten_only(_PRIMITIVE, threshold)

    group_stats: dict[str, list[int]] = {}
    total_events = 0
    skipped_no_label = 0

    for event in events:
        total_events += 1
        label_str = extract_label(event, protected_class_key)
        if label_str is None:
            skipped_no_label += 1
            continue

        if label_str not in group_stats:
            group_stats[label_str] = [0, 0]
        if positive_outcome_predicate(event):
            group_stats[label_str][0] += 1
        group_stats[label_str][1] += 1

    if len(group_stats) < 2:
        raise ValueError(
            f"At least two distinct protected-class groups required; found {len(group_stats)}"
        )

    labeled_events = sum(total for _, total in group_stats.values())
    coverage = labeled_events / total_events if total_events > 0 else 1.0
    low_coverage = coverage < MIN_LABEL_COVERAGE

    rates: dict[str, float] = {
        label: positive / total
        for label, (positive, total) in group_stats.items()
        if total >= MIN_EVALUABLE_GROUP_SIZE
    }
    evaluable = len(rates) >= 2

    spd: float | None = None
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
        spd = high_rate - low_rate
        flagged = spd > threshold

    return StatisticalParityResult(
        spd=spd,
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
