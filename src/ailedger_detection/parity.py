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

from ailedger_detection.thresholds import (
    enforce_tighten_only,
    get_standard,
    registry_digest,
    rejected_thresholds_for,
)
from ailedger_detection.warrant import Warrant

# Default flag threshold for statistical parity difference. Customers tighten.
DEFAULT_SPD_THRESHOLD: float = 0.10

_PRIMITIVE = "statistical_parity_difference"


def _predicate_identity(fn: Callable[[dict[str, Any]], bool]) -> str:
    """A stable, recordable identity for a caller-supplied predicate."""
    name = getattr(fn, "__qualname__", None) or getattr(fn, "__name__", None)
    module = getattr(fn, "__module__", None)
    if name:
        return f"{module}.{name}" if module else name
    return repr(fn)


@dataclass(frozen=True)
class StatisticalParityResult:
    """Result of a statistical-parity-difference calculation."""

    spd: float
    """Statistical parity difference = high_rate - low_rate. Range [0, 1]."""

    threshold: float
    """Threshold above which parity violation is flagged."""

    flagged: bool
    """True if evaluable and spd > threshold."""

    evaluable: bool
    """True if ≥2 groups met `min_group_size` so an SPD is defined. When False
    the sample was too small to evaluate and `flagged` is False."""

    high_group: str
    high_rate: float
    low_group: str
    low_rate: float
    group_stats: dict[str, tuple[int, int]]

    total_events: int
    """Total events seen in the cohort."""

    skipped_no_group: int
    """Events dropped because they carried no protected-class label. Counted and
    recorded — never silently suppressed (the F2 loosening surface)."""

    skipped_small_group: int
    """Groups excluded from the SPD because they fell below `min_group_size`."""

    coverage: float
    """Fraction of the cohort that carried a usable protected-class label."""

    coverage_flagged: bool
    """True if `coverage` fell below the caller's `min_coverage` guard."""

    protected_class_key: str
    """The class key the cohort was partitioned on (recorded for the auditor)."""

    predicate_identity: str
    """Identity of the positive-outcome predicate (the real loosening surface)."""

    def to_warrant(self, *, created_at: str | None = None) -> Warrant:
        """Memorialize this result as a warrant."""
        std = get_standard(_PRIMITIVE)
        return Warrant.build(
            primitive=_PRIMITIVE,
            result={
                "flagged": self.flagged,
                "metric": "statistical_parity_difference",
                "value": self.spd,
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


def statistical_parity_difference(
    events: Iterable[dict[str, Any]],
    *,
    protected_class_key: str,
    positive_outcome_predicate: Callable[[dict[str, Any]], bool],
    threshold: float = DEFAULT_SPD_THRESHOLD,
    min_group_size: int = 1,
    min_coverage: float = 0.0,
) -> StatisticalParityResult:
    """
    Compute statistical parity difference across protected-class groups.

    SPD = max_group_rate - min_group_rate.

    Like `disparate_impact_ratio`, events missing the class label are counted
    (`skipped_no_group`) and the predicate/key identity is recorded in the
    warrant (F2): the caller-supplied predicate/key is the real loosening
    surface, so its effect is made auditable instead of invisible.

    Args:
        events: Detection Event records.
        protected_class_key: Key inside protected_class_context for the dimension.
        positive_outcome_predicate: Predicate that determines positive outcome.
        threshold: Flag threshold. Default 0.10 (10 percentage points).
        min_group_size: Minimum per-group event count for a group to enter the
            SPD (F6). Groups below it are excluded and counted; if fewer than two
            remain the result is `evaluable=False`.
        min_coverage: If > 0, the fraction of the cohort that must carry the
            class label; below it the result records `coverage_flagged=True`.

    Returns:
        StatisticalParityResult with SPD value, threshold, per-group rates, and
        the drop/coverage accounting.

    Raises:
        ValueError: If fewer than two groups present.
        ValueError: If threshold is out of range or LOOSENS detection above the
            0.10 baseline. Per Charter v1.1 the refusal is structural: customers
            tighten (lower toward 0), never loosen.
    """
    threshold = enforce_tighten_only(_PRIMITIVE, threshold)

    group_stats: dict[str, list[int]] = {}
    total_events = 0
    skipped_no_group = 0

    for event in events:
        total_events += 1
        ctx = event.get("protected_class_context")
        if isinstance(ctx, dict) and protected_class_key in ctx:
            label = ctx[protected_class_key]
        elif protected_class_key in event:
            label = event[protected_class_key]
        else:
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
            f"At least two distinct protected-class groups required; found {len(group_stats)}"
        )

    labeled = total_events - skipped_no_group
    coverage = (labeled / total_events) if total_events else 1.0
    coverage_flagged = min_coverage > 0.0 and coverage < min_coverage

    rates: dict[str, float] = {}
    skipped_small_group = 0
    for label, (positive, total) in group_stats.items():
        if total < min_group_size:
            skipped_small_group += 1
            continue
        rates[label] = positive / total

    evaluable = len(rates) >= 2
    if not evaluable:
        return StatisticalParityResult(
            spd=0.0,
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
    spd = rates[high_group] - rates[low_group]

    return StatisticalParityResult(
        spd=spd,
        threshold=threshold,
        flagged=spd > threshold,
        evaluable=True,
        high_group=high_group,
        high_rate=rates[high_group],
        low_group=low_group,
        low_rate=rates[low_group],
        group_stats={k: (v[0], v[1]) for k, v in group_stats.items()},
        total_events=total_events,
        skipped_no_group=skipped_no_group,
        skipped_small_group=skipped_small_group,
        coverage=coverage,
        coverage_flagged=coverage_flagged,
        protected_class_key=protected_class_key,
        predicate_identity=_predicate_identity(positive_outcome_predicate),
    )
