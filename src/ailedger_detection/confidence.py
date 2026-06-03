"""
Confidence-stratified outcome analysis — bias-by-confidence-stratum primitive.

Raw disparate-impact ratio over a whole population can mask a subtler bias: the
model treats groups equally *on average* but concentrates its adverse,
high-confidence decisions on one protected class. Slicing the population into
confidence strata and running the four-fifths test *within each stratum*
surfaces that pattern.

Design (resolving the v0.2.0 stub's open questions):

- **Bucket boundaries** are caller-supplied (`bucket_boundaries`), an ascending
  tuple of interior edges in (0, 1). Boundaries `(0.5, 0.7, 0.85, 0.95)` produce
  five half-open buckets ``[0,0.5) [0.5,0.7) [0.7,0.85) [0.85,0.95) [0.95,1.0]``.
  Equi-width vs quantile bucketing is the caller's choice — pass quantile edges
  if that is the desired stratification. The default is a confidence ladder that
  isolates the highest-confidence decisions where automation-bias risk is worst.
- **Minimum stratum size** for inference is `min_group_size` (default 1): a group
  with fewer than this many events in a stratum is excluded from that stratum's
  ratio (recorded under `evaluable=False`) rather than producing a noisy ratio.
- **Per-bucket disparate impact** composes the four-fifths rule (the same
  threshold registry entry family) per stratum. The overall result flags if
  *any* evaluable stratum is below the four-fifths threshold.

Per Charter v1.1 the threshold is tighten-only (raise toward 1.0); the structural
refusal is enforced via the shared threshold registry.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from ailedger_detection.thresholds import (
    enforce_tighten_only,
    get_standard,
    rejected_thresholds_for,
)
from ailedger_detection.warrant import Warrant

_PRIMITIVE = "confidence_stratified_outcome_analysis"

DEFAULT_BUCKET_BOUNDARIES: tuple[float, ...] = (0.5, 0.7, 0.85, 0.95)
"""Default interior edges; isolates the highest-confidence stratum."""


@dataclass(frozen=True)
class ConfidenceBucketStat:
    """Per-stratum statistics."""

    label: str
    """Human-readable stratum label, e.g. "[0.85,0.95)"."""

    lower: float
    upper: float
    """Half-open stratum bounds [lower, upper). The top stratum is closed."""

    group_stats: dict[str, tuple[int, int]]
    """Per-group (positive_count, total_count) within this stratum."""

    evaluable: bool
    """True if ≥2 groups met `min_group_size`, so a ratio is defined."""

    ratio: float | None
    """Within-stratum disparate impact ratio (low_rate / high_rate), or None."""

    flagged: bool
    """True if evaluable and ratio < threshold."""

    high_group: str | None
    low_group: str | None


@dataclass(frozen=True)
class ConfidenceStratifiedResult:
    """Result of a confidence-stratified outcome analysis."""

    flagged: bool
    """True if any evaluable stratum's ratio is below threshold."""

    threshold: float
    buckets: tuple[ConfidenceBucketStat, ...]
    skipped_no_confidence: int
    """Events skipped because they carried no usable confidence value."""

    skipped_no_group: int
    """Events skipped because they carried no protected-class label."""

    def to_warrant(self, *, created_at: str | None = None) -> Warrant:
        """Memorialize this result as a warrant."""
        std = get_standard(_PRIMITIVE)
        flagged_strata = [b.label for b in self.buckets if b.flagged]
        return Warrant.build(
            primitive=_PRIMITIVE,
            result={
                "flagged": self.flagged,
                "metric": "min_stratum_disparate_impact_ratio",
                "flagged_strata": flagged_strata,
            },
            evidence={
                "buckets": [
                    {
                        "label": b.label,
                        "lower": b.lower,
                        "upper": b.upper,
                        "evaluable": b.evaluable,
                        "ratio": b.ratio,
                        "flagged": b.flagged,
                        "high_group": b.high_group,
                        "low_group": b.low_group,
                        "group_stats": {k: list(v) for k, v in b.group_stats.items()},
                    }
                    for b in self.buckets
                ],
                "skipped_no_confidence": self.skipped_no_confidence,
                "skipped_no_group": self.skipped_no_group,
            },
            standard=std.standard,
            threshold=self.threshold,
            rejected_thresholds=rejected_thresholds_for(_PRIMITIVE, self.threshold),
            created_at=created_at,
        )


def _bucket_labels(boundaries: tuple[float, ...]) -> list[tuple[str, float, float]]:
    edges = [0.0, *boundaries, 1.0]
    out: list[tuple[str, float, float]] = []
    for i in range(len(edges) - 1):
        lo, hi = edges[i], edges[i + 1]
        closing = "]" if i == len(edges) - 2 else ")"
        out.append((f"[{lo:.2f},{hi:.2f}{closing}", lo, hi))
    return out


def _bucket_index(confidence: float, boundaries: tuple[float, ...]) -> int:
    # Half-open buckets [lo, hi); the final bucket is closed on the right.
    for i, edge in enumerate(boundaries):
        if confidence < edge:
            return i
    return len(boundaries)


def confidence_stratified_outcome_analysis(
    events: Iterable[dict[str, Any]],
    *,
    protected_class_key: str,
    positive_outcome_predicate: Callable[[dict[str, Any]], bool],
    bucket_boundaries: tuple[float, ...] = DEFAULT_BUCKET_BOUNDARIES,
    confidence_extractor: Callable[[dict[str, Any]], float | None] | None = None,
    min_group_size: int = 1,
    threshold: float | None = None,
) -> ConfidenceStratifiedResult:
    """
    Run the four-fifths disparate-impact test within each confidence stratum.

    Args:
        events: Detection Event records.
        protected_class_key: Key inside `protected_class_context` (or top-level)
            for the protected-class dimension.
        positive_outcome_predicate: Predicate defining a positive outcome.
        bucket_boundaries: Ascending interior edges in (0, 1). Defaults to a
            confidence ladder isolating the top stratum.
        confidence_extractor: Returns an event's confidence in [0, 1], or None
            to skip the event. Defaults to reading the `confidence` field.
        min_group_size: Minimum per-group event count for a stratum to evaluate
            that group. Groups below this are excluded from the stratum's ratio.
        threshold: Four-fifths threshold. Defaults to the registry baseline
            (0.80). Tighten-only: a looser value is refused structurally.

    Returns:
        A ConfidenceStratifiedResult with per-stratum ratios and an overall flag.

    Raises:
        ValueError: If bucket_boundaries is not ascending and within (0, 1).
        ValueError: If a confidence value is outside [0, 1].
        ValueError: If threshold loosens detection below baseline.
    """
    if threshold is None:
        threshold = get_standard(_PRIMITIVE).baseline
    threshold = enforce_tighten_only(_PRIMITIVE, threshold)

    if not bucket_boundaries:
        raise ValueError("bucket_boundaries must contain at least one edge")
    prev = 0.0
    for b in bucket_boundaries:
        if not (0.0 < b < 1.0):
            raise ValueError(f"bucket boundary {b} must be in (0, 1)")
        if b <= prev:
            raise ValueError(
                f"bucket_boundaries must be strictly ascending; got {bucket_boundaries}"
            )
        prev = b

    conf_extract = confidence_extractor or (lambda e: e.get("confidence"))
    labels = _bucket_labels(bucket_boundaries)

    # bucket_index -> {group_label: [positive, total]}
    buckets: list[dict[str, list[int]]] = [{} for _ in labels]
    skipped_no_confidence = 0
    skipped_no_group = 0

    for event in events:
        confidence = conf_extract(event)
        if confidence is None:
            skipped_no_confidence += 1
            continue
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"confidence {confidence} outside [0, 1]")

        ctx = event.get("protected_class_context")
        if isinstance(ctx, dict) and protected_class_key in ctx:
            label = ctx[protected_class_key]
        elif protected_class_key in event:
            label = event[protected_class_key]
        else:
            skipped_no_group += 1
            continue

        idx = _bucket_index(confidence, bucket_boundaries)
        group = buckets[idx].setdefault(str(label), [0, 0])
        if positive_outcome_predicate(event):
            group[0] += 1
        group[1] += 1

    bucket_stats: list[ConfidenceBucketStat] = []
    overall_flagged = False

    for (label, lo, hi), raw in zip(labels, buckets, strict=True):
        rates: dict[str, float] = {
            g: pos / total for g, (pos, total) in raw.items() if total >= min_group_size
        }
        evaluable = len(rates) >= 2
        ratio: float | None = None
        flagged = False
        high_group: str | None = None
        low_group: str | None = None

        if evaluable:
            high_group = max(rates, key=lambda k: rates[k])
            low_group = min(rates, key=lambda k: rates[k])
            high_rate = rates[high_group]
            ratio = 1.0 if high_rate == 0 else rates[low_group] / high_rate
            flagged = ratio < threshold
            overall_flagged = overall_flagged or flagged

        bucket_stats.append(
            ConfidenceBucketStat(
                label=label,
                lower=lo,
                upper=hi,
                group_stats={g: (v[0], v[1]) for g, v in raw.items()},
                evaluable=evaluable,
                ratio=ratio,
                flagged=flagged,
                high_group=high_group,
                low_group=low_group,
            )
        )

    return ConfidenceStratifiedResult(
        flagged=overall_flagged,
        threshold=threshold,
        buckets=tuple(bucket_stats),
        skipped_no_confidence=skipped_no_confidence,
        skipped_no_group=skipped_no_group,
    )
