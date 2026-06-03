"""
Confidence-stratified outcome analysis — bias detection primitive.

Slices a population of Detection Events by confidence bucket and reports the
within-bucket disparate impact ratio per bucket. Use case: detecting whether
the model's high-confidence decisions concentrate adverse outcomes on a
protected class — a subtle bias signal that the raw, population-wide
disparate-impact ratio averages away.

A model can clear the four-fifths rule in aggregate while its
*high-confidence* decisions disproportionately deny one group. Stratifying by
confidence surfaces that: each bucket gets its own disparate-impact ratio, and
any bucket whose ratio falls below threshold is flagged.

Threshold convention: AILedger ships with the EEOC four-fifths-rule baseline of
0.8 as the per-bucket default (same standard as `disparate_impact_ratio`).
Per Charter v1.1, customers tighten (raise toward 1.0), never loosen.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from itertools import pairwise
from typing import Any

# EEOC Uniform Guidelines four-fifths-rule baseline, applied per bucket.
FOUR_FIFTHS_BASELINE: float = 0.8

# Default confidence-bucket cut points. Buckets are
# [0, 0.5), [0.5, 0.7), [0.7, 0.85), [0.85, 0.95), [0.95, 1.0].
DEFAULT_BUCKET_BOUNDARIES: tuple[float, ...] = (0.5, 0.7, 0.85, 0.95)


@dataclass(frozen=True)
class ConfidenceBucketStat:
    """Per-confidence-bucket disparate-impact statistics."""

    label: str
    """Human-readable bucket label, e.g. "[0.85, 0.95)"."""

    lower: float
    """Inclusive lower confidence bound."""

    upper: float
    """Exclusive upper confidence bound (inclusive for the top bucket)."""

    total: int
    """Total events that fell into this bucket."""

    group_stats: dict[str, tuple[int, int]]
    """Per-protected-class (positive_count, total_count) within this bucket."""

    ratio: float | None
    """Within-bucket disparate impact ratio (low_rate / high_rate). None when
    fewer than two protected-class groups are present in the bucket (ratio
    undefined)."""

    flagged: bool
    """True if ratio is not None and ratio < threshold."""


@dataclass(frozen=True)
class ConfidenceStratifiedResult:
    """Result of a confidence-stratified outcome analysis."""

    threshold: float
    """Per-bucket disparate-impact threshold. Default FOUR_FIFTHS_BASELINE."""

    buckets: tuple[ConfidenceBucketStat, ...]
    """Per-bucket statistics, ordered from lowest to highest confidence."""

    flagged: bool
    """True if any bucket is flagged (within-bucket adverse impact)."""

    skipped_no_confidence: int
    """Events skipped because they carried no usable confidence value."""

    skipped_no_class: int
    """Events skipped because they carried no protected-class label."""


def _bucket_index(confidence: float, boundaries: tuple[float, ...]) -> int:
    """Return the bucket index for a confidence value. Buckets are
    left-closed/right-open, except the final bucket which is closed on both
    ends so confidence == 1.0 lands in the top bucket."""
    for i, edge in enumerate(boundaries):
        if confidence < edge:
            return i
    return len(boundaries)


def _bucket_bounds(index: int, boundaries: tuple[float, ...]) -> tuple[float, float]:
    lower = 0.0 if index == 0 else boundaries[index - 1]
    upper = 1.0 if index == len(boundaries) else boundaries[index]
    return lower, upper


def confidence_stratified_outcome_analysis(
    events: Iterable[dict[str, Any]],
    *,
    protected_class_key: str,
    positive_outcome_predicate: Callable[[dict[str, Any]], bool],
    confidence_extractor: Callable[[dict[str, Any]], float | None] | None = None,
    bucket_boundaries: tuple[float, ...] = DEFAULT_BUCKET_BOUNDARIES,
    threshold: float = FOUR_FIFTHS_BASELINE,
) -> ConfidenceStratifiedResult:
    """
    Compute the within-bucket disparate impact ratio across confidence buckets.

    Args:
        events: An iterable of Detection Event records (dicts). Each record
            should carry a confidence value and a protected-class label.
        protected_class_key: Key used to extract the protected-class label.
            Looked up inside `protected_class_context` first, then top-level.
        positive_outcome_predicate: Callable returning True for a positive
            outcome (e.g. hired, approved). The decision-domain-specific
            positive-outcome definition.
        confidence_extractor: Callable returning the confidence value for an
            event, or None if absent. Defaults to reading the `confidence`
            field. Events with a None / non-numeric / out-of-range confidence
            are counted in `skipped_no_confidence`.
        bucket_boundaries: Strictly-increasing cut points in (0, 1). Default
            (0.5, 0.7, 0.85, 0.95) yields five buckets.
        threshold: Per-bucket disparate-impact threshold. Default is the
            four-fifths-rule baseline (0.8). Customers tighten, never loosen.

    Returns:
        A ConfidenceStratifiedResult with one ConfidenceBucketStat per bucket
        and an overall flag if any bucket shows adverse impact.

    Raises:
        ValueError: If threshold is not in (0, 1].
        ValueError: If bucket_boundaries is empty, not strictly increasing, or
            contains values outside (0, 1).
    """
    if not 0 < threshold <= 1:
        raise ValueError(f"threshold must be in (0, 1]; got {threshold}")

    if not bucket_boundaries:
        raise ValueError("bucket_boundaries must contain at least one cut point")
    for prev, nxt in pairwise(bucket_boundaries):
        if nxt <= prev:
            raise ValueError(
                f"bucket_boundaries must be strictly increasing; got {bucket_boundaries}"
            )
    if not all(0 < b < 1 for b in bucket_boundaries):
        raise ValueError(
            f"bucket_boundaries must all be in (0, 1); got {bucket_boundaries}"
        )

    extractor = confidence_extractor or (lambda e: e.get("confidence"))

    n_buckets = len(bucket_boundaries) + 1
    # Per bucket: label -> [positive, total]
    bucket_group_stats: list[dict[str, list[int]]] = [{} for _ in range(n_buckets)]
    bucket_totals = [0] * n_buckets
    skipped_no_confidence = 0
    skipped_no_class = 0

    for event in events:
        raw_conf = extractor(event)
        if isinstance(raw_conf, bool) or not isinstance(raw_conf, (int, float)):
            skipped_no_confidence += 1
            continue
        conf = float(raw_conf)
        if not 0.0 <= conf <= 1.0:
            skipped_no_confidence += 1
            continue

        ctx = event.get("protected_class_context")
        if isinstance(ctx, dict) and protected_class_key in ctx:
            label = ctx[protected_class_key]
        elif protected_class_key in event:
            label = event[protected_class_key]
        else:
            skipped_no_class += 1
            continue

        idx = _bucket_index(conf, bucket_boundaries)
        label_str = str(label)
        stats = bucket_group_stats[idx]
        if label_str not in stats:
            stats[label_str] = [0, 0]
        if positive_outcome_predicate(event):
            stats[label_str][0] += 1
        stats[label_str][1] += 1
        bucket_totals[idx] += 1

    buckets: list[ConfidenceBucketStat] = []
    any_flagged = False
    for idx in range(n_buckets):
        lower, upper = _bucket_bounds(idx, bucket_boundaries)
        upper_bracket = "]" if idx == n_buckets - 1 else ")"
        label = f"[{lower}, {upper}{upper_bracket}"
        stats = bucket_group_stats[idx]

        ratio: float | None
        if len(stats) < 2:
            ratio = None
            flagged = False
        else:
            rates = {k: (p / t) for k, (p, t) in stats.items() if t > 0}
            high_rate = max(rates.values())
            low_rate = min(rates.values())
            ratio = 1.0 if high_rate == 0 else low_rate / high_rate
            flagged = ratio < threshold

        if flagged:
            any_flagged = True

        buckets.append(
            ConfidenceBucketStat(
                label=label,
                lower=lower,
                upper=upper,
                total=bucket_totals[idx],
                group_stats={k: (v[0], v[1]) for k, v in stats.items()},
                ratio=ratio,
                flagged=flagged,
            )
        )

    return ConfidenceStratifiedResult(
        threshold=threshold,
        buckets=tuple(buckets),
        flagged=any_flagged,
        skipped_no_confidence=skipped_no_confidence,
        skipped_no_class=skipped_no_class,
    )
