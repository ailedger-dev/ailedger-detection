"""
Unresolved-flag accumulation — compliance-gap detection primitive.

A Detection Event can raise flags (`flags_raised`) and declare the remediation a
flag demands (`required_actions`). What was actually done lands in
`actions_taken`. The compliance gap is the diff:

    unresolved_actions = set(required_actions) - set(actions_taken)

An event is *flagged-but-unresolved* when it raised at least one flag AND its
required remediation was not all taken. Regulators audit the *accumulation* of
that gap — a system that keeps flagging "clinician-review-required" while
`actions_taken` stays empty is the failure mode EU AI Act Art. 14 (human
oversight) and NIST AI RMF GOVERN-1.5 exist to catch.

Design (resolving the v0.2.0 stub's open questions):

- **Window**: the primitive operates over whatever cohort the caller passes.
  Scope a time/subject/tenant window upstream with `EventQuery` (see query.py);
  this keeps the accumulation definition orthogonal to windowing policy.
- **Threshold**: the metric is the *rate* of unresolved events among flagged
  events. Baseline 0.0 — any accumulation flags. Tighten-only (lower toward 0,
  already the floor), so the baseline is effectively "no unresolved flag is
  acceptable"; loosening is structurally refused.
- **Granularity**: both aggregate (`unresolved_by_flag`) and, when a
  `group_by_extractor` is supplied, per-entity (`unresolved_by_group`) — so a
  caller can see *which* subject/tenant the gap is accumulating against.
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

_PRIMITIVE = "unresolved_flag_accumulation"


@dataclass(frozen=True)
class UnresolvedFlagResult:
    """Result of an unresolved-flag-accumulation calculation."""

    rate: float
    """Fraction of flagged events whose required remediation was not all taken.
    Range [0, 1]. 0 when no events raised flags."""

    threshold: float
    flagged: bool
    """True if rate > threshold."""

    total_events: int
    flagged_event_count: int
    """Events that raised at least one flag."""

    unresolved_event_count: int
    """Flagged events with a non-empty required-minus-taken action gap."""

    unresolved_by_flag: dict[str, int]
    """Per-flag count of flagged-but-unresolved events that raised that flag."""

    unresolved_by_group: dict[str, int]
    """Per-group count of unresolved events (empty unless group_by supplied)."""

    per_event_unresolved: list[tuple[str, tuple[str, ...], tuple[str, ...]]]
    """(event_id, sorted unresolved actions, sorted flags) per unresolved event.
    Sorted tuples are stable for downstream digest/hashing."""

    def to_warrant(self, *, created_at: str | None = None) -> Warrant:
        """Memorialize this result as a LARP warrant."""
        std = get_standard(_PRIMITIVE)
        return Warrant.build(
            primitive=_PRIMITIVE,
            result={
                "flagged": self.flagged,
                "metric": "unresolved_flag_rate",
                "value": self.rate,
            },
            evidence={
                "total_events": self.total_events,
                "flagged_event_count": self.flagged_event_count,
                "unresolved_event_count": self.unresolved_event_count,
                "unresolved_by_flag": dict(self.unresolved_by_flag),
                "unresolved_by_group": dict(self.unresolved_by_group),
                "per_event_unresolved": [
                    [eid, list(actions), list(flags)]
                    for eid, actions, flags in self.per_event_unresolved
                ],
            },
            standard=std.standard,
            threshold=self.threshold,
            rejected_thresholds=rejected_thresholds_for(_PRIMITIVE, self.threshold),
            created_at=created_at,
        )


def unresolved_flag_accumulation(
    events: Iterable[dict[str, Any]],
    *,
    flags_extractor: Callable[[dict[str, Any]], Iterable[str]] | None = None,
    required_actions_extractor: Callable[[dict[str, Any]], Iterable[str]] | None = None,
    actions_taken_extractor: Callable[[dict[str, Any]], Iterable[str]] | None = None,
    event_id_extractor: Callable[[dict[str, Any]], str] | None = None,
    group_by_extractor: Callable[[dict[str, Any]], str] | None = None,
    threshold: float | None = None,
) -> UnresolvedFlagResult:
    """
    Compute the rate at which raised flags go unresolved across the cohort.

    Args:
        events: Detection Event records.
        flags_extractor: Returns an event's raised flags. Defaults to the
            `flags_raised` field.
        required_actions_extractor: Returns the remediation a flag demands.
            Defaults to the `required_actions` field.
        actions_taken_extractor: Returns the remediation actually taken.
            Defaults to the `actions_taken` field.
        event_id_extractor: Returns a stable event id. Defaults to `event_id`.
        group_by_extractor: Optional. Returns a grouping key (e.g. subject_id,
            tenant_id) so the result reports per-entity accumulation.
        threshold: Flag if rate > threshold. Defaults to the registry baseline
            (0.0). Tighten-only: a looser value is refused structurally.

    Returns:
        An UnresolvedFlagResult with the rate, per-flag and per-group counts,
        and full per-event detail.

    Raises:
        ValueError: If threshold loosens detection above the 0.0 baseline.
    """
    if threshold is None:
        threshold = get_standard(_PRIMITIVE).baseline
    threshold = enforce_tighten_only(_PRIMITIVE, threshold)

    flags_extract = flags_extractor or (lambda e: e.get("flags_raised") or [])
    req_extract = required_actions_extractor or (lambda e: e.get("required_actions") or [])
    taken_extract = actions_taken_extractor or (lambda e: e.get("actions_taken") or [])
    id_extract = event_id_extractor or (lambda e: str(e.get("event_id", "")))

    total_events = 0
    flagged_event_count = 0
    unresolved_event_count = 0
    unresolved_by_flag: dict[str, int] = {}
    unresolved_by_group: dict[str, int] = {}
    per_event_unresolved: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = []

    for event in events:
        total_events += 1
        flags = list(flags_extract(event))
        if not flags:
            continue
        flagged_event_count += 1

        unresolved_actions = set(req_extract(event)) - set(taken_extract(event))
        if not unresolved_actions:
            continue

        unresolved_event_count += 1
        sorted_actions = tuple(sorted(unresolved_actions))
        sorted_flags = tuple(sorted(flags))
        per_event_unresolved.append((id_extract(event), sorted_actions, sorted_flags))

        for flag in set(flags):
            unresolved_by_flag[flag] = unresolved_by_flag.get(flag, 0) + 1

        if group_by_extractor is not None:
            key = group_by_extractor(event)
            unresolved_by_group[key] = unresolved_by_group.get(key, 0) + 1

    rate = unresolved_event_count / flagged_event_count if flagged_event_count else 0.0

    return UnresolvedFlagResult(
        rate=rate,
        threshold=threshold,
        flagged=rate > threshold,
        total_events=total_events,
        flagged_event_count=flagged_event_count,
        unresolved_event_count=unresolved_event_count,
        unresolved_by_flag=unresolved_by_flag,
        unresolved_by_group=unresolved_by_group,
        per_event_unresolved=per_event_unresolved,
    )
