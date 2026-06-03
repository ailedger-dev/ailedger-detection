"""
Unresolved-flag accumulation — compliance-gap detection primitive.

An event flags a condition (`flags_raised`) and the policy attaches a remedy
(`required_actions`). When the remedy is missing from `actions_taken`, the
required action is *unresolved*:

    unresolved = set(required_actions) - set(actions_taken)

A single unresolved action may simply be in flight. The audit signal is
*accumulation*: the same subject (or tenant) carrying unresolved required
actions across multiple events. That accumulating gap is what regulators
review under EU AI Act Article 14 (human oversight) and is the dual of the
agent-overreach signal in `tool_calls.py` (taken-minus-required vs
required-minus-taken).

Flagging convention: a group whose count of events-with-unresolved-actions
reaches `min_accumulation` is flagged. AILedger ships `min_accumulation = 2`
(one gap is transient; two is a pattern). Per Charter v1.1 customers TIGHTEN
(lower toward 1, flagging sooner), never loosen — a value above the baseline
is refused at the call boundary, mirroring the threshold refusals on the
ratio-based primitives.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

# AILedger default. One unresolved required action may be in flight; two or more
# on the same group is the accumulation pattern. Customers tighten (lower toward
# 1), never loosen.
DEFAULT_MIN_ACCUMULATION: int = 2


@dataclass(frozen=True)
class UnresolvedFlagResult:
    """Result of an unresolved-flag accumulation analysis."""

    min_accumulation: int
    """Per-group event count at or above which a group is flagged."""

    flagged: bool
    """True if any group reached min_accumulation unresolved events."""

    total_events: int
    """Total events considered."""

    unresolved_event_count: int
    """Events with at least one unresolved required action."""

    rate: float
    """Fraction of events with at least one unresolved required action."""

    accumulation_by_group: dict[str, int]
    """group_key -> count of events with unresolved required actions. Only
    groups with a non-zero count are present."""

    accumulating_groups: tuple[str, ...]
    """Groups whose count reached min_accumulation, sorted for stable digests."""

    unresolved_by_action: dict[str, int]
    """required-action -> count of events where it was left unresolved."""

    per_event_unresolved: list[tuple[str, tuple[str, ...]]]
    """Per-event detail: (event_id, sorted tuple of unresolved required
    actions). Empty if no event had unresolved actions."""


def unresolved_flag_accumulation(
    events: Iterable[dict[str, Any]],
    *,
    required_actions_extractor: Callable[[dict[str, Any]], Iterable[str]] | None = None,
    actions_taken_extractor: Callable[[dict[str, Any]], Iterable[str]] | None = None,
    group_key_extractor: Callable[[dict[str, Any]], str] | None = None,
    event_id_extractor: Callable[[dict[str, Any]], str] | None = None,
    min_accumulation: int = DEFAULT_MIN_ACCUMULATION,
) -> UnresolvedFlagResult:
    """
    Detect accumulation of unresolved required actions across a population.

    Args:
        events: An iterable of Detection Event records (dicts). Each record
            should carry `required_actions` and `actions_taken` arrays per the
            Decision Events schema. Missing fields are treated as empty lists.
        required_actions_extractor: Returns the iterable of required actions for
            an event. Defaults to reading the `required_actions` field.
        actions_taken_extractor: Returns the iterable of actions taken for an
            event. Defaults to reading the `actions_taken` field.
        group_key_extractor: Returns the accumulation grouping key for an event.
            Defaults to `subject_id`, falling back to `tenant_id`, then the
            literal "__ungrouped__".
        event_id_extractor: Returns a stable identifier for the event (used in
            per-event detail). Defaults to reading `event_id`.
        min_accumulation: Per-group count at or above which the group is
            flagged. Default 2. Per Charter v1.1, customers tighten (lower
            toward 1); a value above the baseline is refused.

    Returns:
        An UnresolvedFlagResult with the accumulating groups, per-group counts,
        per-action counts, and full per-event detail.

    Raises:
        ValueError: If min_accumulation < 1.
        ValueError: If min_accumulation exceeds DEFAULT_MIN_ACCUMULATION
            (loosening detection is refused at the schema level).
    """
    if min_accumulation < 1:
        raise ValueError(f"min_accumulation must be >= 1; got {min_accumulation}")
    if min_accumulation > DEFAULT_MIN_ACCUMULATION:
        raise ValueError(
            f"min_accumulation={min_accumulation} loosens detection beyond the "
            f"AILedger baseline of {DEFAULT_MIN_ACCUMULATION}. Customers tighten "
            f"(lower toward 1), never loosen (Charter v1.1)."
        )

    req_extract = required_actions_extractor or (lambda e: e.get("required_actions") or [])
    taken_extract = actions_taken_extractor or (lambda e: e.get("actions_taken") or [])
    id_extract = event_id_extractor or (lambda e: str(e.get("event_id", "")))
    group_extract = group_key_extractor or (
        lambda e: str(e.get("subject_id") or e.get("tenant_id") or "__ungrouped__")
    )

    total_events = 0
    unresolved_event_count = 0
    accumulation_by_group: dict[str, int] = {}
    unresolved_by_action: dict[str, int] = {}
    per_event_unresolved: list[tuple[str, tuple[str, ...]]] = []

    for event in events:
        total_events += 1
        required = set(req_extract(event))
        taken = set(taken_extract(event))
        unresolved = required - taken
        if unresolved:
            unresolved_event_count += 1
            group = group_extract(event)
            accumulation_by_group[group] = accumulation_by_group.get(group, 0) + 1
            sorted_unresolved = tuple(sorted(unresolved))
            per_event_unresolved.append((id_extract(event), sorted_unresolved))
            for action in unresolved:
                unresolved_by_action[action] = unresolved_by_action.get(action, 0) + 1

    accumulating_groups = tuple(
        sorted(g for g, c in accumulation_by_group.items() if c >= min_accumulation)
    )
    rate = unresolved_event_count / total_events if total_events > 0 else 0.0

    return UnresolvedFlagResult(
        min_accumulation=min_accumulation,
        flagged=len(accumulating_groups) > 0,
        total_events=total_events,
        unresolved_event_count=unresolved_event_count,
        rate=rate,
        accumulation_by_group=accumulation_by_group,
        accumulating_groups=accumulating_groups,
        unresolved_by_action=unresolved_by_action,
        per_event_unresolved=per_event_unresolved,
    )
