"""
Tool-call unauthorized-action rate — agent-overreach / confabulation primitive.

For tool-using LLM agent systems, a Decision Event records the tool the model
invoked. Customers encode policy by populating `required_actions` with the
set of allowed tools (or per-event allowed actions). The model's actual
invocation lands in `actions_taken`. The diff:

    unauthorized = set(actions_taken) - set(required_actions)

is the set of model-driven actions that fell outside the policy-allowed
envelope. The rate of events with a non-empty unauthorized set is the primitive
this module returns.

Use case: an LLM agent is policy-restricted to `play_media`, `pause_media`,
and `set_volume`. The model gets a vague prompt ("play it everywhere") and
fabricates a tool call to a tool that was not on the allowed list, or
invokes the allowed tool with arguments that bypass policy controls. The
unauthorized-action rate surfaces this without requiring access to raw inputs.

This primitive intentionally measures only the set-difference of declared
policy vs. taken actions. It does not attempt to evaluate whether the
arguments to an allowed tool were themselves grounded in user input — that's
the role of a separate `tool_call_argument_grounding` primitive (v0.3.0+
target; requires the `detection.replay` or `detection.perturb` extractor rung
to obtain raw inputs).

Regulatory anchors:
- FDIC SR 11-7 and OCC 2011-12: "model use outside of intended scope" is
  one of the documented model risk categories. An agent invoking unauthorized
  tools is model-outside-scope by definition.
- EU AI Act Article 14 (human oversight): agent action outside the policy
  envelope is a signal that human-in-the-loop controls have been bypassed
  or were never wired correctly.
- NIST AI RMF 1.0 MAP-3 and MEASURE-2.6: AI system monitoring outside
  intended operational scope.

Threshold convention: AILedger ships with a default threshold of 0.0 (any
unauthorized action across the event population is flagged). Customers tighten
policy by adding to `required_actions` upstream (not by tuning this threshold).
The threshold parameter exists for API symmetry with other primitives; per
Charter v1.1, customers tighten, never loosen.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from ailedger_detection._coverage import callable_identity
from ailedger_detection.thresholds import (
    enforce_tighten_only,
    get_standard,
    rejected_thresholds_for,
)
from ailedger_detection.warrant import Warrant

# Default: any unauthorized action flags the population. Customers tighten
# policy in required_actions, not by raising this threshold.
UNAUTHORIZED_ACTION_BASELINE: float = 0.0

_PRIMITIVE = "tool_call_unauthorized_action_rate"


@dataclass(frozen=True)
class UnauthorizedToolCallResult:
    """Result of a tool-call unauthorized-action-rate calculation."""

    rate: float
    """Fraction of events with at least one unauthorized action. 0 to 1."""

    threshold: float
    """Threshold above which the population is flagged. Default 0.0."""

    flagged: bool
    """True if rate > threshold."""

    total_events: int
    """Total events considered (after extractor filtering)."""

    unauthorized_event_count: int
    """Events with at least one action in actions_taken not in required_actions."""

    unauthorized_actions_by_tool: dict[str, int]
    """Per-tool count of unauthorized invocations. Sums to total unauthorized
    action invocations (which may exceed unauthorized_event_count if a single
    event contained multiple unauthorized actions)."""

    per_event_unauthorized: list[tuple[str, tuple[str, ...]]]
    """Per-event detail: (event_id, sorted tuple of unauthorized actions).
    Sorted tuple is stable for downstream digest/hashing. Empty list if no
    events had unauthorized actions."""

    policy_extractor_id: str
    """Module-qualified identity of the required-actions (policy) extractor — the
    real loosening surface for this primitive. Recorded so an auditor sees *which*
    policy definition produced the unauthorized set (F2)."""

    actions_extractor_id: str
    """Module-qualified identity of the actions-taken extractor (F2)."""

    def to_warrant(self, *, created_at: str | None = None) -> Warrant:
        """Memorialize this result as a LARP warrant (1-cell + 2-cell)."""
        std = get_standard(_PRIMITIVE)
        return Warrant.build(
            primitive=_PRIMITIVE,
            result={
                "flagged": self.flagged,
                "metric": "unauthorized_action_rate",
                "value": self.rate,
            },
            evidence={
                "total_events": self.total_events,
                "unauthorized_event_count": self.unauthorized_event_count,
                "unauthorized_actions_by_tool": dict(self.unauthorized_actions_by_tool),
                "policy_extractor_id": self.policy_extractor_id,
                "actions_extractor_id": self.actions_extractor_id,
                "per_event_unauthorized": [
                    [event_id, list(actions)] for event_id, actions in self.per_event_unauthorized
                ],
            },
            standard=std.standard,
            threshold=self.threshold,
            rejected_thresholds=rejected_thresholds_for(_PRIMITIVE, self.threshold),
            created_at=created_at,
        )


def tool_call_unauthorized_action_rate(
    events: Iterable[dict[str, Any]],
    *,
    required_actions_extractor: Callable[[dict[str, Any]], Iterable[str]] | None = None,
    actions_taken_extractor: Callable[[dict[str, Any]], Iterable[str]] | None = None,
    event_id_extractor: Callable[[dict[str, Any]], str] | None = None,
    threshold: float = UNAUTHORIZED_ACTION_BASELINE,
) -> UnauthorizedToolCallResult:
    """
    Compute the rate of events with model-driven actions outside the policy
    envelope encoded in `required_actions`.

    Args:
        events: An iterable of Detection Event records (dicts). Each record
            should carry `required_actions` and `actions_taken` arrays per the
            Decision Events schema. Events missing either field are treated as
            having an empty list for that field.
        required_actions_extractor: Function returning the iterable of allowed
            actions for an event. Defaults to reading the `required_actions`
            top-level field.
        actions_taken_extractor: Function returning the iterable of actions the
            model actually took. Defaults to reading the `actions_taken`
            top-level field.
        event_id_extractor: Function returning a stable identifier for the
            event (used in per-event detail). Defaults to reading the
            `event_id` field; falls back to the empty string.
        threshold: Population-level rate above which the result is flagged.
            Default 0.0 (any unauthorized event flags). Per Charter v1.1,
            customers tighten policy upstream (in `required_actions`), never
            loosen detection by raising this knob.

    Returns:
        An UnauthorizedToolCallResult with the rate, per-tool counts, and full
        per-event detail for inspectability.

    Raises:
        ValueError: If threshold is out of range or above the 0.0 baseline.
            Raising this knob would suppress detection of unauthorized actions,
            which the Charter forbids; the refusal is structural. Customers
            tighten policy upstream in `required_actions`, never here.

    Example:
        >>> events = [
        ...     {
        ...         "event_id": "evt-1",
        ...         "required_actions": ["tool.play_media", "tool.pause_media"],
        ...         "actions_taken": ["tool.play_media"],
        ...     },
        ...     {
        ...         "event_id": "evt-2",
        ...         "required_actions": ["tool.play_media"],
        ...         "actions_taken": ["tool.play_media", "tool.unlock_door"],
        ...     },
        ... ]
        >>> result = tool_call_unauthorized_action_rate(events)
        >>> result.flagged
        True
        >>> result.rate
        0.5
        >>> result.unauthorized_actions_by_tool
        {'tool.unlock_door': 1}
    """
    threshold = enforce_tighten_only(_PRIMITIVE, threshold)

    req_extract = required_actions_extractor or (lambda e: e.get("required_actions") or [])
    taken_extract = actions_taken_extractor or (lambda e: e.get("actions_taken") or [])
    id_extract = event_id_extractor or (lambda e: str(e.get("event_id", "")))

    total_events = 0
    unauthorized_event_count = 0
    unauthorized_by_tool: dict[str, int] = {}
    per_event_unauthorized: list[tuple[str, tuple[str, ...]]] = []

    for event in events:
        total_events += 1
        required = set(req_extract(event))
        taken = set(taken_extract(event))
        unauthorized = taken - required
        if unauthorized:
            unauthorized_event_count += 1
            sorted_unauth = tuple(sorted(unauthorized))
            per_event_unauthorized.append((id_extract(event), sorted_unauth))
            for action in unauthorized:
                unauthorized_by_tool[action] = unauthorized_by_tool.get(action, 0) + 1

    # Define rate as 0.0 on empty input rather than raising; an empty population
    # is degenerate but a callable primitive over an empty stream should not
    # itself be a failure mode (callers may stream from a filtered query that
    # legitimately produced zero results during a quiet window).
    rate = unauthorized_event_count / total_events if total_events > 0 else 0.0

    return UnauthorizedToolCallResult(
        rate=rate,
        threshold=threshold,
        flagged=rate > threshold,
        total_events=total_events,
        unauthorized_event_count=unauthorized_event_count,
        unauthorized_actions_by_tool=unauthorized_by_tool,
        per_event_unauthorized=per_event_unauthorized,
        policy_extractor_id=callable_identity(req_extract),
        actions_extractor_id=callable_identity(taken_extract),
    )
