"""
Decision-Event query interface — cohort selection over Detection Event streams.

The statistical primitives operate on *cohorts*: a disparate-impact run wants
"hire decisions for tenant T in Q2", a drift run wants two cohorts split by
model version. This module is the small, dependency-free query layer that builds
those cohorts from a stream of Detection Event dicts.

`EventQuery` is a fluent, immutable filter: each method returns a new query with
one more predicate, and a terminal (`cohort`, `count`, iteration) applies them.
The in-memory reference implementation materializes its source once so a query
can be reused and split (e.g. into reference/current cohorts) without exhausting
an iterator.

It is deliberately a thin reference implementation over `Iterable[dict]`. A
database-backed deployment subclasses `EventQuery` and overrides `_evaluate()`
(or the individual filters) to push predicates down into SQL against
`ledger.decision_events` — the fluent surface stays identical so primitive call
sites do not change.

Timestamp filtering assumes RFC3339 / ISO-8601 UTC strings (the Detection Event
`timestamp` shape), for which lexicographic comparison is chronological. Pass
`timestamp_extractor` if your events carry the instant elsewhere.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from typing import Any

Predicate = Callable[[dict[str, Any]], bool]


class EventQuery:
    """An immutable, chainable filter over a Detection Event stream."""

    def __init__(
        self,
        events: Iterable[dict[str, Any]],
        *,
        _predicates: tuple[Predicate, ...] = (),
        _materialized: tuple[dict[str, Any], ...] | None = None,
    ) -> None:
        # Materialize once so the query is reusable and splittable. Subclasses
        # backed by a database should bypass this by overriding _evaluate().
        if _materialized is not None:
            self._events = _materialized
        else:
            self._events = tuple(events)
        self._predicates = _predicates

    def _with(self, predicate: Predicate) -> EventQuery:
        return type(self)(
            (),
            _predicates=(*self._predicates, predicate),
            _materialized=self._events,
        )

    # --- Filters -------------------------------------------------------------

    def where(self, predicate: Predicate) -> EventQuery:
        """Add an arbitrary predicate."""
        return self._with(predicate)

    def field_equals(self, key: str, value: Any) -> EventQuery:
        """Filter to events whose top-level `key` equals `value`."""
        return self._with(lambda e: e.get(key) == value)

    def tenant(self, tenant_id: str) -> EventQuery:
        return self.field_equals("tenant_id", tenant_id)

    def system(self, system_id: str) -> EventQuery:
        return self.field_equals("system_id", system_id)

    def decision_type(self, decision_type: str) -> EventQuery:
        return self.field_equals("decision_type", decision_type)

    def model_version(self, model_version: str) -> EventQuery:
        return self.field_equals("model_version", model_version)

    def between(
        self,
        start: str | None = None,
        end: str | None = None,
        *,
        timestamp_extractor: Callable[[dict[str, Any]], str | None] | None = None,
    ) -> EventQuery:
        """
        Filter to events with `start <= timestamp < end` (RFC3339 UTC strings).

        Either bound may be None (open-ended). Start is inclusive, end exclusive.
        """
        extract = timestamp_extractor or (lambda e: e.get("timestamp"))

        def predicate(event: dict[str, Any]) -> bool:
            ts = extract(event)
            if ts is None:
                return False
            if start is not None and ts < start:
                return False
            if end is not None and ts >= end:
                return False
            return True

        return self._with(predicate)

    # --- Terminals -----------------------------------------------------------

    def _evaluate(self) -> Iterator[dict[str, Any]]:
        for event in self._events:
            if all(p(event) for p in self._predicates):
                yield event

    def cohort(self) -> list[dict[str, Any]]:
        """Materialize the matching events as a list."""
        return list(self._evaluate())

    def count(self) -> int:
        """Count matching events without retaining them."""
        return sum(1 for _ in self._evaluate())

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return self._evaluate()
