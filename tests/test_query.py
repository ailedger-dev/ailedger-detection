"""Tests for the Decision-Event query interface."""

from __future__ import annotations

from ailedger_detection.query import EventQuery


def _event(**fields: object) -> dict:
    return dict(fields)


EVENTS = [
    _event(
        event_id="e1",
        tenant_id="t1",
        system_id="s1",
        decision_type="hire",
        model_version="v1",
        timestamp="2026-01-01T00:00:00+00:00",
    ),
    _event(
        event_id="e2",
        tenant_id="t1",
        system_id="s1",
        decision_type="deny",
        model_version="v1",
        timestamp="2026-02-01T00:00:00+00:00",
    ),
    _event(
        event_id="e3",
        tenant_id="t2",
        system_id="s2",
        decision_type="hire",
        model_version="v2",
        timestamp="2026-03-01T00:00:00+00:00",
    ),
]


class TestEventQuery:
    def test_tenant_filter(self) -> None:
        ids = [e["event_id"] for e in EventQuery(EVENTS).tenant("t1")]
        assert ids == ["e1", "e2"]

    def test_chained_filters_are_and(self) -> None:
        cohort = EventQuery(EVENTS).tenant("t1").decision_type("hire").cohort()
        assert [e["event_id"] for e in cohort] == ["e1"]

    def test_model_version_split_for_drift(self) -> None:
        q = EventQuery(EVENTS)
        ref = q.model_version("v1").cohort()
        cur = q.model_version("v2").cohort()
        assert len(ref) == 2 and len(cur) == 1

    def test_between_is_start_inclusive_end_exclusive(self) -> None:
        cohort = (
            EventQuery(EVENTS)
            .between("2026-01-01T00:00:00+00:00", "2026-03-01T00:00:00+00:00")
            .cohort()
        )
        assert [e["event_id"] for e in cohort] == ["e1", "e2"]

    def test_between_open_ended(self) -> None:
        cohort = EventQuery(EVENTS).between(start="2026-02-01T00:00:00+00:00").cohort()
        assert [e["event_id"] for e in cohort] == ["e2", "e3"]

    def test_where_arbitrary_predicate(self) -> None:
        cohort = EventQuery(EVENTS).where(lambda e: e["event_id"] != "e2").cohort()
        assert [e["event_id"] for e in cohort] == ["e1", "e3"]

    def test_count(self) -> None:
        assert EventQuery(EVENTS).system("s1").count() == 2

    def test_query_is_reusable_from_iterator_source(self) -> None:
        # Source is a one-shot generator; query must still be splittable.
        q = EventQuery(e for e in EVENTS)
        assert q.tenant("t1").count() == 2
        assert q.tenant("t2").count() == 1

    def test_immutability_original_query_unchanged(self) -> None:
        base = EventQuery(EVENTS)
        _ = base.tenant("t1")
        assert base.count() == 3
