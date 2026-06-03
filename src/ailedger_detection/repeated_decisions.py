"""
Subject-level repeated-decision pattern detection.

Detects subjects (HMAC-pseudonymized `subject_id`) who accumulate adverse
outcomes across multiple Detection Events. Each decision may be individually
defensible; the *pattern* is the bias signal.

Use case: an applicant rejected three times across a six-month window by the
same employer's AI screening system. No single rejection is dispositive, but a
subject crossing the repetition threshold is exactly what a Federal Rule 707
expert reconstructs from the ledger.

Flagging convention: a subject whose adverse-decision count reaches
`min_repetitions` is flagged. AILedger ships `min_repetitions = 3` (the
canonical "three strikes" pattern in the disparate-treatment literature). Per
Charter v1.1 customers TIGHTEN (lower toward 2, flagging sooner), never loosen —
a value above the baseline is refused at the call boundary.

What "adverse" means is domain-specific and supplied by the caller via
`adverse_outcome_predicate`, mirroring the `positive_outcome_predicate`
contract used by `disparate_impact_ratio`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

# AILedger default: three adverse decisions on the same subject is the pattern.
# Customers tighten (lower toward 2), never loosen.
DEFAULT_MIN_REPETITIONS: int = 3


@dataclass(frozen=True)
class SubjectPattern:
    """Repeated-decision statistics for a single subject."""

    subject_id: str
    total_decisions: int
    adverse_decisions: int
    event_ids: tuple[str, ...]
    """Stable, input-order tuple of the adverse event ids for this subject."""


@dataclass(frozen=True)
class RepeatedDecisionResult:
    """Result of a subject-level repeated-decision pattern analysis."""

    min_repetitions: int
    """Adverse-decision count at or above which a subject is flagged."""

    flagged: bool
    """True if any subject reached min_repetitions adverse decisions."""

    flagged_subjects: tuple[SubjectPattern, ...]
    """Subjects meeting the pattern, sorted by adverse count (desc) then id."""

    subjects_examined: int
    """Distinct subjects seen in the population."""

    skipped_no_subject: int
    """Events skipped because they carried no subject identifier."""


def subject_repeated_decision_patterns(
    events: Iterable[dict[str, Any]],
    *,
    adverse_outcome_predicate: Callable[[dict[str, Any]], bool],
    subject_id_extractor: Callable[[dict[str, Any]], str | None] | None = None,
    event_id_extractor: Callable[[dict[str, Any]], str] | None = None,
    min_repetitions: int = DEFAULT_MIN_REPETITIONS,
) -> RepeatedDecisionResult:
    """
    Detect subjects with repeated adverse decisions.

    Args:
        events: An iterable of Detection Event records (dicts).
        adverse_outcome_predicate: Callable returning True when an event is an
            adverse decision for the subject (e.g. rejected, denied). The
            decision-domain-specific adverse-outcome definition.
        subject_id_extractor: Returns the subject identifier for an event, or
            None when absent. Defaults to reading `subject_id`. Events without a
            subject are counted in `skipped_no_subject`.
        event_id_extractor: Returns a stable event identifier (recorded in each
            SubjectPattern). Defaults to reading `event_id`.
        min_repetitions: Adverse-count at or above which a subject is flagged.
            Default 3. Per Charter v1.1, customers tighten (lower toward 2); a
            value above the baseline is refused.

    Returns:
        A RepeatedDecisionResult listing flagged subjects with their counts and
        contributing event ids.

    Raises:
        ValueError: If min_repetitions < 2 (a single decision is not a pattern).
        ValueError: If min_repetitions exceeds DEFAULT_MIN_REPETITIONS
            (loosening detection is refused at the schema level).
    """
    if min_repetitions < 2:
        raise ValueError(
            f"min_repetitions must be >= 2 (a single decision is not a pattern); "
            f"got {min_repetitions}"
        )
    if min_repetitions > DEFAULT_MIN_REPETITIONS:
        raise ValueError(
            f"min_repetitions={min_repetitions} loosens detection beyond the "
            f"AILedger baseline of {DEFAULT_MIN_REPETITIONS}. Customers tighten "
            f"(lower toward 2), never loosen (Charter v1.1)."
        )

    id_extract = event_id_extractor or (lambda e: str(e.get("event_id", "")))
    subject_extract = subject_id_extractor or (lambda e: e.get("subject_id"))

    total_by_subject: dict[str, int] = {}
    adverse_by_subject: dict[str, int] = {}
    adverse_events_by_subject: dict[str, list[str]] = {}
    skipped_no_subject = 0

    for event in events:
        raw_subject = subject_extract(event)
        if raw_subject is None or raw_subject == "":
            skipped_no_subject += 1
            continue
        subject = str(raw_subject)
        total_by_subject[subject] = total_by_subject.get(subject, 0) + 1
        if adverse_outcome_predicate(event):
            adverse_by_subject[subject] = adverse_by_subject.get(subject, 0) + 1
            adverse_events_by_subject.setdefault(subject, []).append(id_extract(event))

    flagged_subjects = tuple(
        sorted(
            (
                SubjectPattern(
                    subject_id=subject,
                    total_decisions=total_by_subject[subject],
                    adverse_decisions=count,
                    event_ids=tuple(adverse_events_by_subject.get(subject, [])),
                )
                for subject, count in adverse_by_subject.items()
                if count >= min_repetitions
            ),
            key=lambda p: (-p.adverse_decisions, p.subject_id),
        )
    )

    return RepeatedDecisionResult(
        min_repetitions=min_repetitions,
        flagged=len(flagged_subjects) > 0,
        flagged_subjects=flagged_subjects,
        subjects_examined=len(total_by_subject),
        skipped_no_subject=skipped_no_subject,
    )
