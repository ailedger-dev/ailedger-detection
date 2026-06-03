"""
Subject-level repeated-decision pattern detection — pattern-of-practice primitive.

A single adverse decision may be individually defensible; the bias signal is the
*pattern* — the same subject receiving adverse decisions again and again from the
same system. An applicant rejected three times in six months by one employer's
screening model is the canonical example: each rejection might survive scrutiny
alone, the repetition is what a Federal Rule 707 pattern-of-practice analysis
targets.

Design (resolving the v0.2.0 stub's open questions):

- **Subject identity**: events are grouped by an HMAC-pseudonymized `subject_id`
  (caller-overridable via `subject_id_extractor`). Cross-reference resolution
  (linking different ids to one person) is explicitly out of scope — that is an
  upstream identity-resolution concern; this primitive trusts the id it is given.
- **Pattern definition**: a subject is flagged when its count of *adverse*
  decisions reaches the threshold. "Adverse" is caller-defined via
  `adverse_outcome_predicate` (the decision-domain's negative outcome). Count of
  adverse is the chosen pattern metric; it is robust to interleaved favorable
  decisions in a way a "consecutive adverse" rule is not.
- **Window**: scope the time window upstream with `EventQuery` (see query.py);
  the primitive counts over whatever cohort it receives.

Threshold is a count (default 3), tighten-only: lowering it (catching shorter
patterns) is allowed; raising it (ignoring patterns) is structurally refused.
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

_PRIMITIVE = "subject_repeated_decision_patterns"


@dataclass(frozen=True)
class SubjectPattern:
    """Per-subject decision counts."""

    subject_id: str
    adverse_count: int
    total_count: int
    flagged: bool
    """True if adverse_count >= threshold."""


@dataclass(frozen=True)
class RepeatedDecisionResult:
    """Result of a subject-repeated-decision-pattern analysis."""

    flagged: bool
    """True if any subject reached the adverse-count threshold."""

    threshold: int
    """Adverse-decision count at or above which a subject is flagged."""

    total_subjects: int
    flagged_subjects: tuple[str, ...]
    """Subject ids that met the pattern threshold, most-adverse first."""

    subject_patterns: dict[str, SubjectPattern]
    """Full per-subject inspectability."""

    skipped_no_subject: int
    """Events skipped because they carried no subject id."""

    def to_warrant(self, *, created_at: str | None = None) -> Warrant:
        """Memorialize this result as a LARP warrant (1-cell + 2-cell)."""
        std = get_standard(_PRIMITIVE)
        return Warrant.build(
            primitive=_PRIMITIVE,
            result={
                "flagged": self.flagged,
                "metric": "max_subject_adverse_count",
                "flagged_subjects": list(self.flagged_subjects),
            },
            evidence={
                "total_subjects": self.total_subjects,
                "skipped_no_subject": self.skipped_no_subject,
                "subject_patterns": {
                    sid: {
                        "adverse_count": p.adverse_count,
                        "total_count": p.total_count,
                        "flagged": p.flagged,
                    }
                    for sid, p in self.subject_patterns.items()
                },
            },
            standard=std.standard,
            threshold=float(self.threshold),
            rejected_thresholds=rejected_thresholds_for(_PRIMITIVE, float(self.threshold)),
            created_at=created_at,
        )


def subject_repeated_decision_patterns(
    events: Iterable[dict[str, Any]],
    *,
    adverse_outcome_predicate: Callable[[dict[str, Any]], bool],
    subject_id_extractor: Callable[[dict[str, Any]], str | None] | None = None,
    threshold: int | None = None,
) -> RepeatedDecisionResult:
    """
    Detect subjects accumulating repeated adverse decisions.

    Args:
        events: Detection Event records.
        adverse_outcome_predicate: Returns True for an adverse decision (the
            decision-domain's negative outcome, e.g. rejected / denied).
        subject_id_extractor: Returns an event's subject id, or None to skip.
            Defaults to reading the `subject_id` field.
        threshold: Adverse-count at or above which a subject is flagged.
            Defaults to the registry baseline (3). Tighten-only: a higher
            (laxer) value is refused structurally.

    Returns:
        A RepeatedDecisionResult with per-subject patterns and an overall flag.

    Raises:
        ValueError: If threshold loosens detection above the baseline, or is
            below the minimum of 1.
    """
    if threshold is None:
        threshold = int(get_standard(_PRIMITIVE).baseline)
    enforce_tighten_only(_PRIMITIVE, float(threshold))

    id_extract = subject_id_extractor or (lambda e: e.get("subject_id"))

    counts: dict[str, list[int]] = {}  # subject -> [adverse, total]
    skipped_no_subject = 0

    for event in events:
        subject = id_extract(event)
        if subject is None:
            skipped_no_subject += 1
            continue
        sid = str(subject)
        rec = counts.setdefault(sid, [0, 0])
        if adverse_outcome_predicate(event):
            rec[0] += 1
        rec[1] += 1

    subject_patterns: dict[str, SubjectPattern] = {}
    flagged_pairs: list[tuple[str, int]] = []
    for sid, (adverse, total) in counts.items():
        is_flagged = adverse >= threshold
        subject_patterns[sid] = SubjectPattern(
            subject_id=sid,
            adverse_count=adverse,
            total_count=total,
            flagged=is_flagged,
        )
        if is_flagged:
            flagged_pairs.append((sid, adverse))

    # Most-adverse first; ties broken by subject id for determinism.
    flagged_pairs.sort(key=lambda p: (-p[1], p[0]))
    flagged_subjects = tuple(sid for sid, _ in flagged_pairs)

    return RepeatedDecisionResult(
        flagged=bool(flagged_subjects),
        threshold=threshold,
        total_subjects=len(counts),
        flagged_subjects=flagged_subjects,
        subject_patterns=subject_patterns,
        skipped_no_subject=skipped_no_subject,
    )
