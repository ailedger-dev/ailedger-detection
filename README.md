# ailedger-detection

Open-source statistical primitives for AILedger Detection Event chains.

**Version:** 0.3.0
**License:** Apache 2.0 (per posture v2; customer + regulator + adversarial-reviewer auditable)
**Python:** 3.10+
**Author:** Jake Joyner / Joyner Ventures LLC
**Charter:** https://ailedger.dev/charter

---

## What this is

The Apache-2.0 Detection layer of AILedger. The open-source artifact that customers, regulators, and adversarial reviewers can read, audit, and run independently against any Detection Event chain.

Per the AILedger Charter v1.1 anti-theater commitments:
- Detection thresholds are anchored to published standards (EEOC four-fifths rule = 0.8; FDIC SR 11-7 / OCC 2011-12 PSI ladder)
- Customers TIGHTEN thresholds (toward stricter detection), never loosen
- Per-customer detection disablement is REFUSED at the schema level
- "Compliance mode" that bypasses detection is REFUSED at the schema level

This package is the substrate that makes those commitments verifiable.

## What v0.3.0 ships

Seven production statistical primitives:

- `disparate_impact_ratio` — four-fifths-rule baseline (EEOC Uniform Guidelines 29 CFR 1607). Returns minimum cross-group positive-outcome ratio + flag.
- `statistical_parity_difference` — absolute difference between group positive-outcome rates. Complementary to disparate impact ratio (stable when one group has very low rates).
- `model_drift_between_versions` — Population Stability Index (PSI) across decision type distribution between two cohorts. FDIC/OCC threshold ladder.
- `tool_call_unauthorized_action_rate` — agent-overreach / confabulation detector for tool-using LLM systems (the `actions_taken − required_actions` diff).
- `confidence_stratified_outcome_analysis` — **(new in 0.3.0)** disparate impact computed *per confidence bucket*. Surfaces models that clear the four-fifths rule in aggregate while their high-confidence decisions concentrate adverse outcomes on a protected class.
- `unresolved_flag_accumulation` — **(new in 0.3.0)** accumulation of unresolved required actions (`required_actions − actions_taken`) per subject/tenant. A single gap may be in flight; accumulation is the audit signal.
- `subject_repeated_decision_patterns` — **(new in 0.3.0)** subjects accumulating repeated adverse decisions across events (the "three strikes" disparate-treatment pattern).

LARP audit-spine layer **(new in 0.3.0)**:

- `warrant_detection_result` — wrap any detection result as a **warranted Decision**: the result is the 1-cell, and the `Warrant` (cited standard, observed value, threshold, and the *rejected alternatives*) is the 2-cell that justifies it. The log of warranted Decisions is the auditable product. Flag suppression is refused structurally: `WarrantedDecision` re-checks that `warrant.flagged == result.flagged` at construction, so no warrant can claim "clean" over a flagged result.

Typed contracts:

- `DetectionEvent` and `InferredDetectionEvent` TypedDicts mirroring `ledger.decision_events` schema + the 2026-05-18 inferred-event extension (matches `@ailedger/sdk` TypeScript types)
- `ExtractorMethod` Literal type for the 4-rung method ladder
- `ProtectedClassCollectionMethod` Literal type (`direct` / `inferred` / `blind`)

TypedDict is structural, so existing callers passing untyped `dict` continue to work; the types add static-analysis + IDE assistance without runtime cost.

The three v0.2.0 stubs (`confidence_stratified_outcome_analysis`, `unresolved_flag_accumulation`, `subject_repeated_decision_patterns`) are now fully implemented and no longer raise `NotImplementedError`.

## Test coverage

v0.3.0 ships:

- `tests/test_disparate_impact.py` — disparate impact: baseline / threshold / borderline / custom-tighter / single-group / no-positive-outcomes / invalid-threshold / inspectable-stats
- `tests/test_parity.py` — statistical parity: parity / large gap / borderline / custom-threshold / invalid-threshold / disparate-impact complement / single-group
- `tests/test_drift.py` — model drift: FDIC/OCC threshold ladder / no-drift / moderate / significant / custom-extractor / empty cohorts / invalid thresholds / new-bucket / sum-to-psi
- `tests/test_tool_calls.py` — unauthorized tool-call rate
- `tests/test_confidence.py` — confidence-stratified disparate impact: per-bucket flagging / aggregate-clean-but-stratified-flags / single-group buckets / boundary validation / skip semantics / custom extractor / tighten-only
- `tests/test_unresolved_flags.py` — unresolved-action accumulation: per-group accumulation / baseline / tighten-to-one / loosening-refused / per-action+per-event detail / tenant fallback
- `tests/test_repeated_decisions.py` — subject repeated decisions: three-strikes flagging / baseline / mixed outcomes / tighten-to-two / loosening-refused / sort order / skip semantics
- `tests/test_warrant.py` — warranted Decisions: wrapping / ladder results / unknown-type refusal / anti-theater invariant (suppression refused at the schema level)

Total: 82 tests. Run with `pytest`.

## Why these specific primitives

Per `gt-lab/docs/compliance-architecture/ARCHITECTURE-detection-taxonomy.md` and the strategic pivot validation, the v0.1.0 set covers the three failure modes most likely to surface in adversarial review:

1. **Disparate impact** is the load-bearing primitive for Federal Rule 707 admissibility in employment + credit + insurance discrimination cases. The four-fifths rule is the standard a plaintiff's expert will run.
2. **Statistical parity** is the complementary view favored by EU AI Act Article 26 (deployer obligations) and academic fairness literature.
3. **Model drift** is the load-bearing primitive for FDIC-regulated AI model governance and for rare-disease research integrity (was the model that produced these decisions the same as the model under review?).

## Install

```
pip install ailedger-detection
```

## Usage

```python
from ailedger_detection import (
    disparate_impact_ratio,
    statistical_parity_difference,
    model_drift_between_versions,
)

# events: an iterable of Detection Event records (dicts) from the
# AILedger ledger.decision_events table.
# Each record is expected to carry protected_class_context (JSONB).

result = disparate_impact_ratio(
    events,
    protected_class_key="race",
    positive_outcome_predicate=lambda e: e["output"]["decision"] == "hire",
)

print(f"Ratio: {result.ratio:.3f}")
print(f"Flagged: {result.flagged}")
print(f"High group: {result.high_group} ({result.high_rate:.3f})")
print(f"Low group: {result.low_group} ({result.low_rate:.3f})")
```

### Warranted Decisions (LARP)

A bare result is a 1-cell with no 2-cell — not auditable. Wrap it so it carries
its own justification (cited standard, observed value, and the alternatives that
were considered and rejected). The log of these warranted Decisions is the
product a regulator audits:

```python
from ailedger_detection import disparate_impact_ratio, warrant_detection_result

result = disparate_impact_ratio(
    events,
    protected_class_key="race",
    positive_outcome_predicate=lambda e: e["output"]["decision"] == "hire",
)

decision = warrant_detection_result(
    result,
    decision_id="dec-2026-06-03-0001",
    rejected_alternatives=(
        "statistical_parity_difference: rejected — ratio is the Rule 707 standard here",
    ),
)

print(decision.warrant.standard)   # EEOC Uniform Guidelines four-fifths rule (29 CFR 1607)
print(decision.warrant.flagged)    # mirrors result.flagged — cannot be overridden
```

`warrant.flagged` is read directly off the result. There is no parameter to
override it, and `WarrantedDecision` re-checks the invariant at construction, so
a warrant can never claim "clean" over a flagged result — suppression is refused
at the schema level, not by policy.

## Charter posture

This package's threshold defaults follow the AILedger Charter v1.1:

| Primitive | Default threshold | Source | Customer can tighten? | Customer can loosen? |
|---|---|---|---|---|
| `disparate_impact_ratio` | 0.80 | EEOC Uniform Guidelines (29 CFR 1607) | Yes (raise toward 1.0) | **No** |
| `statistical_parity_difference` | 0.10 | AILedger default | Yes (lower toward 0) | **No** |
| `model_drift_between_versions` | PSI ≥ 0.25 = action | FDIC SR 11-7 / OCC 2011-12 | Yes (lower action threshold) | **No** |
| `tool_call_unauthorized_action_rate` | 0.0 | AILedger default (tighten upstream in `required_actions`) | Yes | **No** |
| `confidence_stratified_outcome_analysis` | 0.80 per bucket | EEOC four-fifths rule (29 CFR 1607) | Yes (raise toward 1.0) | **No** |
| `unresolved_flag_accumulation` | 2 per group | AILedger default | Yes (lower toward 1) | **No** |
| `subject_repeated_decision_patterns` | 3 per subject | AILedger default | Yes (lower toward 2) | **No** |

A consumer call site that passes a looser threshold receives a `ValueError`. The refusal is structural, not policy. For the count-based primitives (`unresolved_flag_accumulation`, `subject_repeated_decision_patterns`), "tighten" means *lowering* the count so detection fires sooner; a value above the baseline is refused.

## Spec linkage

- Detection Event schema: `proxy/migrations/20260512_decision_events_schema.sql`
- Param canonicalization spec: `gt-lab/docs/param-canonicalization-spec-v1.md`
- Detection taxonomy: `gt-lab/docs/compliance-architecture/ARCHITECTURE-detection-taxonomy.md`
- Charter: [ailedger-dev/charter/CHARTER.md](https://github.com/ailedger-dev/charter/blob/main/CHARTER.md)

## Testing

```
cd detection
pip install -e ".[test]"
pytest
```

## What this is NOT

- Not a turn-key AI compliance product. The primitives are the substrate; consumers apply them against their own Detection Event streams with their own decision-domain-specific predicates.
- Not the integrity layer. The hash chain lives in `proxy/migrations/`; this package does not verify chain integrity, only statistics over the events.
- Not the only package. The producer-side SDK is at `sdk/` (`@ailedger/sdk` v0.1.0 TypeScript).

## Repo posture (separate repo planned)

Per AILedger posture v2 (`gt-lab/memory/project_ailedger_posture_v2_2026_05_12.md`), the Detection layer ships as a SEPARATE public repo from day one. v0.1.0 lives in the ailedger monorepo for development convenience; extraction to `github.com/jakejjoyner/ailedger-detection` (or canonical equivalent) is bead `hq-77p` work and gates the public-differentiation claim.

The Apache 2.0 license is unchanged when the package extracts to its own repo. Issue tracking and contributions migrate at extraction time.

## Authority

- Spec: `gt-lab/docs/param-canonicalization-spec-v1.md`
- Posture: `gt-lab/memory/project_ailedger_posture_v2_2026_05_12.md`
- Charter: [ailedger-dev/charter/CHARTER.md](https://github.com/ailedger-dev/charter/blob/main/CHARTER.md)
- Competitive matrix: `gt-lab/docs/ailedger-competitive-matrix-v2.md`
