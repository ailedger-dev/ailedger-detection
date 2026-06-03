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

v0.3.0 is the FULL Detection layer: seven production primitives, the LARP warrant
spine, the orchestration engine, the query interface, and structural anti-theater
enforcement.

**Seven production statistical primitives** (the three stubs from v0.2.0 are now
implemented):

Bias / disparate impact:
- `disparate_impact_ratio` — four-fifths-rule baseline (EEOC Uniform Guidelines 29 CFR 1607). Minimum cross-group positive-outcome ratio + flag.
- `statistical_parity_difference` — absolute difference between group positive-outcome rates. Complementary to disparate impact ratio (stable when one group has very low rates).
- `confidence_stratified_outcome_analysis` — runs the four-fifths test *within each confidence stratum*, surfacing bias concentrated in high-confidence decisions that whole-population ratio masks.

Drift:
- `model_drift_between_versions` — Population Stability Index (PSI) across the decision-type distribution between two cohorts. FDIC/OCC threshold ladder.

Agent / tool-use:
- `tool_call_unauthorized_action_rate` — agent-overreach / confabulation detector: rate of events whose `actions_taken` fall outside the `required_actions` policy envelope.

Compliance gaps:
- `unresolved_flag_accumulation` — rate at which raised flags lack the remediation `required_actions` demand (the `required − taken` gap regulators audit).
- `subject_repeated_decision_patterns` — pattern-of-practice detection: subjects accumulating repeated adverse decisions across a cohort.

**LARP warrant spine.** Every primitive result exposes `.to_warrant()`, producing
a `Warrant` that memorializes the run: the result is a **1-cell** (the decision),
and the evidence + the **rejected thresholds** are the **2-cell** ("chose this
threshold rather than a looser one, because <standard>"). Each warrant carries a
content digest (`warrant_digest`) over its substantive cells — deterministic
across wall-clock time, so a verifier can re-run a detection and confirm the
warrant's content. This is the auditable spine the Interchange (fleet federation)
and the Grafana LARP monitor consume. See [LARP warrant](#larp-warrant) below.

**Detection engine.** `DetectionEngine` runs a configured set of primitives over a
cohort and returns a digest-chained `DetectionRun` bundling one warrant per
primitive.

**Query interface.** `EventQuery` is a fluent, immutable filter over a Detection
Event stream (`tenant`, `system`, `decision_type`, `model_version`, `between`,
`where`) for building the cohorts primitives consume. Subclass it to push
predicates down into SQL against `ledger.decision_events`.

Typed contracts:

- `DetectionEvent` and `InferredDetectionEvent` TypedDicts mirroring `ledger.decision_events` schema + the 2026-05-18 inferred-event extension (matches `@ailedger/sdk` TypeScript types)
- `ExtractorMethod` Literal type for the 4-rung method ladder
- `ProtectedClassCollectionMethod` Literal type (`direct` / `inferred` / `blind`)

TypedDict is structural, so existing callers passing untyped `dict` continue to work; the types add static-analysis + IDE assistance without runtime cost.

## Anti-theater enforcement (structural, not policy)

The Charter v1.1 anti-theater commitments are enforced by the *type*, not by
configuration a customer can override:

- **Tighten-only thresholds.** `thresholds.py` is the single source of truth for
  every threshold's baseline, anchoring standard, and tighten direction. A call
  site that passes a *looser* threshold receives a `ValueError` — e.g.
  `disparate_impact_ratio(..., threshold=0.7)` is refused because 0.7 loosens
  detection below the EEOC four-fifths baseline of 0.8.
- **No disablement surface.** `DetectionEngine` / `DetectionSpec` have no
  `enabled` flag, no `compliance_mode`, no per-customer "skip" knob. Any
  suppression-flavored config key (`disable`, `compliance_mode`, `bypass`,
  `suppress`, …) raises `DetectionSuppressionError` at construction. The only way
  to reduce scope is to omit a primitive — and that absence is recorded in the
  run (the set of warrants is the record of exactly what was checked).

## Test coverage

v0.3.0 ships **111 tests** across the primitives, the warrant spine, the threshold
registry, the engine, and the query interface:

- `tests/test_disparate_impact.py`, `tests/test_parity.py`, `tests/test_drift.py`, `tests/test_tool_calls.py` — the four bias/drift/agent primitives (baselines, borderlines, custom-tighter thresholds, anti-theater refusal of loosening, single-group / empty-cohort edge cases, inspectable stats).
- `tests/test_confidence.py` — confidence-stratified disparate impact (per-stratum flagging, non-evaluable strata, `min_group_size`, boundary validation, warrant).
- `tests/test_unresolved_flags.py` — unresolved-flag accumulation (required-minus-taken gap, denominator excludes unflagged events, per-group breakdown, warrant).
- `tests/test_repeated_decisions.py` — subject pattern-of-practice (threshold, favorable decisions excluded, ranking, tighten/refuse, warrant).
- `tests/test_warrant.py` — digest determinism across timestamps, tamper detection, serialization.
- `tests/test_thresholds.py` — tighten-only enforcement in both directions, rejected-threshold construction.
- `tests/test_engine.py` — suppression-key refusal, one-warrant-per-spec, deterministic run digest, shared cohort, JSON round-trip.
- `tests/test_query.py` — filter composition, model-version cohort split for drift, time-window bounds, reusability from a one-shot iterator.

Run with `pytest`.

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

## LARP warrant

Every result memorializes itself. The warrant is the auditable record — result as
1-cell, evidence + rejected thresholds as 2-cell — with a content digest.

```python
warrant = result.to_warrant()

print(warrant.flagged)            # the 1-cell decision
print(warrant.standard)           # "EEOC Uniform Guidelines four-fifths rule (29 CFR 1607)"
print(warrant.threshold)          # 0.8
for rt in warrant.rejected_thresholds:   # the 2-cell: what was refused, and why
    print(rt.value, "—", rt.reason)      # "< 0.8 — would loosen detection past ..."

warrant.verify_digest()           # True — content matches the digest
record = warrant.to_dict()        # JSON-friendly audit-ledger record
```

## Detection engine

Run a fixed set of primitives over a cohort; get back one warrant per primitive,
chained by a run digest. There is no way to disable a registered detection.

```python
from ailedger_detection import DetectionEngine, DetectionSpec, EventQuery

# Build a cohort with the query interface.
cohort = EventQuery(events).tenant("t-acme").decision_type("hire").cohort()

engine = DetectionEngine([
    DetectionSpec(
        name="disparate_impact",
        fn=disparate_impact_ratio,
        kwargs={
            "protected_class_key": "race",
            "positive_outcome_predicate": lambda e: e["output"]["decision"] == "hire",
        },
    ),
])

run = engine.run(cohort)
print(run.flagged)                # any constituent warrant flagged
print(run.run_digest)             # chains the run into the audit ledger
record = run.to_dict()            # the full warranted run, JSON-serializable

# Attempting to suppress detection is refused structurally:
DetectionSpec(name="x", fn=disparate_impact_ratio, kwargs={"compliance_mode": True})
# -> DetectionSuppressionError
```

## Charter posture

This package's threshold defaults follow the AILedger Charter v1.1:

| Primitive | Default threshold | Source | Customer can tighten? | Customer can loosen? |
|---|---|---|---|---|
| `disparate_impact_ratio` | 0.80 | EEOC Uniform Guidelines (29 CFR 1607) | Yes (raise toward 1.0) | **No** |
| `statistical_parity_difference` | 0.10 | AILedger default | Yes (lower toward 0) | **No** |
| `confidence_stratified_outcome_analysis` | 0.80 | EEOC four-fifths, per stratum | Yes (raise toward 1.0) | **No** |
| `model_drift_between_versions` | PSI ≥ 0.25 = action | FDIC SR 11-7 / OCC 2011-12 | Yes (lower action threshold) | **No** |
| `tool_call_unauthorized_action_rate` | 0.0 | FDIC model-outside-scope; EU AI Act Art. 14 | Already at floor (tighten upstream in `required_actions`) | **No** |
| `unresolved_flag_accumulation` | 0.0 | EU AI Act Art. 14; NIST AI RMF GOVERN-1.5 | Already at floor | **No** |
| `subject_repeated_decision_patterns` | 3 (adverse count) | AILedger default (cf. Federal Rule 707) | Yes (lower toward 1) | **No** |

A consumer call site that passes a looser threshold receives a `ValueError`. The
refusal is structural, not policy — see `thresholds.py` for the single source of
truth and `enforce_tighten_only`.

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
