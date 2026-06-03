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

v0.3.0 is the FULL Detection layer: seven production primitives, the warrant
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

**Warrant spine.** Every primitive result exposes `.to_warrant()`, producing
a `Warrant` that memorializes the run: the **decision** itself, together with the
evidence and the **rejected thresholds** that ground it ("chose this threshold
rather than a looser one, because <standard>"). A warrant is *sound* by
construction — an empty justification (no standard, no refused alternative) and a
warrant with no recorded decision are both refused at build time. Each warrant
carries a content digest (`warrant_digest`) over its substantive fields,
deterministic across wall-clock time, so a verifier can re-run a detection and
re-derive the identical digest. The unkeyed digest is a *consistency* check, not
tamper-evidence; for tamper-evidence, runs are chained (`prev_digest`) into an
append-only ledger, or the digest can be HMAC-keyed. This is the auditable spine
the Grafana monitor consumes. See [Warrant](#warrant) below.

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
configuration a customer can override. "Structural" here means: the guarantee
survives an adversary who reads the source and reaches for the nearest bypass.

- **Tighten-only thresholds, on a sealed registry.** `thresholds.py` is the
  single source of truth for every threshold's baseline, anchoring standard, and
  tighten direction. A call site that passes a *looser* threshold receives a
  `ValueError` — e.g. `disparate_impact_ratio(..., threshold=0.7)` is refused
  because 0.7 loosens detection below the EEOC four-fifths baseline of 0.8. The
  registry is sealed (`MappingProxyType`) so a baseline cannot be mutated in
  place, and a registry-integrity self-check fails *closed* — no threshold
  validates and no warrant mints — if anyone reaches past the type to rebind it.
- **The predicate is guarded, not just the threshold.** The caller-supplied
  positive-outcome predicate and protected-class key are the real loosening
  surface — strip a label and adverse rows silently vanish. So every dropped or
  unlabeled event is *counted* (`skipped_no_group`), the cohort coverage is
  recorded, an optional `min_coverage` guard flags a thinly-labeled cohort, and
  the predicate/key identity is memorialized in the warrant. Silence is
  auditable, not invisible.
- **Sound warrants only.** A warrant must cite a non-empty standard and refuse at
  least one looser threshold (or record an explicit no-looser-alternative
  sentinel), and it must carry a recorded `flagged` decision — all enforced at
  build time. An empty-justification or decision-less warrant is unrepresentable.
- **No disablement surface.** `DetectionEngine` / `DetectionSpec` have no
  `enabled` flag, no `compliance_mode`, no per-customer "skip" knob. Any
  suppression-flavored config key (`disable`, `compliance_mode`, `bypass`,
  `suppress`, …) raises `DetectionSuppressionError` at construction. The only way
  to reduce scope is to omit a primitive — and that absence is recorded in the
  run (the set of warrants is the record of exactly what was checked).
- **No small-sample theater.** A minimum-sample gate (`min_group_size`) marks a
  trivially small cohort non-evaluable instead of manufacturing a flag from one
  or two data points — false positives that would otherwise train operators to
  ignore the dashboard.

The content digest is determinism, not tamper-evidence. The unkeyed
`warrant_digest` lets a verifier re-derive the same hash from the same content;
genuine tamper-evidence comes from chaining runs (`prev_digest`) into the
append-only ledger or HMAC-keying the digest with a signing key.

## Test coverage

v0.3.0 ships **129 tests** across the primitives, the warrant spine, the threshold
registry, the engine, the query interface, and the structural anti-theater
guarantees:

- `tests/test_disparate_impact.py`, `tests/test_parity.py`, `tests/test_drift.py`, `tests/test_tool_calls.py` — the four bias/drift/agent primitives (baselines, borderlines, custom-tighter thresholds, anti-theater refusal of loosening, single-group / empty-cohort edge cases, inspectable stats).
- `tests/test_confidence.py` — confidence-stratified disparate impact (per-stratum flagging, non-evaluable strata, `min_group_size`, boundary validation, warrant).
- `tests/test_unresolved_flags.py` — unresolved-flag accumulation (required-minus-taken gap, denominator excludes unflagged events, per-group breakdown, warrant).
- `tests/test_repeated_decisions.py` — subject pattern-of-practice (threshold, favorable decisions excluded, ranking, tighten/refuse, warrant).
- `tests/test_warrant.py` — digest determinism across timestamps, content-consistency verification, serialization.
- `tests/test_hardening.py` — structural guarantees pinned closed: sealed registry + integrity self-check, counted/recorded label drops + predicate identity, warrant soundness, HMAC keying + run chaining, fail-closed decision cell, min-sample gates.
- `tests/test_thresholds.py` — tighten-only enforcement in both directions, rejected-threshold construction.
- `tests/test_engine.py` — suppression-key refusal, one-warrant-per-spec, deterministic run digest, shared cohort, JSON round-trip.
- `tests/test_query.py` — filter composition, model-version cohort split for drift, time-window bounds, reusability from a one-shot iterator.

Run with `pytest`.

## Why these specific primitives

The v0.1.0 set covers the three failure modes most likely to surface in adversarial review:

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

## Warrant

Every result memorializes itself. The warrant is the auditable record — the
decision together with its evidence and the rejected thresholds — with a content
digest.

```python
warrant = result.to_warrant()

print(warrant.flagged)            # the decision
print(warrant.standard)           # "EEOC Uniform Guidelines four-fifths rule (29 CFR 1607)"
print(warrant.threshold)          # 0.8
for rt in warrant.rejected_thresholds:   # what was refused, and why
    print(rt.value, "—", rt.reason)      # "< 0.8 — would loosen detection past ..."

warrant.verify_digest()           # True — content is consistent with the digest
record = warrant.to_dict()        # JSON-friendly audit-ledger record
```

The unkeyed digest above is a *consistency* check. For standalone tamper-evidence,
mint with an HMAC signing key and verify with the same key:

```python
from ailedger_detection.warrant import Warrant

signed = Warrant.build(..., signing_key=key)   # keyed=True
signed.verify_digest(signing_key=key)          # True; tampering or a wrong key -> False
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

## Repo posture

The Detection layer ships as a standalone public repository under Apache 2.0,
separate from the AILedger integrity and producer-side layers. Issue tracking and
contributions happen in this repository.
