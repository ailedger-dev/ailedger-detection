"""
ailedger-detection — Open-source statistical primitives for AILedger Detection
Event chains.

Apache 2.0. See LICENSE.

Primitives shipped in v0.1.0:
- disparate_impact_ratio (four-fifths-rule baseline)
- statistical_parity_difference
- model_drift_between_versions
- confidence_stratified_outcome_analysis (stub)
- unresolved_flag_accumulation (stub)
- subject_repeated_decision_patterns (stub)

These primitives operate on Detection Event records as produced by the AILedger
Decision Events schema (proxy/migrations/20260512_decision_events_schema.sql)
plus inferred-event extension (proxy/migrations/20260518_inferred_detection_events.sql).

The Detection layer is intentionally Apache 2.0 + open-source so customers,
regulators, and adversarial reviewers can audit exactly what is being checked.
Detection thresholds are anchored to standards (four-fifths rule = 0.8 per
EEOC Uniform Guidelines); customers tighten, never loosen, per Charter v1.1.

Authority: gt-lab/docs/param-canonicalization-spec-v1.md +
gt-lab/docs/compliance-architecture/ARCHITECTURE-detection-taxonomy.md.
"""

from ailedger_detection.disparate_impact import (
    DisparateImpactResult,
    disparate_impact_ratio,
)
from ailedger_detection.parity import (
    StatisticalParityResult,
    statistical_parity_difference,
)
from ailedger_detection.drift import (
    ModelDriftResult,
    model_drift_between_versions,
)

__version__ = "0.1.0"

__all__ = [
    "DisparateImpactResult",
    "disparate_impact_ratio",
    "StatisticalParityResult",
    "statistical_parity_difference",
    "ModelDriftResult",
    "model_drift_between_versions",
    "__version__",
]
