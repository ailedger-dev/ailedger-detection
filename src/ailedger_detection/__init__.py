"""
ailedger-detection — Open-source statistical primitives for AILedger Detection
Event chains.

Apache 2.0. See LICENSE.

Production primitives (v0.3.0):
- disparate_impact_ratio (four-fifths-rule baseline)
- statistical_parity_difference
- model_drift_between_versions
- tool_call_unauthorized_action_rate (agent-overreach / confabulation detector)
- confidence_stratified_outcome_analysis (bias-by-confidence-stratum)
- unresolved_flag_accumulation (compliance-gap accumulation)
- subject_repeated_decision_patterns (pattern-of-practice)

Every primitive result memorializes itself as a warrant via `to_warrant()`
(see warrant.py): the result records the decision together with its evidence and
the looser thresholds it refused. The DetectionEngine (engine.py) orchestrates
primitives over a cohort and returns a warranted, digest-chained DetectionRun —
the auditable spine the Grafana monitor consumes.

Anti-theater is structural, not policy (per Charter v1.1):
- Thresholds are tighten-only — a looser value raises ValueError (thresholds.py).
- Detection has no disablement surface — suppression/compliance-mode config is
  refused at construction (engine.py).

These primitives operate on Detection Event records as produced by the AILedger
Decision Events schema (proxy/migrations/20260512_decision_events_schema.sql)
plus inferred-event extension (proxy/migrations/20260518_inferred_detection_events.sql).

The Detection layer is intentionally Apache 2.0 + open-source so customers,
regulators, and adversarial reviewers can audit exactly what is being checked.

Authority: gt-lab/docs/param-canonicalization-spec-v1.md +
gt-lab/docs/compliance-architecture/ARCHITECTURE-detection-taxonomy.md.
"""

from ailedger_detection.confidence import (
    ConfidenceBucketStat,
    ConfidenceStratifiedResult,
    confidence_stratified_outcome_analysis,
)
from ailedger_detection.disparate_impact import (
    DisparateImpactResult,
    disparate_impact_ratio,
)
from ailedger_detection.drift import (
    ModelDriftResult,
    model_drift_between_versions,
)
from ailedger_detection.engine import (
    DetectionEngine,
    DetectionRun,
    DetectionSpec,
    DetectionSuppressionError,
    refuse_suppression,
)
from ailedger_detection.parity import (
    StatisticalParityResult,
    statistical_parity_difference,
)
from ailedger_detection.query import EventQuery
from ailedger_detection.repeated_decisions import (
    RepeatedDecisionResult,
    SubjectPattern,
    subject_repeated_decision_patterns,
)
from ailedger_detection.thresholds import (
    ThresholdStandard,
    TightenDirection,
    enforce_tighten_only,
    get_standard,
    rejected_thresholds_for,
)
from ailedger_detection.tool_calls import (
    UnauthorizedToolCallResult,
    tool_call_unauthorized_action_rate,
)
from ailedger_detection.types import (
    DetectionEvent,
    ExtractorMethod,
    InferredDetectionEvent,
    ProtectedClassCollectionMethod,
)
from ailedger_detection.unresolved_flags import (
    UnresolvedFlagResult,
    unresolved_flag_accumulation,
)
from ailedger_detection.warrant import RejectedThreshold, Warrant

__version__ = "0.3.0"

__all__ = [
    "ConfidenceBucketStat",
    "ConfidenceStratifiedResult",
    "DetectionEngine",
    "DetectionEvent",
    "DetectionRun",
    "DetectionSpec",
    "DetectionSuppressionError",
    "DisparateImpactResult",
    "EventQuery",
    "ExtractorMethod",
    "InferredDetectionEvent",
    "ModelDriftResult",
    "ProtectedClassCollectionMethod",
    "RejectedThreshold",
    "RepeatedDecisionResult",
    "StatisticalParityResult",
    "SubjectPattern",
    "ThresholdStandard",
    "TightenDirection",
    "UnauthorizedToolCallResult",
    "UnresolvedFlagResult",
    "Warrant",
    "__version__",
    "confidence_stratified_outcome_analysis",
    "disparate_impact_ratio",
    "enforce_tighten_only",
    "get_standard",
    "model_drift_between_versions",
    "refuse_suppression",
    "rejected_thresholds_for",
    "statistical_parity_difference",
    "subject_repeated_decision_patterns",
    "tool_call_unauthorized_action_rate",
    "unresolved_flag_accumulation",
]
