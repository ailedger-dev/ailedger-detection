"""
ailedger-detection — Open-source statistical primitives for AILedger Detection
Event chains.

Apache 2.0. See LICENSE.

Production primitives:
- disparate_impact_ratio (four-fifths-rule baseline)
- statistical_parity_difference
- model_drift_between_versions
- tool_call_unauthorized_action_rate (agent-overreach / confabulation detector)
- confidence_stratified_outcome_analysis (per-confidence-bucket disparate impact)
- unresolved_flag_accumulation (accumulating unresolved required actions)
- subject_repeated_decision_patterns (repeated adverse decisions per subject)

LARP / audit-spine layer:
- warrant_detection_result — wrap any detection result as a warranted Decision
  (the result is the 1-cell; the warrant + rejected alternatives is the 2-cell).
  The log of warranted Decisions is the auditable product. Flag suppression is
  refused at the schema level (Charter v1.1).

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
from ailedger_detection.parity import (
    StatisticalParityResult,
    statistical_parity_difference,
)
from ailedger_detection.repeated_decisions import (
    RepeatedDecisionResult,
    SubjectPattern,
    subject_repeated_decision_patterns,
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
from ailedger_detection.warrant import (
    Warrant,
    WarrantedDecision,
    warrant_detection_result,
)

__version__ = "0.3.0"

__all__ = [
    "ConfidenceBucketStat",
    "ConfidenceStratifiedResult",
    "DetectionEvent",
    "DisparateImpactResult",
    "ExtractorMethod",
    "InferredDetectionEvent",
    "ModelDriftResult",
    "ProtectedClassCollectionMethod",
    "RepeatedDecisionResult",
    "StatisticalParityResult",
    "SubjectPattern",
    "UnauthorizedToolCallResult",
    "UnresolvedFlagResult",
    "Warrant",
    "WarrantedDecision",
    "__version__",
    "confidence_stratified_outcome_analysis",
    "disparate_impact_ratio",
    "model_drift_between_versions",
    "statistical_parity_difference",
    "subject_repeated_decision_patterns",
    "tool_call_unauthorized_action_rate",
    "unresolved_flag_accumulation",
    "warrant_detection_result",
]
