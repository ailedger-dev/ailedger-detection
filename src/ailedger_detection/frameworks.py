"""
Governance-framework cross-walk for the detection primitives.

The threshold registry (`thresholds.py`) anchors each primitive to the *legal*
standard that fixes its baseline (EEOC four-fifths rule, FDIC/OCC PSI ladder).
This module is the complementary *governance-framework* cross-walk: it maps each
primitive to the AI-management-system clauses it helps an operator satisfy.

Three frameworks are covered, because they are the three an auditor of a
high-risk AI system most often holds the operator to:

- **ISO/IEC 42001:2023** — the AI management system standard. Its Annex A
  controls require impact assessment, performance monitoring, and operation
  records for AI systems.
- **NIST AI RMF 1.0** — the MEASURE and MANAGE functions require AI risks to be
  measured with quantitative metrics and managed over the system lifecycle.
- **EU AI Act Article 12 (record-keeping)** — high-risk AI systems must
  *automatically* record events ("logs") over their lifetime to a degree
  appropriate to their purpose, enabling traceability. This is the clause the
  warrant mechanism directly serves: every detection run emits a warranted,
  digest-chained record (see `warrant.py`), which *is* the automatic log
  Article 12 requires.

Nothing here changes detection behavior or thresholds. It is a read-only
cross-walk an operator can render into a compliance matrix, and it is wired so
that adding a primitive without a framework anchor is caught by a test
(`coverage()` reports any unmapped primitive).
"""

from __future__ import annotations

from dataclasses import dataclass

from ailedger_detection.thresholds import _REGISTRY

# Framework identifiers, cited once so call sites and the matrix stay consistent.
ISO_42001 = "ISO/IEC 42001:2023"
NIST_AI_RMF = "NIST AI RMF 1.0"
EU_AI_ACT = "EU AI Act (Regulation (EU) 2024/1689)"


@dataclass(frozen=True)
class FrameworkAnchor:
    """One governance-framework clause a primitive helps satisfy."""

    framework: str
    """Framework identifier, e.g. ``ISO/IEC 42001:2023``."""

    clause: str
    """The specific clause/control/function, e.g. ``Annex A A.6.2.4``."""

    requirement: str
    """Short description of what the clause requires."""

    def to_dict(self) -> dict[str, str]:
        return {
            "framework": self.framework,
            "clause": self.clause,
            "requirement": self.requirement,
        }


# EU AI Act Article 12 record-keeping applies to *every* primitive, because every
# primitive emits a warrant and a warrant is the automatic, traceable log entry
# Article 12 requires. Held as a shared anchor rather than repeated per primitive.
RECORD_KEEPING_ANCHOR = FrameworkAnchor(
    framework=EU_AI_ACT,
    clause="Article 12 (record-keeping)",
    requirement=(
        "High-risk AI systems must automatically record events over their "
        "lifetime to ensure traceability. Each detection run emits a warrant "
        "(result + evidence + refused thresholds + content digest) — the "
        "automatic, tamper-evident log entry this Article requires."
    ),
)


# Per-primitive anchors. RECORD_KEEPING_ANCHOR is appended to every primitive by
# `framework_anchors`, so it is intentionally absent from these tuples.
_FRAMEWORK_MAP: dict[str, tuple[FrameworkAnchor, ...]] = {
    "disparate_impact_ratio": (
        FrameworkAnchor(
            ISO_42001,
            "Annex A A.6.2.4",
            "AI system performance must be measured against defined criteria; "
            "disparate impact is a defined fairness criterion.",
        ),
        FrameworkAnchor(
            NIST_AI_RMF,
            "MEASURE 2.11",
            "Fairness and bias are evaluated with quantitative metrics.",
        ),
        FrameworkAnchor(
            EU_AI_ACT,
            "Article 10(2)(f)-(g)",
            "Examination for possible biases and detection of data gaps that "
            "may affect fundamental rights.",
        ),
    ),
    "statistical_parity_difference": (
        FrameworkAnchor(
            ISO_42001,
            "Annex A A.6.2.4",
            "Fairness performance measured against defined criteria.",
        ),
        FrameworkAnchor(
            NIST_AI_RMF,
            "MEASURE 2.11",
            "Fairness and bias evaluated quantitatively; parity is the "
            "absolute-difference complement to the ratio metric.",
        ),
        FrameworkAnchor(
            EU_AI_ACT,
            "Article 26(5)",
            "Deployers monitor operation for risks to fundamental rights.",
        ),
    ),
    "model_drift_between_versions": (
        FrameworkAnchor(
            ISO_42001,
            "Annex A A.6.2.6",
            "AI system operation and performance are monitored over time, "
            "including across version changes.",
        ),
        FrameworkAnchor(
            NIST_AI_RMF,
            "MANAGE 4.1",
            "Post-deployment monitoring detects distribution shift and "
            "degradation across the AI lifecycle.",
        ),
        FrameworkAnchor(
            EU_AI_ACT,
            "Article 72",
            "Post-market monitoring of high-risk AI system performance.",
        ),
    ),
    "tool_call_unauthorized_action_rate": (
        FrameworkAnchor(
            ISO_42001,
            "Annex A A.6.2.6",
            "Operation is monitored for behaviour outside the intended scope.",
        ),
        FrameworkAnchor(
            NIST_AI_RMF,
            "MEASURE 2.6",
            "AI system operation outside the intended operational envelope is "
            "measured.",
        ),
        FrameworkAnchor(
            EU_AI_ACT,
            "Article 14",
            "Human oversight: action outside the policy envelope signals "
            "oversight controls were bypassed or never wired.",
        ),
    ),
    "confidence_stratified_outcome_analysis": (
        FrameworkAnchor(
            ISO_42001,
            "Annex A A.6.2.4",
            "Performance measured against defined criteria, sliced by the "
            "system's own confidence stratum.",
        ),
        FrameworkAnchor(
            NIST_AI_RMF,
            "MEASURE 2.11",
            "Bias evaluated within confidence strata, surfacing disparity that "
            "the pooled metric hides.",
        ),
        FrameworkAnchor(
            EU_AI_ACT,
            "Article 10(2)(f)",
            "Examination for biases, including bias concentrated in "
            "high-confidence decisions.",
        ),
    ),
    "unresolved_flag_accumulation": (
        FrameworkAnchor(
            ISO_42001,
            "Annex A A.9.3",
            "Records of AI system operation, including raised-but-unactioned "
            "conditions, are maintained.",
        ),
        FrameworkAnchor(
            NIST_AI_RMF,
            "GOVERN 1.5",
            "Mechanisms to act on identified AI risks exist; an accumulating "
            "unresolved-flag backlog is a governance failure.",
        ),
        FrameworkAnchor(
            EU_AI_ACT,
            "Article 14",
            "Human oversight: flags requiring action that go unactioned defeat "
            "the oversight obligation.",
        ),
    ),
    "subject_repeated_decision_patterns": (
        FrameworkAnchor(
            ISO_42001,
            "Annex A A.6.2.4",
            "Performance measured against defined criteria at the affected-"
            "person level, not only in aggregate.",
        ),
        FrameworkAnchor(
            NIST_AI_RMF,
            "MEASURE 2.11",
            "Bias evaluated for pattern-of-practice harm to a single subject "
            "across repeated decisions.",
        ),
        FrameworkAnchor(
            EU_AI_ACT,
            "Article 26(5)",
            "Deployers monitor for risks accruing to individuals from repeated "
            "automated decisions.",
        ),
    ),
}


def framework_anchors(primitive: str) -> tuple[FrameworkAnchor, ...]:
    """
    Return the governance-framework anchors for a primitive.

    The shared EU AI Act Article 12 record-keeping anchor is appended to every
    primitive's specific anchors, because every primitive emits a warrant.

    Args:
        primitive: The primitive name (matching the threshold registry; for the
            two-threshold drift primitive use ``model_drift_between_versions``).

    Returns:
        A tuple of FrameworkAnchor, specific anchors first then the shared
        record-keeping anchor.

    Raises:
        KeyError: If the primitive has no registered anchors.
    """
    try:
        specific = _FRAMEWORK_MAP[primitive]
    except KeyError:
        raise KeyError(
            f"No framework anchors registered for '{primitive}'. "
            f"Known: {sorted(_FRAMEWORK_MAP)}"
        ) from None
    return (*specific, RECORD_KEEPING_ANCHOR)


def frameworks_for(primitive: str) -> frozenset[str]:
    """Return the distinct framework identifiers a primitive helps satisfy."""
    return frozenset(a.framework for a in framework_anchors(primitive))


def coverage() -> dict[str, list[str]]:
    """
    Cross-walk every primitive to the frameworks it helps satisfy.

    Returns a mapping ``primitive -> sorted framework identifiers``. Primitives
    are taken from the threshold registry so that a primitive shipped with a
    threshold but no framework anchor surfaces as a ``KeyError`` here — the test
    suite calls this to keep the cross-walk complete.

    The drift primitive registers two thresholds (``model_drift.no_drift`` and
    ``model_drift.action``); both map to the single ``model_drift_between_versions``
    primitive entry.
    """
    threshold_to_primitive = {
        "model_drift.no_drift": "model_drift_between_versions",
        "model_drift.action": "model_drift_between_versions",
    }
    out: dict[str, list[str]] = {}
    for threshold_name in _REGISTRY:
        primitive = threshold_to_primitive.get(threshold_name, threshold_name)
        if primitive in out:
            continue
        out[primitive] = sorted(frameworks_for(primitive))
    return out


@dataclass(frozen=True)
class RegulatoryProfile:
    """
    A named bundle of primitives selected to satisfy a regulatory posture.

    A deployer subject to, say, the EU AI Act high-risk regime runs the profile's
    primitives and renders `compliance_matrix()` into its technical documentation.
    The profile selects *which* primitives to run; it cannot loosen any threshold
    (that is refused structurally in `thresholds.py`) nor disable detection (that
    is refused structurally in `engine.py`).
    """

    name: str
    primitives: tuple[str, ...]

    def compliance_matrix(self) -> dict[str, list[dict[str, str]]]:
        """Render ``primitive -> [anchor dicts]`` for compliance documentation."""
        return {p: [a.to_dict() for a in framework_anchors(p)] for p in self.primitives}

    def frameworks(self) -> frozenset[str]:
        """The union of frameworks the profile's primitives help satisfy."""
        return frozenset().union(*(frameworks_for(p) for p in self.primitives))


# Preset profiles. Each lists the primitives whose framework anchors include the
# profile's target framework — the natural starting set for that posture.
EU_AI_ACT_HIGH_RISK = RegulatoryProfile(
    name="eu_ai_act_high_risk",
    primitives=tuple(_FRAMEWORK_MAP),
)

ISO_42001_AIMS = RegulatoryProfile(
    name="iso_42001_aims",
    primitives=tuple(_FRAMEWORK_MAP),
)

NIST_AI_RMF_PROFILE = RegulatoryProfile(
    name="nist_ai_rmf",
    primitives=tuple(_FRAMEWORK_MAP),
)

_PROFILES: dict[str, RegulatoryProfile] = {
    p.name: p for p in (EU_AI_ACT_HIGH_RISK, ISO_42001_AIMS, NIST_AI_RMF_PROFILE)
}


def regulatory_profile(name: str) -> RegulatoryProfile:
    """Look up a preset RegulatoryProfile by name."""
    try:
        return _PROFILES[name]
    except KeyError:
        raise KeyError(
            f"No preset regulatory profile '{name}'. Known: {sorted(_PROFILES)}"
        ) from None
