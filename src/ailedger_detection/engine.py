"""
Detection engine — orchestration + structural anti-theater enforcement.

The engine runs a configured set of detection primitives over an event cohort
and returns a `DetectionRun`: a bundle of LARP warrants (one per primitive) with
a chaining digest. Every run is therefore self-describing and auditable — the
audit spine the Interchange (fleet federation) and the Grafana LARP monitor
consume.

Anti-theater, enforced at the schema level (per the AILedger Charter v1.1):

- There is **no disablement surface.** The engine has no `enabled` flag, no
  `compliance_mode`, no per-customer "skip this detection" knob. You cannot
  construct a DetectionEngine, DetectionSpec, or run that turns a detection off.
- Any attempt to pass a suppression-flavored config key (`disable`,
  `compliance_mode`, `bypass`, `suppress`, …) raises `DetectionSuppressionError`
  at construction time. The refusal is a property of the type, not policy a
  customer can override.
- Thresholds are already tighten-only (see thresholds.py); the engine adds no
  way around that.

The only way to "reduce" detection is to not register a primitive — and that
absence is visible in the run (the set of warrants produced is the record of
exactly what was checked). Silence is auditable; suppression is refused.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from ailedger_detection.thresholds import registry_digest, verify_registry_integrity
from ailedger_detection.warrant import Warrant


class _WarrantProducer(Protocol):
    """A primitive result that can memorialize itself as a warrant."""

    def to_warrant(self, *, created_at: str | None = ...) -> Warrant: ...


# Config keys that would suppress detection. Refused structurally — there is no
# legitimate reason for any of these to reach the engine.
FORBIDDEN_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "enabled",
        "disabled",
        "disable",
        "suppress",
        "suppression",
        "suppressed",
        "compliance_mode",
        "bypass",
        "skip",
        "skip_detection",
        "mute",
        "muted",
        "off",
        "ignore",
        "override",
    }
)


class DetectionSuppressionError(ValueError):
    """Raised when a config tries to disable/suppress a detection."""


def refuse_suppression(config: Mapping[str, Any]) -> None:
    """
    Raise if `config` contains any suppression-flavored key.

    This is the structural anti-theater guard. It is called on every
    DetectionSpec's kwargs and on engine-level config so there is no path that
    silently disables detection.
    """
    found = sorted(k for k in config if str(k).lower() in FORBIDDEN_CONFIG_KEYS)
    if found:
        raise DetectionSuppressionError(
            f"Refused suppression config key(s): {found}. Detection cannot be "
            f"disabled, bypassed, or put in a 'compliance mode'. Per AILedger "
            f"Charter v1.1 this refusal is structural, not policy. To reduce "
            f"scope, omit the primitive — its absence is recorded in the run."
        )


@dataclass(frozen=True)
class DetectionSpec:
    """
    Binds a detection primitive to its keyword arguments.

    `fn` is any primitive that returns a result exposing `to_warrant()` (all
    primitives in this package do). `kwargs` are forwarded to it after the event
    cohort. Suppression-flavored kwargs are refused at construction.
    """

    name: str
    fn: Callable[..., _WarrantProducer]
    kwargs: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        refuse_suppression(self.kwargs)

    def evaluate(self, events: list[dict[str, Any]], *, created_at: str | None = None) -> Warrant:
        """Run the primitive over `events` and return its warrant."""
        result = self.fn(events, **self.kwargs)
        return result.to_warrant(created_at=created_at)


@dataclass(frozen=True)
class DetectionRun:
    """The result of an engine run: a bundle of warrants with a chaining digest."""

    warrants: tuple[Warrant, ...]
    created_at: str
    run_digest: str
    """SHA-256 over (prev_digest, registry_digest, ordered warrant digests) —
    chains the run into the ledger. Passing the previous run's `run_digest` as
    `prev_digest` links run N to run N-1, so the run sequence is an append-only
    chain (not just per-run-internal). Like `warrant_digest`, this is a
    consistency digest; cross-run tamper-evidence is the DB hash-chain's job."""

    registry_digest: str
    """Content digest of the threshold registry this run executed against,
    recorded so a loosened registry is visible in the audit record (F1)."""

    registry_intact: bool
    """True iff `registry_digest` matched the sealed canonical baselines at run
    time. False means the tighten-only registry was altered — a loud audit flag."""

    prev_digest: str | None = None
    """The prior run's `run_digest`, if this run was chained onto one."""

    @property
    def flagged(self) -> bool:
        """True if any constituent warrant flagged."""
        return any(w.flagged for w in self.warrants)

    def flagged_warrants(self) -> tuple[Warrant, ...]:
        return tuple(w for w in self.warrants if w.flagged)

    def to_dict(self) -> dict[str, Any]:
        return {
            "created_at": self.created_at,
            "run_digest": self.run_digest,
            "prev_digest": self.prev_digest,
            "registry_digest": self.registry_digest,
            "registry_intact": self.registry_intact,
            "flagged": self.flagged,
            "warrants": [w.to_dict() for w in self.warrants],
        }


class DetectionEngine:
    """
    Runs a fixed set of detection specs over event cohorts.

    Construct with the specs to run. There is intentionally no way to disable a
    registered spec; the engine's whole surface is "run everything, warrant
    everything".
    """

    def __init__(self, specs: Iterable[DetectionSpec]) -> None:
        self._specs: tuple[DetectionSpec, ...] = tuple(specs)
        names = [s.name for s in self._specs]
        dupes = sorted({n for n in names if names.count(n) > 1})
        if dupes:
            raise ValueError(f"Duplicate detection spec name(s): {dupes}")

    @property
    def specs(self) -> tuple[DetectionSpec, ...]:
        return self._specs

    def with_spec(self, spec: DetectionSpec) -> DetectionEngine:
        """Return a new engine with `spec` appended."""
        return DetectionEngine((*self._specs, spec))

    @staticmethod
    def _run_digest(warrants: tuple[Warrant, ...], prev_digest: str | None, reg_digest: str) -> str:
        payload = json.dumps(
            {
                "prev": prev_digest,
                "registry": reg_digest,
                "warrants": [w.warrant_digest for w in warrants],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def run(
        self,
        events: Iterable[dict[str, Any]],
        *,
        created_at: str | None = None,
        prev_digest: str | None = None,
    ) -> DetectionRun:
        """
        Run every registered spec over `events` and return a warranted run.

        Args:
            events: The Detection Event cohort. Materialized once so every spec
                sees the same cohort.
            created_at: RFC3339 UTC timestamp stamped on every warrant and the
                run. Defaults to now(UTC); pass explicitly for deterministic
                replay/tests.
            prev_digest: The prior run's `run_digest`, to chain run N onto run
                N-1. Folded into this run's digest so the run sequence forms an
                append-only chain, not just a per-run-internal hash.

        Returns:
            A DetectionRun bundling one warrant per spec plus a chaining digest
            and the threshold-registry integrity record for this run.
        """
        if created_at is None:
            created_at = datetime.now(timezone.utc).isoformat()

        cohort = list(events)
        warrants = tuple(spec.evaluate(cohort, created_at=created_at) for spec in self._specs)
        reg_digest = registry_digest()
        return DetectionRun(
            warrants=warrants,
            created_at=created_at,
            run_digest=self._run_digest(warrants, prev_digest, reg_digest),
            registry_digest=reg_digest,
            registry_intact=verify_registry_integrity(),
            prev_digest=prev_digest,
        )
