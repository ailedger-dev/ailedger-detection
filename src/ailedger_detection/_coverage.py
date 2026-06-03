"""
Shared label-extraction + identity helpers for the fairness primitives.

This is the F2-hardening seam. The red team's thesis-breaker was that the
caller-supplied loosening surface — the `protected_class_key`, the
`positive_outcome_predicate` — was *wholly unguarded*, and events the caller's
definitions dropped (e.g. adverse rows with the protected-class label stripped)
vanished from the denominator **uncounted and invisible**. A customer could pass
every "structural" tighten-only check while detecting nothing.

The remedy is not to forbid caller definitions (they are domain-necessary) but to
make their effect *auditable*:

- `extract_label` is the single label-extraction path, so every primitive counts
  dropped/unlabeled events the same way (the count then lands in the warrant).
- `callable_identity` records *which* predicate/extractor produced a number —
  by module-qualified name, never by `repr()` (whose memory address would break
  the deterministic warrant digest) — so an auditor sees the definition behind
  the count. Silence is made visible; it is no longer free.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


def extract_label(event: dict[str, Any], protected_class_key: str) -> str | None:
    """
    Extract the protected-class label for a dimension, or None if unlabeled.

    Looks inside `protected_class_context` first (the canonical AILedger
    Detection Event shape), then falls back to a top-level key (so the primitive
    also works over arbitrary dict shapes). Returns None when the event carries
    no label for this dimension — the caller counts that as a dropped event.
    """
    ctx = event.get("protected_class_context")
    if isinstance(ctx, dict) and protected_class_key in ctx:
        return str(ctx[protected_class_key])
    if protected_class_key in event:
        return str(event[protected_class_key])
    return None


def callable_identity(fn: Callable[..., Any]) -> str:
    """
    A deterministic, audit-stable identity for a caller-supplied callable.

    Uses `module.qualname` (never `repr`, which embeds a memory address and would
    make the warrant digest non-deterministic). For a lambda this is e.g.
    `mypkg.audit.<locals>.<lambda>` — enough to point an auditor at the
    definition site without leaking process state.
    """
    mod = getattr(fn, "__module__", None) or "?"
    qn = getattr(fn, "__qualname__", None) or getattr(fn, "__name__", None) or repr(fn)
    return f"{mod}.{qn}"
