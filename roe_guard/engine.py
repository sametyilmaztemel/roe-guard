"""
roe_guard.engine

Decision engine — evaluates (target, action_type) against an engagement
policy using the fail-closed priority order defined in the spec (§5).

Implemented in T4.  At present only the function signature and docstring
are provided.
"""

from __future__ import annotations

from typing import Any

from roe_guard.models import Decision, Engagement


def enforce(
    engagement: Engagement,
    target: str,
    action_type: str,
    metadata: dict[str, Any] | None = None,
) -> Decision:
    """Evaluate *one* action against the engagement policy.

    Decision priority (spec §5):

        1. ``valid_until`` passed?           → DENY (PolicyExpiredError)
        2. Inside a blackout window?         → DENY
        3. Target in ``scope.deny``?         → DENY
        4. Target not in ``scope.allow``?    → DENY
        5. Action type in ``actions.deny``?  → DENY
        6. Action type in ``approval_required_for``? → REQUIRES_APPROVAL
        7. Action type in ``actions.allow``? → ALLOW
        8. None of the above?                → DENY (fail-closed)

    Args:
        engagement:  The active :class:`~roe_guard.models.Engagement`.
        target:      Target identifier (IP, hostname, or glob).
        action_type: The action type to evaluate.
        metadata:    Optional extra context for audit logging.

    Returns:
        A :class:`~roe_guard.models.Decision` with the resolved outcome
        and a human-readable reason.
    """
    raise NotImplementedError("enforce() — implemented in T4")


__all__ = ["enforce"]
