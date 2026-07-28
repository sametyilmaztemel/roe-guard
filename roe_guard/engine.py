"""
roe_guard.engine

Decision engine — evaluates (target, action_type) against an engagement
policy using the **fail-closed priority order** defined in spec §5.

This is the security-critical core of roe-guard.  The 8-step priority
order is intentional and MUST NOT be reordered (e.g. ``scope.deny``
overrides ``scope.allow`` — a target in both lists is denied).

Implemented in T4.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from datetime import datetime, timezone
from typing import Any

from roe_guard.exceptions import PolicyExpiredError
from roe_guard.models import Decision, DecisionType, Engagement, ScopeEntry

# ---------------------------------------------------------------------------
# Target matching
# ---------------------------------------------------------------------------


def _target_matches(target: str, entry: ScopeEntry) -> bool:
    """Return True if *target* matches a single :class:`ScopeEntry`.

    Matching rules:
        - If the entry has a CIDR and the target is a valid IP address,
          membership is tested via :class:`ipaddress.ip_network`.
        - If the entry has a hostname, wildcard matching is done via
          :func:`fnmatch.fnmatch` (case-insensitive).
        - If the entry has neither, returns False.

    The target format is auto-detected: ``ipaddress.ip_address(target)``
    is attempted first; ``ValueError`` falls back to hostname matching.
    """
    if entry.cidr is not None:
        try:
            ip = ipaddress.ip_address(target)
        except ValueError:
            return False
        try:
            network = ipaddress.ip_network(entry.cidr, strict=False)
        except ValueError:
            # Invalid CIDR (should have been caught at load time).
            return False
        return ip in network

    if entry.hostname is not None:
        # fnmatch is case-insensitive via fnmatchcase + lowered strings.
        return fnmatch.fnmatchcase(target.lower(), entry.hostname.lower())

    return False


def _matches_any(target: str, entries: list[ScopeEntry]) -> bool:
    """Return True if *target* matches **any** entry in the list."""
    return any(_target_matches(target, e) for e in entries)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def enforce(
    engagement: Engagement,
    target: str,
    action_type: str,
    now: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> Decision:
    """Evaluate *one* action against the engagement policy (spec §5).

    The 8-step priority order is intentional and MUST NOT be reordered:

        1. now < valid_from  OR  now >= valid_until  → DENY (expired)
        2. now in any blackout_window                   → DENY
        3. target in scope.deny                         → DENY (deny > allow)
        4. target NOT in scope.allow                    → DENY
        5. action_type in actions.deny                  → DENY
        6. action_type in approval_required_for         → REQUIRES_APPROVAL
        7. action_type in actions.allow                 → ALLOW
        8. none of the above                            → DENY (fail-closed)

    Args:
        engagement:  The active :class:`~roe_guard.models.Engagement`.
        target:      Target identifier (IP, hostname, or glob).
        action_type: The action type to evaluate.
        now:         Override the evaluation time (UTC). Defaults to
            ``datetime.now(timezone.utc)``. Used for testability.
        metadata:    Optional extra context for audit logging (T5).

    Returns:
        A :class:`~roe_guard.models.Decision` with the resolved outcome,
        a human-readable reason, and ``timestamp == now``.

    Raises:
        roe_guard.exceptions.PolicyExpiredError: If the policy is expired
            AND the caller wants the explicit exception form (kept for
            backward compatibility — T7 CLI may use it).  The primary
            decision path returns ``Decision(outcome=DENY, ...)`` instead.
    """
    policy = engagement.policy
    if now is None:
        now = datetime.now(timezone.utc)

    # --- (a) Time-window check -------------------------------------------
    if not (policy.valid_from <= now < policy.valid_until):
        return Decision(
            outcome=DecisionType.DENY,
            reason="policy expired or not yet active",
            target=target,
            action_type=action_type,
            timestamp=now,
        )

    # --- (b) Blackout-window check --------------------------------------
    for bw in policy.blackout_windows:
        if bw.start <= now < bw.end:
            reason = "inside blackout window"
            if bw.reason:
                reason = f"{reason}: {bw.reason}"
            return Decision(
                outcome=DecisionType.DENY,
                reason=reason,
                target=target,
                action_type=action_type,
                timestamp=now,
            )

    # --- (c) Explicit deny overrides allow ------------------------------
    if _matches_any(target, policy.scope.deny):
        return Decision(
            outcome=DecisionType.DENY,
            reason="target explicitly denied in scope",
            target=target,
            action_type=action_type,
            timestamp=now,
        )

    # --- (d) Target must be in scope.allow ------------------------------
    if not _matches_any(target, policy.scope.allow):
        return Decision(
            outcome=DecisionType.DENY,
            reason="target not in allowed scope",
            target=target,
            action_type=action_type,
            timestamp=now,
        )

    # --- (e) actions.deny check -----------------------------------------
    if action_type in policy.actions_deny:
        return Decision(
            outcome=DecisionType.DENY,
            reason=f"action type {action_type!r} explicitly denied",
            target=target,
            action_type=action_type,
            timestamp=now,
        )

    # --- (f) approval_required_for check (NOT ALLOW) --------------------
    if action_type in policy.approval_required_for:
        return Decision(
            outcome=DecisionType.REQUIRES_APPROVAL,
            reason=f"action type {action_type!r} requires human approval",
            target=target,
            action_type=action_type,
            timestamp=now,
        )

    # --- (g) actions.allow check ----------------------------------------
    if action_type in policy.actions_allow:
        return Decision(
            outcome=DecisionType.ALLOW,
            reason=f"action type {action_type!r} allowed",
            target=target,
            action_type=action_type,
            timestamp=now,
        )

    # --- (h) Fail-closed default ----------------------------------------
    return Decision(
        outcome=DecisionType.DENY,
        reason="action type not explicitly allowed",
        target=target,
        action_type=action_type,
        timestamp=now,
    )


def raise_if_expired(engagement: Engagement, now: datetime | None = None) -> None:
    """Raise :class:`PolicyExpiredError` if the engagement is outside its window.

    Convenience helper — most callers should use :func:`enforce` which
    returns a DENY ``Decision`` instead of raising.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    if not (engagement.policy.valid_from <= now < engagement.policy.valid_until):
        raise PolicyExpiredError(engagement_id=engagement.policy.engagement_id)


__all__ = ["enforce", "raise_if_expired"]
