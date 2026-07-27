"""
roe_guard.models

Core data models for roe-guard.

These dataclasses will be fully populated in T2.  At present they define
the shape of every domain object used throughout the library so that other
modules can reference them with correct type annotations.

Planned classes (stubs):
    - ScopeEntry     — a single allow/deny entry (CIDR or hostname glob).
    - Scope          — collection of allow/deny entries.
    - BlackoutWindow — a time-range during which all actions are denied.
    - Policy         — the fully parsed engagement policy.
    - Engagement     — a Policy bound to an active operation.
    - Decision       — the outcome of a single enforce() call.
    - AuditEntry     — one record in the append-only audit chain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DecisionType(str, Enum):
    """Possible outcomes of a policy check.

    ALLOW              — the action is permitted.
    DENY               — the action is blocked (fail-closed default).
    REQUIRES_APPROVAL  — the action needs human sign-off before proceeding.
    """

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopeEntry:
    """A single allow/deny entry.

    Exactly one of ``cidr`` / ``hostname`` should be set.

    Attributes:
        cidr:     CIDR notation string, e.g. ``"10.20.0.0/16"``.
        hostname: Hostname glob, e.g. ``"*.staging.acme.internal"``.
    """

    cidr: str | None = None
    hostname: str | None = None


@dataclass(frozen=True)
class Scope:
    """Collection of allowed and denied scope entries.

    ``deny`` always takes precedence over ``allow``.
    """

    allow: list[ScopeEntry] = field(default_factory=list)
    deny: list[ScopeEntry] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Blackout window
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BlackoutWindow:
    """A time-range during which **all** actions are denied.

    Attributes:
        start:  UTC datetime — window begins (inclusive).
        end:    UTC datetime — window ends (exclusive).
        reason: Human-readable explanation (optional).
    """

    start: datetime
    end: datetime
    reason: str | None = None


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Policy:
    """Fully-parsed engagement policy.

    Populated by :func:`roe_guard.policy.load_policy` (T3).

    Attributes:
        engagement_id:          Unique identifier for the engagement.
        valid_from:             Engagement start (inclusive, UTC).
        valid_until:            Engagement end (exclusive, UTC).
        scope:                  Allowed/denied targets.
        actions_allow:          Permitted action types.
        actions_deny:           Explicitly denied action types.
        blackout_windows:       Time-ranges where everything is denied.
        approval_required_for:  Action types needing human approval.
        approvers:              Email/identifier list of authorised approvers.
    """

    engagement_id: str = ""
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    scope: Scope = field(default_factory=Scope)
    actions_allow: list[str] = field(default_factory=list)
    actions_deny: list[str] = field(default_factory=list)
    blackout_windows: list[BlackoutWindow] = field(default_factory=list)
    approval_required_for: list[str] = field(default_factory=list)
    approvers: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Engagement
# ---------------------------------------------------------------------------


@dataclass
class Engagement:
    """A :class:`Policy` bound to a concrete operation context.

    This is the primary user-facing object.  Created from a policy file
    via ``Engagement.from_file()`` (implemented in T3) and queried with
    ``check()`` / ``enforce()`` (implemented in T4).

    Attributes:
        policy:       The parsed engagement policy.
        operation_id: Optional runtime operation identifier.
    """

    policy: Policy
    operation_id: str | None = None

    # --- Planned public API (T3 / T4 / T6) -------------------------------

    @classmethod
    def from_file(cls, path: str) -> Engagement:
        """Load a policy from a YAML file and return an :class:`Engagement`.

        Implemented in T3 (:func:`roe_guard.policy.load_policy`).
        """
        raise NotImplementedError("Engagement.from_file() — implemented in T3")

    def check(
        self,
        target: str,
        action_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> Decision:
        """Evaluate a single action against the policy.

        Returns a :class:`Decision` (ALLOW / DENY / REQUIRES_APPROVAL).
        Implemented in T4.
        """
        raise NotImplementedError("Engagement.check() — implemented in T4")

    def enforce(
        self,
        target: str,
        action_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> Decision:
        """Alias for :meth:`check`; enforced by the decision engine (T4)."""
        raise NotImplementedError("Engagement.enforce() — implemented in T4")


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """The outcome of a single policy evaluation.

    Attributes:
        decision:      ALLOW, DENY, or REQUIRES_APPROVAL.
        target:        The evaluated target string.
        action_type:   The evaluated action type.
        reason:        Human-readable explanation of the decision.
        engagement_id: ID of the engagement whose policy produced this.
    """

    decision: DecisionType
    target: str
    action_type: str
    reason: str = ""
    engagement_id: str = ""

    @property
    def allowed(self) -> bool:
        """``True`` only when the decision is ALLOW."""
        return self.decision is DecisionType.ALLOW

    def raise_if_denied(self) -> None:
        """Raise :class:`OutOfScopeError` if this decision is DENY.

        Implemented in T4 alongside the decision engine.
        """
        raise NotImplementedError("Decision.raise_if_denied() — implemented in T4")


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditEntry:
    """A single record in the append-only audit chain.

    Attributes:
        engagement_id: Engagement this entry belongs to.
        timestamp:     UTC time of the decision.
        target:        The evaluated target.
        action_type:   The evaluated action type.
        decision:      ALLOW / DENY / REQUIRES_APPROVAL.
        reason:        Explanation.
        prev_hash:     SHA-256 of the previous entry's canonical JSON.
        entry_hash:    SHA-256 of this entry's canonical JSON (incl. prev_hash).
    """

    engagement_id: str
    timestamp: datetime
    target: str
    action_type: str
    decision: DecisionType
    reason: str
    prev_hash: str
    entry_hash: str


__all__ = [
    "AuditEntry",
    "BlackoutWindow",
    "Decision",
    "DecisionType",
    "Engagement",
    "Policy",
    "Scope",
    "ScopeEntry",
]
