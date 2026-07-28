"""
roe_guard.exceptions

All custom exceptions raised by roe-guard.

Every exception inherits from :class:`RoeGuardError` so that callers can
catch any roe-guard failure with a single ``except`` clause.
"""

from __future__ import annotations


class RoeGuardError(Exception):
    """Base exception for all roe-guard errors.

    Catch this to handle any failure originating from the roe-guard library.
    """


class OutOfScopeError(RoeGuardError):
    """Raised when a target or action is denied by the active policy.

    This is raised by integration helpers (``raise_if_denied()``, the
    ``@guarded`` decorator) when a decision resolves to DENY.
    """


class PolicyExpiredError(RoeGuardError):
    """Raised when the engagement's ``valid_until`` has passed.

    An expired policy causes every check to fail-closed (DENY).
    """

    def __init__(self, message: str = "", engagement_id: str = "") -> None:
        if engagement_id and not message:
            message = f"Policy for engagement {engagement_id!r} has expired"
        elif engagement_id and message:
            message = f"[engagement={engagement_id}] {message}"
        super().__init__(message)
        self.engagement_id = engagement_id


class PolicyParseError(RoeGuardError):
    """Raised when a policy file cannot be parsed or fails schema validation.

    Covers: missing required fields, invalid date formats, malformed CIDR
    notation, and YAML syntax errors.

    Attributes:
        field: The name of the field that failed validation (if applicable),
            e.g. ``"scope.allow[2].cidr"``.
        reason: Short human-readable reason for the failure.
    """

    def __init__(self, message: str = "", field: str = "", reason: str = "") -> None:
        if field and reason and not message:
            message = f"Invalid policy at {field!r}: {reason}"
        elif field and message:
            message = f"[{field}] {message}"
        super().__init__(message)
        self.field = field
        self.reason = reason


__all__ = [
    "OutOfScopeError",
    "PolicyExpiredError",
    "PolicyParseError",
    "RoeGuardError",
]
