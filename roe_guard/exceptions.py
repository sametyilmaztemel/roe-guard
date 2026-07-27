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


class PolicyParseError(RoeGuardError):
    """Raised when a policy file cannot be parsed or fails schema validation.

    Covers: missing required fields, invalid date formats, malformed CIDR
    notation, and YAML syntax errors.
    """


__all__ = [
    "OutOfScopeError",
    "PolicyExpiredError",
    "PolicyParseError",
    "RoeGuardError",
]
