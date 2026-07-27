"""
roe_guard.policy

YAML policy loading and schema validation.

Implemented in T3.  At present only the function signatures and docstrings
are provided.
"""

from __future__ import annotations

from pathlib import Path

from roe_guard.models import Policy


def load_policy(path: str | Path) -> Policy:
    """Load and validate a policy from a YAML file.

    Uses ``yaml.safe_load`` (never ``yaml.load``) to eliminate RCE risk.

    Validates:
        - Required top-level fields (``engagement_id``, ``valid_from``,
          ``valid_until``, ``scope``).
        - ISO-8601 datetime format for all timestamps.
        - CIDR validity for ``scope.*.cidr`` entries.
        - At least one ``scope.allow`` entry.

    Args:
        path: Path to the policy YAML file.

    Returns:
        A fully-populated, immutable :class:`~roe_guard.models.Policy`.

    Raises:
        roe_guard.exceptions.PolicyParseError: On any structural or
            semantic validation failure.
    """
    raise NotImplementedError("load_policy() — implemented in T3")


__all__ = ["load_policy"]
