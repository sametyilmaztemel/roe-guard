"""
roe_guard.integrations.decorator

``@guarded`` decorator — transparently protect an existing function.

Usage (once implemented in T6)::

    @guarded(engagement, action_type="exploit", target_arg="host")
    def run_exploit(host: str):
        ...

Before the decorated function executes, roe-guard evaluates the target and
action against the engagement policy.  If the decision is DENY,
:class:`~roe_guard.exceptions.OutOfScopeError` is raised and the function
body never runs.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from roe_guard.models import Engagement


def guarded(
    engagement: Engagement,
    action_type: str,
    target_arg: str = "target",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator factory that enforces scope on a function call.

    Args:
        engagement:  The active :class:`~roe_guard.models.Engagement`.
        action_type: The action type this function represents.
        target_arg:  Name of the kwarg/positional arg holding the target.

    Returns:
        A decorator that checks scope before invoking the wrapped function.

    Raises:
        roe_guard.exceptions.OutOfScopeError: If the policy denies the
            action (implemented in T6).
    """
    raise NotImplementedError("@guarded decorator — implemented in T6")


__all__ = ["guarded"]
