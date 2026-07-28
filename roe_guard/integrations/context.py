"""
roe_guard.integrations.context

Context manager — activate an engagement window for a code block.

Usage (spec §6)::

    with engagement.window():
        for host in discovered_hosts:
            engagement.check(host, "recon").raise_if_denied()
            scan(host)

Implemented in T6.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone

from roe_guard.exceptions import PolicyExpiredError
from roe_guard.models import Engagement


@contextmanager
def window(engagement: Engagement) -> Iterator[None]:
    """Activate an engagement scope for a code block.

    On entry, the engagement's time window is validated: if the
    ``valid_from`` / ``valid_until`` range does not cover *now*,
    :class:`~roe_guard.exceptions.PolicyExpiredError` is raised before
    the block runs.  On exit, no bookkeeping is performed (v0.1) —
    the placeholder is reserved for v0.2 time-window tracking.

    Inside the ``with`` block, callers must perform their own checks
    via ``engagement.check(target, action_type)`` and call
    ``.raise_if_denied()`` on the resulting :class:`Decision`.

    Args:
        engagement: The :class:`~roe_guard.models.Engagement` to activate.

    Yields:
        ``None`` — the caller performs checks inside the block.

    Raises:
        roe_guard.exceptions.PolicyExpiredError: If the engagement is
            outside its ``valid_from`` / ``valid_until`` range at entry.
    """
    now = datetime.now(timezone.utc)
    policy = engagement.policy
    if not (policy.valid_from <= now < policy.valid_until):
        raise PolicyExpiredError(engagement_id=policy.engagement_id)
    try:
        yield
    finally:
        # v0.2: emit audit entry for window exit (placeholder).
        pass


__all__ = ["window"]
