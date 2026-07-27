"""
roe_guard.integrations.context

Context manager — activate an engagement window for a code block.

Usage (once implemented in T6)::

    with engagement.window():
        for host in discovered_hosts:
            engagement.check(host, "recon").raise_if_denied()
            scan(host)
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from roe_guard.models import Engagement


@contextmanager
def window(engagement: Engagement) -> Iterator[None]:
    """Context manager that activates an engagement scope.

    Within the ``with`` block, the engagement is considered active.  Any
    scope violation raises :class:`~roe_guard.exceptions.OutOfScopeError`.

    Args:
        engagement: The :class:`~roe_guard.models.Engagement` to activate.

    Yields:
        ``None`` — the caller performs checks inside the block.
    """
    raise NotImplementedError("window() context manager — implemented in T6")
    # The yield below is unreachable until T6; present for type-checkers.
    yield  # pragma: no cover


__all__ = ["window"]
