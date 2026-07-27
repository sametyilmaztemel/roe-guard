"""
roe_guard — Rules of Engagement policy-enforcement library.

Provides programmatic scope-control for security operations: define what
targets, time-windows, and action types are allowed, and every out-of-scope
action is automatically denied and logged to a tamper-evident audit chain.

Public API will be exposed in later tickets.  This package currently ships
only the module skeleton.
"""

__version__ = "0.1.0a1"

__all__ = [
    "__version__",
]
