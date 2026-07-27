"""Smoke tests for T1 — verify all modules import and the package skeleton is intact.

Real tests will be added in T2-T9.
"""

import roe_guard
from roe_guard import __version__
from roe_guard.cli import main
from roe_guard.exceptions import (
    OutOfScopeError,
    PolicyExpiredError,
    PolicyParseError,
    RoeGuardError,
)
from roe_guard.models import (
    DecisionType,
)


def test_version():
    assert __version__ == "0.1.0a1"


def test_all_modules_import():
    # If we got here, every module above imported successfully.
    assert roe_guard is not None


def test_decision_type_values():
    assert {dt.value for dt in DecisionType} == {
        "ALLOW",
        "DENY",
        "REQUIRES_APPROVAL",
    }


def test_exception_hierarchy():
    assert issubclass(OutOfScopeError, RoeGuardError)
    assert issubclass(PolicyExpiredError, RoeGuardError)
    assert issubclass(PolicyParseError, RoeGuardError)


def test_cli_main_no_args_returns_zero():
    assert main([]) == 0
