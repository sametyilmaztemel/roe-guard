"""Tests for roe_guard.integrations — T6 decorator + context manager.

Covers:
    - @guarded ALLOW: function called, result returned
    - @guarded DENY: function NOT called, OutOfScopeError raised
    - @guarded REQUIRES_APPROVAL: function NOT called, ApprovalRequiredError raised
    - target_arg: positional + keyword both work
    - engagement.window(): expired policy raises PolicyExpiredError
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from roe_guard.exceptions import (
    ApprovalRequiredError,
    OutOfScopeError,
    PolicyExpiredError,
)
from roe_guard.integrations.decorator import guarded
from roe_guard.models import (
    BlackoutWindow,
    DecisionType,
    Engagement,
    Policy,
    Scope,
    ScopeEntry,
)

NOW = datetime.now(timezone.utc)
VALID_FROM = NOW - timedelta(days=1)
VALID_UNTIL = NOW + timedelta(days=10)


def _make_policy(**kwargs: object) -> Policy:
    return Policy(
        engagement_id="test-001",
        valid_from=VALID_FROM,
        valid_until=VALID_UNTIL,
        scope=Scope(
            allow=kwargs.get("scope_allow", [ScopeEntry(cidr="10.20.0.0/16")]),  # type: ignore[arg-type]
            deny=kwargs.get("scope_deny", []),  # type: ignore[arg-type]
        ),
        actions_allow=kwargs.get("actions_allow", ["recon", "exploit"]),  # type: ignore[arg-type]
        actions_deny=kwargs.get("actions_deny", ["destructive"]),  # type: ignore[arg-type]
        blackout_windows=kwargs.get("blackout_windows", []),  # type: ignore[arg-type]
        approval_required_for=kwargs.get("approval_required_for", []),  # type: ignore[arg-type]
    )


def _eng(**kwargs: object) -> Engagement:
    return Engagement(policy=_make_policy(**kwargs))


# ---------------------------------------------------------------------------
# @guarded — ALLOW
# ---------------------------------------------------------------------------


class TestGuardedAllow:
    def test_function_called_and_result_returned(self) -> None:
        eng = _eng()

        @guarded(eng, action_type="recon", target_arg="host")
        def scan(host: str) -> str:
            return f"scanned:{host}"

        assert scan("10.20.3.5") == "scanned:10.20.3.5"

    def test_function_called_with_extra_args(self) -> None:
        eng = _eng()

        @guarded(eng, action_type="recon", target_arg="host")
        def scan(host: str, port: int, *, verbose: bool = False) -> str:
            return f"{host}:{port}:{verbose}"

        assert scan("10.20.3.5", 80, verbose=True) == "10.20.3.5:80:True"

    def test_functor_metadata_preserved(self) -> None:
        eng = _eng()

        @guarded(eng, action_type="recon", target_arg="host")
        def scan(host: str) -> str:
            """Scan a host."""
            return host

        assert scan.__name__ == "scan"
        assert "Scan a host" in (scan.__doc__ or "")

    def test_function_can_return_none(self) -> None:
        eng = _eng()

        @guarded(eng, action_type="recon", target_arg="host")
        def noop(host: str) -> None:
            return None

        assert noop("10.20.3.5") is None


# ---------------------------------------------------------------------------
# @guarded — DENY (CORE: function must NOT be called)
# ---------------------------------------------------------------------------


class TestGuardedDeny:
    def test_function_not_called_on_deny(self) -> None:
        """CORE TEST: function must NOT be called when policy denies."""
        eng = _eng(actions_deny=["destructive"])
        calls: list[str] = []

        @guarded(eng, action_type="destructive", target_arg="host")
        def destroy(host: str) -> None:
            calls.append(host)  # side-effect: would be observed if called

        with pytest.raises(OutOfScopeError):
            destroy("10.20.3.5")
        assert calls == [], "wrapped function was called despite DENY"

    def test_function_not_called_when_target_out_of_scope(self) -> None:
        eng = _eng()  # scope.allow = 10.20.0.0/16
        calls: list[str] = []

        @guarded(eng, action_type="recon", target_arg="host")
        def scan(host: str) -> None:
            calls.append(host)

        with pytest.raises(OutOfScopeError):
            scan("8.8.8.8")  # not in scope
        assert calls == []

    def test_function_not_called_when_policy_expired(self) -> None:
        eng = _eng()
        # Make policy expired by mutating valid_until via replacement.
        expired = Policy(
            engagement_id="test-001",
            valid_from=VALID_FROM,
            valid_until=NOW - timedelta(seconds=1),
            scope=eng.policy.scope,
            actions_allow=eng.policy.actions_allow,
            actions_deny=eng.policy.actions_deny,
        )
        eng = Engagement(policy=expired)
        calls: list[str] = []

        @guarded(eng, action_type="recon", target_arg="host")
        def scan(host: str) -> None:
            calls.append(host)

        with pytest.raises(OutOfScopeError):
            scan("10.20.3.5")
        assert calls == []

    def test_out_of_scope_error_carries_reason(self) -> None:
        eng = _eng()
        with pytest.raises(OutOfScopeError) as exc_info:
            scan = guarded(eng, action_type="recon", target_arg="host")(
                lambda host: None
            )
            scan("8.8.8.8")
        assert "8.8.8.8" in str(exc_info.value)


# ---------------------------------------------------------------------------
# @guarded — REQUIRES_APPROVAL
# ---------------------------------------------------------------------------


class TestGuardedApprovalRequired:
    def test_function_not_called_on_approval_required(self) -> None:
        eng = _eng(
            actions_allow=["persistence-test"],
            approval_required_for=["persistence-test"],
        )
        calls: list[str] = []

        @guarded(eng, action_type="persistence-test", target_arg="host")
        def persist(host: str) -> None:
            calls.append(host)

        with pytest.raises(ApprovalRequiredError):
            persist("10.20.3.5")
        assert calls == []

    def test_approval_error_carries_target_and_action(self) -> None:
        eng = _eng(
            actions_allow=["persistence-test"],
            approval_required_for=["persistence-test"],
        )

        @guarded(eng, action_type="persistence-test", target_arg="host")
        def persist(host: str) -> None:
            return None

        with pytest.raises(ApprovalRequiredError) as exc_info:
            persist("10.20.3.5")
        assert exc_info.value.target == "10.20.3.5"
        assert exc_info.value.action_type == "persistence-test"


# ---------------------------------------------------------------------------
# @guarded — target_arg binding (positional + keyword)
# ---------------------------------------------------------------------------


class TestGuardedTargetArg:
    def test_positional_target(self) -> None:
        eng = _eng()

        @guarded(eng, action_type="recon", target_arg="host")
        def scan(host: str) -> str:
            return f"got:{host}"

        # host is the first positional arg
        assert scan("10.20.3.5") == "got:10.20.3.5"

    def test_keyword_target(self) -> None:
        eng = _eng()

        @guarded(eng, action_type="recon", target_arg="host")
        def scan(host: str) -> str:
            return f"got:{host}"

        # host passed as keyword
        assert scan(host="10.20.3.5") == "got:10.20.3.5"

    def test_target_not_first_positional(self) -> None:
        eng = _eng()

        @guarded(eng, action_type="recon", target_arg="host")
        def scan(mode: str, host: str) -> str:
            return f"{mode}:{host}"

        # host is the SECOND positional arg
        assert scan("quick", "10.20.3.5") == "quick:10.20.3.5"
        assert scan(mode="quick", host="10.20.3.5") == "quick:10.20.3.5"

    def test_missing_target_raises_typeerror(self) -> None:
        eng = _eng()

        @guarded(eng, action_type="recon", target_arg="host")
        def scan(port: int) -> int:
            return port

        with pytest.raises(TypeError, match="target_arg"):
            scan(80)  # no 'host' arg

    def test_non_string_target_raises_typeerror(self) -> None:
        eng = _eng()

        @guarded(eng, action_type="recon", target_arg="host")
        def scan(host: int) -> int:
            return host

        with pytest.raises(TypeError, match="must be a string"):
            scan(12345)


# ---------------------------------------------------------------------------
# engagement.window() — context manager
# ---------------------------------------------------------------------------


class TestEngagementWindow:
    def test_active_window_does_not_raise(self) -> None:
        eng = _eng()
        with eng.window():
            pass  # no error

    def test_active_window_allows_inner_checks(self) -> None:
        eng = _eng()
        results = []
        with eng.window():
            for host in ("10.20.3.5", "10.20.3.6"):
                d = eng.check(host, "recon")
                results.append(d.outcome)
        assert all(o is DecisionType.ALLOW for o in results)

    def test_expired_policy_raises_at_entry(self) -> None:
        scope = _eng().policy.scope
        expired = Policy(
            engagement_id="test-001",
            valid_from=VALID_FROM,
            valid_until=NOW - timedelta(seconds=1),
            scope=scope,
            actions_allow=["recon"],
            actions_deny=[],
        )
        eng = Engagement(policy=expired)
        with pytest.raises(PolicyExpiredError), eng.window():
            pass

    def test_not_yet_active_raises_at_entry(self) -> None:
        future = Policy(
            engagement_id="test-001",
            valid_from=NOW + timedelta(hours=1),
            valid_until=VALID_UNTIL,
            scope=_eng().policy.scope,
            actions_allow=[],
            actions_deny=[],
        )
        eng = Engagement(policy=future)
        with pytest.raises(PolicyExpiredError), eng.window():
            pass

    def test_inside_blackout_is_not_blocked_at_window_entry(self) -> None:
        """The window() context manager only checks the time window, not blackout."""
        # Spec §6 example uses engagement.check inside the block to evaluate
        # each action, so blackout enforcement happens at check-time, not at
        # window-entry.
        bw = BlackoutWindow(
            start=NOW - timedelta(hours=1),
            end=NOW + timedelta(hours=1),
            reason="maintenance",
        )
        eng = _eng(blackout_windows=[bw])
        # Window entry itself doesn't trip on blackout.
        with eng.window():
            d = eng.check("10.20.3.5", "recon", now=NOW)
            assert d.outcome is DecisionType.DENY  # caught at check time

    def test_block_body_runs_after_valid_entry(self) -> None:
        eng = _eng()
        executed = []
        with eng.window():
            executed.append("inside")
        assert executed == ["inside"]


# ---------------------------------------------------------------------------
# Spec §6 example — verbatim
# ---------------------------------------------------------------------------


class TestSpecExamples:
    def test_spec_context_manager_example(self) -> None:
        """Spec §6 example::

        with engagement.window():
            for host in discovered_hosts:
                engagement.check(host, "recon").raise_if_denied()
                scan(host)
        """
        eng = _eng()
        discovered_hosts = ["10.20.3.5", "10.20.3.6", "10.20.3.7"]
        scanned: list[str] = []

        def scan(host: str) -> None:
            scanned.append(host)

        with eng.window():
            for host in discovered_hosts:
                eng.check(host, "recon").raise_if_denied()
                scan(host)

        assert scanned == discovered_hosts

    def test_spec_decorator_example(self) -> None:
        """Spec §6 example::

        @guarded(engagement, action_type="exploit", target_arg="host")
        def run_exploit(host: str):
            ...
        """
        eng = _eng()
        results: list[str] = []

        @guarded(eng, action_type="exploit", target_arg="host")
        def run_exploit(host: str) -> str:
            results.append(host)
            return f"exploited:{host}"

        assert run_exploit("10.20.3.5") == "exploited:10.20.3.5"
        assert results == ["10.20.3.5"]
