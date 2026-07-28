"""Tests for roe_guard.engine.enforce — T4 decision engine.

Covers all 8 priority steps of spec §5, plus CIDR/hostname matching.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from roe_guard.engine import enforce, raise_if_expired
from roe_guard.exceptions import PolicyExpiredError
from roe_guard.models import (
    BlackoutWindow,
    Decision,
    DecisionType,
    Engagement,
    Policy,
    Scope,
    ScopeEntry,
)

NOW = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
VALID_FROM = NOW - timedelta(days=1)
VALID_UNTIL = NOW + timedelta(days=10)


def _make_policy(
    *,
    scope_allow: list[ScopeEntry] | None = None,
    scope_deny: list[ScopeEntry] | None = None,
    actions_allow: list[str] | None = None,
    actions_deny: list[str] | None = None,
    approval_required_for: list[str] | None = None,
    blackout_windows: list[BlackoutWindow] | None = None,
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
) -> Policy:
    return Policy(
        engagement_id="test-001",
        valid_from=valid_from or VALID_FROM,
        valid_until=valid_until or VALID_UNTIL,
        scope=Scope(
            allow=scope_allow
            if scope_allow is not None
            else [ScopeEntry(cidr="10.20.0.0/16")],
            deny=scope_deny if scope_deny is not None else [],
        ),
        actions_allow=actions_allow
        if actions_allow is not None
        else ["recon", "exploit"],
        actions_deny=actions_deny if actions_deny is not None else ["destructive"],
        blackout_windows=blackout_windows if blackout_windows is not None else [],
        approval_required_for=approval_required_for
        if approval_required_for is not None
        else [],
        approvers=[],
    )


def _eng(
    *,
    scope_allow: list[ScopeEntry] | None = None,
    scope_deny: list[ScopeEntry] | None = None,
    actions_allow: list[str] | None = None,
    actions_deny: list[str] | None = None,
    approval_required_for: list[str] | None = None,
    blackout_windows: list[BlackoutWindow] | None = None,
    valid_from: datetime | None = None,
    valid_until: datetime | None = None,
) -> Engagement:
    return Engagement(
        policy=_make_policy(
            scope_allow=scope_allow,
            scope_deny=scope_deny,
            actions_allow=actions_allow,
            actions_deny=actions_deny,
            approval_required_for=approval_required_for,
            blackout_windows=blackout_windows,
            valid_from=valid_from,
            valid_until=valid_until,
        )
    )


# ---------------------------------------------------------------------------
# Step (a) — Time-window check
# ---------------------------------------------------------------------------


class TestTimeWindow:
    def test_expired_policy_denies(self) -> None:
        eng = _eng(valid_until=NOW - timedelta(seconds=1))
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY
        assert "expired" in d.reason.lower() or "not yet active" in d.reason.lower()

    def test_not_yet_active_denies(self) -> None:
        eng = _eng(valid_from=NOW + timedelta(hours=1))
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY
        assert "not yet active" in d.reason

    def test_inside_window_allows_target(self) -> None:
        eng = _eng()
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.ALLOW

    def test_valid_until_is_exclusive(self) -> None:
        eng = _eng(valid_until=NOW)
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        # now == valid_until → outside window (exclusive end)
        assert d.outcome is DecisionType.DENY


# ---------------------------------------------------------------------------
# Step (b) — Blackout window check
# ---------------------------------------------------------------------------


class TestBlackoutWindow:
    def test_inside_blackout_denies(self) -> None:
        bw = BlackoutWindow(
            start=NOW - timedelta(hours=1),
            end=NOW + timedelta(hours=1),
            reason="maintenance",
        )
        eng = _eng(blackout_windows=[bw])
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY
        assert "blackout" in d.reason.lower()
        assert "maintenance" in d.reason

    def test_outside_blackout_allows(self) -> None:
        bw = BlackoutWindow(
            start=NOW + timedelta(hours=2),
            end=NOW + timedelta(hours=3),
            reason="future",
        )
        eng = _eng(blackout_windows=[bw])
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.ALLOW

    def test_blackout_takes_precedence_over_target_match(self) -> None:
        # Even when target is in scope.allow, blackout should deny first.
        bw = BlackoutWindow(
            start=NOW - timedelta(hours=1),
            end=NOW + timedelta(hours=1),
            reason="stop everything",
        )
        eng = _eng(blackout_windows=[bw])
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY
        assert "blackout" in d.reason.lower()


# ---------------------------------------------------------------------------
# Step (c) — Explicit deny overrides allow
# ---------------------------------------------------------------------------


class TestDenyOverridesAllow:
    def test_target_in_deny_is_denied(self) -> None:
        eng = _eng(
            scope_allow=[ScopeEntry(cidr="10.20.0.0/16")],
            scope_deny=[ScopeEntry(cidr="10.20.5.0/24")],
        )
        d = enforce(eng, "10.20.5.7", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY
        assert "denied" in d.reason.lower()

    def test_deny_overrides_even_when_in_allow(self) -> None:
        """CRITICAL: deny MUST be checked BEFORE allow (priority order)."""
        # Both lists cover the same target.
        eng = _eng(
            scope_allow=[ScopeEntry(cidr="10.20.0.0/16")],
            scope_deny=[ScopeEntry(cidr="10.20.0.0/16")],  # same range
        )
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY, (
            "deny MUST override allow even when both match (spec §5 priority)"
        )
        assert "denied" in d.reason.lower()

    def test_target_not_in_deny_proceeds_to_allow_check(self) -> None:
        eng = _eng(
            scope_allow=[ScopeEntry(cidr="10.20.0.0/16")],
            scope_deny=[ScopeEntry(cidr="10.20.5.0/24")],  # different subnet
        )
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.ALLOW


# ---------------------------------------------------------------------------
# Step (d) — Target must be in scope.allow
# ---------------------------------------------------------------------------


class TestScopeAllow:
    def test_target_outside_allow_denies(self) -> None:
        eng = _eng(scope_allow=[ScopeEntry(cidr="10.20.0.0/16")])
        d = enforce(eng, "10.99.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY
        assert "not in allowed scope" in d.reason.lower()

    def test_target_in_allow_proceeds(self) -> None:
        eng = _eng(scope_allow=[ScopeEntry(cidr="10.20.0.0/16")])
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.ALLOW

    def test_empty_scope_allow_denies(self) -> None:
        eng = _eng(scope_allow=[])
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY


# ---------------------------------------------------------------------------
# Step (e) — actions.deny
# ---------------------------------------------------------------------------


class TestActionsDeny:
    def test_action_in_deny_denies(self) -> None:
        eng = _eng(actions_allow=["recon"], actions_deny=["destructive"])
        d = enforce(eng, "10.20.3.5", "destructive", now=NOW)
        assert d.outcome is DecisionType.DENY
        assert "destructive" in d.reason

    def test_action_in_allow_is_allowed(self) -> None:
        eng = _eng(actions_allow=["recon"], actions_deny=["destructive"])
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.ALLOW

    def test_action_in_both_deny_and_allow_denies(self) -> None:
        """Deny MUST win when same action is in both lists (priority order)."""
        eng = _eng(actions_allow=["recon"], actions_deny=["recon"])
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY


# ---------------------------------------------------------------------------
# Step (f) — approval_required_for
# ---------------------------------------------------------------------------


class TestApprovalRequired:
    def test_action_in_approval_required_returns_requires_approval(self) -> None:
        """CRITICAL: REQUIRES_APPROVAL must NOT be confused with ALLOW."""
        eng = _eng(
            actions_allow=["persistence-test"],
            approval_required_for=["persistence-test"],
        )
        d = enforce(eng, "10.20.3.5", "persistence-test", now=NOW)
        assert d.outcome is DecisionType.REQUIRES_APPROVAL
        assert d.allowed is False  # not ALLOW
        assert d.denied is False  # not DENY
        assert "approval" in d.reason.lower()

    def test_approval_required_checked_before_actions_allow(self) -> None:
        """Order check: approval list wins even if action is also in allow."""
        eng = _eng(
            actions_allow=["persistence-test"],
            approval_required_for=["persistence-test"],
        )
        d = enforce(eng, "10.20.3.5", "persistence-test", now=NOW)
        assert d.outcome is DecisionType.REQUIRES_APPROVAL


# ---------------------------------------------------------------------------
# Step (g) — actions.allow
# ---------------------------------------------------------------------------


class TestActionsAllow:
    def test_action_in_allow_allows(self) -> None:
        eng = _eng(actions_allow=["recon", "exploit"])
        d = enforce(eng, "10.20.3.5", "exploit", now=NOW)
        assert d.outcome is DecisionType.ALLOW


# ---------------------------------------------------------------------------
# Step (h) — Fail-closed default
# ---------------------------------------------------------------------------


class TestFailClosed:
    def test_unknown_action_denies(self) -> None:
        """If action is in neither allow/deny/approval list → DENY."""
        eng = _eng(actions_allow=["recon"], actions_deny=[])
        d = enforce(eng, "10.20.3.5", "unknown-action", now=NOW)
        assert d.outcome is DecisionType.DENY
        assert "not explicitly allowed" in d.reason.lower()

    def test_empty_allow_list_denies_known_action(self) -> None:
        eng = _eng(actions_allow=[], actions_deny=[])
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY


# ---------------------------------------------------------------------------
# Target matching (CIDR + hostname)
# ---------------------------------------------------------------------------


class TestTargetMatching:
    def test_cidr_match_inside(self) -> None:
        eng = _eng(scope_allow=[ScopeEntry(cidr="10.20.0.0/16")])
        assert enforce(eng, "10.20.5.7", "recon", now=NOW).outcome is DecisionType.ALLOW

    def test_cidr_match_outside(self) -> None:
        eng = _eng(scope_allow=[ScopeEntry(cidr="10.20.0.0/16")])
        assert enforce(eng, "10.21.0.1", "recon", now=NOW).outcome is DecisionType.DENY

    def test_cidr_at_boundary(self) -> None:
        eng = _eng(scope_allow=[ScopeEntry(cidr="10.20.0.0/16")])
        # 10.20.0.0 is network; 10.20.255.255 is last usable
        assert enforce(eng, "10.20.0.0", "recon", now=NOW).outcome is DecisionType.ALLOW
        assert (
            enforce(eng, "10.20.255.255", "recon", now=NOW).outcome
            is DecisionType.ALLOW
        )
        assert enforce(eng, "10.21.0.0", "recon", now=NOW).outcome is DecisionType.DENY

    def test_hostname_wildcard_match(self) -> None:
        eng = _eng(scope_allow=[ScopeEntry(hostname="*.staging.acme.internal")])
        d = enforce(eng, "web.staging.acme.internal", "recon", now=NOW)
        assert d.outcome is DecisionType.ALLOW

    def test_hostname_wildcard_no_match(self) -> None:
        eng = _eng(scope_allow=[ScopeEntry(hostname="*.staging.acme.internal")])
        d = enforce(eng, "web.prod.acme.internal", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY

    def test_hostname_match_is_case_insensitive(self) -> None:
        eng = _eng(scope_allow=[ScopeEntry(hostname="*.STAGING.acme.internal")])
        d = enforce(eng, "WEB.staging.Acme.Internal", "recon", now=NOW)
        assert d.outcome is DecisionType.ALLOW

    def test_ip_target_does_not_match_hostname_entry(self) -> None:
        """IP target should NOT match a hostname entry."""
        eng = _eng(scope_allow=[ScopeEntry(hostname="*.staging.acme.internal")])
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY

    def test_hostname_target_does_not_match_cidr_entry(self) -> None:
        """Hostname target should NOT match a CIDR entry."""
        eng = _eng(scope_allow=[ScopeEntry(cidr="10.20.0.0/16")])
        d = enforce(eng, "web.staging.acme.internal", "recon", now=NOW)
        assert d.outcome is DecisionType.DENY

    def test_multiple_scope_entries_any_matches(self) -> None:
        eng = _eng(
            scope_allow=[
                ScopeEntry(cidr="10.20.0.0/16"),
                ScopeEntry(hostname="*.staging.acme.internal"),
            ]
        )
        assert enforce(eng, "10.20.3.5", "recon", now=NOW).outcome is DecisionType.ALLOW
        assert (
            enforce(eng, "web.staging.acme.internal", "recon", now=NOW).outcome
            is DecisionType.ALLOW
        )
        assert enforce(eng, "8.8.8.8", "recon", now=NOW).outcome is DecisionType.DENY


# ---------------------------------------------------------------------------
# Decision metadata + Engagement.check() integration
# ---------------------------------------------------------------------------


class TestDecisionMetadata:
    def test_decision_timestamp_is_now(self) -> None:
        eng = _eng()
        d = enforce(eng, "10.20.3.5", "recon", now=NOW)
        assert d.timestamp == NOW

    def test_decision_carries_target_and_action(self) -> None:
        eng = _eng()
        d = enforce(eng, "10.20.3.5", "exploit", now=NOW)
        assert d.target == "10.20.3.5"
        assert d.action_type == "exploit"

    def test_default_now_uses_current_time(self) -> None:
        # Build engagement valid for a wide window so default now works.
        eng = _eng(
            valid_from=NOW - timedelta(days=1),
            valid_until=NOW + timedelta(days=365),
        )
        d = enforce(eng, "10.20.3.5", "recon")
        # Should not raise and should produce a sensible timestamp.
        assert isinstance(d, Decision)
        assert d.timestamp.tzinfo is not None


class TestEngagementCheck:
    def test_check_returns_decision(self) -> None:
        eng = _eng()
        d = eng.check(target="10.20.3.5", action_type="recon", now=NOW)
        assert isinstance(d, Decision)
        assert d.outcome is DecisionType.ALLOW

    def test_check_no_longer_raises_not_implemented(self) -> None:
        eng = _eng()
        # Before T4 this raised NotImplementedError. Now it returns a Decision.
        d = eng.check(target="10.20.3.5", action_type="recon", now=NOW)
        assert d.outcome is DecisionType.ALLOW


class TestRaiseIfExpired:
    def test_does_not_raise_inside_window(self) -> None:
        eng = _eng()
        raise_if_expired(eng, now=NOW)  # should not raise

    def test_raises_outside_window(self) -> None:
        eng = _eng(valid_until=NOW - timedelta(seconds=1))
        with pytest.raises(PolicyExpiredError) as exc_info:
            raise_if_expired(eng, now=NOW)
        assert exc_info.value.engagement_id == "test-001"
