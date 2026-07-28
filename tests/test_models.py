"""Tests for roe_guard.models — T2 data models.

Covers:
    - Valid construction of every dataclass
    - ScopeEntry validation (at least one of cidr/hostname required)
    - Decision.raise_if_denied() behavior (ALLOW no-op, DENY raises)
    - Immutability (frozen=True enforcement)
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from roe_guard.exceptions import OutOfScopeError
from roe_guard.models import (
    AuditEntry,
    BlackoutWindow,
    Decision,
    DecisionType,
    Engagement,
    Policy,
    Scope,
    ScopeEntry,
)

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

NOW = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)


def _make_policy() -> Policy:
    """Return a minimal but fully valid Policy."""
    return Policy(
        engagement_id="acme-2026-08",
        valid_from=datetime(2026, 8, 1, tzinfo=timezone.utc),
        valid_until=datetime(2026, 8, 28, tzinfo=timezone.utc),
        scope=Scope(
            allow=[ScopeEntry(cidr="10.20.0.0/16")],
            deny=[ScopeEntry(cidr="10.20.5.0/24")],
        ),
        actions_allow=["recon", "exploit"],
        actions_deny=["destructive"],
        blackout_windows=[
            BlackoutWindow(
                start=datetime(2026, 8, 15, tzinfo=timezone.utc),
                end=datetime(2026, 8, 16, tzinfo=timezone.utc),
                reason="maintenance",
            )
        ],
        approval_required_for=["persistence-test"],
        approvers=["ops-lead@acme.example"],
    )


# ---------------------------------------------------------------------------
# ScopeEntry
# ---------------------------------------------------------------------------


class TestScopeEntry:
    def test_create_with_cidr(self) -> None:
        entry = ScopeEntry(cidr="10.20.0.0/16")
        assert entry.cidr == "10.20.0.0/16"
        assert entry.hostname is None

    def test_create_with_hostname(self) -> None:
        entry = ScopeEntry(hostname="*.staging.acme.internal")
        assert entry.hostname == "*.staging.acme.internal"
        assert entry.cidr is None

    def test_both_none_raises(self) -> None:
        with pytest.raises(ValueError, match="at least one"):
            ScopeEntry()

    def test_frozen(self) -> None:
        entry = ScopeEntry(cidr="10.20.0.0/16")
        with pytest.raises(FrozenInstanceError):
            entry.cidr = "10.30.0.0/16"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


class TestScope:
    def test_valid_creation(self) -> None:
        scope = Scope(
            allow=[ScopeEntry(cidr="10.20.0.0/16")],
            deny=[ScopeEntry(hostname="prod-db.acme.internal")],
        )
        assert len(scope.allow) == 1
        assert len(scope.deny) == 1

    def test_defaults_empty(self) -> None:
        scope = Scope()
        assert scope.allow == []
        assert scope.deny == []

    def test_frozen(self) -> None:
        scope = Scope(allow=[ScopeEntry(cidr="10.20.0.0/16")])
        with pytest.raises(FrozenInstanceError):
            scope.allow = []  # type: ignore[misc]


# ---------------------------------------------------------------------------
# BlackoutWindow
# ---------------------------------------------------------------------------


class TestBlackoutWindow:
    def test_valid_creation(self) -> None:
        bw = BlackoutWindow(
            start=datetime(2026, 8, 15, tzinfo=timezone.utc),
            end=datetime(2026, 8, 16, tzinfo=timezone.utc),
            reason="maintenance",
        )
        assert bw.reason == "maintenance"

    def test_default_reason_empty(self) -> None:
        bw = BlackoutWindow(
            start=datetime(2026, 8, 15, tzinfo=timezone.utc),
            end=datetime(2026, 8, 16, tzinfo=timezone.utc),
        )
        assert bw.reason == ""

    def test_frozen(self) -> None:
        bw = BlackoutWindow(
            start=datetime(2026, 8, 15, tzinfo=timezone.utc),
            end=datetime(2026, 8, 16, tzinfo=timezone.utc),
        )
        with pytest.raises(FrozenInstanceError):
            bw.reason = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_valid_creation(self) -> None:
        p = _make_policy()
        assert p.engagement_id == "acme-2026-08"
        assert p.valid_from == datetime(2026, 8, 1, tzinfo=timezone.utc)
        assert p.valid_until == datetime(2026, 8, 28, tzinfo=timezone.utc)
        assert len(p.scope.allow) == 1
        assert len(p.scope.deny) == 1
        assert "recon" in p.actions_allow
        assert "destructive" in p.actions_deny
        assert len(p.blackout_windows) == 1
        assert "persistence-test" in p.approval_required_for

    def test_frozen(self) -> None:
        p = _make_policy()
        with pytest.raises(FrozenInstanceError):
            p.engagement_id = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Engagement
# ---------------------------------------------------------------------------


class TestEngagement:
    def test_valid_creation(self) -> None:
        eng = Engagement(policy=_make_policy())
        assert eng.policy.engagement_id == "acme-2026-08"

    def test_frozen(self) -> None:
        eng = Engagement(policy=_make_policy())
        with pytest.raises(FrozenInstanceError):
            eng.policy = _make_policy()  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------


class TestDecision:
    def _make_decision(self, outcome: DecisionType) -> Decision:
        return Decision(
            outcome=outcome,
            reason="test reason",
            target="10.20.3.5",
            action_type="exploit",
            timestamp=NOW,
        )

    def test_allow_creation(self) -> None:
        d = self._make_decision(DecisionType.ALLOW)
        assert d.allowed is True
        assert d.denied is False
        assert d.outcome == DecisionType.ALLOW

    def test_deny_creation(self) -> None:
        d = self._make_decision(DecisionType.DENY)
        assert d.allowed is False

    def test_allowed_property(self) -> None:
        assert self._make_decision(DecisionType.ALLOW).allowed is True
        assert self._make_decision(DecisionType.DENY).allowed is False
        assert self._make_decision(DecisionType.REQUIRES_APPROVAL).allowed is False

    def test_raise_if_denied_allow_is_noop(self) -> None:
        d = self._make_decision(DecisionType.ALLOW)
        d.raise_if_denied()  # should not raise

    def test_raise_if_denied_requires_approval_is_noop(self) -> None:
        d = self._make_decision(DecisionType.REQUIRES_APPROVAL)
        d.raise_if_denied()  # should not raise

    def test_raise_if_denied_deny_raises(self) -> None:
        d = self._make_decision(DecisionType.DENY)
        with pytest.raises(OutOfScopeError, match="Denied"):
            d.raise_if_denied()

    def test_raise_if_denied_error_message_content(self) -> None:
        d = self._make_decision(DecisionType.DENY)
        with pytest.raises(OutOfScopeError) as exc_info:
            d.raise_if_denied()
        msg = str(exc_info.value)
        assert "10.20.3.5" in msg
        assert "exploit" in msg
        assert "test reason" in msg

    def test_frozen(self) -> None:
        d = self._make_decision(DecisionType.ALLOW)
        with pytest.raises(FrozenInstanceError):
            d.reason = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# AuditEntry
# ---------------------------------------------------------------------------


class TestAuditEntry:
    def test_valid_creation(self) -> None:
        from datetime import datetime, timezone

        entry = AuditEntry(
            engagement_id="eng-1",
            timestamp=datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc),
            target="10.20.3.5",
            action_type="recon",
            decision=DecisionType.ALLOW,
            reason="test",
            prev_hash="0" * 64,
            entry_hash="a" * 64,
        )
        assert entry.decision == DecisionType.ALLOW
        assert len(entry.prev_hash) == 64
        assert len(entry.entry_hash) == 64

    def test_frozen(self) -> None:
        from datetime import datetime, timezone

        entry = AuditEntry(
            engagement_id="eng-1",
            timestamp=datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc),
            target="10.20.3.5",
            action_type="recon",
            decision=DecisionType.DENY,
            reason="test",
            prev_hash="0" * 64,
            entry_hash="a" * 64,
        )
        with pytest.raises(FrozenInstanceError):
            entry.prev_hash = "b" * 64  # type: ignore[misc]
