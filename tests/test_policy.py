"""Tests for roe_guard.policy.load_policy — T3.

Covers:
    - Valid policy fixture loads successfully into a Policy object
    - Missing required field (engagement_id) -> PolicyParseError
    - Invalid CIDR -> PolicyParseError
    - Malformed date -> PolicyParseError
    - Empty scope entry (neither cidr nor hostname) -> PolicyParseError
    - Omitted optional fields default to empty lists
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from roe_guard.exceptions import PolicyParseError
from roe_guard.models import Policy, ScopeEntry
from roe_guard.policy import load_policy

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Valid policy
# ---------------------------------------------------------------------------


class TestValidPolicy:
    def test_loads_valid_policy(self) -> None:
        p = load_policy(FIXTURES / "valid_policy.yaml")
        assert isinstance(p, Policy)
        assert p.engagement_id == "acme-fintech-2026-08"

    def test_timestamps_are_utc_aware(self) -> None:
        p = load_policy(FIXTURES / "valid_policy.yaml")
        assert p.valid_from.tzinfo is not None
        assert p.valid_from.utcoffset().total_seconds() == 0
        assert p.valid_until.tzinfo is not None
        assert p.valid_until == datetime(2026, 8, 28, 23, 59, 59, tzinfo=timezone.utc)

    def test_scope_allow_and_deny(self) -> None:
        p = load_policy(FIXTURES / "valid_policy.yaml")
        assert len(p.scope.allow) == 2
        assert any(e.cidr == "10.20.0.0/16" for e in p.scope.allow)
        assert any(e.hostname == "*.staging.acme.internal" for e in p.scope.allow)
        assert len(p.scope.deny) == 1
        assert p.scope.deny[0].cidr == "10.20.5.0/24"

    def test_actions(self) -> None:
        p = load_policy(FIXTURES / "valid_policy.yaml")
        assert "recon" in p.actions_allow
        assert "persistence-test" in p.actions_allow
        assert "destructive" in p.actions_deny
        assert "data-exfil" in p.actions_deny

    def test_blackout_window(self) -> None:
        p = load_policy(FIXTURES / "valid_policy.yaml")
        assert len(p.blackout_windows) == 1
        bw = p.blackout_windows[0]
        assert bw.start == datetime(2026, 8, 15, tzinfo=timezone.utc)
        assert bw.end == datetime(2026, 8, 16, tzinfo=timezone.utc)
        assert bw.reason  # non-empty

    def test_approval_and_approvers(self) -> None:
        p = load_policy(FIXTURES / "valid_policy.yaml")
        assert p.approval_required_for == ["persistence-test"]
        assert p.approvers == ["ops-lead@acme.example"]

    def test_returns_immutable_policy(self) -> None:
        from dataclasses import FrozenInstanceError

        p = load_policy(FIXTURES / "valid_policy.yaml")
        with pytest.raises(FrozenInstanceError):
            p.engagement_id = "changed"  # type: ignore[misc]


class TestOptionalDefaults:
    def test_minimal_policy_loads_with_empty_defaults(self) -> None:
        # Minimal valid policy: only required fields + scope.allow
        minimal = FIXTURES / "valid_minimal.yaml"
        minimal.write_text(
            yaml.safe_dump(
                {
                    "engagement_id": "minimal-001",
                    "valid_from": "2026-09-01T00:00:00Z",
                    "valid_until": "2026-09-30T23:59:59Z",
                    "scope": {"allow": [{"cidr": "10.0.0.0/8"}]},
                }
            )
        )
        try:
            p = load_policy(minimal)
            assert p.actions_allow == []
            assert p.actions_deny == []
            assert p.blackout_windows == []
            assert p.approval_required_for == []
            assert p.approvers == []
            assert p.scope.allow == [ScopeEntry(cidr="10.0.0.0/8")]
            assert p.scope.deny == []
        finally:
            minimal.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Missing required field
# ---------------------------------------------------------------------------


class TestMissingRequiredField:
    def test_missing_engagement_id_raises(self) -> None:
        with pytest.raises(PolicyParseError) as exc_info:
            load_policy(FIXTURES / "missing_required_field.yaml")
        msg = str(exc_info.value)
        assert "engagement_id" in msg or "missing" in msg.lower()

    def test_missing_field_error_has_field_context(self) -> None:
        with pytest.raises(PolicyParseError) as exc_info:
            load_policy(FIXTURES / "missing_required_field.yaml")
        # Either field or reason set, not both required
        assert exc_info.value.field or "engagement_id" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Invalid CIDR
# ---------------------------------------------------------------------------


class TestInvalidCIDR:
    def test_invalid_cidr_raises(self) -> None:
        with pytest.raises(PolicyParseError) as exc_info:
            load_policy(FIXTURES / "invalid_cidr.yaml")
        msg = str(exc_info.value)
        assert "CIDR" in msg or "cidr" in msg
        assert "10.20.0.0/99" in msg or "scope.allow" in msg

    def test_invalid_cidr_field_context(self) -> None:
        with pytest.raises(PolicyParseError) as exc_info:
            load_policy(FIXTURES / "invalid_cidr.yaml")
        assert "scope.allow" in (exc_info.value.field or "")


# ---------------------------------------------------------------------------
# Malformed date
# ---------------------------------------------------------------------------


class TestMalformedDates:
    def test_bad_valid_from_raises(self) -> None:
        with pytest.raises(PolicyParseError) as exc_info:
            load_policy(FIXTURES / "malformed_dates.yaml")
        msg = str(exc_info.value)
        assert "valid_from" in msg
        assert "not-a-real-date" in msg or "ISO-8601" in msg

    def test_bad_date_field_context(self) -> None:
        with pytest.raises(PolicyParseError) as exc_info:
            load_policy(FIXTURES / "malformed_dates.yaml")
        assert exc_info.value.field == "valid_from"


# ---------------------------------------------------------------------------
# Empty scope entry
# ---------------------------------------------------------------------------


class TestEmptyScopeEntry:
    def test_empty_scope_entry_raises(self) -> None:
        f = FIXTURES / "empty_scope_entry.yaml"
        f.write_text(
            yaml.safe_dump(
                {
                    "engagement_id": "empty-scope",
                    "valid_from": "2026-08-01T00:00:00Z",
                    "valid_until": "2026-08-28T23:59:59Z",
                    "scope": {"allow": [{}]},
                }
            )
        )
        try:
            with pytest.raises(PolicyParseError) as exc_info:
                load_policy(f)
            assert "scope.allow[0]" in (exc_info.value.field or str(exc_info.value))
        finally:
            f.unlink(missing_ok=True)

    def test_scope_entry_with_both_cidr_and_hostname_raises(self) -> None:
        f = FIXTURES / "both_cidr_hostname.yaml"
        f.write_text(
            yaml.safe_dump(
                {
                    "engagement_id": "both-fields",
                    "valid_from": "2026-08-01T00:00:00Z",
                    "valid_until": "2026-08-28T23:59:59Z",
                    "scope": {"allow": [{"cidr": "10.0.0.0/8", "hostname": "x"}]},
                }
            )
        )
        try:
            with pytest.raises(PolicyParseError):
                load_policy(f)
        finally:
            f.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Other edge cases
# ---------------------------------------------------------------------------


class TestOtherEdgeCases:
    def test_missing_file_raises(self) -> None:
        with pytest.raises(PolicyParseError, match="not found"):
            load_policy(FIXTURES / "does-not-exist.yaml")

    def test_empty_file_raises(self) -> None:
        f = FIXTURES / "empty.yaml"
        f.write_text("")
        try:
            with pytest.raises(PolicyParseError, match="empty"):
                load_policy(f)
        finally:
            f.unlink(missing_ok=True)

    def test_malformed_yaml_raises(self) -> None:
        f = FIXTURES / "broken_yaml.yaml"
        f.write_text("engagement_id: 'unterminated\n  scope: [oops")
        try:
            with pytest.raises(PolicyParseError, match="YAML"):
                load_policy(f)
        finally:
            f.unlink(missing_ok=True)

    def test_naive_datetime_coerced_to_utc(self) -> None:
        f = FIXTURES / "naive_datetime.yaml"
        f.write_text(
            yaml.safe_dump(
                {
                    "engagement_id": "naive-ts",
                    "valid_from": "2026-08-01T00:00:00",  # no Z, no offset
                    "valid_until": "2026-08-28T23:59:59Z",
                    "scope": {"allow": [{"cidr": "10.0.0.0/8"}]},
                }
            )
        )
        try:
            p = load_policy(f)
            assert p.valid_from.tzinfo == timezone.utc
        finally:
            f.unlink(missing_ok=True)

    def test_inverted_dates_raise(self) -> None:
        f = FIXTURES / "inverted_dates.yaml"
        f.write_text(
            yaml.safe_dump(
                {
                    "engagement_id": "inverted",
                    "valid_from": "2026-09-01T00:00:00Z",
                    "valid_until": "2026-08-01T00:00:00Z",  # before valid_from
                    "scope": {"allow": [{"cidr": "10.0.0.0/8"}]},
                }
            )
        )
        try:
            with pytest.raises(PolicyParseError, match="strictly before"):
                load_policy(f)
        finally:
            f.unlink(missing_ok=True)

    def test_blackout_window_inverted_raises(self) -> None:
        f = FIXTURES / "inverted_blackout.yaml"
        f.write_text(
            yaml.safe_dump(
                {
                    "engagement_id": "inverted-bw",
                    "valid_from": "2026-08-01T00:00:00Z",
                    "valid_until": "2026-08-28T23:59:59Z",
                    "scope": {"allow": [{"cidr": "10.0.0.0/8"}]},
                    "blackout_windows": [
                        {
                            "start": "2026-08-16T00:00:00Z",
                            "end": "2026-08-15T00:00:00Z",  # inverted
                        }
                    ],
                }
            )
        )
        try:
            with pytest.raises(PolicyParseError, match="strictly before"):
                load_policy(f)
        finally:
            f.unlink(missing_ok=True)
