"""Tests for roe_guard.audit — T5 append-only hash-chained audit log.

Covers:
    - First record uses genesis prev_hash
    - Subsequent records chain via prev_hash → entry_hash
    - verify() returns valid=True on clean chain
    - Tampered entry detected: valid=False + broken_at_index points at it
    - Empty file → valid=True, total_entries=0
    - Duplicate decisions produce different hashes (timestamp differs)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from roe_guard.audit import GENESIS_PREV_HASH, AuditLog
from roe_guard.exceptions import AuditIntegrityError
from roe_guard.models import (
    AuditVerificationResult,
    Decision,
    DecisionType,
)

NOW = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)


def _decision(
    target: str = "10.20.3.5",
    action_type: str = "recon",
    outcome: DecisionType = DecisionType.ALLOW,
    reason: str = "test",
    timestamp: datetime | None = None,
) -> Decision:
    return Decision(
        outcome=outcome,
        reason=reason,
        target=target,
        action_type=action_type,
        timestamp=timestamp or NOW,
    )


@pytest.fixture
def tmp_audit(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


# ---------------------------------------------------------------------------
# Basic recording
# ---------------------------------------------------------------------------


class TestRecord:
    def test_first_record_uses_genesis_prev_hash(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        entry = log.record(_decision(), engagement_id="eng-1")
        assert entry.prev_hash == GENESIS_PREV_HASH
        assert len(entry.entry_hash) == 64

    def test_first_record_writes_one_line(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        log.record(_decision())
        lines = tmp_audit.read_text().splitlines()
        assert len(lines) == 1

    def test_second_record_chains_to_first(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        e1 = log.record(_decision(reason="first"), engagement_id="eng-1")
        e2 = log.record(_decision(reason="second"), engagement_id="eng-1")
        assert e2.prev_hash == e1.entry_hash
        assert e2.entry_hash != e1.entry_hash

    def test_record_carries_decision_fields(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        d = _decision(target="host.example", action_type="exploit", reason="r")
        e = log.record(d, engagement_id="eng-x")
        assert e.target == "host.example"
        assert e.action_type == "exploit"
        assert e.reason == "r"
        assert e.decision is DecisionType.ALLOW
        assert e.engagement_id == "eng-x"

    def test_multiple_records_chain_correctly(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        entries = [
            log.record(_decision(reason=f"r{i}"), engagement_id="e") for i in range(5)
        ]
        for i in range(1, 5):
            assert entries[i].prev_hash == entries[i - 1].entry_hash

    def test_duplicate_decisions_produce_different_hashes(
        self, tmp_audit: Path
    ) -> None:
        """Same decision recorded twice should still hash differently.

        (timestamps may be identical here, but we use timestamp in the
        canonical payload; two records written at distinct instants get
        different timestamps.)
        """
        log = AuditLog(tmp_audit)
        t1 = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 8, 10, 12, 0, 1, tzinfo=timezone.utc)  # +1s
        d1 = _decision(reason="same", timestamp=t1)
        d2 = _decision(reason="same", timestamp=t2)
        e1 = log.record(d1)
        e2 = log.record(d2)
        assert e1.entry_hash != e2.entry_hash

    def test_append_only_no_overwrite(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        e1 = log.record(_decision(reason="original"))
        # Reopen and append; original line must remain unchanged.
        log2 = AuditLog(tmp_audit)
        log2.record(_decision(reason="new"))
        lines = tmp_audit.read_text().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["entry_hash"] == e1.entry_hash
        assert json.loads(lines[0])["reason"] == "original"

    def test_open_existing_log_continues_chain(self, tmp_audit: Path) -> None:
        log1 = AuditLog(tmp_audit)
        e1 = log1.record(_decision(reason="a"))
        log2 = AuditLog(tmp_audit)  # reopen
        e2 = log2.record(_decision(reason="b"))
        assert e2.prev_hash == e1.entry_hash


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------


class TestVerify:
    def test_clean_chain_returns_valid(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        for i in range(3):
            log.record(_decision(reason=f"r{i}"), engagement_id="e")
        result = log.verify()
        assert isinstance(result, AuditVerificationResult)
        assert result.valid is True
        assert result.total_entries == 3
        assert result.broken_at_index is None
        assert result.reason is None

    def test_empty_file_returns_valid_zero(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        result = log.verify()
        assert result.valid is True
        assert result.total_entries == 0
        assert result.broken_at_index is None

    def test_single_entry_valid(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        log.record(_decision())
        result = log.verify()
        assert result.valid is True
        assert result.total_entries == 1


# ---------------------------------------------------------------------------
# Tampering detection
# ---------------------------------------------------------------------------


class TestTampering:
    def test_middle_line_modified_detected(self, tmp_audit: Path) -> None:
        """CORE SECURITY TEST: modify a middle entry → verify detects it."""
        log = AuditLog(tmp_audit)
        for i in range(4):
            log.record(_decision(reason=f"r{i}"), engagement_id="e")

        # Tamper with line index 1 (the second entry): change its reason.
        lines = tmp_audit.read_text().splitlines()
        payload = json.loads(lines[1])
        payload["reason"] = "TAMPERED"
        lines[1] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        tmp_audit.write_text("\n".join(lines) + "\n")

        result = log.verify()
        assert result.valid is False
        assert result.broken_at_index == 1
        assert result.reason and "entry_hash mismatch" in result.reason

    def test_first_line_modified_detected(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        for i in range(3):
            log.record(_decision(reason=f"r{i}"))
        lines = tmp_audit.read_text().splitlines()
        payload = json.loads(lines[0])
        payload["target"] = "evil.target"
        lines[0] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        tmp_audit.write_text("\n".join(lines) + "\n")

        result = log.verify()
        assert result.valid is False
        assert result.broken_at_index == 0

    def test_last_line_modified_detected(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        for i in range(3):
            log.record(_decision(reason=f"r{i}"))
        lines = tmp_audit.read_text().splitlines()
        payload = json.loads(lines[-1])
        payload["decision"] = "DENY"  # was ALLOW
        lines[-1] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        tmp_audit.write_text("\n".join(lines) + "\n")

        result = log.verify()
        assert result.valid is False
        assert result.broken_at_index == 2

    def test_line_inserted_in_middle_detected(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        for i in range(3):
            log.record(_decision(reason=f"r{i}"))
        lines = tmp_audit.read_text().splitlines()
        # Inject a fake entry between line 0 and line 1.
        fake = {
            "engagement_id": "fake",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "target": "x",
            "action_type": "x",
            "decision": "ALLOW",
            "reason": "FAKE",
            "prev_hash": "x" * 64,
            "entry_hash": "y" * 64,
        }
        lines.insert(1, json.dumps(fake, sort_keys=True, separators=(",", ":")))
        tmp_audit.write_text("\n".join(lines) + "\n")

        result = log.verify()
        assert result.valid is False
        assert result.broken_at_index == 1
        assert result.reason and "prev_hash mismatch" in result.reason

    def test_line_deleted_detected(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        for i in range(4):
            log.record(_decision(reason=f"r{i}"))
        lines = tmp_audit.read_text().splitlines()
        # Delete line 2 — line 3's prev_hash will no longer match.
        del lines[2]
        tmp_audit.write_text("\n".join(lines) + "\n")

        result = log.verify()
        assert result.valid is False
        assert result.broken_at_index == 2
        assert result.reason and "prev_hash mismatch" in result.reason

    def test_corrupt_json_detected(self, tmp_audit: Path) -> None:
        log = AuditLog(tmp_audit)
        for i in range(3):
            log.record(_decision(reason=f"r{i}"))
        lines = tmp_audit.read_text().splitlines()
        lines[1] = "{not json"
        tmp_audit.write_text("\n".join(lines) + "\n")

        result = log.verify()
        assert result.valid is False
        assert result.broken_at_index == 1
        assert result.reason and "invalid JSON" in result.reason


# ---------------------------------------------------------------------------
# Exceptions module — AuditIntegrityError
# ---------------------------------------------------------------------------


class TestExceptions:
    def test_audit_integrity_error_inherits_roe_guard_error(self) -> None:
        from roe_guard.exceptions import RoeGuardError

        assert issubclass(AuditIntegrityError, RoeGuardError)

    def test_audit_integrity_error_message(self) -> None:
        e = AuditIntegrityError(broken_at_index=42)
        assert "42" in str(e)
        assert e.broken_at_index == 42
