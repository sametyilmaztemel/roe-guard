"""
roe_guard.audit

Tamper-evident, append-only audit logger using a SHA-256 hash chain.

Every record includes the hash of the previous record, so any after-the-fact
modification or deletion can be detected by :func:`verify`.

Implemented in T5.  At present only the class skeleton and docstrings are
provided.
"""

from __future__ import annotations

from pathlib import Path

from roe_guard.models import AuditEntry, Decision


class AuditLog:
    """Append-only JSONL audit log with SHA-256 hash chaining.

    Attributes:
        path: Path to the JSONL audit file.
    """

    def __init__(self, path: str | Path) -> None:
        """Open (or create) an audit log at *path*.

        Args:
            path: Filesystem path for the JSONL audit log.
        """
        self.path = Path(path)
        raise NotImplementedError("AuditLog.__init__() — implemented in T5")

    def record(self, decision: Decision) -> AuditEntry:
        """Append a decision to the audit chain.

        Computes the entry hash from the previous entry's hash plus the
        current record's canonical JSON, then writes a single JSONL line.

        Args:
            decision: The :class:`~roe_guard.models.Decision` to record.

        Returns:
            The :class:`~roe_guard.models.AuditEntry` that was written.
        """
        raise NotImplementedError("AuditLog.record() — implemented in T5")

    def verify(self) -> bool:
        """Verify the integrity of the entire hash chain.

        Reads every line, recomputes each entry hash, and confirms it
        matches the stored value **and** that ``prev_hash`` links are
        consistent.

        Returns:
            ``True`` if the chain is intact, ``False`` if any tampering
            is detected.
        """
        raise NotImplementedError("AuditLog.verify() — implemented in T5")


__all__ = ["AuditLog"]
