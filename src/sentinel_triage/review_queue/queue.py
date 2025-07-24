"""Lightweight analyst review queue: a SQLite-backed table of triaged
incidents that an analyst works through with three actions -- approve
(confirmed true positive, escalate to Tier-2 handled outside this queue's
scope unless ``escalate`` is used), reject (confirmed false positive), or
escalate (needs a senior analyst / IR). This intentionally stops short of a
full SOC console (no case management, no ticketing integration, no
multi-analyst assignment) per the trimmed prototype scope.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from sentinel_triage.triage.llm_client import TriageResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS review_queue (
    incident_id TEXT PRIMARY KEY,
    entity_key TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    cited_event_ids TEXT NOT NULL,
    detection_titles TEXT NOT NULL,
    mitre_techniques TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    reviewed_at TEXT,
    reviewer_note TEXT
);
"""


class ReviewStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"


class InvalidTransitionError(ValueError):
    """Raised when attempting to review an incident that is not pending,
    or that does not exist in the queue."""


# An incident can only be reviewed once from PENDING; already-reviewed
# incidents must not be silently overwritten (an analyst re-clicking
# "approve" is a bug, not a valid re-review) -- callers that want to
# change a decision must do so explicitly, which this module does not
# expose, keeping an audit-safe single decision per incident.
_TERMINAL = {ReviewStatus.APPROVED, ReviewStatus.REJECTED, ReviewStatus.ESCALATED}


@dataclass
class ReviewItem:
    incident_id: str
    entity_key: str
    summary: str
    severity: str
    confidence: float
    cited_event_ids: list[str]
    detection_titles: list[str]
    mitre_techniques: list[str]
    status: ReviewStatus
    created_at: str
    reviewed_at: str | None
    reviewer_note: str | None

    @staticmethod
    def _from_row(row: sqlite3.Row) -> "ReviewItem":
        return ReviewItem(
            incident_id=row["incident_id"],
            entity_key=row["entity_key"],
            summary=row["summary"],
            severity=row["severity"],
            confidence=row["confidence"],
            cited_event_ids=json.loads(row["cited_event_ids"]),
            detection_titles=json.loads(row["detection_titles"]),
            mitre_techniques=json.loads(row["mitre_techniques"]),
            status=ReviewStatus(row["status"]),
            created_at=row["created_at"],
            reviewed_at=row["reviewed_at"],
            reviewer_note=row["reviewer_note"],
        )


class ReviewQueue:
    """SQLite-backed review queue. Pass ``":memory:"`` (the default) for
    tests / ephemeral use, or a file path to persist across process
    restarts."""

    def __init__(self, db_path: str | Path = ":memory:"):
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def enqueue(self, triage_result: TriageResult, entity_key: str) -> None:
        payload = triage_result.to_dict()
        self._conn.execute(
            """
            INSERT INTO review_queue (
                incident_id, entity_key, summary, severity, confidence,
                cited_event_ids, detection_titles, mitre_techniques,
                status, created_at, reviewed_at, reviewer_note
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL)
            ON CONFLICT(incident_id) DO UPDATE SET
                summary=excluded.summary,
                severity=excluded.severity,
                confidence=excluded.confidence,
                cited_event_ids=excluded.cited_event_ids,
                detection_titles=excluded.detection_titles,
                mitre_techniques=excluded.mitre_techniques
            WHERE review_queue.status = 'pending'
            """,
            (
                triage_result.incident_id,
                entity_key,
                payload["summary"],
                payload["severity"],
                payload["confidence"],
                json.dumps(payload["cited_event_ids"]),
                json.dumps(payload["detection_titles"]),
                json.dumps(payload["mitre_techniques"]),
                ReviewStatus.PENDING.value,
                _now(),
            ),
        )
        self._conn.commit()

    def get(self, incident_id: str) -> ReviewItem | None:
        row = self._conn.execute(
            "SELECT * FROM review_queue WHERE incident_id = ?", (incident_id,)
        ).fetchone()
        return ReviewItem._from_row(row) if row else None

    def list_pending(self, order_by_severity: bool = True) -> list[ReviewItem]:
        rows = self._conn.execute("SELECT * FROM review_queue WHERE status = 'pending'").fetchall()
        items = [ReviewItem._from_row(r) for r in rows]
        if order_by_severity:
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            items.sort(key=lambda i: (order.get(i.severity, 99), -i.confidence))
        return items

    def list_all(self) -> list[ReviewItem]:
        rows = self._conn.execute("SELECT * FROM review_queue").fetchall()
        return [ReviewItem._from_row(r) for r in rows]

    def _transition(self, incident_id: str, new_status: ReviewStatus, note: str | None) -> ReviewItem:
        item = self.get(incident_id)
        if item is None:
            raise InvalidTransitionError(f"No such incident in review queue: {incident_id}")
        if item.status != ReviewStatus.PENDING:
            raise InvalidTransitionError(
                f"Incident {incident_id} is already {item.status.value}; cannot transition to "
                f"{new_status.value}"
            )
        self._conn.execute(
            "UPDATE review_queue SET status = ?, reviewed_at = ?, reviewer_note = ? WHERE incident_id = ?",
            (new_status.value, _now(), note, incident_id),
        )
        self._conn.commit()
        updated = self.get(incident_id)
        assert updated is not None
        return updated

    def approve(self, incident_id: str, note: str | None = None) -> ReviewItem:
        return self._transition(incident_id, ReviewStatus.APPROVED, note)

    def reject(self, incident_id: str, note: str | None = None) -> ReviewItem:
        return self._transition(incident_id, ReviewStatus.REJECTED, note)

    def escalate(self, incident_id: str, note: str | None = None) -> ReviewItem:
        return self._transition(incident_id, ReviewStatus.ESCALATED, note)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
