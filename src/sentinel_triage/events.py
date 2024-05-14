"""Canonical event schema shared across ingestion, correlation, detection,
and triage. Keeping this in one module avoids schema drift between the
components of the pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass(frozen=True)
class Event:
    """A single normalized endpoint/auth log event.

    ``event_id`` is stable and derived from the source dataset row so that
    citations produced by the LLM triage step can be checked against the
    original data (citation grounding).
    """

    event_id: str
    timestamp: datetime
    host: str
    user: str
    src_ip: str
    event_type: str
    raw: str
    country: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def entity_key(self) -> str:
        """Entity used for correlation grouping: a user is the primary
        identity we track across a session, host disambiguates shared
        service accounts."""
        return f"{self.user}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "user": self.user,
            "src_ip": self.src_ip,
            "event_type": self.event_type,
            "raw": self.raw,
            "country": self.country,
            **self.extra,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "Event":
        known = {"event_id", "timestamp", "host", "user", "src_ip", "event_type", "raw", "country"}
        ts = data["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        extra = {k: v for k, v in data.items() if k not in known}
        return Event(
            event_id=str(data["event_id"]),
            timestamp=ts,
            host=data["host"],
            user=data["user"],
            src_ip=data["src_ip"],
            event_type=data["event_type"],
            raw=data.get("raw", ""),
            country=data.get("country"),
            extra=extra,
        )
