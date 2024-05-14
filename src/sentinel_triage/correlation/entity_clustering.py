"""Correlation engine: groups raw events into candidate incidents using a
sliding time window per entity (default entity = user, since that is the
identity a Tier-1 analyst actually investigates for auth logs).

Algorithm ("time-window + entity clustering"):

1. Partition all events by ``entity_key`` (e.g. username).
2. Within each entity's events (sorted chronologically), greedily walk the
   sequence and start a new candidate incident whenever the gap since the
   *previous* event in the entity's timeline exceeds ``window``. Otherwise
   the event is appended to the currently open incident.

This is a single-linkage clustering over the time axis: it is equivalent to
building a graph where two events for the same entity are connected if they
are within ``window`` of *some* chain of intermediate events, then taking
connected components. That makes a burst of 10 failed logins 5 minutes
apart -- each individually within the window of its neighbor -- one
incident even though the first and last event might be 45 minutes apart,
which matches how a SOC analyst would read a single sustained attack
session.

The window is intentionally per-entity rather than global: two unrelated
users each behaving normally at the same time must never be merged into
one incident just because their timestamps overlap.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import timedelta

from sentinel_triage.events import Event

DEFAULT_WINDOW = timedelta(minutes=15)


@dataclass
class CandidateIncident:
    incident_id: str
    entity_key: str
    events: list[Event]

    @property
    def start_time(self):
        return self.events[0].timestamp

    @property
    def end_time(self):
        return self.events[-1].timestamp

    @property
    def src_ips(self) -> set[str]:
        return {e.src_ip for e in self.events}

    @property
    def hosts(self) -> set[str]:
        return {e.host for e in self.events}

    @property
    def countries(self) -> set[str]:
        return {e.country for e in self.events if e.country}

    @property
    def event_types(self) -> list[str]:
        return [e.event_type for e in self.events]

    def event_ids(self) -> set[str]:
        return {e.event_id for e in self.events}

    def to_summary_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "entity_key": self.entity_key,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "num_events": len(self.events),
            "src_ips": sorted(self.src_ips),
            "hosts": sorted(self.hosts),
            "countries": sorted(self.countries),
            "event_types": self.event_types,
        }


def correlate_events(
    events: list[Event],
    window: timedelta = DEFAULT_WINDOW,
    entity_fn=None,
) -> list[CandidateIncident]:
    """Groups ``events`` into :class:`CandidateIncident` objects.

    Args:
        events: events to correlate, any order.
        window: maximum gap between consecutive events (for the same
            entity) for them to be considered part of the same incident.
        entity_fn: optional override for how to derive the entity key from
            an event (defaults to ``Event.entity_key``, i.e. username).

    Returns:
        Incidents sorted by start time. Deterministic given the same input
        regardless of input ordering.
    """
    if window <= timedelta(0):
        raise ValueError("window must be a positive timedelta")

    entity_fn = entity_fn or (lambda e: e.entity_key)

    by_entity: dict[str, list[Event]] = {}
    for e in events:
        by_entity.setdefault(entity_fn(e), []).append(e)

    incidents: list[CandidateIncident] = []
    for entity_key, entity_events in by_entity.items():
        entity_events = sorted(entity_events, key=lambda e: (e.timestamp, e.event_id))
        current: list[Event] = []
        for ev in entity_events:
            if current and (ev.timestamp - current[-1].timestamp) > window:
                incidents.append(
                    CandidateIncident(incident_id=_new_id(), entity_key=entity_key, events=current)
                )
                current = []
            current.append(ev)
        if current:
            incidents.append(
                CandidateIncident(incident_id=_new_id(), entity_key=entity_key, events=current)
            )

    incidents.sort(key=lambda inc: (inc.start_time, inc.entity_key))
    return incidents


def _new_id() -> str:
    return f"inc-{uuid.uuid4().hex[:12]}"
