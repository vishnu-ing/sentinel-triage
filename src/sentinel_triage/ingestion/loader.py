"""Loads the single supported source type for this trimmed prototype:
endpoint/auth logs in the canonical CSV schema produced by
``scripts/generate_dataset.py`` (or any real dataset conforming to the same
columns -- see README "Swapping in a real dataset").

Multi-format ingestion (syslog/CEF/JSON) is a documented stretch goal, not
implemented here (see README "Stretch goals").
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterator

from sentinel_triage.events import Event


REQUIRED_COLUMNS = {"event_id", "timestamp", "host", "user", "src_ip", "event_type"}


def iter_events_from_csv(path: str | Path) -> Iterator[Event]:
    """Streams :class:`Event` objects out of a CSV file one row at a time,
    so ingestion memory use stays flat regardless of dataset size."""
    path = Path(path)
    with path.open(newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or not REQUIRED_COLUMNS.issubset(set(reader.fieldnames)):
            missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
            raise ValueError(f"CSV at {path} is missing required columns: {sorted(missing)}")
        for row in reader:
            yield Event.from_dict(row)


def load_events_from_csv(path: str | Path) -> list[Event]:
    """Materializes all events from a CSV file into a list, sorted by
    timestamp (ingestion order is not guaranteed to be chronological for
    real multi-host log sources)."""
    events = list(iter_events_from_csv(path))
    events.sort(key=lambda e: e.timestamp)
    return events
