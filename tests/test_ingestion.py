from __future__ import annotations

import csv

import pytest

from sentinel_triage.events import Event
from sentinel_triage.ingestion.loader import load_events_from_csv
from sentinel_triage.ingestion.opensearch_client import FakeOpenSearchIndexer
from sentinel_triage.ingestion.stream import InMemoryEventStream
from tests.conftest import make_event, DATASET_PATH


def test_load_events_from_csv_returns_sorted_events():
    events = load_events_from_csv(DATASET_PATH)
    assert len(events) > 0
    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)
    assert all(isinstance(e, Event) for e in events)


def test_load_events_from_csv_rejects_missing_columns(tmp_path):
    bad_csv = tmp_path / "bad.csv"
    with bad_csv.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["event_id", "host"])
        writer.writeheader()
        writer.writerow({"event_id": "e1", "host": "h1"})
    with pytest.raises(ValueError, match="missing required columns"):
        load_events_from_csv(bad_csv)


def test_event_extra_fields_round_trip_through_csv(tmp_path):
    csv_path = tmp_path / "with_extra.csv"
    fields = ["event_id", "timestamp", "host", "user", "src_ip", "event_type", "raw", "is_malicious"]
    with csv_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerow(
            {
                "event_id": "e1",
                "timestamp": "2024-01-01T00:00:00+00:00",
                "host": "h1",
                "user": "u1",
                "src_ip": "1.1.1.1",
                "event_type": "login_success",
                "raw": "raw line",
                "is_malicious": "1",
            }
        )
    events = load_events_from_csv(csv_path)
    assert events[0].extra["is_malicious"] == "1"


def test_fake_opensearch_indexer_filters_by_user_src_ip_and_time():
    indexer = FakeOpenSearchIndexer()
    events = [
        make_event("e1", 0, user="alice", src_ip="1.1.1.1"),
        make_event("e2", 5, user="bob", src_ip="2.2.2.2"),
        make_event("e3", 10, user="alice", src_ip="3.3.3.3"),
    ]
    indexer.index_events(events)
    assert indexer.count() == 3

    alice_events = indexer.search(user="alice")
    assert {e.event_id for e in alice_events} == {"e1", "e3"}

    ip_events = indexer.search(src_ip="2.2.2.2")
    assert {e.event_id for e in ip_events} == {"e2"}

    from datetime import datetime, timedelta, timezone

    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    ranged = indexer.search(start=base + timedelta(minutes=4), end=base + timedelta(minutes=6))
    assert {e.event_id for e in ranged} == {"e2"}


def test_fake_opensearch_indexer_all_events_sorted():
    indexer = FakeOpenSearchIndexer()
    events = [make_event("e2", 5), make_event("e1", 0)]
    indexer.index_events(events)
    all_events = indexer.all_events()
    assert [e.event_id for e in all_events] == ["e1", "e2"]


def test_in_memory_event_stream_read_new_and_cursor():
    stream = InMemoryEventStream()
    assert len(stream) == 0
    e1, e2, e3 = make_event("e1", 0), make_event("e2", 1), make_event("e3", 2)
    stream.add(e1)
    stream.add(e2)
    assert len(stream) == 2

    first_batch = stream.read_new()
    assert [e.event_id for e in first_batch] == ["e1", "e2"]

    # nothing new yet
    assert stream.read_new() == []

    stream.add(e3)
    second_batch = stream.read_new()
    assert [e.event_id for e in second_batch] == ["e3"]


def test_in_memory_event_stream_read_new_respects_count():
    stream = InMemoryEventStream()
    for i in range(5):
        stream.add(make_event(f"e{i}", i))
    batch = stream.read_new(count=2)
    assert [e.event_id for e in batch] == ["e0", "e1"]
    remaining = stream.read_new()
    assert [e.event_id for e in remaining] == ["e2", "e3", "e4"]


def test_in_memory_event_stream_reset_cursor():
    stream = InMemoryEventStream()
    stream.add(make_event("e1", 0))
    stream.read_new()
    assert stream.read_new() == []
    stream.reset_cursor()
    replayed = stream.read_new()
    assert [e.event_id for e in replayed] == ["e1"]
