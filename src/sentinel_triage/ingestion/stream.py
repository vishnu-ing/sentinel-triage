"""Buffering layer between log producers and the OpenSearch indexer,
modeled on Redis Streams semantics (append-only log with consumer offsets)
so ingestion can be replayed / fanned out to multiple consumers (indexer,
correlation engine) without coupling them directly.

``InMemoryEventStream`` implements the same minimal interface without any
external service and is what tests and the offline demo use.
``RedisEventStream`` is a thin real adapter around ``redis.Redis`` streams
(XADD/XREAD) for production use; it is never exercised at test time (no
network / Redis daemon available in CI), matching the offline-verifiable
requirement for this prototype.
"""

from __future__ import annotations

from typing import Protocol

from sentinel_triage.events import Event


class EventStream(Protocol):
    def add(self, event: Event) -> str: ...

    def read_new(self, count: int | None = None) -> list[Event]:
        """Reads events that have not yet been read by this consumer."""
        ...

    def __len__(self) -> int: ...


class InMemoryEventStream:
    """A minimal in-process stand-in for a Redis Stream. Supports a single
    consumer cursor, which is all the ingestion pipeline needs."""

    def __init__(self) -> None:
        self._entries: list[Event] = []
        self._cursor = 0

    def add(self, event: Event) -> str:
        self._entries.append(event)
        return event.event_id

    def read_new(self, count: int | None = None) -> list[Event]:
        pending = self._entries[self._cursor :]
        if count is not None:
            pending = pending[:count]
        self._cursor += len(pending)
        return pending

    def reset_cursor(self) -> None:
        self._cursor = 0

    def __len__(self) -> int:
        return len(self._entries)


class RedisEventStream:
    """Real Redis Streams-backed adapter. Requires a running Redis instance
    and the ``redis`` package; not used in the test suite. Kept dependency
    imports lazy so importing this module never requires Redis to be
    installed or reachable."""

    def __init__(self, redis_url: str, stream_key: str = "sentinel:events") -> None:
        import redis  # noqa: PLC0415 (intentionally lazy; optional dependency)

        self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
        self._stream_key = stream_key
        self._last_id = "0-0"

    def add(self, event: Event) -> str:
        return self._redis.xadd(self._stream_key, event.to_dict())

    def read_new(self, count: int | None = None) -> list[Event]:
        results = self._redis.xread(
            {self._stream_key: self._last_id}, count=count, block=None
        )
        events: list[Event] = []
        for _stream_name, entries in results:
            for entry_id, fields in entries:
                self._last_id = entry_id
                events.append(Event.from_dict(fields))
        return events

    def __len__(self) -> int:
        return self._redis.xlen(self._stream_key)
