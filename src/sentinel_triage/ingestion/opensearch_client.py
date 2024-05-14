"""OpenSearch indexing layer.

``OpenSearchIndexer`` is the real adapter used against a live cluster (e.g.
the one started by ``docker-compose.yml``). It is a thin wrapper around
``opensearch-py`` and is never exercised in the unit test suite -- there is
no running cluster in CI / this sandbox, matching the offline-verifiable
requirement.

``FakeOpenSearchIndexer`` implements the same small interface backed by an
in-memory list with a couple of the filter/aggregation query shapes the
rest of the pipeline actually needs (term filters + time range + simple
terms-count aggregation), which is enough to unit test correlation and
detection end-to-end without a cluster.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, Protocol

from sentinel_triage.events import Event

DEFAULT_INDEX = "auth-events"


class EventIndexer(Protocol):
    def index_events(self, events: list[Event]) -> int: ...

    def search(
        self,
        *,
        user: Optional[str] = None,
        src_ip: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> list[Event]: ...

    def count(self) -> int: ...


class FakeOpenSearchIndexer:
    """In-memory stand-in for OpenSearch used by tests and the offline demo."""

    def __init__(self) -> None:
        self._events: dict[str, Event] = {}

    def index_events(self, events: list[Event]) -> int:
        for e in events:
            self._events[e.event_id] = e
        return len(events)

    def search(
        self,
        *,
        user: Optional[str] = None,
        src_ip: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> list[Event]:
        results = list(self._events.values())
        if user is not None:
            results = [e for e in results if e.user == user]
        if src_ip is not None:
            results = [e for e in results if e.src_ip == src_ip]
        if start is not None:
            results = [e for e in results if e.timestamp >= start]
        if end is not None:
            results = [e for e in results if e.timestamp <= end]
        results.sort(key=lambda e: e.timestamp)
        return results

    def count(self) -> int:
        return len(self._events)

    def all_events(self) -> list[Event]:
        return sorted(self._events.values(), key=lambda e: e.timestamp)


class OpenSearchIndexer:
    """Real ``opensearch-py``-backed indexer. Import of the client library is
    lazy so the package is only required in environments that actually run
    against a cluster (e.g. inside the Docker image), not at unit-test
    time."""

    def __init__(self, hosts: list[dict[str, Any]], index: str = DEFAULT_INDEX, **client_kwargs: Any) -> None:
        from opensearchpy import OpenSearch  # noqa: PLC0415 (intentionally lazy; optional dependency)

        self._client = OpenSearch(hosts=hosts, **client_kwargs)
        self._index = index
        if not self._client.indices.exists(index=self._index):
            self._client.indices.create(index=self._index)

    def index_events(self, events: list[Event]) -> int:
        for e in events:
            self._client.index(index=self._index, id=e.event_id, body=e.to_dict())
        return len(events)

    def search(
        self,
        *,
        user: Optional[str] = None,
        src_ip: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> list[Event]:
        must: list[dict[str, Any]] = []
        if user is not None:
            must.append({"term": {"user": user}})
        if src_ip is not None:
            must.append({"term": {"src_ip": src_ip}})
        if start is not None or end is not None:
            range_query: dict[str, Any] = {}
            if start is not None:
                range_query["gte"] = start.isoformat()
            if end is not None:
                range_query["lte"] = end.isoformat()
            must.append({"range": {"timestamp": range_query}})
        body = {"query": {"bool": {"must": must}} if must else {"match_all": {}}}
        resp = self._client.search(index=self._index, body=body, size=10_000)
        return [Event.from_dict(hit["_source"]) for hit in resp["hits"]["hits"]]

    def count(self) -> int:
        return self._client.count(index=self._index)["count"]
