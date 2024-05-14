"""End-to-end orchestration: ingestion -> correlation -> Sigma/MITRE
detection -> LLM triage -> analyst review queue.

This module wires the other packages together but contains no detection or
scoring logic of its own -- that all lives in ``correlation``,
``detection``, and ``triage`` where it is unit tested directly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from sentinel_triage.correlation.entity_clustering import DEFAULT_WINDOW, CandidateIncident, correlate_events
from sentinel_triage.detection.sigma_engine import DetectionMatch, SigmaEngine
from sentinel_triage.events import Event
from sentinel_triage.ingestion.opensearch_client import EventIndexer, FakeOpenSearchIndexer
from sentinel_triage.review_queue.queue import ReviewQueue
from sentinel_triage.triage.llm_client import LLMClient
from sentinel_triage.triage.summarizer import triage_incidents


@dataclass
class PipelineResult:
    incidents: list[CandidateIncident]
    detections_by_incident: dict[str, list[DetectionMatch]]
    triage_results: list = field(default_factory=list)


def run_pipeline(
    events: list[Event],
    sigma_engine: SigmaEngine,
    llm_client: LLMClient,
    *,
    indexer: EventIndexer | None = None,
    review_queue: ReviewQueue | None = None,
    window: timedelta = DEFAULT_WINDOW,
) -> PipelineResult:
    """Runs the full pipeline over a batch of events.

    Args:
        events: normalized events to process (already loaded from a
            source, e.g. via ``ingestion.load_events_from_csv``).
        sigma_engine: detection rules to evaluate against each incident.
        llm_client: triage backend (``FakeLLMClient`` for offline use).
        indexer: optional OpenSearch(-like) indexer to persist events to;
            defaults to an in-memory fake so the pipeline is runnable with
            zero external services.
        review_queue: optional review queue to enqueue triaged incidents
            into; if omitted, triage still runs but nothing is persisted.
        window: correlation time window (see ``correlation`` module).
    """
    indexer = indexer or FakeOpenSearchIndexer()
    indexer.index_events(events)

    incidents = correlate_events(events, window=window)
    detections_by_incident = sigma_engine.evaluate_all(incidents)
    triage_results = triage_incidents(incidents, detections_by_incident, llm_client)

    if review_queue is not None:
        incidents_by_id = {inc.incident_id: inc for inc in incidents}
        for result in triage_results:
            entity_key = incidents_by_id[result.incident_id].entity_key
            review_queue.enqueue(result, entity_key)

    return PipelineResult(
        incidents=incidents,
        detections_by_incident=detections_by_incident,
        triage_results=triage_results,
    )
