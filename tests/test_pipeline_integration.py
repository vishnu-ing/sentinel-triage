from __future__ import annotations

from datetime import timedelta

from sentinel_triage.detection.sigma_engine import SigmaEngine, load_rules_from_dir
from sentinel_triage.ingestion.loader import load_events_from_csv
from sentinel_triage.ingestion.opensearch_client import FakeOpenSearchIndexer
from sentinel_triage.pipeline import run_pipeline
from sentinel_triage.review_queue.queue import ReviewQueue, ReviewStatus
from sentinel_triage.triage.llm_client import FakeLLMClient, Severity
from tests.conftest import SIGMA_RULES_DIR, DATASET_PATH


def test_full_pipeline_end_to_end_offline():
    """Runs ingestion -> OpenSearch(fake) indexing -> correlation ->
    Sigma/MITRE detection -> LLM triage -> review queue entirely offline,
    against the bundled labeled dataset, and checks the whole chain is
    internally consistent."""
    events = load_events_from_csv(DATASET_PATH)
    assert len(events) > 0

    indexer = FakeOpenSearchIndexer()
    engine = SigmaEngine(load_rules_from_dir(SIGMA_RULES_DIR))
    llm_client = FakeLLMClient()
    review_queue = ReviewQueue(":memory:")

    result = run_pipeline(
        events,
        engine,
        llm_client,
        indexer=indexer,
        review_queue=review_queue,
        window=timedelta(minutes=15),
    )

    # every event made it into the (fake) OpenSearch index
    assert indexer.count() == len(events)

    # correlation produced incidents that partition all events exactly once
    all_incident_event_ids = set()
    for inc in result.incidents:
        assert not (all_incident_event_ids & inc.event_ids()), "event assigned to two incidents"
        all_incident_event_ids |= inc.event_ids()
    assert all_incident_event_ids == {e.event_id for e in events}

    # at least some incidents triggered a detection given the labeled attack data
    total_detections = sum(len(v) for v in result.detections_by_incident.values())
    assert total_detections > 0

    # every triage result is grounded in its own incident's real events
    incidents_by_id = {inc.incident_id: inc for inc in result.incidents}
    for triage in result.triage_results:
        incident = incidents_by_id[triage.incident_id]
        assert set(triage.cited_event_ids).issubset(incident.event_ids())

    # high-severity triage results made it into the review queue as pending
    pending = review_queue.list_pending()
    assert len(pending) == len(result.triage_results)
    assert all(p.status == ReviewStatus.PENDING for p in pending)

    high_severity_incidents = [t for t in result.triage_results if t.severity in (Severity.HIGH, Severity.CRITICAL)]
    assert len(high_severity_incidents) > 0


def test_pipeline_is_deterministic_across_runs():
    events = load_events_from_csv(DATASET_PATH)
    engine = SigmaEngine(load_rules_from_dir(SIGMA_RULES_DIR))

    result1 = run_pipeline(events, engine, FakeLLMClient(), window=timedelta(minutes=15))
    result2 = run_pipeline(events, engine, FakeLLMClient(), window=timedelta(minutes=15))

    def fingerprint(result):
        return sorted(
            (inc.entity_key, tuple(sorted(inc.event_ids())))
            for inc in result.incidents
        )

    assert fingerprint(result1) == fingerprint(result2)
    assert len(result1.triage_results) == len(result2.triage_results)


def test_analyst_can_approve_a_flagged_incident_end_to_end():
    events = load_events_from_csv(DATASET_PATH)
    engine = SigmaEngine(load_rules_from_dir(SIGMA_RULES_DIR))
    review_queue = ReviewQueue(":memory:")

    result = run_pipeline(events, engine, FakeLLMClient(), review_queue=review_queue)
    pending = review_queue.list_pending()
    assert pending, "expected at least one pending review item"

    top = pending[0]
    approved = review_queue.approve(top.incident_id, note="verified via endpoint logs")
    assert approved.status == ReviewStatus.APPROVED
    assert len(review_queue.list_pending()) == len(pending) - 1
