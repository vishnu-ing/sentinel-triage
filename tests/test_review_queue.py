from __future__ import annotations

from datetime import timedelta

import pytest

from sentinel_triage.correlation.entity_clustering import correlate_events
from sentinel_triage.detection.sigma_engine import SigmaEngine, load_rules_from_dir
from sentinel_triage.review_queue.queue import InvalidTransitionError, ReviewQueue, ReviewStatus
from sentinel_triage.triage.llm_client import FakeLLMClient
from tests.conftest import SIGMA_RULES_DIR, make_event


def _make_triage_result(entity_key="alice", n_failures=6):
    engine = SigmaEngine(load_rules_from_dir(SIGMA_RULES_DIR))
    events = [make_event(f"e{i}", i * 1.5, user=entity_key, event_type="login_failure") for i in range(n_failures)]
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    detections = engine.evaluate_incident(incident)
    result = FakeLLMClient().triage(incident, detections)
    return incident, result


@pytest.fixture
def queue() -> ReviewQueue:
    q = ReviewQueue(":memory:")
    yield q
    q.close()


def test_enqueue_and_list_pending(queue: ReviewQueue):
    incident, result = _make_triage_result()
    queue.enqueue(result, incident.entity_key)
    pending = queue.list_pending()
    assert len(pending) == 1
    assert pending[0].incident_id == incident.incident_id
    assert pending[0].status == ReviewStatus.PENDING
    assert pending[0].entity_key == "alice"
    assert set(pending[0].cited_event_ids).issubset(incident.event_ids())


def test_approve_transitions_out_of_pending(queue: ReviewQueue):
    incident, result = _make_triage_result()
    queue.enqueue(result, incident.entity_key)
    item = queue.approve(incident.incident_id, note="confirmed brute force, IP blocked")
    assert item.status == ReviewStatus.APPROVED
    assert item.reviewer_note == "confirmed brute force, IP blocked"
    assert item.reviewed_at is not None
    assert queue.list_pending() == []


def test_reject_transitions_out_of_pending(queue: ReviewQueue):
    incident, result = _make_triage_result()
    queue.enqueue(result, incident.entity_key)
    item = queue.reject(incident.incident_id, note="known QA load-test account")
    assert item.status == ReviewStatus.REJECTED


def test_escalate_transitions_out_of_pending(queue: ReviewQueue):
    incident, result = _make_triage_result()
    queue.enqueue(result, incident.entity_key)
    item = queue.escalate(incident.incident_id, note="paging IR")
    assert item.status == ReviewStatus.ESCALATED


def test_cannot_review_already_reviewed_incident(queue: ReviewQueue):
    incident, result = _make_triage_result()
    queue.enqueue(result, incident.entity_key)
    queue.approve(incident.incident_id)
    with pytest.raises(InvalidTransitionError):
        queue.reject(incident.incident_id)


def test_cannot_review_unknown_incident(queue: ReviewQueue):
    with pytest.raises(InvalidTransitionError):
        queue.approve("does-not-exist")


def test_list_pending_orders_by_severity_then_confidence(queue: ReviewQueue):
    inc_high, res_high = _make_triage_result(entity_key="alice", n_failures=6)
    # bob has a single benign event (zero login-failure events -> no detections)
    from sentinel_triage.correlation.entity_clustering import correlate_events as _c
    low_events = [make_event("b1", 0, user="bob", event_type="login_success")]
    inc_low = _c(low_events, window=timedelta(minutes=15))[0]
    engine = SigmaEngine(load_rules_from_dir(SIGMA_RULES_DIR))
    res_low = FakeLLMClient().triage(inc_low, engine.evaluate_incident(inc_low))

    queue.enqueue(res_low, inc_low.entity_key)
    queue.enqueue(res_high, inc_high.entity_key)

    pending = queue.list_pending()
    assert pending[0].incident_id == inc_high.incident_id
    assert pending[-1].incident_id == inc_low.incident_id


def test_get_returns_none_for_unknown_incident(queue: ReviewQueue):
    assert queue.get("nope") is None


def test_persists_to_file(tmp_path):
    db_path = tmp_path / "queue.db"
    q = ReviewQueue(db_path)
    incident, result = _make_triage_result()
    q.enqueue(result, incident.entity_key)
    q.close()

    q2 = ReviewQueue(db_path)
    pending = q2.list_pending()
    assert len(pending) == 1
    assert pending[0].incident_id == incident.incident_id
    q2.close()


def test_list_all_includes_reviewed_and_pending(queue: ReviewQueue):
    inc1, res1 = _make_triage_result(entity_key="alice")
    queue.enqueue(res1, inc1.entity_key)
    queue.approve(inc1.incident_id)
    assert len(queue.list_all()) == 1
    assert queue.list_all()[0].status == ReviewStatus.APPROVED
