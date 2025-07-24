from __future__ import annotations

import importlib
import os
from datetime import timedelta

import pytest
from hypothesis import given, strategies as st

from sentinel_triage.correlation.entity_clustering import correlate_events
from sentinel_triage.detection.sigma_engine import SigmaEngine, load_rules_from_dir
from sentinel_triage.triage.llm_client import (
    FakeLLMClient,
    GroundingError,
    Severity,
    TRIAGE_FUNCTION_SCHEMA,
    validate_citation_grounding,
)
from tests.conftest import SIGMA_RULES_DIR, make_event


@pytest.fixture
def engine() -> SigmaEngine:
    return SigmaEngine(load_rules_from_dir(SIGMA_RULES_DIR))


def test_function_schema_shape_is_openai_tool_compatible():
    assert TRIAGE_FUNCTION_SCHEMA["name"] == "submit_triage_assessment"
    props = TRIAGE_FUNCTION_SCHEMA["parameters"]["properties"]
    assert set(props) == {"summary", "severity", "confidence", "cited_event_ids"}
    assert set(TRIAGE_FUNCTION_SCHEMA["parameters"]["required"]) == set(props)
    assert set(props["severity"]["enum"]) == {"low", "medium", "high", "critical"}


def test_validate_citation_grounding_keeps_only_real_ids():
    events = [make_event("e1", 0), make_event("e2", 1)]
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    grounded = validate_citation_grounding(["e1", "fabricated-id"], incident)
    assert grounded == ["e1"]


def test_validate_citation_grounding_raises_when_all_hallucinated():
    events = [make_event("e1", 0)]
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    with pytest.raises(GroundingError):
        validate_citation_grounding(["not-real-1", "not-real-2"], incident)


def test_validate_citation_grounding_raises_on_empty_list():
    events = [make_event("e1", 0)]
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    with pytest.raises(GroundingError):
        validate_citation_grounding([], incident)


def test_fake_llm_client_flags_brute_force_as_high_or_above(engine: SigmaEngine):
    events = [make_event(f"e{i}", i * 1.5, event_type="login_failure") for i in range(6)]
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    detections = engine.evaluate_incident(incident)
    result = FakeLLMClient().triage(incident, detections)
    assert result.severity in (Severity.HIGH, Severity.CRITICAL)
    assert 0.0 <= result.confidence <= 1.0
    assert set(result.cited_event_ids).issubset(incident.event_ids())
    assert len(result.cited_event_ids) > 0
    assert incident.entity_key in result.summary


def test_fake_llm_client_flags_benign_incident_as_low(engine: SigmaEngine):
    events = [make_event("e1", 0, event_type="login_success")]
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    detections = engine.evaluate_incident(incident)
    assert detections == []
    result = FakeLLMClient().triage(incident, detections)
    assert result.severity == Severity.LOW
    assert set(result.cited_event_ids).issubset(incident.event_ids())


def test_fake_llm_client_never_cites_event_ids_outside_the_incident(engine: SigmaEngine):
    events = [make_event(f"e{i}", i, event_type="login_failure") for i in range(8)]
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    detections = engine.evaluate_incident(incident)
    result = FakeLLMClient().triage(incident, detections)
    assert set(result.cited_event_ids) <= incident.event_ids()


@given(
    n_failures=st.integers(min_value=0, max_value=12),
    n_success=st.integers(min_value=0, max_value=3),
)
def test_fake_llm_client_grounding_holds_for_arbitrary_incident_sizes(n_failures, n_success):
    """Property-based check: no matter how many/few events an incident has,
    the fake client must never fabricate a citation."""
    engine = SigmaEngine(load_rules_from_dir(SIGMA_RULES_DIR))
    events = [make_event(f"f{i}", i * 0.5, event_type="login_failure") for i in range(n_failures)]
    events += [make_event(f"s{i}", 100 + i * 0.5, event_type="login_success") for i in range(n_success)]
    if not events:
        return
    incidents = correlate_events(events, window=timedelta(minutes=200))
    for incident in incidents:
        detections = engine.evaluate_incident(incident)
        result = FakeLLMClient().triage(incident, detections)
        assert set(result.cited_event_ids).issubset(incident.event_ids())


def test_more_detections_increase_confidence_monotonically(engine: SigmaEngine):
    # triggers only the privilege-escalation rule (3 failures + priv_use)
    few_events = [make_event(f"e{i}", i * 1.5, event_type="login_failure") for i in range(3)]
    few_events.append(make_event("p1", 6, event_type="privilege_use"))
    incident_few = correlate_events(few_events, window=timedelta(minutes=15))[0]
    detections_few = engine.evaluate_incident(incident_few)

    # triggers BOTH brute-force (>=5 failures) and privilege-escalation
    many_events = [make_event(f"e{i}", i * 1.5, event_type="login_failure") for i in range(6)]
    many_events.append(make_event("p1", 10, event_type="privilege_use"))
    incident_many = correlate_events(many_events, window=timedelta(minutes=15))[0]
    detections_many = engine.evaluate_incident(incident_many)

    result_few = FakeLLMClient().triage(incident_few, detections_few)
    result_many = FakeLLMClient().triage(incident_many, detections_many)
    assert len(detections_many) > len(detections_few)
    assert result_many.confidence >= result_few.confidence


@pytest.mark.integration
def test_openai_client_requires_network_and_api_key_skipped_offline():
    """Real LLM integration is intentionally never run offline. This test
    documents that and is excluded from the default test run via the
    'integration' marker (see pyproject.toml addopts)."""
    if importlib.util.find_spec("openai") is None or not os.environ.get("OPENAI_API_KEY"):
        pytest.skip("openai package / OPENAI_API_KEY not available in this environment")
