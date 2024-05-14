"""Thin orchestration wrapper: runs an incident + its detections through an
``LLMClient`` and returns a grounded :class:`TriageResult`, isolating
callers from needing to know about ``GroundingError`` handling directly."""

from __future__ import annotations

import logging

from sentinel_triage.correlation.entity_clustering import CandidateIncident
from sentinel_triage.detection.sigma_engine import DetectionMatch
from sentinel_triage.triage.llm_client import GroundingError, LLMClient, TriageResult

logger = logging.getLogger(__name__)


def triage_incident(
    incident: CandidateIncident,
    detections: list[DetectionMatch],
    client: LLMClient,
) -> TriageResult | None:
    """Runs triage for one incident. Returns ``None`` (rather than raising)
    if the LLM's response fails citation grounding entirely, since a
    downstream review queue should never receive an ungrounded assessment;
    the failure is logged so it is visible rather than silently dropped."""
    try:
        return client.triage(incident, detections)
    except GroundingError:
        logger.warning("Dropping ungrounded triage for incident %s", incident.incident_id, exc_info=True)
        return None


def triage_incidents(
    incidents: list[CandidateIncident],
    detections_by_incident: dict[str, list[DetectionMatch]],
    client: LLMClient,
) -> list[TriageResult]:
    results = []
    for incident in incidents:
        result = triage_incident(incident, detections_by_incident.get(incident.incident_id, []), client)
        if result is not None:
            results.append(result)
    return results
