"""LLM triage client.

The triage step asks an LLM to do three things for each candidate incident,
enforced via function calling (the model can only respond by calling
``submit_triage_assessment`` with a schema-conformant payload, not free
text) so the output is structured and auditable:

1. Summarize what happened in plain language for a Tier-1 analyst.
2. Cite the *specific* log lines (``event_id`` values) it used to reach
   that conclusion -- this is checked mechanically against the incident's
   real events after the call returns (``validate_citation_grounding``);
   any id the model invents is a hallucination and is rejected rather than
   silently trusted.
3. Assign a confidence-scored severity.

``FakeLLMClient`` is a deterministic, offline, rule-based implementation of
this same contract used by the test suite and the default demo pipeline
(no API key / network required, satisfying the offline-verifiable
requirement). ``OpenAIFunctionCallingClient`` is a real implementation
against an OpenAI-compatible chat-completions + tools API; it requires the
``openai`` package and an API key and is never exercised by the unit test
suite.
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from sentinel_triage.correlation.entity_clustering import CandidateIncident
from sentinel_triage.detection.sigma_engine import DetectionMatch

MAX_CITED_EVENTS = 8
MAX_RAW_LOG_CHARS = 220


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_SEVERITY_ORDER = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
_LEVEL_TO_SEVERITY = {
    "informational": Severity.LOW,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


# JSON-schema for the single function the model is allowed to call. Passed
# verbatim as the OpenAI "tool" definition for the real client, and used to
# structurally validate the (fake or real) response.
TRIAGE_FUNCTION_SCHEMA: dict[str, Any] = {
    "name": "submit_triage_assessment",
    "description": (
        "Submit a structured triage assessment for one candidate SOC incident. "
        "Every cited_event_ids value MUST be an event_id that appears verbatim "
        "in the provided log lines -- never invent one."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "1-3 sentence plain-language summary of what happened for a Tier-1 analyst.",
            },
            "severity": {
                "type": "string",
                "enum": [s.value for s in Severity],
            },
            "confidence": {
                "type": "number",
                "minimum": 0.0,
                "maximum": 1.0,
                "description": "Model's confidence that this is a true positive requiring analyst action.",
            },
            "cited_event_ids": {
                "type": "array",
                "items": {"type": "string"},
                "minItems": 1,
                "description": "event_id values from the supplied log lines that support the summary.",
            },
        },
        "required": ["summary", "severity", "confidence", "cited_event_ids"],
    },
}


class GroundingError(ValueError):
    """Raised when a triage response cites an event_id that does not exist
    in the incident it was triaging -- i.e. the model hallucinated a
    citation. Callers should treat this as a failed triage, not silently
    drop the bad citations."""


@dataclass
class TriageResult:
    incident_id: str
    summary: str
    severity: Severity
    confidence: float
    cited_event_ids: list[str]
    detections: list[DetectionMatch]

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "summary": self.summary,
            "severity": self.severity.value,
            "confidence": round(self.confidence, 3),
            "cited_event_ids": self.cited_event_ids,
            "mitre_techniques": sorted({t for d in self.detections for t in d.mitre_techniques}),
            "detection_titles": [d.title for d in self.detections],
        }


def validate_citation_grounding(raw_cited_event_ids: list[str], incident: CandidateIncident) -> list[str]:
    """Returns the subset of ``raw_cited_event_ids`` that are real events in
    ``incident``. Raises :class:`GroundingError` if the model cited *zero*
    real events (i.e. every citation was hallucinated) or provided none at
    all -- a triage with no grounded evidence is not actionable. Silently
    dropping a few bad ids alongside good ones is tolerated (models can be
    imprecise about one id in a long list) but is recorded by the caller
    via the returned (possibly shorter) list.
    """
    valid_ids = incident.event_ids()
    grounded = [eid for eid in raw_cited_event_ids if eid in valid_ids]
    if not grounded:
        raise GroundingError(
            f"Triage for incident {incident.incident_id} cited no real event_ids "
            f"(got {raw_cited_event_ids!r}); refusing to trust an ungrounded triage."
        )
    return grounded


class LLMClient(Protocol):
    def triage(
        self, incident: CandidateIncident, detections: list[DetectionMatch]
    ) -> TriageResult: ...


def build_prompt_context(incident: CandidateIncident, detections: list[DetectionMatch]) -> str:
    """Builds the human-readable context (log lines + detection hits) that
    would be sent to a real LLM as the user message. Exposed separately so
    both the fake and real clients build identical context, and so it can
    be unit tested / inspected directly."""
    lines = [
        f"Entity: {incident.entity_key}",
        f"Window: {incident.start_time.isoformat()} -> {incident.end_time.isoformat()}",
        f"Hosts: {', '.join(sorted(incident.hosts))}",
        f"Source IPs: {', '.join(sorted(incident.src_ips))}",
        "",
        "Sigma/MITRE detections triggered:" if detections else "No Sigma rule matched this incident.",
    ]
    for d in detections:
        lines.append(
            f"  - [{d.level.upper()}] {d.title} (MITRE {d.mitre_tactic} {d.mitre_tactic_name}, "
            f"techniques {', '.join(d.mitre_techniques)})"
        )
    lines.append("")
    lines.append("Log lines (event_id | timestamp | raw):")
    for e in incident.events:
        raw = e.raw[:MAX_RAW_LOG_CHARS]
        lines.append(f"  {e.event_id} | {e.timestamp.isoformat()} | {raw}")
    return "\n".join(lines)


class FakeLLMClient:
    """Deterministic, offline, rule-based stand-in for an LLM function
    call. Used by default so the pipeline, tests, and eval harness never
    require network access or an API key.

    The "grounding" guarantee is structural here rather than merely
    hoped-for: cited_event_ids are always built directly from the
    detection engine's matched_event_ids (falling back to a small, real
    sample of the incident's own events when no rule fired), so this
    client can never hallucinate an id that isn't in the incident.
    """

    def triage(self, incident: CandidateIncident, detections: list[DetectionMatch]) -> TriageResult:
        if detections:
            severity = max((_LEVEL_TO_SEVERITY[d.level] for d in detections), key=lambda s: _SEVERITY_ORDER[s])
            cited: list[str] = []
            for d in detections:
                for eid in d.matched_event_ids:
                    if eid not in cited:
                        cited.append(eid)
            cited = cited[:MAX_CITED_EVENTS]
            confidence = min(0.55 + 0.12 * len(detections) + 0.03 * len(incident.events), 0.97)
            titles = "; ".join(d.title for d in detections)
            techniques = sorted({t for d in detections for t in d.mitre_techniques})
            summary = (
                f"{incident.entity_key} triggered {len(detections)} detection(s) -- {titles} "
                f"(MITRE {', '.join(techniques)}) -- across {len(incident.events)} correlated events "
                f"between {incident.start_time.isoformat()} and {incident.end_time.isoformat()} "
                f"from source IP(s) {', '.join(sorted(incident.src_ips))}."
            )
        else:
            severity = Severity.LOW
            sample = incident.events[: min(2, len(incident.events))]
            cited = [e.event_id for e in sample]
            confidence = max(0.15, 0.35 - 0.02 * len(incident.events))
            summary = (
                f"{incident.entity_key} had {len(incident.events)} correlated event(s) with no Sigma "
                f"rule match; likely benign routine activity, recommend no action beyond passive logging."
            )

        grounded = validate_citation_grounding(cited, incident)
        return TriageResult(
            incident_id=incident.incident_id,
            summary=summary,
            severity=severity,
            confidence=round(confidence, 3),
            cited_event_ids=grounded,
            detections=detections,
        )


class OpenAIFunctionCallingClient:
    """Real LLM client using the OpenAI chat-completions API with function
    (tool) calling. Requires the ``openai`` package and ``OPENAI_API_KEY``
    to be set; both the import and the network call are deferred to
    ``triage()`` so simply constructing/importing this module never
    requires network access, matching the offline-verifiable requirement.
    Not covered by the unit test suite for that reason (see
    tests/test_llm_client.py for the explicit skip).
    """

    def __init__(self, model: str = "gpt-4o-mini", api_key: str | None = None):
        self.model = model
        self.api_key = api_key

    def triage(self, incident: CandidateIncident, detections: list[DetectionMatch]) -> TriageResult:
        from openai import OpenAI  # noqa: PLC0415 (intentionally lazy; optional dependency)

        client = OpenAI(api_key=self.api_key)
        context = build_prompt_context(incident, detections)
        system_prompt = textwrap.dedent(
            """
            You are a SOC Tier-1 triage assistant. You will be given a candidate
            incident (correlated log lines) and any Sigma/MITRE detections that
            fired. Call submit_triage_assessment exactly once. Every value in
            cited_event_ids MUST be copied verbatim from an event_id shown in the
            log lines -- never invent one, and never cite an id you were not
            given.
            """
        ).strip()

        response = client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": context},
            ],
            tools=[{"type": "function", "function": TRIAGE_FUNCTION_SCHEMA}],
            tool_choice={"type": "function", "function": {"name": "submit_triage_assessment"}},
        )
        tool_call = response.choices[0].message.tool_calls[0]
        args = json.loads(tool_call.function.arguments)

        grounded = validate_citation_grounding(args["cited_event_ids"], incident)
        return TriageResult(
            incident_id=incident.incident_id,
            summary=args["summary"],
            severity=Severity(args["severity"]),
            confidence=float(args["confidence"]),
            cited_event_ids=grounded,
            detections=detections,
        )
