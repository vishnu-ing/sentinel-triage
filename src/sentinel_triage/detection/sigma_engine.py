"""A practical subset of Sigma (https://github.com/SigmaHQ/sigma) tailored
to this prototype's needs, mapped to MITRE ATT&CK.

What is implemented, and why it's a defensible subset rather than a toy:

* Standard Sigma ``logsource`` / field-equality ``selection`` blocks
  (a field maps to a scalar for equality, or a list for "field is one of").
* A ``condition`` mini-language limited to boolean combinations (``and`` /
  ``or``, left-to-right, ``and`` binding tighter) of aggregation clauses
  ``count(<selection>)`` and ``distinct_count(<selection>.<field>)``
  compared against a threshold. This mirrors Sigma's newer "correlation
  rule" concept (``type: event_count`` / ``value_count`` with a
  ``timeframe``), reimplemented directly since a full pySigma backend is
  unnecessary for a single log source.
* A sliding-window evaluator: rather than only checking the aggregate over
  an entire (correlation-engine-produced) incident, it finds the *tightest
  qualifying sub-window* of length ``timeframe`` and reports exactly which
  events fall inside it. Those event ids are what get handed to the LLM
  triage step for citation grounding -- the model is never given the
  freedom to cite events outside what actually tripped the rule.

Not implemented (documented, not a hidden gap): full Sigma condition
grammar (nested parens, ``1 of selection*``, wildcards/regex field
matching), and non-authentication logsources. See README "Stretch goals".
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from sentinel_triage.correlation.entity_clustering import CandidateIncident
from sentinel_triage.events import Event

_CLAUSE_RE = re.compile(
    r"^\s*(count|distinct_count)\(\s*([a-zA-Z_][a-zA-Z0-9_]*)"
    r"(?:\.([a-zA-Z_][a-zA-Z0-9_]*))?\s*\)\s*(>=|<=|==|>|<)\s*(\d+)\s*$"
)

_TIMEFRAME_RE = re.compile(r"^(\d+)([smhd])$")

_OPS = {
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    "==": lambda a, b: a == b,
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
}


def parse_timeframe(text: str) -> timedelta:
    m = _TIMEFRAME_RE.match(text.strip())
    if not m:
        raise ValueError(f"Unsupported timeframe format: {text!r} (expected e.g. '10m', '1h')")
    value, unit = int(m.group(1)), m.group(2)
    return {
        "s": timedelta(seconds=value),
        "m": timedelta(minutes=value),
        "h": timedelta(hours=value),
        "d": timedelta(days=value),
    }[unit]


@dataclass
class _Clause:
    aggregate: str  # "count" | "distinct_count"
    selection: str
    field: str | None
    op: str
    threshold: int

    def matches_event(self, event: Event, selections: dict[str, dict[str, Any]]) -> bool:
        return _event_matches_selection(event, selections[self.selection])


def _parse_condition(condition: str) -> list[list[_Clause]]:
    """Returns a list of AND-groups (OR'd together): ``[[c1, c2], [c3]]``
    represents ``(c1 and c2) or c3``."""
    or_groups = [g.strip() for g in condition.split(" or ")]
    parsed: list[list[_Clause]] = []
    for group in or_groups:
        and_parts = [p.strip() for p in group.split(" and ")]
        clauses = []
        for part in and_parts:
            m = _CLAUSE_RE.match(part)
            if not m:
                raise ValueError(f"Unsupported condition clause: {part!r}")
            aggregate, selection, field, op, threshold = m.groups()
            if aggregate == "distinct_count" and not field:
                raise ValueError(f"distinct_count requires a field, e.g. distinct_count(sel.field): {part!r}")
            clauses.append(_Clause(aggregate, selection, field, op, int(threshold)))
        parsed.append(clauses)
    return parsed


def _event_matches_selection(event: Event, selection: dict[str, Any]) -> bool:
    event_dict = event.to_dict()
    for field, expected in selection.items():
        actual = event_dict.get(field)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


def _sliding_window_best(
    events: list[Event], clause: _Clause, timeframe: timedelta
) -> tuple[bool, list[Event]]:
    """Finds the sub-window of length ``timeframe`` that best satisfies
    ``clause`` (maximum count / distinct_count). Returns whether the clause
    is satisfied anywhere, and the matching events inside the winning
    window (for citation grounding)."""
    events = sorted(events, key=lambda e: e.timestamp)
    n = len(events)
    if n == 0:
        return False, []

    best_metric = -1
    best_slice: list[Event] = []
    left = 0
    for right in range(n):
        while events[right].timestamp - events[left].timestamp > timeframe:
            left += 1
        window = events[left : right + 1]
        if clause.aggregate == "count":
            metric = len(window)
        else:  # distinct_count
            metric = len({e.to_dict().get(clause.field) for e in window})
        if metric > best_metric:
            best_metric = metric
            best_slice = window

    satisfied = _OPS[clause.op](best_metric, clause.threshold)
    return satisfied, (best_slice if satisfied else [])


@dataclass
class SigmaRule:
    rule_id: str
    title: str
    description: str
    level: str
    mitre_tactic: str
    mitre_tactic_name: str
    mitre_techniques: list[str]
    selections: dict[str, dict[str, Any]]
    condition_groups: list[list[_Clause]]
    timeframe: timedelta

    @staticmethod
    def from_yaml_dict(data: dict[str, Any]) -> "SigmaRule":
        detection = data["detection"]
        mitre = data.get("mitre_attack", {})
        return SigmaRule(
            rule_id=str(data["id"]),
            title=data["title"],
            description=data.get("description", "").strip(),
            level=data.get("level", "medium"),
            mitre_tactic=mitre.get("tactic", ""),
            mitre_tactic_name=mitre.get("tactic_name", ""),
            mitre_techniques=list(mitre.get("techniques", [])),
            selections=detection["selections"],
            condition_groups=_parse_condition(detection["condition"]),
            timeframe=parse_timeframe(str(data["timeframe"])),
        )

    def evaluate(self, incident: CandidateIncident) -> "DetectionMatch | None":
        """Evaluates this rule against an incident's events. A rule
        matches if any OR-group of its clauses is fully satisfied
        (every clause in that AND-group finds a qualifying sliding
        window). The matched event ids returned are the union of the
        winning windows for the satisfied group, restricted to real
        events from the incident -- never fabricated."""
        for clauses in self.condition_groups:
            matched_ids: set[str] = set()
            all_satisfied = True
            for clause in clauses:
                selection_events = [
                    e for e in incident.events if _event_matches_selection(e, self.selections[clause.selection])
                ]
                satisfied, window_events = _sliding_window_best(selection_events, clause, self.timeframe)
                if not satisfied:
                    all_satisfied = False
                    break
                matched_ids.update(e.event_id for e in window_events)
            if all_satisfied:
                matched_events = [e for e in incident.events if e.event_id in matched_ids]
                matched_events.sort(key=lambda e: e.timestamp)
                return DetectionMatch(
                    rule_id=self.rule_id,
                    title=self.title,
                    level=self.level,
                    mitre_tactic=self.mitre_tactic,
                    mitre_tactic_name=self.mitre_tactic_name,
                    mitre_techniques=list(self.mitre_techniques),
                    incident_id=incident.incident_id,
                    matched_event_ids=[e.event_id for e in matched_events],
                )
        return None


@dataclass
class DetectionMatch:
    rule_id: str
    title: str
    level: str
    mitre_tactic: str
    mitre_tactic_name: str
    mitre_techniques: list[str]
    incident_id: str
    matched_event_ids: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "level": self.level,
            "mitre_tactic": self.mitre_tactic,
            "mitre_tactic_name": self.mitre_tactic_name,
            "mitre_techniques": self.mitre_techniques,
            "incident_id": self.incident_id,
            "matched_event_ids": self.matched_event_ids,
        }


_LEVEL_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def load_rules_from_dir(path: str | Path) -> list[SigmaRule]:
    path = Path(path)
    rules = []
    for file_path in sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")):
        with file_path.open() as f:
            data = yaml.safe_load(f)
        rules.append(SigmaRule.from_yaml_dict(data))
    if not rules:
        raise ValueError(f"No Sigma rules found in {path}")
    return rules


class SigmaEngine:
    """Evaluates a rule set against candidate incidents."""

    def __init__(self, rules: list[SigmaRule]):
        self.rules = rules

    @classmethod
    def from_dir(cls, path: str | Path) -> "SigmaEngine":
        return cls(load_rules_from_dir(path))

    def evaluate_incident(self, incident: CandidateIncident) -> list[DetectionMatch]:
        matches = [m for rule in self.rules if (m := rule.evaluate(incident)) is not None]
        matches.sort(key=lambda m: _LEVEL_ORDER.get(m.level, 0), reverse=True)
        return matches

    def evaluate_all(self, incidents: list[CandidateIncident]) -> dict[str, list[DetectionMatch]]:
        return {inc.incident_id: self.evaluate_incident(inc) for inc in incidents}
