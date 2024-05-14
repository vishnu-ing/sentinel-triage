"""Evaluation harness: runs the full pipeline (minus the review queue) over
a labeled dataset and measures precision / recall / false-positive rate
against ground truth, at the *incident* level -- the unit an analyst
actually reviews, not the raw event level.

Ground truth for an incident is "positive" if any event correlated into it
was labeled malicious in the source dataset. A prediction is "positive" if
the triage step assigned it anything above LOW severity (equivalently:
at least one Sigma rule fired -- see ``FakeLLMClient``, which only ever
raises severity when a detection matched).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Callable

from sentinel_triage.correlation.entity_clustering import DEFAULT_WINDOW
from sentinel_triage.detection.sigma_engine import SigmaEngine
from sentinel_triage.ingestion.loader import load_events_from_csv
from sentinel_triage.pipeline import run_pipeline
from sentinel_triage.triage.llm_client import FakeLLMClient, LLMClient, Severity, TriageResult

PositivePredicate = Callable[[TriageResult], bool]


def default_positive_predicate(result: TriageResult) -> bool:
    return result.severity != Severity.LOW


@dataclass
class EvalReport:
    num_incidents: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    per_attack_type_recall: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "num_incidents": self.num_incidents,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "per_attack_type_recall": {k: round(v, 4) for k, v in self.per_attack_type_recall.items()},
        }

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))


def _incident_ground_truth(incident) -> tuple[bool, str | None]:
    """Returns (is_malicious, dominant_attack_type) for an incident, derived
    from the per-event labels bundled in the dataset."""
    malicious_types = [
        e.extra.get("attack_type")
        for e in incident.events
        if str(e.extra.get("is_malicious", "0")) in ("1", "True", "true")
    ]
    if not malicious_types:
        return False, None
    # dominant = most common non-benign attack type in this incident
    return True, max(set(malicious_types), key=malicious_types.count)


def evaluate_dataset(
    dataset_path: str | Path,
    sigma_engine: SigmaEngine,
    llm_client: LLMClient | None = None,
    *,
    window: timedelta = DEFAULT_WINDOW,
    positive_predicate: PositivePredicate = default_positive_predicate,
) -> EvalReport:
    llm_client = llm_client or FakeLLMClient()
    events = load_events_from_csv(dataset_path)
    result = run_pipeline(events, sigma_engine, llm_client, window=window)

    triage_by_incident = {t.incident_id: t for t in result.triage_results}

    tp = fp = fn = tn = 0
    attack_type_totals: dict[str, int] = {}
    attack_type_caught: dict[str, int] = {}

    for incident in result.incidents:
        ground_truth, attack_type = _incident_ground_truth(incident)
        triage = triage_by_incident.get(incident.incident_id)
        predicted = bool(triage and positive_predicate(triage))

        if ground_truth and predicted:
            tp += 1
        elif ground_truth and not predicted:
            fn += 1
        elif not ground_truth and predicted:
            fp += 1
        else:
            tn += 1

        if ground_truth and attack_type:
            attack_type_totals[attack_type] = attack_type_totals.get(attack_type, 0) + 1
            if predicted:
                attack_type_caught[attack_type] = attack_type_caught.get(attack_type, 0) + 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    per_attack_type_recall = {
        attack_type: attack_type_caught.get(attack_type, 0) / total
        for attack_type, total in attack_type_totals.items()
    }

    return EvalReport(
        num_incidents=len(result.incidents),
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=fpr,
        per_attack_type_recall=per_attack_type_recall,
    )
