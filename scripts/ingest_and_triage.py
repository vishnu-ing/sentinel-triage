#!/usr/bin/env python3
"""End-to-end offline demo CLI: ingests the bundled dataset, correlates it,
runs Sigma/MITRE detection, triages incidents with the (offline, fake) LLM
client, enqueues results into a persistent SQLite review queue, and prints
what an analyst would see in the review queue.

Usage:
    python scripts/ingest_and_triage.py
    python scripts/ingest_and_triage.py --db /tmp/review_queue.db
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from sentinel_triage.detection.sigma_engine import SigmaEngine  # noqa: E402
from sentinel_triage.ingestion.loader import load_events_from_csv  # noqa: E402
from sentinel_triage.pipeline import run_pipeline  # noqa: E402
from sentinel_triage.review_queue.queue import ReviewQueue  # noqa: E402
from sentinel_triage.triage.llm_client import FakeLLMClient  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default=str(REPO_ROOT / "data" / "labeled_auth_events.csv"))
    parser.add_argument("--rules", default=str(REPO_ROOT / "sigma_rules"))
    parser.add_argument("--db", default=":memory:", help="SQLite path for the review queue")
    args = parser.parse_args()

    events = load_events_from_csv(args.dataset)
    engine = SigmaEngine.from_dir(args.rules)
    queue = ReviewQueue(args.db)

    result = run_pipeline(events, engine, FakeLLMClient(), review_queue=queue)

    print(f"Ingested {len(events)} events -> {len(result.incidents)} candidate incidents")
    print(f"Triaged {len(result.triage_results)} incidents\n")

    print("=== Analyst review queue (pending, highest severity first) ===")
    for item in queue.list_pending():
        print(f"[{item.severity.upper():8}] conf={item.confidence:.2f}  {item.entity_key}")
        print(f"   {item.summary}")
        print(f"   detections: {', '.join(item.detection_titles) or 'none'}")
        print(f"   mitre: {', '.join(item.mitre_techniques) or 'none'}")
        print(f"   cited events: {', '.join(item.cited_event_ids)}")
        print()

    queue.close()


if __name__ == "__main__":
    main()
