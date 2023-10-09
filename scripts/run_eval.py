#!/usr/bin/env python3
"""CLI entry point for the eval harness: measures precision/recall/FPR of
the correlation + Sigma/MITRE + LLM-triage pipeline against the bundled
labeled dataset (or any dataset conforming to the same CSV schema).

Usage:
    python scripts/run_eval.py
    python scripts/run_eval.py --dataset data/labeled_auth_events.csv --out eval_report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from sentinel_triage.detection.sigma_engine import SigmaEngine  # noqa: E402
from sentinel_triage.eval.harness import evaluate_dataset  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default=str(REPO_ROOT / "data" / "labeled_auth_events.csv"))
    parser.add_argument("--rules", default=str(REPO_ROOT / "sigma_rules"))
    parser.add_argument("--out", default=None, help="optional path to write the JSON report")
    args = parser.parse_args()

    engine = SigmaEngine.from_dir(args.rules)
    report = evaluate_dataset(args.dataset, engine)

    print(json.dumps(report.to_dict(), indent=2))
    if args.out:
        report.save(args.out)
        print(f"\nwrote report to {args.out}")


if __name__ == "__main__":
    main()
