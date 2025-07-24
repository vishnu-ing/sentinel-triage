from __future__ import annotations

import csv
from datetime import timedelta

import pytest

from sentinel_triage.detection.sigma_engine import SigmaEngine, load_rules_from_dir
from sentinel_triage.eval.harness import EvalReport, evaluate_dataset
from tests.conftest import SIGMA_RULES_DIR, DATASET_PATH


@pytest.fixture(scope="module")
def engine() -> SigmaEngine:
    return SigmaEngine(load_rules_from_dir(SIGMA_RULES_DIR))


def _write_controlled_dataset(path, rows):
    fields = ["event_id", "timestamp", "host", "user", "src_ip", "country", "event_type", "raw", "is_malicious", "attack_type"]
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_evaluate_dataset_on_bundled_labeled_data_produces_reasonable_metrics(engine: SigmaEngine):
    report = evaluate_dataset(DATASET_PATH, engine)
    assert isinstance(report, EvalReport)
    assert report.num_incidents > 0
    # This is a defensible solo prototype, not a tuned production model:
    # we assert strong-but-not-perfect bounds so the test is meaningful
    # (it would fail if detection/correlation regressed) without being
    # brittle to exact floating point values.
    assert report.precision >= 0.8
    assert report.recall >= 0.8
    assert report.false_positive_rate <= 0.05
    for attack_type, recall in report.per_attack_type_recall.items():
        assert 0.0 <= recall <= 1.0


def test_evaluate_dataset_report_serializes(engine: SigmaEngine, tmp_path):
    report = evaluate_dataset(DATASET_PATH, engine)
    out_path = tmp_path / "report.json"
    report.save(out_path)
    assert out_path.exists()
    import json

    data = json.loads(out_path.read_text())
    assert "precision" in data and "recall" in data and "false_positive_rate" in data


def test_evaluate_dataset_exact_confusion_matrix_on_controlled_fixture(engine: SigmaEngine, tmp_path):
    """Builds a tiny fixture with a KNOWN confusion matrix: one true brute
    force (should be caught), one benign user (should not fire), and one
    malicious-but-subtle single failed login (below detection threshold,
    a deliberate false negative) -- so we can assert exact tp/fp/fn/tn
    rather than just bounds.
    """
    base = "2024-06-01T00:00:00+00:00"
    rows = []
    # attacker: 6 failed logins within a few minutes -> should be caught (TP)
    for i in range(6):
        rows.append(
            {
                "event_id": f"atk-{i}",
                "timestamp": f"2024-06-01T00:0{i}:00+00:00",
                "host": "h1",
                "user": "attacker1",
                "src_ip": "1.2.3.4",
                "country": "RU",
                "event_type": "login_failure",
                "raw": "x",
                "is_malicious": 1,
                "attack_type": "brute_force",
            }
        )
    # benign user: normal single login success (true negative)
    rows.append(
        {
            "event_id": "benign-1",
            "timestamp": base,
            "host": "h2",
            "user": "gooduser1",
            "src_ip": "9.9.9.9",
            "country": "US",
            "event_type": "login_success",
            "raw": "x",
            "is_malicious": 0,
            "attack_type": "benign",
        }
    )
    # subtle attacker: only 1 failed login, below our detection threshold
    # -> ground truth malicious but pipeline will miss it (false negative)
    rows.append(
        {
            "event_id": "subtle-1",
            "timestamp": base,
            "host": "h3",
            "user": "subtleattacker",
            "src_ip": "5.5.5.5",
            "country": "CN",
            "event_type": "login_failure",
            "raw": "x",
            "is_malicious": 1,
            "attack_type": "brute_force",
        }
    )

    dataset_path = tmp_path / "controlled.csv"
    _write_controlled_dataset(dataset_path, rows)

    report = evaluate_dataset(dataset_path, engine, window=timedelta(minutes=15))

    assert report.num_incidents == 3
    assert report.true_positives == 1
    assert report.false_positives == 0
    assert report.false_negatives == 1
    assert report.true_negatives == 1
    assert report.precision == 1.0
    assert report.recall == 0.5
    assert report.false_positive_rate == 0.0
    assert report.per_attack_type_recall["brute_force"] == 0.5


def test_evaluate_dataset_all_benign_gives_zero_division_safe_metrics(engine: SigmaEngine, tmp_path):
    rows = [
        {
            "event_id": "b1",
            "timestamp": "2024-06-01T00:00:00+00:00",
            "host": "h1",
            "user": "gooduser",
            "src_ip": "9.9.9.9",
            "country": "US",
            "event_type": "login_success",
            "raw": "x",
            "is_malicious": 0,
            "attack_type": "benign",
        }
    ]
    dataset_path = tmp_path / "all_benign.csv"
    _write_controlled_dataset(dataset_path, rows)
    report = evaluate_dataset(dataset_path, engine)
    assert report.true_positives == 0
    assert report.false_positives == 0
    # recall of 0/0 is defined as 0.0, not NaN or an exception
    assert report.recall == 0.0
    assert report.precision == 0.0
    assert report.false_positive_rate == 0.0
