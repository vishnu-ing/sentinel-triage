from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinel_triage.detection.sigma_engine import SigmaEngine, load_rules_from_dir
from sentinel_triage.events import Event

REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parent.parent
SIGMA_RULES_DIR = REPO_ROOT / "sigma_rules"
DATASET_PATH = REPO_ROOT / "data" / "labeled_auth_events.csv"


def make_event(
    event_id: str,
    minute: float,
    user: str = "alice",
    host: str = "ws-01",
    src_ip: str = "10.0.0.1",
    event_type: str = "login_failure",
    country: str = "US",
    base: datetime | None = None,
    **extra,
) -> Event:
    base = base or datetime(2024, 1, 1, tzinfo=timezone.utc)
    return Event(
        event_id=event_id,
        timestamp=base + timedelta(minutes=minute),
        host=host,
        user=user,
        src_ip=src_ip,
        event_type=event_type,
        raw=f"synthetic raw line for {event_id}",
        country=country,
        extra=extra,
    )


@pytest.fixture
def base_time() -> datetime:
    return datetime(2024, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(scope="session")
def sigma_engine() -> SigmaEngine:
    return SigmaEngine(load_rules_from_dir(SIGMA_RULES_DIR))


@pytest.fixture(scope="session")
def dataset_path():
    assert DATASET_PATH.exists(), "bundled labeled dataset is missing"
    return DATASET_PATH
