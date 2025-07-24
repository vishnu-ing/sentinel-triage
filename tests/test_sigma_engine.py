from __future__ import annotations

from datetime import timedelta

import pytest

from sentinel_triage.correlation.entity_clustering import correlate_events
from sentinel_triage.detection.sigma_engine import (
    SigmaEngine,
    load_rules_from_dir,
    parse_timeframe,
)
from tests.conftest import SIGMA_RULES_DIR, make_event


def test_loads_all_bundled_rules():
    rules = load_rules_from_dir(SIGMA_RULES_DIR)
    titles = {r.title for r in rules}
    assert "Brute Force Authentication Attempts" in titles
    assert "Impossible Travel Between Successful Logins" in titles
    assert "Privilege Use Following Repeated Authentication Failures" in titles
    assert len(rules) == 4


def test_missing_rules_dir_raises(tmp_path):
    with pytest.raises(ValueError):
        load_rules_from_dir(tmp_path)


@pytest.mark.parametrize(
    "text,expected",
    [("10m", timedelta(minutes=10)), ("1h", timedelta(hours=1)), ("30s", timedelta(seconds=30)), ("1d", timedelta(days=1))],
)
def test_parse_timeframe(text, expected):
    assert parse_timeframe(text) == expected


def test_parse_timeframe_rejects_bad_format():
    with pytest.raises(ValueError):
        parse_timeframe("10 minutes")


def test_brute_force_rule_fires_on_five_failures_in_ten_minutes(sigma_engine: SigmaEngine):
    events = [make_event(f"e{i}", i * 1.5, event_type="login_failure") for i in range(5)]
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    matches = sigma_engine.evaluate_incident(incident)
    titles = {m.title for m in matches}
    assert "Brute Force Authentication Attempts" in titles
    bf = next(m for m in matches if m.title == "Brute Force Authentication Attempts")
    assert bf.mitre_tactic == "TA0006"
    assert "T1110" in bf.mitre_techniques
    # citations must be real events from the incident
    assert set(bf.matched_event_ids).issubset(incident.event_ids())
    assert len(bf.matched_event_ids) >= 5


def test_brute_force_rule_does_not_fire_on_four_failures(sigma_engine: SigmaEngine):
    events = [make_event(f"e{i}", i * 1.5, event_type="login_failure") for i in range(4)]
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    matches = sigma_engine.evaluate_incident(incident)
    assert not any(m.title == "Brute Force Authentication Attempts" for m in matches)


def test_brute_force_requires_five_within_the_rule_timeframe_not_just_the_incident():
    # 6 failures but spread across 40 minutes -- the *incident* window
    # (correlation) is wide, yet no 10-minute sub-window contains 5.
    events = [make_event(f"e{i}", i * 8, event_type="login_failure") for i in range(6)]
    incident = correlate_events(events, window=timedelta(minutes=45))[0]
    engine = SigmaEngine(load_rules_from_dir(SIGMA_RULES_DIR))
    matches = engine.evaluate_incident(incident)
    assert not any(m.title == "Brute Force Authentication Attempts" for m in matches)


def test_impossible_travel_fires_on_two_countries_within_thirty_minutes(sigma_engine: SigmaEngine):
    events = [
        make_event("e1", 0, event_type="login_success", country="US"),
        make_event("e2", 10, event_type="login_success", country="RU"),
    ]
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    matches = sigma_engine.evaluate_incident(incident)
    titles = {m.title for m in matches}
    assert "Impossible Travel Between Successful Logins" in titles
    it = next(m for m in matches if m.title == "Impossible Travel Between Successful Logins")
    assert it.mitre_tactic == "TA0001"
    assert set(it.matched_event_ids) == {"e1", "e2"}


def test_impossible_travel_does_not_fire_for_single_country(sigma_engine: SigmaEngine):
    events = [
        make_event("e1", 0, event_type="login_success", country="US"),
        make_event("e2", 10, event_type="login_success", country="US"),
    ]
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    matches = sigma_engine.evaluate_incident(incident)
    assert not any(m.title == "Impossible Travel Between Successful Logins" for m in matches)


def test_privilege_escalation_requires_both_failures_and_priv_use(sigma_engine: SigmaEngine):
    events = [make_event(f"f{i}", i, event_type="login_failure") for i in range(3)]
    events.append(make_event("s1", 3.5, event_type="login_success"))
    events.append(make_event("p1", 4, event_type="privilege_use"))
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    matches = sigma_engine.evaluate_incident(incident)
    titles = {m.title for m in matches}
    assert "Privilege Use Following Repeated Authentication Failures" in titles


def test_privilege_escalation_does_not_fire_without_priv_use_event(sigma_engine: SigmaEngine):
    events = [make_event(f"f{i}", i, event_type="login_failure") for i in range(3)]
    events.append(make_event("s1", 3.5, event_type="login_success"))
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    matches = sigma_engine.evaluate_incident(incident)
    assert not any(m.title == "Privilege Use Following Repeated Authentication Failures" for m in matches)


def test_benign_low_volume_incident_triggers_nothing(sigma_engine: SigmaEngine):
    events = [
        make_event("e1", 0, event_type="login_failure"),
        make_event("e2", 1, event_type="login_success"),
        make_event("e3", 30, event_type="logoff"),
    ]
    incident = correlate_events(events, window=timedelta(minutes=45))[0]
    matches = sigma_engine.evaluate_incident(incident)
    assert matches == []


def test_evaluate_all_maps_every_incident_id(sigma_engine: SigmaEngine):
    events = [
        make_event("a1", 0, user="alice", event_type="login_success"),
        make_event("b1", 0, user="bob", event_type="login_success"),
    ]
    incidents = correlate_events(events, window=timedelta(minutes=15))
    result = sigma_engine.evaluate_all(incidents)
    assert set(result.keys()) == {inc.incident_id for inc in incidents}


def test_matches_sorted_by_severity_level_descending():
    events = [make_event(f"f{i}", i, event_type="login_failure") for i in range(5)]
    events.append(make_event("lockout", 5, event_type="account_lockout"))
    incident = correlate_events(events, window=timedelta(minutes=15))[0]
    engine = SigmaEngine(load_rules_from_dir(SIGMA_RULES_DIR))
    matches = engine.evaluate_incident(incident)
    levels = [m.level for m in matches]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    assert levels == sorted(levels, key=lambda lvl: order[lvl])
