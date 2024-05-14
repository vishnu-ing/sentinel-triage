from __future__ import annotations

import random
from datetime import timedelta

import pytest

from sentinel_triage.correlation.entity_clustering import correlate_events
from tests.conftest import make_event


def test_empty_input_returns_no_incidents():
    assert correlate_events([]) == []


def test_single_event_is_its_own_incident():
    events = [make_event("e1", 0)]
    incidents = correlate_events(events)
    assert len(incidents) == 1
    assert incidents[0].events == events


def test_events_within_window_merge_into_one_incident():
    events = [make_event("e1", 0), make_event("e2", 5), make_event("e3", 9)]
    incidents = correlate_events(events, window=timedelta(minutes=15))
    assert len(incidents) == 1
    assert len(incidents[0].events) == 3


def test_events_beyond_window_split_into_separate_incidents():
    events = [make_event("e1", 0), make_event("e2", 30)]
    incidents = correlate_events(events, window=timedelta(minutes=15))
    assert len(incidents) == 2
    assert [len(i.events) for i in incidents] == [1, 1]


def test_chained_bursts_merge_even_if_first_and_last_exceed_window():
    # 0, 10, 20, 30 minutes: consecutive gaps are 10 min (<= 15 min window)
    # but first-to-last gap is 30 min, which must NOT force a split.
    events = [make_event(f"e{i}", i * 10) for i in range(4)]
    incidents = correlate_events(events, window=timedelta(minutes=15))
    assert len(incidents) == 1
    assert len(incidents[0].events) == 4


def test_window_boundary_is_inclusive():
    events = [make_event("e1", 0), make_event("e2", 15)]
    incidents = correlate_events(events, window=timedelta(minutes=15))
    assert len(incidents) == 1


def test_just_over_window_boundary_splits():
    # second event is 15 minutes and 1 second after the first: 1 second
    # past the boundary, so it must NOT merge.
    events = [make_event("e1", 0), make_event("e2", 15 + 1 / 60)]
    incidents = correlate_events(events, window=timedelta(minutes=15))
    assert len(incidents) == 2


def test_different_entities_are_never_merged_even_if_overlapping_in_time():
    events = [
        make_event("a1", 0, user="alice"),
        make_event("b1", 0, user="bob"),
        make_event("a2", 1, user="alice"),
        make_event("b2", 1, user="bob"),
    ]
    incidents = correlate_events(events, window=timedelta(minutes=15))
    assert len(incidents) == 2
    entities = {inc.entity_key for inc in incidents}
    assert entities == {"alice", "bob"}
    for inc in incidents:
        assert len(inc.events) == 2


def test_result_is_deterministic_regardless_of_input_order():
    events = [
        make_event("a1", 0, user="alice"),
        make_event("a2", 5, user="alice"),
        make_event("b1", 1, user="bob"),
        make_event("b2", 40, user="bob"),
    ]
    shuffled = events[:]
    random.Random(7).shuffle(shuffled)

    incidents_in_order = correlate_events(events, window=timedelta(minutes=15))
    incidents_shuffled = correlate_events(shuffled, window=timedelta(minutes=15))

    def fingerprint(incidents):
        return sorted(
            (inc.entity_key, tuple(sorted(e.event_id for e in inc.events)))
            for inc in incidents
        )

    assert fingerprint(incidents_in_order) == fingerprint(incidents_shuffled)


def test_incidents_sorted_by_start_time():
    events = [
        make_event("late", 100, user="alice"),
        make_event("early", 0, user="bob"),
    ]
    incidents = correlate_events(events, window=timedelta(minutes=5))
    assert incidents[0].entity_key == "bob"
    assert incidents[1].entity_key == "alice"


def test_candidate_incident_summary_fields():
    events = [
        make_event("e1", 0, host="h1", src_ip="1.1.1.1", country="US", event_type="login_failure"),
        make_event("e2", 2, host="h2", src_ip="2.2.2.2", country="RU", event_type="login_success"),
    ]
    incidents = correlate_events(events, window=timedelta(minutes=15))
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.hosts == {"h1", "h2"}
    assert inc.src_ips == {"1.1.1.1", "2.2.2.2"}
    assert inc.countries == {"US", "RU"}
    assert inc.event_types == ["login_failure", "login_success"]
    assert inc.event_ids() == {"e1", "e2"}
    summary = inc.to_summary_dict()
    assert summary["num_events"] == 2
    assert summary["incident_id"] == inc.incident_id


def test_rejects_non_positive_window():
    events = [make_event("e1", 0)]
    with pytest.raises(ValueError):
        correlate_events(events, window=timedelta(0))
    with pytest.raises(ValueError):
        correlate_events(events, window=timedelta(minutes=-1))


def test_custom_entity_fn_groups_by_src_ip_instead_of_user():
    events = [
        make_event("e1", 0, user="alice", src_ip="9.9.9.9"),
        make_event("e2", 1, user="mallory", src_ip="9.9.9.9"),
    ]
    incidents = correlate_events(events, window=timedelta(minutes=5), entity_fn=lambda e: e.src_ip)
    assert len(incidents) == 1
    assert incidents[0].entity_key == "9.9.9.9"
    assert len(incidents[0].events) == 2
