#!/usr/bin/env python3
"""Generates the bundled synthetic labeled auth-log dataset used for the demo
pipeline and the eval harness.

This is NOT a live scraper of a public dataset -- network access is not
available in this environment / at test time. It instead synthesizes a
compact dataset that mirrors the *shape* of well-known public auth-log
corpora (e.g. the LANL Comprehensive, Multi-Source Cyber-Security Events
dataset and CICIDS2017's authentication-log subset): one row per
authentication-relevant event with a user, host, source IP, coarse
geo-country, event type, and a ground-truth malicious label plus attack
family. Swapping in a real dataset only requires conforming to the same
CSV columns (see README "Swapping in a real dataset").

Run with: python scripts/generate_dataset.py
"""

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT_PATH = Path(__file__).resolve().parent.parent / "data" / "labeled_auth_events.csv"

RNG_SEED = 20240115
HOSTS = ["ws-fin-01", "ws-eng-07", "ws-hr-03", "jump-box-01", "db-prod-02", "vpn-gw-01"]
BENIGN_COUNTRIES = ["US", "US", "US", "CA", "GB"]
ATTACKER_COUNTRIES = ["RU", "CN", "NG", "KP", "RO"]

FIELDS = [
    "event_id",
    "timestamp",
    "host",
    "user",
    "src_ip",
    "country",
    "event_type",
    "raw",
    "is_malicious",
    "attack_type",
]


def _ip(rng: random.Random, country: str) -> str:
    prefix = {"US": 10, "CA": 172, "GB": 192, "RU": 45, "CN": 116, "NG": 105, "KP": 175, "RO": 82}.get(
        country, 203
    )
    return f"{prefix}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _row(
    rng: random.Random,
    idx: int,
    ts: datetime,
    host: str,
    user: str,
    src_ip: str,
    country: str,
    event_type: str,
    is_malicious: bool,
    attack_type: str,
) -> dict:
    raw = (
        f"{ts.isoformat()} host={host} user={user} src_ip={src_ip} "
        f"country={country} action={event_type}"
    )
    return {
        "event_id": f"evt-{idx:06d}",
        "timestamp": ts.isoformat(),
        "host": host,
        "user": user,
        "src_ip": src_ip,
        "country": country,
        "event_type": event_type,
        "raw": raw,
        "is_malicious": int(is_malicious),
        "attack_type": attack_type,
    }


def generate() -> list[dict]:
    rng = random.Random(RNG_SEED)
    rows: list[dict] = []
    idx = 0
    base_day = datetime(2024, 1, 15, 0, 0, tzinfo=timezone.utc)

    normal_users = [f"user{i:02d}" for i in range(1, 41)]

    # --- benign background traffic across the day ---
    for user in normal_users:
        host = rng.choice(HOSTS)
        country = rng.choice(BENIGN_COUNTRIES)
        src_ip = _ip(rng, country)
        n_events = rng.randint(2, 5)
        t = base_day + timedelta(hours=rng.uniform(0, 23), minutes=rng.uniform(0, 59))
        for _ in range(n_events):
            t += timedelta(minutes=rng.uniform(20, 240))
            # occasional single mistyped-password failure is normal, not an incident
            if rng.random() < 0.12:
                rows.append(
                    _row(rng, idx, t, host, user, src_ip, country, "login_failure", False, "benign")
                )
                idx += 1
                t += timedelta(seconds=rng.uniform(5, 40))
            rows.append(
                _row(rng, idx, t, host, user, src_ip, country, "login_success", False, "benign")
            )
            idx += 1
            t += timedelta(minutes=rng.uniform(5, 90))
            rows.append(_row(rng, idx, t, host, user, src_ip, country, "logoff", False, "benign"))
            idx += 1

    # --- brute force incidents: 5 victims, 6-10 rapid failures from one attacker IP ---
    for i in range(5):
        user = f"target_bf_{i:02d}"
        host = rng.choice(HOSTS)
        country = rng.choice(ATTACKER_COUNTRIES)
        src_ip = _ip(rng, country)
        t = base_day + timedelta(hours=rng.uniform(0, 23))
        n_failures = rng.randint(6, 10)
        for _ in range(n_failures):
            rows.append(
                _row(rng, idx, t, host, user, src_ip, country, "login_failure", True, "brute_force")
            )
            idx += 1
            t += timedelta(seconds=rng.uniform(5, 45))
        # roughly half succeed at the end (credential-stuffing hit), half get locked out
        if i % 2 == 0:
            rows.append(
                _row(rng, idx, t, host, user, src_ip, country, "login_success", True, "brute_force")
            )
        else:
            rows.append(
                _row(rng, idx, t, host, user, src_ip, country, "account_lockout", True, "brute_force")
            )
        idx += 1

    # --- impossible travel: legit login from home country, then success from
    #     a distant country minutes later using stolen creds ---
    for i in range(4):
        user = f"target_travel_{i:02d}"
        host = rng.choice(HOSTS)
        home_country = rng.choice(BENIGN_COUNTRIES)
        home_ip = _ip(rng, home_country)
        t = base_day + timedelta(hours=rng.uniform(0, 20))
        rows.append(
            _row(rng, idx, t, host, user, home_ip, home_country, "login_success", False, "benign")
        )
        idx += 1
        attacker_country = rng.choice(ATTACKER_COUNTRIES)
        attacker_ip = _ip(rng, attacker_country)
        t2 = t + timedelta(minutes=rng.uniform(4, 25))
        rows.append(
            _row(
                rng, idx, t2, host, user, attacker_ip, attacker_country,
                "login_success", True, "impossible_travel",
            )
        )
        idx += 1

    # --- privilege escalation chains: several failures then a privilege_use ---
    for i in range(3):
        user = f"target_priv_{i:02d}"
        host = rng.choice(HOSTS)
        country = rng.choice(ATTACKER_COUNTRIES)
        src_ip = _ip(rng, country)
        t = base_day + timedelta(hours=rng.uniform(0, 22))
        n_failures = rng.randint(3, 5)
        for _ in range(n_failures):
            rows.append(
                _row(rng, idx, t, host, user, src_ip, country, "login_failure", True, "privilege_escalation")
            )
            idx += 1
            t += timedelta(seconds=rng.uniform(8, 30))
        rows.append(
            _row(rng, idx, t, host, user, src_ip, country, "login_success", True, "privilege_escalation")
        )
        idx += 1
        t += timedelta(seconds=rng.uniform(10, 60))
        rows.append(
            _row(rng, idx, t, host, user, src_ip, country, "privilege_use", True, "privilege_escalation")
        )
        idx += 1

    rows.sort(key=lambda r: r["timestamp"])
    return rows


def main() -> None:
    rows = generate()
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    n_mal = sum(r["is_malicious"] for r in rows)
    print(f"wrote {len(rows)} events ({n_mal} malicious) to {OUT_PATH}")


if __name__ == "__main__":
    main()
