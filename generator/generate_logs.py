import json
import random
from pathlib import Path
from datetime import datetime, timedelta, UTC

EVENTS_FILE = Path("data/raw/events.jsonl")


def _random_ts(base_time, offset_seconds):
    return (base_time + timedelta(seconds=offset_seconds)).isoformat()


def generate(total_events=20000, attack_injections=12):
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)

    base_time = datetime.now(UTC) - timedelta(hours=2)
    users = ["jsmith", "adoe", "bthomas", "svc-backup"]
    devices = ["WKSTN-102", "WKSTN-205", "ENG-LT-07", "HR-LT-22", "DC-01"]
    event_types = ["ProcessCreate", "NetworkConnection", "FileOpen", "LogonSuccess"]

    with EVENTS_FILE.open("w", encoding="utf-8") as f:
        for i in range(total_events):
            event = {
                "TimeGenerated": _random_ts(base_time, i),
                "DeviceName": random.choice(devices),
                "User": random.choice(users),
                "EventType": random.choice(event_types),
                "Scenario": "benign",
                "ProcessName": random.choice(["chrome.exe", "outlook.exe", "teams.exe", "explorer.exe"])
            }
            f.write(json.dumps(event) + "\n")

    return total_events