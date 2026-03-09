import json
from pathlib import Path
from datetime import datetime, timedelta, UTC
import random

EVENTS_FILE = Path("data/raw/events.jsonl")


def _ts(offset_minutes: int) -> str:
    return (datetime.now(UTC) + timedelta(minutes=offset_minutes)).isoformat()


def _append_events(events):
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with EVENTS_FILE.open("a", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def generate_campaign():
    user = random.choice(["jsmith", "adoe", "bthomas"])
    device = random.choice(["WKSTN-102", "WKSTN-205", "ENG-LT-07"])
    dc = "DC-01"

    events = [
        {
            "TimeGenerated": _ts(0),
            "DeviceName": device,
            "User": user,
            "EventType": "FileOpen",
            "Scenario": "phishing_doc",
            "FileName": "invoice_q1.docm",
            "ProcessName": "WINWORD.EXE",
            "ParentProcessName": "explorer.exe"
        },
        {
            "TimeGenerated": _ts(1),
            "DeviceName": device,
            "User": user,
            "EventType": "ProcessCreate",
            "Scenario": "encoded_powershell",
            "ProcessName": "powershell.exe",
            "ParentProcessName": "WINWORD.EXE",
            "CommandLine": "powershell.exe -enc SQBFAFgAIAByAGUAZAB0AGUAYQBtAA=="
        },
        {
            "TimeGenerated": _ts(2),
            "DeviceName": device,
            "User": user,
            "EventType": "ProcessCreate",
            "Scenario": "discovery",
            "ProcessName": "cmd.exe",
            "ParentProcessName": "powershell.exe",
            "CommandLine": "cmd.exe /c whoami && ipconfig && net user"
        },
        {
            "TimeGenerated": _ts(3),
            "DeviceName": dc,
            "User": user,
            "EventType": "AuthenticationFailure",
            "Scenario": "password_spray",
            "FailureCount": random.randint(8, 15),
            "SourceDevice": device,
            "DestinationIP": "10.0.0.10"
        },
        {
            "TimeGenerated": _ts(4),
            "DeviceName": device,
            "User": user,
            "EventType": "NetworkConnection",
            "Scenario": "c2_beacon",
            "ProcessName": "powershell.exe",
            "DestinationIP": "198.51.100.25",
            "DestinationPort": 443,
            "Protocol": "TCP"
        },
        {
            "TimeGenerated": _ts(5),
            "DeviceName": "FS-01",
            "User": user,
            "EventType": "LogonSuccess",
            "Scenario": "lateral_movement",
            "SourceDevice": device,
            "DestinationIP": "10.0.0.20",
            "Protocol": "SMB"
        },
        {
            "TimeGenerated": _ts(6),
            "DeviceName": device,
            "User": user,
            "EventType": "RegistryModification",
            "Scenario": "runkey_persistence",
            "ProcessName": "reg.exe",
            "ParentProcessName": "powershell.exe",
            "RegistryPath": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
        }
    ]

    _append_events(events)
    return len(events)