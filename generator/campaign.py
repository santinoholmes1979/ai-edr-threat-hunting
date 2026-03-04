import json
import random
from datetime import datetime, timedelta
from pathlib import Path

EVENTS_FILE = Path("data/raw/events.jsonl")

devices = ["ENG-WKS01", "ENG-WKS02", "FIN-WKS01"]
users = ["svc-deploy", "j.smith", "m.jones"]

def now():
    return datetime.utcnow()

def write_event(event):
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with EVENTS_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

def generate_campaign():
    device = random.choice(devices)
    user = random.choice(users)

    base = now()

    campaign = [

        {
            "TimeGenerated": (base).isoformat(),
            "DeviceName": device,
            "User": user,
            "EventType": "ProcessCreate",
            "ProcessName": "winword.exe",
            "CommandLine": "winword.exe invoice.docm",
            "Scenario": "phishing_doc"
        },

        {
            "TimeGenerated": (base + timedelta(seconds=30)).isoformat(),
            "DeviceName": device,
            "User": user,
            "EventType": "ProcessCreate",
            "ProcessName": "powershell.exe",
            "CommandLine": "powershell -enc SQBFAFgA",
            "Scenario": "encoded_powershell"
        },

        {
            "TimeGenerated": (base + timedelta(seconds=60)).isoformat(),
            "DeviceName": device,
            "User": user,
            "EventType": "Logon",
            "LogonType": "Network",
            "Result": "Failure",
            "Scenario": "password_spray"
        },

        {
            "TimeGenerated": (base + timedelta(seconds=90)).isoformat(),
            "DeviceName": device,
            "User": user,
            "EventType": "RegistrySet",
            "RegistryKey": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "Value": "evil.exe",
            "Scenario": "runkey_persistence"
        }

    ]

    for e in campaign:
        write_event(e)

    return len(campaign)


if __name__ == "__main__":
    n = generate_campaign()
    print(f"Generated adversary campaign with {n} events")