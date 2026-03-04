import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pandas as pd

EVENTS_FILE = Path("data/raw/events.jsonl")

MITRE_MAP = {
    "EncodedPowerShell": [("T1059.001", "Command and Scripting Interpreter: PowerShell"),
                          ("T1105", "Ingress Tool Transfer")],
    "PasswordSpray": [("T1110", "Brute Force")],
    "RunKeyPersistence": [("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder")]
}

NEXT_STEPS = {
    "EncodedPowerShell": [
        "Review full PowerShell command line and any child processes",
        "Pivot on destination domain/IP and check for additional connections",
        "Check if Office spawned PowerShell on other hosts/users"
    ],
    "PasswordSpray": [
        "Validate source IP reputation and geolocation (if available)",
        "Check for any subsequent successful logons from the same source",
        "Reset affected credentials / enforce MFA where applicable"
    ],
    "RunKeyPersistence": [
        "Inspect Run key value data path and confirm file exists on disk",
        "Check for additional persistence mechanisms (scheduled tasks, services)",
        "Isolate endpoint if persistence is confirmed and collect triage artifacts"
    ]
}

def _parse_ts(ts: str) -> datetime:
    # expects Z suffix
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)

def load_events(limit=None):
    rows = []
    with EVENTS_FILE.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            rows.append(json.loads(line))
    df = pd.json_normalize(rows)
    df["TimeGenerated_dt"] = pd.to_datetime(df["TimeGenerated"], utc=True, errors="coerce")
    return df

def events_around(df: pd.DataFrame, device: str, user: str, center_ts: str, minutes=10):
    center = _parse_ts(center_ts)
    start = center - timedelta(minutes=minutes)
    end = center + timedelta(minutes=minutes)

    q = df.copy()
    if device:
        q = q[q["DeviceName"] == device]
    if user:
        q = q[q["User"] == user]
    q = q[(q["TimeGenerated_dt"] >= start) & (q["TimeGenerated_dt"] <= end)]
    q = q.sort_values("TimeGenerated_dt", ascending=True)
    return q

def generate_soc_note(alert: dict, context_events: pd.DataFrame) -> dict:
    atype = alert.get("AlertType", "Unknown")
    mitre = MITRE_MAP.get(atype, [])
    steps = NEXT_STEPS.get(atype, ["Pivot on DeviceName/User and review event timeline."])

    # Lightweight “AI-style” summary (local heuristic)
    top_event_types = context_events["EventType"].value_counts().head(5).to_dict() if "EventType" in context_events else {}
    suspicious = context_events[context_events.get("Scenario", "") != "benign"] if "Scenario" in context_events else context_events

    summary = {
        "Title": f"{atype} on {alert.get('DeviceName')} ({alert.get('User')})",
        "Severity": alert.get("Severity", "Medium"),
        "Time": alert.get("TimeGenerated"),
        "WhatHappened": alert.get("Summary"),
        "Context": {
            "EventsInWindow": int(len(context_events)),
            "TopEventTypes": top_event_types,
            "NonBenignEvents": int(len(suspicious)) if suspicious is not None else 0
        },
        "MITRE_ATTCK": [{"Technique": t, "Name": n} for t, n in mitre],
        "RecommendedNextSteps": steps
    }
    return summary