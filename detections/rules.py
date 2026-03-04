import sys
from pathlib import Path

# Add repo root to Python path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import json
from pathlib import Path
from collections import defaultdict
from detections.scoring import load_allowlist, apply_allowlist, score_alert

DATA_FILE = Path("data/raw/events.jsonl")

def load_events():
    with DATA_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            yield json.loads(line)

def detect_encoded_powershell(events):
    alerts = []
    for e in events:
        if e.get("EventType") != "ProcessCreate":
            continue
        cmd = (e.get("Process") or {}).get("CommandLine", "") or ""
        img = (e.get("Process") or {}).get("Image", "") or ""
        if "powershell" in img.lower() and " -enc " in cmd.lower():
            alerts.append({
                "AlertType": "EncodedPowerShell",
                "Severity": "High",
                "TimeGenerated": e["TimeGenerated"],
                "DeviceName": e["DeviceName"],
                "User": e["User"],
                "Summary": "PowerShell executed with -enc (encoded command)",
                "Pivot": {"DeviceName": e["DeviceName"], "User": e["User"], "Scenario": e.get("Scenario", "")}
            })
    return alerts

def detect_password_spray(events, fail_threshold=8, window_key="SourceIP"):
    # Count failures per SourceIP (simple lab model)
    counts = defaultdict(int)
    last_event = {}
    for e in events:
        if e.get("EventType") != "Logon":
            continue
        auth = e.get("Auth") or {}
        if auth.get("LogonResult") != "Failure":
            continue
        src = auth.get("SourceIP")
        if not src:
            continue
        counts[src] += 1
        last_event[src] = e

    alerts = []
    for src, c in counts.items():
        if c >= fail_threshold:
            e = last_event[src]
            alerts.append({
                "AlertType": "PasswordSpray",
                "Severity": "High" if c >= fail_threshold + 4 else "Medium",
                "TimeGenerated": e["TimeGenerated"],
                "DeviceName": e["DeviceName"],
                "User": e["User"],
                "Summary": f"Multiple failed logons from same SourceIP ({c} failures)",
                "Pivot": {"SourceIP": src, "DeviceName": e["DeviceName"]}
            })
    return alerts

def detect_runkey_persistence(events):
    alerts = []
    for e in events:
        if e.get("EventType") != "RegistrySet":
            continue
        reg = e.get("Registry") or {}
        key = (reg.get("Key") or "").lower()
        if "currentversion\\run" in key:
            alerts.append({
                "AlertType": "RunKeyPersistence",
                "Severity": "High",
                "TimeGenerated": e["TimeGenerated"],
                "DeviceName": e["DeviceName"],
                "User": e["User"],
                "Summary": "Registry Run key modified (possible persistence)",
                "Pivot": {"DeviceName": e["DeviceName"], "User": e["User"]}
            })
    return alerts

def main():
    n, out = run_all()
    print(f"Wrote {n} alerts -> {out}")

def run_all():

    events = list(load_events())

    alerts = []
    alerts += detect_encoded_powershell(events)
    alerts += detect_password_spray(events)
    alerts += detect_runkey_persistence(events)

    alerts.sort(key=lambda a: a["TimeGenerated"], reverse=True)

    allowlist = load_allowlist()

    for a in alerts:

        conf, rationale = score_alert(a)
        a["Confidence"] = conf
        a["Rationale"] = rationale

        suppressed, reason = apply_allowlist(a, allowlist)

        a["Suppressed"] = suppressed

        if suppressed:
            a["SuppressionReason"] = reason

    out = Path("data/alerts.json")
    out.parent.mkdir(parents=True, exist_ok=True)

    out.write_text(json.dumps(alerts, indent=2), encoding="utf-8")

    return len(alerts), out

if __name__ == "__main__":
    main()