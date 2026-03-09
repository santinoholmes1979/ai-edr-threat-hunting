import sys
from pathlib import Path

# Add repo root to Python path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import json
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

        cmd = (e.get("CommandLine") or "")
        proc = (e.get("ProcessName") or "")

        if "powershell" in proc.lower() and "-enc" in cmd.lower():
            alerts.append({
                "AlertType": "EncodedPowerShell",
                "Severity": "High",
                "TimeGenerated": e["TimeGenerated"],
                "DeviceName": e["DeviceName"],
                "User": e["User"],
                "ProcessName": proc,
                "CommandLine": cmd,
                "Summary": "PowerShell executed with -enc (encoded command)",
                "Pivot": {
                    "DeviceName": e["DeviceName"],
                    "User": e["User"],
                    "Scenario": e.get("Scenario", "")
                }
            })

    return alerts


def detect_password_spray(events, fail_threshold=8):
    alerts = []

    for e in events:
        if e.get("EventType") != "AuthenticationFailure":
            continue

        failure_count = int(e.get("FailureCount", 0))

        if failure_count >= fail_threshold:
            alerts.append({
                "AlertType": "PasswordSpray",
                "Severity": "High" if failure_count >= fail_threshold + 4 else "Medium",
                "TimeGenerated": e["TimeGenerated"],
                "DeviceName": e["DeviceName"],
                "User": e["User"],
                "FailureCount": failure_count,
                "SourceDevice": e.get("SourceDevice", ""),
                "DestinationIP": e.get("DestinationIP", ""),
                "Summary": f"Multiple failed logons detected ({failure_count} failures)",
                "Pivot": {
                    "DeviceName": e["DeviceName"],
                    "User": e["User"],
                    "SourceDevice": e.get("SourceDevice", ""),
                    "DestinationIP": e.get("DestinationIP", ""),
                    "Scenario": e.get("Scenario", "")
                }
            })

    return alerts


def detect_runkey_persistence(events):
    alerts = []

    for e in events:
        if e.get("EventType") != "RegistryModification":
            continue

        reg_path = (e.get("RegistryPath") or "")

        if "currentversion\\run" in reg_path.lower():
            alerts.append({
                "AlertType": "RunKeyPersistence",
                "Severity": "High",
                "TimeGenerated": e["TimeGenerated"],
                "DeviceName": e["DeviceName"],
                "User": e["User"],
                "ProcessName": e.get("ProcessName", ""),
                "ParentProcessName": e.get("ParentProcessName", ""),
                "RegistryPath": reg_path,
                "Summary": "Registry Run key modified (possible persistence)",
                "Pivot": {
                    "DeviceName": e["DeviceName"],
                    "User": e["User"],
                    "Scenario": e.get("Scenario", "")
                }
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

    REPO_ROOT = Path(__file__).resolve().parents[1]
    out = REPO_ROOT / "outputs" / "alerts_current.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(alerts, indent=2), encoding="utf-8")

    return len(alerts), out


if __name__ == "__main__":
    main()