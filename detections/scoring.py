import json
from pathlib import Path

ALLOWLIST_PATH = Path("detections/config/allowlist.json")

BASE_CONFIDENCE = {
    "EncodedPowerShell": 80,
    "PasswordSpray": 75,
    "RunKeyPersistence": 85
}

def load_allowlist():
    if not ALLOWLIST_PATH.exists():
        return {"users": [], "devices": [], "process_names": [], "commandline_contains": []}

    return json.loads(ALLOWLIST_PATH.read_text())


def apply_allowlist(alert, allowlist):

    user = alert.get("User")
    device = alert.get("DeviceName")
    proc = alert.get("ProcessName")
    cmd = alert.get("CommandLine", "")

    if user in allowlist["users"]:
        return True, f"Allowlisted user {user}"

    if device in allowlist["devices"]:
        return True, f"Allowlisted device {device}"

    if proc in allowlist["process_names"]:
        return True, f"Allowlisted process {proc}"

    for s in allowlist["commandline_contains"]:
        if s.lower() in cmd.lower():
            return True, f"Allowlisted command fragment {s}"

    return False, ""


def score_alert(alert):

    atype = alert.get("AlertType", "")
    score = BASE_CONFIDENCE.get(atype, 50)

    rationale = []

    if atype == "EncodedPowerShell":
        rationale.append("Encoded command detected")

    if atype == "PasswordSpray":
        rationale.append("Multiple authentication failures")

    if atype == "RunKeyPersistence":
        rationale.append("Registry persistence mechanism")

    return score, rationale