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

TUNING_PATH = Path("detections/config/tuning.json")

def load_tuning():
    if not TUNING_PATH.exists():
        return {
            "password_spray_failure_threshold": 10,
            "encoded_powershell_min_length": 20
        }
    return json.loads(TUNING_PATH.read_text(encoding="utf-8"))


def score_alert(alert):

    atype = alert.get("AlertType", "")
    score = BASE_CONFIDENCE.get(atype, 50)

    rationale = []

    tuning = load_tuning()

    # Encoded PowerShell logic
    if atype == "EncodedPowerShell":
        rationale.append("Encoded command detected")

    # Password Spray detection tuning
    if atype == "PasswordSpray":

        thr = int(tuning.get("password_spray_failure_threshold", 10))

        fails = alert.get("FailureCount")

        if isinstance(fails, int):

            if fails >= thr * 2:
                score += 10
                rationale.append(f"FailureCount={fails} greatly exceeds threshold={thr}")

            elif fails >= thr:
                score += 5
                rationale.append(f"FailureCount={fails} meets threshold={thr}")

            else:
                score -= 10
                rationale.append(f"FailureCount={fails} below threshold={thr}")

    # Persistence detection
    if atype == "RunKeyPersistence":
        rationale.append("Registry persistence mechanism")

    return score, rationale