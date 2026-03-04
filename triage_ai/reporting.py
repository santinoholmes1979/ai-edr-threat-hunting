import json
from pathlib import Path
from datetime import datetime


REPORT_DIR = Path("reports")


def generate_incident_report(alert, context_events, soc_note):

    REPORT_DIR.mkdir(exist_ok=True)

    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    report_file = REPORT_DIR / f"incident_report_{ts}.md"

    lines = []

    lines.append("# SOC Incident Report\n")

    lines.append("## Alert Summary\n")
    for k, v in alert.items():
        lines.append(f"- **{k}**: {v}")

    lines.append("\n## MITRE Mapping\n")
    if isinstance(soc_note, dict):
        for k, v in soc_note.items():
            lines.append(f"- **{k}**: {v}")

    lines.append("\n## Context Events\n")

    for _, row in context_events.head(20).iterrows():
        lines.append(f"- {row.get('TimeGenerated')} | {row.get('EventType')} | {row.get('DeviceName')} | {row.get('User')}")

    lines.append("\n## Recommended Actions\n")
    lines.append("- Isolate host if malicious activity confirmed")
    lines.append("- Reset compromised credentials")
    lines.append("- Review lateral movement indicators")
    lines.append("- Hunt for similar activity across environment")

    report_file.write_text("\n".join(lines), encoding="utf-8")

    return report_file