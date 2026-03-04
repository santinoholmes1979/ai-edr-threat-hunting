\# AI-Assisted EDR Threat Hunting Lab (Synthetic Telemetry)



A portfolio-ready cyber project that simulates \*\*EDR/endpoint telemetry\*\*, runs \*\*detection engineering rules\*\*, and provides a \*\*Streamlit investigation console\*\* with an \*\*AI-style SOC triage note\*\* (local) including \*\*MITRE ATT\&CK mapping\*\*.



> Built to demonstrate: \*\*EDR concepts, threat hunting, detection logic, triage workflows, and clean engineering practices.\*\*



---



\## What this project does



\### 1) Generates synthetic EDR telemetry

Creates realistic endpoint-style logs:

\- Process creation (parent/child relationships, command lines)

\- Network connections (domain/IP/port)

\- Authentication events (success/failure, remote logons)

\- Registry modifications (persistence patterns)

\- File creation activity



Output: `data/raw/events.jsonl`



\### 2) Runs detection engineering rules

Creates alerts from the telemetry:

\- \*\*Encoded PowerShell execution\*\* (`-enc`)

\- \*\*Password spray-style failed logons\*\*

\- \*\*Persistence via Run key modification\*\*



Output: `data/alerts.json`



\### 3) Streamlit “EDR console”

A mini investigation UI with:

\- \*\*Alerts table\*\*

\- \*\*Hunt Explorer\*\* pivots (DeviceName/User/EventType/Scenario)

\- \*\*AI Triage\*\* tab: SOC-ready incident note + MITRE mapping + next steps



---



\## Quickstart



```powershell

python -m venv venv

.\\venv\\Scripts\\activate

pip install -r requirements.txt



python .\\generator\\generate\_logs.py

python .\\detections\\rules.py

streamlit run .\\streamlit\_app\\app.py

