AI-Assisted EDR Threat Hunting & Detection Engineering Lab

This project simulates a modern Security Operations Center (SOC) environment focused on endpoint detection, threat hunting, and detection engineering workflows.

The platform generates synthetic endpoint telemetry, runs detection rules aligned with the MITRE ATT&CK framework, and provides an investigation interface for analysts to triage alerts and investigate attack activity.

The goal of this project is to demonstrate how detection logic, adversary simulation, and analyst workflows interact in a realistic SOC environment.

Built to demonstrate: EDR concepts, threat hunting, detection engineering, SOC triage workflows, and clean Python security tooling.

What This Project Does
1. Generates Synthetic EDR Telemetry

Creates realistic endpoint-style events including:

Process creation (parent/child relationships, command lines)

Network connections (domain / IP / port)

Authentication events (success / failure, remote logons)

Registry modifications (persistence patterns)

File creation activity

Output file:

data/raw/events.jsonl

This dataset simulates the type of telemetry typically ingested by EDR platforms.

2. Detection Engineering Rules

The platform runs detection rules that generate alerts from the telemetry.

Current detections include:

Detection	MITRE Technique
Encoded PowerShell execution	T1059 – Command Execution
Password spray behavior	T1110 – Brute Force
Registry Run Key persistence	T1547 – Boot or Logon Autostart

Alerts are written to:

data/alerts.json

Each alert includes:

severity

detection type

confidence score

contextual metadata

3. Streamlit "EDR Console"

A lightweight investigation interface simulating an analyst workflow.

Alerts Tab

Displays generated detections with filtering and inspection capabilities.

Hunt Explorer

Allows analysts to pivot across telemetry fields including:

DeviceName

User

EventType

Scenario

This mimics threat hunting workflows in real SOC environments.

AI Triage

For a selected alert, the platform generates:

contextual event timeline

SOC-style incident note

MITRE ATT&CK mapping

investigation guidance

Detection Engineering Capabilities

This project demonstrates realistic detection tuning workflows used in modern SOC environments.

Alert Confidence Scoring

Alerts are assigned a confidence score based on rule logic and context.

Allowlisting / Suppression

Analysts can suppress alerts for:

known users

known devices

benign processes

Detection Threshold Tuning

Detection thresholds can be adjusted dynamically through a configuration file:

detections/config/tuning.json
Adversary Campaign Simulation

The platform can simulate a realistic attack chain:

Password spray
→ PowerShell execution
→ Persistence via registry Run key

Detections trigger across the attack chain, allowing analysts to observe how alerts correlate during an investigation.

MITRE ATT&CK Coverage

The system maps detections to ATT&CK techniques and visualizes detection coverage.

Current coverage includes:

T1059 – Command Execution

T1110 – Brute Force

T1547 – Persistence

Technology Stack

Python

Streamlit

Pandas

Synthetic telemetry generation

MITRE ATT&CK framework

Quickstart
python -m venv venv
.\venv\Scripts\activate

pip install -r requirements.txt

python .\generator\generate_logs.py
python .\detections\rules.py

streamlit run .\streamlit_app\app.py
Author

Ryan Holmes
B.S. Security & Risk Analysis – Penn State
Focus: Detection Engineering, Threat Hunting, AI-assisted Security Tooling
