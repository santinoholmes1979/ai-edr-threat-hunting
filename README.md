![Python](https://img.shields.io/badge/Python-3.10+-blue)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-orange)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-green)

# AI-Assisted EDR Threat Hunting & Detection Engineering Lab

An AI-assisted SOC and detection engineering lab built in **Python and Streamlit**.

This project simulates endpoint telemetry, generates adversary activity, applies custom detection rules, maps detections to **MITRE ATT&CK**, and provides a **SOC-style investigation dashboard**.

The goal is to demonstrate how modern **detection engineering pipelines convert raw telemetry into actionable SOC investigations.**

---

# Project Demo

This project simulates a full SOC detection engineering pipeline.

## 1. Generate adversary activity

```bash
python -c "from generator.campaign import generate_campaign; print(generate_campaign())"
2. Run detection rules
python .\detections\rules.py
3. Launch the SOC dashboard
python -m streamlit run .\streamlit_app\app.py
Core Capabilities

Synthetic endpoint telemetry generation
Adversary campaign simulation

Custom detection rules for:

Encoded PowerShell execution

Password spraying

Registry run key persistence

Discovery activity

Command-and-control beaconing

Lateral movement

Additional SOC capabilities:

Alert scoring and allowlist suppression

MITRE ATT&CK enrichment and attack chain visualization

Investigation timeline analysis

SOC alert queue with analyst triage outcomes

Detection coverage heatmap and ATT&CK coverage scoring

AI-assisted SOC incident note generation

SOC Workflow Modeled

The platform simulates a realistic SOC analyst investigation workflow:

Endpoint telemetry generation

Detection rule execution

Alert scoring and suppression

MITRE ATT&CK enrichment

Investigation timeline analysis

Analyst triage and disposition

Detection coverage measurement

Architecture
Adversary Campaign Generator
        ↓
Synthetic Telemetry (events.jsonl)
        ↓
Detection Rules Engine
        ↓
Alert Scoring / Suppression
        ↓
MITRE ATT&CK Enrichment
        ↓
SOC Dashboard (Streamlit)
        ↓
Investigation Timeline + Alert Queue + Heatmap
Repository Structure
ai-edr-threat-hunting/
├── data/
│   └── raw/
│       └── events.jsonl
├── detections/
│   ├── rules.py
│   ├── scoring.py
│   └── mitre_mapper.py
├── generator/
│   ├── campaign.py
│   └── generate_logs.py
├── triage_ai/
│   └── triage.py
├── streamlit_app/
│   └── app.py
├── outputs/
├── reports/
├── docs/
│   └── screenshots/
├── requirements.txt
└── README.md
MITRE ATT&CK Coverage

This lab currently simulates and detects attacker activity across several MITRE ATT&CK tactics.

Tactic	Technique	Description
Initial Access	T1566	Phishing document execution
Execution	T1059.001	Encoded PowerShell execution
Discovery	T1087	Account discovery
Credential Access	T1110.003	Password spray
Command & Control	T1071	C2 beaconing
Lateral Movement	T1021	Remote service lateral movement
Persistence	T1547.001	Registry run key persistence
Example Adversary Chain

The simulated attack chain includes:

Phishing document opened

Encoded PowerShell execution

Local discovery activity

Password spray against domain resources

Command-and-control beacon

Lateral movement between hosts

Registry run key persistence

The SOC dashboard correlates these events into an investigation timeline and ATT&CK attack chain graph.

Screenshots
Alerts Dashboard

Investigation Timeline

ATT&CK Graph

MITRE Heatmap

SOC Alert Queue

How to Run
1. Create virtual environment
python -m venv venv
.\venv\Scripts\activate
2. Install dependencies
pip install -r requirements.txt
3. Generate attack activity and detections
python -c "from generator.campaign import generate_campaign; print(generate_campaign())"
python .\detections\rules.py
4. Launch the SOC dashboard
python -m streamlit run .\streamlit_app\app.py
Skills Demonstrated

This project demonstrates practical skills in:

Detection engineering

Security telemetry analysis

SOC triage workflow

MITRE ATT&CK mapping

Investigation timeline analysis

Python security automation

Threat hunting techniques

Security operations dashboards

AI-assisted cyber analysis

Future Improvements

Additional ATT&CK techniques and detections

Improved beaconing simulation

Detection correlation and alert deduplication

Detection performance metrics

Case management workflow

Exportable SOC investigation reports

Author

Ryan Holmes

Cybersecurity | Detection Engineering | Security Operations

LinkedIn
https://www.linkedin.com/in/ryan-holmes-62378a254

GitHub
https://github.com/santinoholmes1979