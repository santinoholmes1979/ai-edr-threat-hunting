# AI-Assisted EDR Threat Hunting Lab

An AI-assisted SOC and detection engineering lab built in **Python** and **Streamlit**.  
This project simulates endpoint telemetry, generates adversary activity, applies custom detection rules, maps detections to **MITRE ATT&CK**, and provides a SOC-style dashboard for investigation, triage, and coverage analysis.

---

# Why I Built This

I built this project to demonstrate practical **blue-team and detection engineering skills** in a hands-on environment.

The goal was to create a **mini SOC lab** that shows how telemetry, detections, investigation, MITRE ATT&CK mapping, analyst workflow, and detection coverage metrics fit together in a realistic security pipeline.

---

# Core Capabilities

- Synthetic endpoint telemetry generation
- Adversary campaign simulation
- Custom detection rules for:
  - Encoded PowerShell
  - Password spraying
  - Run key persistence
  - Discovery activity
  - Command-and-control beaconing
  - Lateral movement
- Alert scoring and allowlist suppression
- MITRE ATT&CK enrichment and attack chain visualization
- Investigation timeline and event activity analysis
- SOC alert queue with analyst triage outcomes
- Detection coverage heatmap and coverage score
- AI-assisted SOC incident note generation

---

# Architecture

Alerts dashboard

Investigation timeline

ATT&CK graph

MITRE heatmap

Alert queue / analyst triage

How to run
1. Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate

2. Install dependencies
pip install -r requirements.txt

3. Generate attack activity and detections
python -c "from generator.campaign import generate_campaign; print(generate_campaign())"
python .\detections\rules.py

4. Run the dashboard
python -m streamlit run .\streamlit_app\app.py

What this project demonstrates

This project demonstrates practical skills in:

Detection engineering

Security telemetry analysis

SOC triage workflow

MITRE ATT&CK mapping

Investigation timeline analysis

Python-based security automation

Dashboard-driven security operations

AI-assisted cyber analysis

Future improvements

Additional ATT&CK techniques and detections

More realistic beaconing and lateral movement telemetry

Alert deduplication and correlation logic

Detection quality trending over time

Exportable reports and case management workflow

Author

Ryan Holmes
Security / Cyber / AI-focused portfolio project


---

# 3. Add a `requirements.txt`

Open:

```powershell
notepad .\requirements.txt

streamlit
pandas
matplotlib
plotly
