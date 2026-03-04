import sys
from pathlib import Path

# Ensure repo root is on PYTHONPATH
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import subprocess
from datetime import datetime
import json
import pandas as pd
import streamlit as st

from generator.campaign import generate_campaign
from generator.generate_logs import generate as generate_dataset
from detections.rules import run_all as run_detections
from triage_ai.triage import load_events as triage_load_events, events_around, generate_soc_note
from triage_ai.reporting import generate_incident_report

# -----------------------------
# MITRE ATT&CK helpers
# -----------------------------
TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Credential Access",
    "Persistence",
    "Discovery",
    "Defense Evasion",
    "Command and Control",
    "Lateral Movement",
    "Exfiltration",
]

ALERTTYPE_TO_ATTACK = {
    "EncodedPowerShell": [("Execution", "T1059.001", "PowerShell")],
    "PasswordSpray": [("Credential Access", "T1110", "Brute Force (Password Spraying)")],
    "RunKeyPersistence": [("Persistence", "T1547.001", "Registry Run Keys/Startup Folder")],
}

SCENARIO_TO_ATTACK = {
    "phishing_doc": [("Initial Access", "T1566", "Phishing")],
    "encoded_powershell": [("Execution", "T1059.001", "PowerShell")],
    "password_spray": [("Credential Access", "T1110", "Brute Force")],
    "runkey_persistence": [("Persistence", "T1547.001", "Registry Run Keys/Startup Folder")],
}

def build_attack_chain(alert: dict, ctx_df):
    chain = []

    # 1) from AlertType
    atype = alert.get("AlertType")
    if atype in ALERTTYPE_TO_ATTACK:
        chain += ALERTTYPE_TO_ATTACK[atype]

    # 2) from scenarios found in context events
    if ctx_df is not None and len(ctx_df) > 0 and "Scenario" in ctx_df.columns:
        scenarios = sorted(set([s for s in ctx_df["Scenario"].dropna().tolist() if isinstance(s, str)]))
        for s in scenarios:
            chain += SCENARIO_TO_ATTACK.get(s, [])

    # de-dupe while preserving order
    seen = set()
    uniq = []
    for item in chain:
        if item not in seen:
            uniq.append(item)
            seen.add(item)

    # sort by tactic order (preserve within-tactic sequence)
    order = {t: i for i, t in enumerate(TACTIC_ORDER)}
    uniq.sort(key=lambda x: order.get(x[0], 999))

    return uniq

def chain_to_dot(chain):
    # DOT string for st.graphviz_chart
    lines = [
        "digraph attack {",
        'rankdir="LR";',
        'node [shape="box", style="rounded"];'
    ]

    # Create tactic nodes (group techniques under tactics visually)
    # We'll render each step as "Tactic\nTechniqueID: Name"
    nodes = []
    for i, (tactic, tid, name) in enumerate(chain):
        label = f"{tactic}\\n{tid}: {name}"
        node_id = f"n{i}"
        nodes.append(node_id)
        lines.append(f'{node_id} [label="{label}"];')

    # Connect sequentially
    for i in range(len(nodes) - 1):
        lines.append(f"{nodes[i]} -> {nodes[i+1]};")

    lines.append("}")
    return "\n".join(lines)

EVENTS_FILE = Path("data/raw/events.jsonl")
ALERTS_FILE = Path("data/alerts.json")

st.set_page_config(page_title="AI EDR Threat Hunting Lab", layout="wide")

@st.cache_data
def load_events(limit=50000):
    rows = []
    with EVENTS_FILE.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i >= limit:
                break
            rows.append(json.loads(line))
    df = pd.json_normalize(rows)
    return df

@st.cache_data
def load_alerts():
    if not ALERTS_FILE.exists():
        return pd.DataFrame()
    alerts = json.loads(ALERTS_FILE.read_text(encoding="utf-8"))
    return pd.DataFrame(alerts)

st.title("AI-Assisted EDR Threat Hunting (Synthetic Telemetry)")

st.sidebar.header("Lab Controls")

with st.sidebar.expander("Generate synthetic dataset", expanded=False):
    total_events = st.sidebar.number_input("Benign events", min_value=1000, max_value=200000, value=20000, step=1000)
    injections = st.sidebar.number_input("Attack injections", min_value=1, max_value=200, value=12, step=1)

    if st.sidebar.button("Generate + Detect", type="primary"):
        with st.spinner("Generating telemetry..."):
            generate_dataset(total_events=total_events, attack_injections=injections)
        with st.spinner("Running detections..."):
            n_alerts, out = run_detections()
        st.sidebar.success(f"Done. Alerts: {n_alerts} ({out})")
        st.cache_data.clear()
        # Rerun (Streamlit version compatibility)
if st.sidebar.button("Launch Adversary Campaign"):

    with st.spinner("Launching simulated attack chain..."):
        events = generate_campaign()

    with st.spinner("Running detections..."):
        n_alerts, out = run_detections()

    st.sidebar.success(f"Campaign generated ({events} events). Alerts now: {n_alerts}")

    st.cache_data.clear()

tab1, tab2, tab3, tab4 = st.tabs(["Alerts", "Hunt Explorer", "AI Triage", "ATT&CK Graph"])

with tab1:
    st.subheader("Detections / Alerts")
    st.caption("Generated locally from synthetic endpoint telemetry (EDR-style events).")

    alerts_df = load_alerts()
    if alerts_df.empty:
        st.warning("No alerts found yet. Run:  python .\\detections\\rules.py")
    else:
        sev = st.multiselect("Severity filter", sorted(alerts_df["Severity"].unique()), default=sorted(alerts_df["Severity"].unique()))
        atype = st.multiselect("AlertType filter", sorted(alerts_df["AlertType"].unique()), default=sorted(alerts_df["AlertType"].unique()))
        filt = alerts_df[alerts_df["Severity"].isin(sev) & alerts_df["AlertType"].isin(atype)]
        st.dataframe(filt, use_container_width=True)

        st.divider()
        st.subheader("Alert details")
        idx = st.number_input("Row index (from table above)", min_value=0, max_value=max(len(filt)-1, 0), value=0)
        if len(filt) > 0:
            row = filt.iloc[int(idx)].to_dict()
            st.json(row)

with tab2:
    st.subheader("Hunt Explorer (KQL-style pivots)")
    df = load_events()

    st.caption("Tip: start with a DeviceName or User pivot, then narrow by EventType/Scenario.")
    colA, colB, colC = st.columns(3)
    with colA:
        device = st.selectbox("DeviceName", ["(any)"] + sorted(df["DeviceName"].dropna().unique().tolist()))
    with colB:
        user = st.selectbox("User", ["(any)"] + sorted(df["User"].dropna().unique().tolist()))
    with colC:
        etype = st.selectbox("EventType", ["(any)"] + sorted(df["EventType"].dropna().unique().tolist()))

    scenario = st.selectbox("Scenario", ["(any)"] + sorted(df.get("Scenario", pd.Series()).dropna().unique().tolist()))

    q = df.copy()
    if device != "(any)":
        q = q[q["DeviceName"] == device]
    if user != "(any)":
        q = q[q["User"] == user]
    if etype != "(any)":
        q = q[q["EventType"] == etype]
    if scenario != "(any)":
        q = q[q["Scenario"] == scenario]

    q = q.sort_values("TimeGenerated", ascending=False).head(2000)
    st.write(f"Showing {len(q)} most recent matching events (max 2000).")
    st.dataframe(q, use_container_width=True)

with tab3:
    st.subheader("AI Triage (Local)")
    st.caption("Generates a SOC-style incident note and MITRE mapping for a selected alert.")

    alerts_df = load_alerts()
    if alerts_df.empty:
        st.warning("No alerts available. Run:  python .\\detections\\rules.py")
    else:
        alerts_df = alerts_df.reset_index(drop=True)
        sel = st.number_input("Select alert index", min_value=0, max_value=len(alerts_df)-1, value=0)
        alert = alerts_df.iloc[int(sel)].to_dict()

        minutes = st.slider("Context window (minutes)", min_value=5, max_value=30, value=10, step=5)

        # load events for triage
        df_events = triage_load_events()
        ctx = events_around(
            df_events,
            alert.get("DeviceName"),
            alert.get("User"),
            alert.get("TimeGenerated"),
            minutes=minutes
        )

        st.write(f"Context events found: {len(ctx)}")

        st.dataframe(
            ctx.sort_values("TimeGenerated", ascending=False).head(200),
            use_container_width=True
        )

        # -----------------------------
        # INCIDENT TIMELINE (NEW)
        # -----------------------------

        st.subheader("Incident Timeline")

        timeline = ctx.copy()

        if "TimeGenerated_dt" in timeline.columns:
            timeline["TimeBucket"] = timeline["TimeGenerated_dt"].dt.floor("1min")
        else:
            timeline["TimeBucket"] = pd.to_datetime(
                timeline["TimeGenerated"], utc=True, errors="coerce"
            ).dt.floor("1min")

        if "EventType" in timeline.columns:

            counts = (
                timeline.groupby(["TimeBucket", "EventType"])
                .size()
                .reset_index(name="Count")
            )

            pivot = (
                counts.pivot(index="TimeBucket", columns="EventType", values="Count")
                .fillna(0)
            )

            st.line_chart(pivot)

        # -----------------------------

        st.divider()

        note = generate_soc_note(alert, ctx)

        st.subheader("SOC Incident Note")
        st.json(note)
# --- Report generation + export ---
# --- Report generation + export ---
if "last_report_path" not in st.session_state:
    st.session_state.last_report_path = None

with tab4:
    st.subheader("MITRE ATT&CK Graph")
    st.caption("Visualizes the inferred attack chain from the selected alert + context telemetry.")

    alerts_df = load_alerts()
    if alerts_df.empty:
        st.warning("No alerts available yet. Generate + Detect or Launch Adversary Campaign.")
    else:
        alerts_df = alerts_df.reset_index(drop=True)

        sel = st.number_input(
            "Select alert index (from alerts.json)",
            min_value=0,
            max_value=len(alerts_df)-1,
            value=0,
            key="attack_graph_alert_idx"
        )
        alert = alerts_df.iloc[int(sel)].to_dict()

        minutes = st.slider(
            "Context window (minutes)",
            min_value=5,
            max_value=30,
            value=10,
            step=5,
            key="attack_graph_minutes"
        )

        # load events and build context
        df_events = triage_load_events()
        ctx = events_around(
            df_events,
            alert.get("DeviceName"),
            alert.get("User"),
            alert.get("TimeGenerated"),
            minutes=minutes
        )

        chain = build_attack_chain(alert, ctx)

        if not chain:
            st.info("No ATT&CK techniques inferred yet. (Check AlertType/Scenario mappings.)")
        else:
            # Table view
            import pandas as pd
            chain_df = pd.DataFrame(chain, columns=["Tactic", "TechniqueID", "Technique"])
            st.dataframe(chain_df, use_container_width=True)

            st.divider()

            # Graph view
            dot = chain_to_dot(chain)
            st.graphviz_chart(dot, use_container_width=True)

            st.divider()
            st.caption("Tip: add more mappings in ALERTTYPE_TO_ATTACK and SCENARIO_TO_ATTACK as you expand detections.")

col1, col2 = st.columns([1, 2])

with col1:
    if st.button("Generate Incident Report", key="btn_gen_report"):
        report_file = generate_incident_report(alert, ctx, note)
        st.session_state.last_report_path = str(report_file)
        st.success(f"Incident report created: {report_file}")

with col2:
    if st.session_state.last_report_path:
        from pathlib import Path
        p = Path(st.session_state.last_report_path)

        if p.exists():
            report_bytes = p.read_bytes()
            st.download_button(
                label="Download Report (.md)",
                data=report_bytes,
                file_name=p.name,
                mime="text/markdown",
                key="btn_dl_report"
            )
        else:
            st.warning("Last report file not found on disk. Generate a new report.")
# --- end report export ---