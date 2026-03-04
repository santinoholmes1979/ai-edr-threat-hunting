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

tab1, tab2, tab3 = st.tabs(["Alerts", "Hunt Explorer", "AI Triage"])

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
if st.button("Generate Incident Report"):

    report_file = generate_incident_report(alert, ctx, note)

    st.success(f"Incident report created: {report_file}")