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

# MITRE ATT&CK tactic order (for heatmap display)
TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

from detections.rules import run_all as run_detections

ALLOWLIST_PATH = Path("detections/config/allowlist.json")

def ensure_allowlist():
    ALLOWLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not ALLOWLIST_PATH.exists():
        ALLOWLIST_PATH.write_text(
            json.dumps({"users": [], "devices": [], "process_names": [], "commandline_contains": []}, indent=2),
            encoding="utf-8"
        )

def add_to_allowlist(kind: str, value: str) -> bool:
    """
    kind: 'users' or 'devices'
    """
    ensure_allowlist()
    data = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    if kind not in data:
        data[kind] = []

    value = (value or "").strip()
    if not value:
        return False

    if value not in data[kind]:
        data[kind].append(value)
        data[kind] = sorted(set(data[kind]))

    ALLOWLIST_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return True

def generate_incident_report(alert, ctx, note):
    from pathlib import Path
    report_path = Path("reports/incident_report.md")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Incident Report\n\nReport generation stub.\n", encoding="utf-8")
    return report_path

from detections.rules import run_all as run_detections
from triage_ai.triage import load_events as triage_load_events, events_around, generate_soc_note
from detections.mitre_mapper import enrich_alert_with_mitre, build_attack_chain, chain_to_dot


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
ALERTS_FILE = REPO_ROOT / "outputs" / "alerts_current.json"
TRIAGE_FILE = REPO_ROOT / "outputs" / "triage.json"

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
    enriched_alerts = [enrich_alert_with_mitre(alert) for alert in alerts]
    return pd.DataFrame(enriched_alerts)

def load_triage():
    if not TRIAGE_FILE.exists():
        return {}
    return json.loads(TRIAGE_FILE.read_text())


def save_triage(data):
    TRIAGE_FILE.parent.mkdir(parents=True, exist_ok=True)
    TRIAGE_FILE.write_text(json.dumps(data, indent=2))

st.title("AI-Assisted EDR Threat Hunting (Synthetic Telemetry)")

st.sidebar.header("Lab Controls")

with st.sidebar.expander("Generate synthetic dataset", expanded=False):
    total_events = st.sidebar.number_input(
        "Benign events", min_value=1000, max_value=200000, value=20000, step=1000
    )
    injections = st.sidebar.number_input(
        "Attack injections", min_value=1, max_value=200, value=12, step=1
    )

    if st.sidebar.button("Generate + Detect", type="primary", key="btn_generate_detect"):
        with st.spinner("Generating telemetry..."):
            generate_dataset(total_events=total_events, attack_injections=injections)
        with st.spinner("Running detections..."):
            n_alerts, out = run_detections()
        st.sidebar.success(f"Done. Alerts: {n_alerts} ({out})")
        st.cache_data.clear()
        try:
            st.rerun()
        except Exception:
            pass

st.sidebar.divider()
st.sidebar.subheader("Attack Simulation")

if st.sidebar.button("Launch Adversary Campaign", key="btn_launch_campaign"):
    with st.spinner("Launching adversary campaign..."):
        generate_campaign()
    with st.spinner("Running detections..."):
        n_alerts, out = run_detections()
    st.sidebar.success(f"Campaign complete. Alerts: {n_alerts} ({out})")
    st.cache_data.clear()
    try:
        st.rerun()
    except Exception:
        pass

if st.sidebar.button("Run Full Attack Chain", type="primary", key="btn_run_attack_chain"):
    with st.spinner("Launching full attack chain..."):
        # Uses your campaign generator; if you later add multi-stage chaining,
        # this is where it will live.
        generate_campaign()
    with st.spinner("Running detections..."):
        n_alerts, out = run_detections()
    st.sidebar.success(f"Attack chain complete. Alerts: {n_alerts} ({out})")
    st.cache_data.clear()
    try:
        st.rerun()
    except Exception:
        pass

    with st.spinner("Launching simulated attack chain..."):
        events = generate_campaign()

    with st.spinner("Running detections..."):
        n_alerts, out = run_detections()

    st.sidebar.success(f"Campaign generated ({events} events). Alerts now: {n_alerts}")

    st.cache_data.clear()

from pathlib import Path
import json

ALLOWLIST_PATH = Path("detections/config/allowlist.json")

def ensure_allowlist():
    ALLOWLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not ALLOWLIST_PATH.exists():
        ALLOWLIST_PATH.write_text(
            json.dumps({"users": [], "devices": [], "process_names": [], "commandline_contains": []}, indent=2),
            encoding="utf-8"
        )

def add_to_allowlist(kind: str, value: str) -> bool:
    """
    kind: 'users' or 'devices'
    """
    ensure_allowlist()
    data = json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))
    if kind not in data:
        data[kind] = []

    value = (value or "").strip()
    if not value:
        return False

    if value not in data[kind]:
        data[kind].append(value)
        data[kind] = sorted(set(data[kind]))

    ALLOWLIST_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return True

tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs(
[
"Alerts",
"Hunt Explorer",
"AI Triage",
"ATT&CK Graph",
"Tuning",
"SOC Dashboard",
"MITRE Heatmap",
"Alert Queue"
])

with tab1:
    st.subheader("Detections / Alerts")
    st.caption("Generated locally from synthetic endpoint telemetry (EDR-style events).")

    alerts_df = load_alerts()

    if alerts_df.empty:
        st.warning("No alerts found yet. Run: python .\\detections\\rules.py")
    else:
        sev = st.multiselect(
            "Severity filter",
            sorted(alerts_df["Severity"].unique()),
            default=sorted(alerts_df["Severity"].unique())
        )

        atype = st.multiselect(
            "AlertType filter",
            sorted(alerts_df["AlertType"].unique()),
            default=sorted(alerts_df["AlertType"].unique())
        )

        filt = alerts_df[
            alerts_df["Severity"].isin(sev) &
            alerts_df["AlertType"].isin(atype)
        ]

        st.dataframe(filt, use_container_width=True)

        st.divider()

        st.subheader("Alert details")

        idx = st.number_input(
            "Row index (from table above)",
            min_value=0,
            max_value=max(len(filt)-1, 0),
            value=0
        )

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
        st.warning("No alerts available. Run: python .\\detections\\rules.py")
    else:
        alerts_df = alerts_df.reset_index(drop=True)
        sel = st.number_input(
            "Select alert index",
            min_value=0,
            max_value=len(alerts_df) - 1,
            value=0
        )
        alert = alerts_df.iloc[int(sel)].to_dict()

        minutes = st.slider(
            "Context window (minutes)",
            min_value=5,
            max_value=30,
            value=10,
            step=5
        )

        df_events = triage_load_events()
        ctx = events_around(
            df_events,
            alert.get("DeviceName"),
            alert.get("User"),
            alert.get("TimeGenerated"),
            minutes=minutes
        )

        if ctx.empty:
            st.warning("No context events found for this alert window.")
        else:
            timeline = ctx.copy()

            if "TimeGenerated_dt" in timeline.columns:
                timeline["TimeBucket"] = timeline["TimeGenerated_dt"].dt.floor("1min")
                timeline["SortTime"] = timeline["TimeGenerated_dt"]
            else:
                timeline["SortTime"] = pd.to_datetime(
                    timeline["TimeGenerated"], utc=True, errors="coerce"
                )
                timeline["TimeBucket"] = timeline["SortTime"].dt.floor("1min")

            timeline = timeline.sort_values("SortTime", ascending=True)

            st.divider()
            st.subheader("Investigation Timeline")

            timeline_display_cols = [
                col for col in [
                    "TimeGenerated",
                    "EventType",
                    "Scenario",
                    "User",
                    "DeviceName",
                    "ProcessName",
                    "CommandLine",
                    "FileName",
                    "ParentProcessName",
                    "DestinationIP"
                ] if col in timeline.columns
            ]

            st.dataframe(
                timeline[timeline_display_cols],
                use_container_width=True
            )

            st.divider()
            st.subheader("Event Activity Over Time")

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
            else:
                st.info("EventType field not available for timeline chart.")

            st.divider()
            st.subheader("Attack Progression by Scenario")

            if "Scenario" in timeline.columns and timeline["Scenario"].notna().any():
                scenario_counts = (
                    timeline.groupby("Scenario")
                    .size()
                    .reset_index(name="Events")
                    .sort_values("Events", ascending=False)
                )

                st.dataframe(scenario_counts, use_container_width=True)
            else:
                st.info("No scenario labels found in this alert context.")

            st.divider()
            st.subheader("Chronological Event Narrative")

            narrative_cols = [
                col for col in ["SortTime", "EventType", "Scenario", "User", "DeviceName", "ProcessName"]
                if col in timeline.columns
            ]

            narrative_df = timeline[narrative_cols].copy().head(25)

            for _, row in narrative_df.iterrows():
                t = row.get("SortTime")
                event_type = row.get("EventType", "UnknownEvent")
                scenario = row.get("Scenario", "UnknownScenario")
                user = row.get("User", "UnknownUser")
                device = row.get("DeviceName", "UnknownDevice")
                proc = row.get("ProcessName", "UnknownProcess")

                ts = str(t) if pd.notna(t) else "UnknownTime"

                st.markdown(
                    f"- **{ts}** — `{event_type}` | scenario=`{scenario}` | user=`{user}` | device=`{device}` | process=`{proc}`"
                )

        note = generate_soc_note(alert, ctx)

        st.divider()
        st.subheader("SOC Incident Note")
        st.json(note)

st.divider()
st.subheader("Tuning Actions (Detection Engineering)")

colA, colB, colC = st.columns([2, 2, 3])

with colA:
    if st.button("Allowlist User", key="tab3_allowlist_user"):
        u = alert.get("User")
        if add_to_allowlist("users", u):
            st.success(f"Added user to allowlist: {u}")
            n_alerts, out = run_detections()
            st.info(f"Re-ran detections. Alerts now: {n_alerts}")
            st.cache_data.clear()
        else:
            st.warning("No User found on this alert to allowlist.")

with colB:
    if st.button("Allowlist Device", key="tab3_allowlist_device"):
        d = alert.get("DeviceName")
        if add_to_allowlist("devices", d):
            st.success(f"Added device to allowlist: {d}")
            n_alerts, out = run_detections()
            st.info(f"Re-ran detections. Alerts now: {n_alerts}")
            st.cache_data.clear()
        else:
            st.warning("No DeviceName found on this alert to allowlist.")

with colC:
    st.caption("Writes to detections/config/allowlist.json and re-runs detections so future alerts can be suppressed.")

st.divider()
st.subheader("Tuning Actions (Detection Engineering)")

colA, colB, colC = st.columns([2, 2, 3])

with colA:
    if st.button("Allowlist User", key="btn_allowlist_user"):
        u = alert.get("User")
        if add_to_allowlist("users", u):
            st.success(f"Added user to allowlist: {u}")
            # re-run detections so suppression takes effect immediately
            n_alerts, out = run_detections()
            st.info(f"Re-ran detections. Alerts now: {n_alerts}")
            st.cache_data.clear()
        else:
            st.warning("No User found on this alert to allowlist.")

with colB:
    if st.button("Allowlist Device", key="btn_allowlist_device"):
        d = alert.get("DeviceName")
        if add_to_allowlist("devices", d):
            st.success(f"Added device to allowlist: {d}")
            n_alerts, out = run_detections()
            st.info(f"Re-ran detections. Alerts now: {n_alerts}")
            st.cache_data.clear()
        else:
            st.warning("No DeviceName found on this alert to allowlist.")

with colC:
    st.caption("This writes to detections/config/allowlist.json and re-runs detections so future alerts can be suppressed.")
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

st.subheader("Rule Tuning Controls")
st.caption("Adjust detection thresholds and re-run detections. Changes persist in detections/config/tuning.json.")

tuning_path = Path("detections/config/tuning.json")
tuning_path.parent.mkdir(parents=True, exist_ok=True)

if tuning_path.exists():
    tuning = json.loads(tuning_path.read_text(encoding="utf-8"))
else:
    tuning = {"password_spray_failure_threshold": 10, "encoded_powershell_min_length": 20}

thr = st.slider(
    "Password Spray failure threshold (FailureCount)",
    min_value=3,
    max_value=50,
    value=int(tuning.get("password_spray_failure_threshold", 10)),
    key="tune_pw_spray_thr"
)

if st.button("Save tuning config + Re-run detections", key="btn_save_tuning"):
    tuning["password_spray_failure_threshold"] = int(thr)
    tuning_path.write_text(json.dumps(tuning, indent=2), encoding="utf-8")
    st.success(f"Saved tuning.json (password_spray_failure_threshold={thr})")

    n_alerts, out = run_detections()
    st.info(f"Re-ran detections. Alerts now: {n_alerts}")
    st.cache_data.clear()

    alerts_df = load_alerts()
    if alerts_df.empty:
        st.warning("No alerts yet. Generate + Detect or Launch Adversary Campaign.")
    else:
        # Ensure fields exist
        if "Confidence" not in alerts_df.columns:
            alerts_df["Confidence"] = 50
        if "Suppressed" not in alerts_df.columns:
            alerts_df["Suppressed"] = False
        if "AlertType" not in alerts_df.columns:
            alerts_df["AlertType"] = "Unknown"
        if "Severity" not in alerts_df.columns:
            alerts_df["Severity"] = "Unknown"

        total = len(alerts_df)
        suppressed = int(alerts_df["Suppressed"].sum()) if alerts_df["Suppressed"].dtype != object else int((alerts_df["Suppressed"] == True).sum())
        suppression_rate = (suppressed / total) * 100 if total else 0

        c1, c2, c3 = st.columns(3)
        c1.metric("Total Alerts", total)
        c2.metric("Suppressed Alerts", suppressed)
        c3.metric("Suppression Rate", f"{suppression_rate:.1f}%")

        st.divider()

        st.subheader("Confidence Distribution")
        st.bar_chart(alerts_df["Confidence"].value_counts().sort_index())

        st.divider()

        st.subheader("Top Noisy Alert Types")
        by_type = alerts_df.groupby("AlertType").size().sort_values(ascending=False).reset_index(name="Count")
        st.dataframe(by_type, use_container_width=True)

        st.divider()

        st.subheader("Suppression Reasons (if any)")
        if "SuppressionReason" in alerts_df.columns and alerts_df["SuppressionReason"].notna().any():
            reasons = alerts_df[alerts_df["Suppressed"] == True]["SuppressionReason"].value_counts().reset_index()
            reasons.columns = ["Reason", "Count"]
            st.dataframe(reasons, use_container_width=True)
        else:
            st.info("No suppressed alerts (or no suppression reasons recorded).")

        st.divider()

        st.subheader("Quick Tuning Notes")
        st.markdown(
            "- If a single AlertType dominates, tune thresholds or add allowlist rules.\n"
            "- If confidence is mostly low, enrich detections with stronger signals.\n"
            "- Suppression should be targeted—avoid suppressing broad users/devices unless verified benign."
        )

        st.divider()

st.subheader("MITRE ATT&CK Coverage")

alerts_df = load_alerts()

if alerts_df.empty:
    st.info("No alerts available for ATT&CK coverage yet.")
else:
    coverage = (
        alerts_df.groupby(["MitreTactic", "MitreTechniqueID", "MitreTechnique"])
        .size()
        .reset_index(name="Detections")
        .sort_values(["MitreTactic", "Detections"], ascending=[True, False])
    )

    st.dataframe(coverage, use_container_width=True)

with tab7:
    st.subheader("MITRE ATT&CK Heatmap")
    st.caption("Detection coverage across ATT&CK tactics and techniques based on current alerts.")

    alerts_df = load_alerts()

    if alerts_df.empty:
        st.warning("No alerts available yet. Generate and detect activity first.")
    else:
        required_cols = ["MitreTactic", "MitreTechniqueID", "MitreTechnique"]
        for col in required_cols:
            if col not in alerts_df.columns:
                alerts_df[col] = "Unknown"

        # Remove unknowns for cleaner display
        mitre_df = alerts_df[
            (alerts_df["MitreTactic"] != "Unknown") &
            (alerts_df["MitreTechniqueID"] != "Unknown")
        ].copy()

        if mitre_df.empty:
            st.info("No mapped MITRE ATT&CK data found in current alerts.")
        else:
            st.divider()
            st.subheader("Coverage by Tactic")

            tactic_counts = (
                mitre_df.groupby("MitreTactic")
                .size()
                .reset_index(name="Detections")
                .sort_values("Detections", ascending=False)
            )

            st.dataframe(tactic_counts, use_container_width=True)
            st.bar_chart(tactic_counts.set_index("MitreTactic")["Detections"])

            st.divider()
            st.subheader("Coverage by Technique")

            technique_counts = (
                mitre_df.groupby(["MitreTechniqueID", "MitreTechnique", "MitreTactic"])
                .size()
                .reset_index(name="Detections")
                .sort_values("Detections", ascending=False)
            )

            st.dataframe(technique_counts, use_container_width=True)

            st.divider()
            st.subheader("ATT&CK Heatmap Matrix")

            heatmap_df = (
                mitre_df.groupby(["MitreTactic", "MitreTechniqueID"])
                .size()
                .reset_index(name="Count")
                .pivot(index="MitreTechniqueID", columns="MitreTactic", values="Count")
                .fillna(0)
                .astype(int)
            )

            # Ensure tactics appear in MITRE order
            heatmap_df = heatmap_df.reindex(columns=TACTIC_ORDER, fill_value=0)

            styled_heatmap = heatmap_df.style.background_gradient(
                cmap="Reds",
                axis=None
            )

            st.dataframe(styled_heatmap, use_container_width=True)

            st.divider()
            st.subheader("Analyst Notes")

            st.markdown(
                "- Higher counts may indicate stronger detection visibility for that ATT&CK area.\n"
                "- Empty tactics suggest coverage gaps or missing ATT&CK mappings.\n"
                "- As you add detections, this heatmap becomes a fast way to show threat coverage maturity."
            )

with tab8:

    st.subheader("SOC Alert Queue")

    alerts_df = load_alerts()

    if alerts_df.empty:
        st.info("No alerts available")
    else:

        triage = load_triage()

        # -----------------------------
        # DETECTION QUALITY METRICS
        # -----------------------------

        st.subheader("Detection Quality Metrics")

        if triage:

            outcomes = list(triage.values())

            tp = outcomes.count("True Positive")
            fp = outcomes.count("False Positive")
            benign = outcomes.count("Benign")
            review = outcomes.count("Needs Review")

            precision = 0
            if tp + fp > 0:
                precision = tp / (tp + fp)

            c1, c2, c3, c4 = st.columns(4)

            c1.metric("True Positives", tp)
            c2.metric("False Positives", fp)
            c3.metric("Benign Alerts", benign)
            c4.metric("Needs Review", review)

            st.metric("Detection Precision", f"{precision:.2%}")

        st.divider()

        alerts_df = alerts_df.reset_index(drop=True)
        alerts_df["AlertID"] = alerts_df.index.astype(str)

        alerts_df["Outcome"] = alerts_df["AlertID"].map(
            lambda x: triage.get(x, "Needs Review")
        )
        st.dataframe(alerts_df, use_container_width=True)

        st.divider()

        idx = st.number_input(
            "Select alert",
            min_value=0,
            max_value=len(alerts_df)-1,
            value=0
        )

        selected = alerts_df.iloc[int(idx)]

        st.json(selected.to_dict())

        outcome = st.selectbox(
            "Set outcome",
            [
                "Needs Review",
                "True Positive",
                "False Positive",
                "Benign"
            ]
        )

        if st.button("Save Decision"):

            triage[str(int(idx))] = outcome
            save_triage(triage)

            st.success("Triage saved")

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
