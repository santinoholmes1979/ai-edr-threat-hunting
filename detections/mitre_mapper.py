from typing import Dict, Any

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
    "EncodedPowerShell": [
        {
            "MitreTactic": "Execution",
            "MitreTechniqueID": "T1059.001",
            "MitreTechnique": "Command and Scripting Interpreter: PowerShell"
        }
    ],
    "PasswordSpray": [
        {
            "MitreTactic": "Credential Access",
            "MitreTechniqueID": "T1110.003",
            "MitreTechnique": "Brute Force: Password Spraying"
        }
    ],
    "RunKeyPersistence": [
        {
            "MitreTactic": "Persistence",
            "MitreTechniqueID": "T1547.001",
            "MitreTechnique": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"
        }
    ],
}

SCENARIO_TO_ATTACK = {
    "phishing_doc": [
        {
            "MitreTactic": "Initial Access",
            "MitreTechniqueID": "T1566",
            "MitreTechnique": "Phishing"
        }
    ],

    "encoded_powershell": [
        {
            "MitreTactic": "Execution",
            "MitreTechniqueID": "T1059.001",
            "MitreTechnique": "Command and Scripting Interpreter: PowerShell"
        }
    ],

    "password_spray": [
        {
            "MitreTactic": "Credential Access",
            "MitreTechniqueID": "T1110.003",
            "MitreTechnique": "Brute Force: Password Spraying"
        }
    ],

    "runkey_persistence": [
        {
            "MitreTactic": "Persistence",
            "MitreTechniqueID": "T1547.001",
            "MitreTechnique": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"
        }
    ],

    "discovery": [
        {
            "MitreTactic": "Discovery",
            "MitreTechniqueID": "T1082",
            "MitreTechnique": "System Information Discovery"
        }
    ],

    "c2_beacon": [
        {
            "MitreTactic": "Command and Control",
            "MitreTechniqueID": "T1071",
            "MitreTechnique": "Application Layer Protocol"
        }
    ],

    "lateral_movement": [
        {
            "MitreTactic": "Lateral Movement",
            "MitreTechniqueID": "T1021",
            "MitreTechnique": "Remote Services"
        }
    ]
}

def enrich_alert_with_mitre(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Add MITRE fields directly to a single alert based on AlertType.
    """
    alert_type = alert.get("AlertType")
    mapping = ALERTTYPE_TO_ATTACK.get(alert_type, [])

    if mapping:
        first = mapping[0]
        alert["MitreTactic"] = first["MitreTactic"]
        alert["MitreTechniqueID"] = first["MitreTechniqueID"]
        alert["MitreTechnique"] = first["MitreTechnique"]
    else:
        alert["MitreTactic"] = "Unknown"
        alert["MitreTechniqueID"] = "Unknown"
        alert["MitreTechnique"] = "Unknown"

    return alert


def build_attack_chain(alert: Dict[str, Any], ctx_df):
    chain = []

    alert_type = alert.get("AlertType")
    if alert_type in ALERTTYPE_TO_ATTACK:
        for item in ALERTTYPE_TO_ATTACK[alert_type]:
            chain.append(
                (item["MitreTactic"], item["MitreTechniqueID"], item["MitreTechnique"])
            )

    if ctx_df is not None and len(ctx_df) > 0 and "Scenario" in ctx_df.columns:
        scenarios = sorted(set([
            s for s in ctx_df["Scenario"].dropna().tolist()
            if isinstance(s, str)
        ]))
        for scenario in scenarios:
            for item in SCENARIO_TO_ATTACK.get(scenario, []):
                chain.append(
                    (item["MitreTactic"], item["MitreTechniqueID"], item["MitreTechnique"])
                )

    seen = set()
    unique_chain = []
    for item in chain:
        if item not in seen:
            unique_chain.append(item)
            seen.add(item)

    order = {t: i for i, t in enumerate(TACTIC_ORDER)}
    unique_chain.sort(key=lambda x: order.get(x[0], 999))

    return unique_chain


def chain_to_dot(chain):
    lines = [
        "digraph attack {",
        'rankdir="LR";',
        'node [shape="box", style="rounded"];'
    ]

    nodes = []
    for i, (tactic, tid, name) in enumerate(chain):
        label = f"{tactic}\\n{tid}: {name}"
        node_id = f"n{i}"
        nodes.append(node_id)
        lines.append(f'{node_id} [label="{label}"];')

    for i in range(len(nodes) - 1):
        lines.append(f"{nodes[i]} -> {nodes[i+1]};")

    lines.append("}")
    return "\n".join(lines)