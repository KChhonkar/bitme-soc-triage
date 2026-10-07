"""Asset-aware risk engine.

All inputs are 0-100. Volume is a small weight so a handful of alerts on a
critical asset outrank a flood on guest Wi-Fi.
"""

from typing import Dict, List, Tuple


CRITICALITY_SCORE = {
    "CRITICAL": 100,
    "HIGH": 75,
    "MEDIUM": 50,
    "LOW": 25,
}  # type: Dict[str, int]

TECHNIQUE_SEVERITY = {
    "T1566": 70,
    "T1204": 70,
    "T1204.002": 70,
    "T1059": 80,
    "T1105": 60,
    "T1110": 85,
    "T1078": 90,
    "T1213": 95,
    "T1046": 20,
}  # type: Dict[str, int]

TECHNIQUE_NAMES = {
    "T1566": "Phishing",
    "T1204": "User Execution",
    "T1204.002": "Malicious File",
    "T1059": "Command and Scripting Interpreter",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1213": "Data from Information Repositories",
    "T1046": "Network Service Discovery",
}  # type: Dict[str, str]

UNKNOWN_TECHNIQUE_SEVERITY = 30


def technique_name(technique_id):
    # type: (str) -> str
    if not technique_id:
        return ""
    return TECHNIQUE_NAMES.get(technique_id, "Unknown technique")


def score_incident(criticality, technique_ids, alert_count):
    # type: (str, List[str], int) -> Tuple[int, str, Dict[str, int]]
    """Return (score, severity_label, breakdown_points).

    risk = 0.5 * criticality_score + 0.3 * technique_severity_score + 0.2 * volume_score
    """
    crit = CRITICALITY_SCORE.get(criticality, 50)
    tech = 0
    for tid in technique_ids:
        if not tid:
            continue
        tech = max(tech, TECHNIQUE_SEVERITY.get(tid, UNKNOWN_TECHNIQUE_SEVERITY))
    if not technique_ids:
        tech = UNKNOWN_TECHNIQUE_SEVERITY
    volume = min(100, int(alert_count) * 2)

    crit_pts = 0.5 * crit
    tech_pts = 0.3 * tech
    vol_pts = 0.2 * volume
    total = crit_pts + tech_pts + vol_pts
    score = int(round(total))

    if score >= 75:
        severity = "Critical"
    elif score >= 50:
        severity = "High"
    else:
        severity = "Low"

    breakdown = {
        "criticality": int(round(crit_pts)),
        "technique": int(round(tech_pts)),
        "volume": int(round(vol_pts)),
    }
    return score, severity, breakdown
