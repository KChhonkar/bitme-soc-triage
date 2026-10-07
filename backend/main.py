"""
BitMe API — synthetic alert replay + real correlation, scoring, briefs, audit.

Run (from this directory, with the venv active):

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    cp .env.example .env   # then paste GEMINI_API_KEY
    uvicorn main:app --port 8000
"""

import os
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import audit
from correlate import build_id_map, correlate, load_alerts
import random
from datetime import timedelta

import pandas as pd

import llm
from llm import draft_prevention, gemini_configured, summarize

HERE = os.path.dirname(os.path.abspath(__file__))
CSV_PATH = os.path.join(HERE, "raw_alerts.csv")

app = FastAPI(title="BitMe")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STATE = {
    "df": None,
    "id_map": None,
}  # type: Dict[str, Any]


class DecisionBody(BaseModel):
    decision: str
    note: Optional[str] = None
    brief: Optional[str] = None


def _status_from_logs(incident_id, logs):
    # type: (str, List[Dict[str, Any]]) -> str
    last = None
    for row in logs:
        if row.get("incident") == incident_id and row.get("decision"):
            last = row
    if last is None:
        return "New"
    if last.get("action", "").startswith("Rule executed"):
        return "Contained"
    if last["decision"] == "Rejected":
        return "Closed"
    if last["decision"] in ("Approved", "Modified"):
        return "Reviewed"
    return "New"


def _with_status(incident, logs):
    # type: (Dict[str, Any], List[Dict[str, Any]]) -> Dict[str, Any]
    out = dict(incident)
    out["status"] = _status_from_logs(incident.get("id") or "", logs)
    return out


def _public_incident(incident, include_alerts=False):
    # type: (Dict[str, Any], bool) -> Dict[str, Any]
    payload = dict(incident)
    if not include_alerts:
        payload = dict(payload)
        payload.pop("alerts", None)
    return payload


def _find_incident(upto, incident_id):
    # type: (int, str) -> Dict[str, Any]
    df = STATE["df"]
    found = None
    for inc in correlate(df, upto, STATE["id_map"]):
        if inc.get("id") == incident_id:
            found = inc
            break
    if found is None:
        raise HTTPException(status_code=404, detail="Incident not found at this replay position")
    return found


@app.on_event("startup")
def startup():
    df = load_alerts(CSV_PATH)
    STATE["df"] = df
    STATE["id_map"] = build_id_map(df)


@app.get("/api/health")
def health():
    df = STATE["df"]
    n = 0 if df is None else int(len(df))
    return {
        "status": "ok",
        "alerts_loaded": n,
        "gemini_configured": gemini_configured(),
        "ai_error": llm.LAST_ERROR["msg"],
    }


@app.get("/api/alerts")
def alerts():
    df = STATE["df"]
    rows = []  # type: List[Dict[str, Any]]
    for record in df.to_dict("records"):
        mitre = str(record.get("mitre_technique_id") or "").strip()
        ts = record["timestamp"]
        ts_s = ts.strftime("%Y-%m-%dT%H:%M:%S")
        rows.append(
            {
                "i": int(record["i"]),
                "ts": ts_s,
                "asset": str(record["asset_name"]),
                "desc": str(record["event_description"]),
                "mitre": mitre,
                "sev": str(record["raw_severity"]),
            }
        )
    return rows


@app.get("/api/incidents")
def incidents(upto: int = Query(0)):
    df = STATE["df"]
    n = max(0, min(int(upto), len(df)))
    logs = audit.read_all()
    items = correlate(df, n, STATE["id_map"])
    alerts_in = sum(inc["alert_count"] for inc in items)
    if n == 0:
        noise = 0
    else:
        noise = int(round(100.0 * (n - alerts_in) / float(n)))
    decorated = [_with_status(inc, logs) for inc in items]
    decorated.sort(key=lambda inc: inc["score"], reverse=True)
    # Open = not Closed. Awaiting = open minus decided (still New).
    awaiting = sum(1 for inc in decorated if inc["status"] == "New")
    open_count = awaiting
    return {
        "incidents": [_public_incident(inc, include_alerts=False) for inc in decorated],
        "stats": {
            "alerts_received": n,
            "alerts_in_incidents": alerts_in,
            "handled": len(decorated) - awaiting,
            "noise_suppressed_pct": noise,
            "incidents_open": open_count,
            "awaiting_decision": awaiting,
        },
    }


@app.get("/api/incidents/{incident_id}")
def incident_detail(incident_id: str, upto: int = Query(3000)):
    logs = audit.read_all()
    inc = _with_status(_find_incident(int(upto), incident_id), logs)
    return _public_incident(inc, include_alerts=True)


@app.post("/api/incidents/{incident_id}/summarize")
def incident_summarize(incident_id: str, upto: int = Query(3000)):
    inc = _find_incident(int(upto), incident_id)
    return summarize(inc)


@app.post("/api/incidents/{incident_id}/prevention")
def incident_prevention(incident_id: str, upto: int = Query(3000)):
    inc = _find_incident(int(upto), incident_id)
    return draft_prevention(inc)


@app.post("/api/incidents/{incident_id}/decision")
def incident_decision(incident_id: str, body: DecisionBody):
    if body.decision not in ("Approved", "Modified", "Rejected"):
        raise HTTPException(status_code=400, detail="decision must be Approved, Modified, or Rejected")
    note = body.note or ""
    if body.brief:
        note = (note + " | " if note else "") + body.brief
    if body.decision == "Approved":
        action = "Decision recorded"
    elif body.decision == "Modified":
        action = "Brief updated"
    else:
        action = "Incident closed"
    audit.append(
        {
            "incident": incident_id,
            "decision": body.decision,
            "action": action,
            "note": note,
        }
    )
    logs = audit.read_all()
    return {"status": _status_from_logs(incident_id, logs)}


@app.post("/api/incidents/{incident_id}/execute")
def incident_execute(incident_id: str, upto: int = Query(3000)):
    # Simulated: executes nothing against any real system.
    inc = _find_incident(int(upto), incident_id)
    asset = inc["asset"]
    ip = inc["likely_attacker"]
    audit.append(
        {
            "incident": incident_id,
            "decision": "Approved",
            "action": "Rule executed (simulated)",
            "note": "{} isolated; {} blocked".format(asset, ip),
        }
    )
    return {
        "message": "Rule executed: {} isolated, {} blocked".format(asset, ip),
        "note": "Simulated for demo, no live systems touched",
    }


@app.get("/api/audit")
def audit_log():
    rows = list(reversed(audit.read_all()))
    return rows


SCENARIOS = [
    ("PAY-API-01", [("Phishing email delivered to payments engineer", "T1566", "HIGH"),
                    ("Macro spawned PowerShell on workstation", "T1059", "HIGH"),
                    ("Repeated failed API admin logins", "T1110", "HIGH"),
                    ("Valid service account used from new host", "T1078", "CRITICAL"),
                    ("Bulk read of payment records", "T1213", "CRITICAL")]),
    ("HR-DB-02", [("Failed logins burst on HR database", "T1110", "HIGH"),
                  ("Service account login from unusual host", "T1078", "HIGH"),
                  ("Large query over employee table", "T1213", "CRITICAL")]),
    ("Mail-Server-02", [("Malicious attachment delivered", "T1566", "HIGH"),
                        ("User opened attachment, script launched", "T1204", "HIGH"),
                        ("Second-stage download from rare domain", "T1105", "MEDIUM")]),
]


@app.post("/api/inject")
def inject():
    """Append a fresh multi-stage attack to the end of the stream (live generation)."""
    df = STATE["df"]
    asset, steps = SCENARIOS[len(df) % 3]
    start = df["timestamp"].max() + timedelta(minutes=25)
    src = "10.10.{}.{}".format(random.randint(20, 90), random.randint(2, 250))
    rows = []
    for k in range(10):
        desc, mitre, sev = steps[k % len(steps)]
        rows.append({
            "timestamp": start + timedelta(seconds=20 * k),
            "source_ip": src, "destination_ip": "10.0.{}.{}".format(random.randint(1, 9), random.randint(2, 250)),
            "asset_name": asset, "event_description": desc,
            "mitre_technique_id": mitre, "raw_severity": sev,
        })
    new = pd.DataFrame(rows)
    df2 = pd.concat([df.drop(columns=["i"]), new], ignore_index=True).sort_values("timestamp").reset_index(drop=True)
    df2["i"] = df2.index
    STATE["df"] = df2
    STATE["id_map"] = build_id_map(df2)
    return {"asset": asset, "alerts_loaded": int(len(df2))}
