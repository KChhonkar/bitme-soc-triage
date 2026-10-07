"""Append-only analyst audit log (JSONL). Starts empty — no fabricated history."""

import json
import os
from datetime import datetime
from typing import Any, Dict, List

LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "audit_log.jsonl")
ANALYST = "A. Sharma"


def append(row):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    payload = {
        "ts": row.get("ts") or datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "analyst": row.get("analyst") or ANALYST,
        "incident": row.get("incident", ""),
        "decision": row.get("decision", ""),
        "action": row.get("action", ""),
        "note": row.get("note") or "",
    }
    with open(LOG_PATH, "a") as handle:
        handle.write(json.dumps(payload) + "\n")
    return payload


def read_all():
    # type: () -> List[Dict[str, Any]]
    if not os.path.exists(LOG_PATH):
        return []
    rows = []  # type: List[Dict[str, Any]]
    with open(LOG_PATH, "r") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows
