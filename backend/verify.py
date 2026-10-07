#!/usr/bin/env python3
"""Assert correlation, ranking, stable IDs, and template LLM fallbacks."""

from __future__ import print_function

import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from correlate import build_id_map, correlate, load_alerts
from llm import draft_prevention, template_prevention, template_summary


def check(name, condition, detail=""):
    if condition:
        print("PASS  {}".format(name))
        return True
    print("FAIL  {} {}".format(name, detail).rstrip())
    return False


def main():
    ok = True
    csv_path = os.path.join(HERE, "raw_alerts.csv")
    df = load_alerts(csv_path)
    id_map = build_id_map(df)

    ok = check("3000 rows", len(df) == 3000, "got {}".format(len(df))) and ok

    full = correlate(df, len(df), id_map)
    ok = check("exactly 3 incidents", len(full) == 3, "got {}".format(len(full))) and ok

    by_asset = {inc["asset"]: inc for inc in full}
    expected = [("FIN-DB-01", 12), ("CEO-Laptop", 8), ("Guest-WiFi-04", 50)]
    pairs = sorted([(inc["asset"], inc["alert_count"]) for inc in full])
    ok = check(
        "(asset, count) planted set",
        pairs == sorted(expected),
        "got {}".format(pairs),
    ) and ok

    ranked = sorted(full, key=lambda inc: inc["score"], reverse=True)
    names = [inc["asset"] for inc in ranked]
    ok = check(
        "score rank FIN-DB-01 > CEO-Laptop > Guest-WiFi-04",
        names[:3] == ["FIN-DB-01", "CEO-Laptop", "Guest-WiFi-04"],
        "got {} scores {}".format(names, [inc["score"] for inc in ranked]),
    ) and ok

    ids_full = {(inc["asset"], inc["id"]) for inc in full}
    part = correlate(df, 2000, id_map)
    stable = True
    for inc in part:
        match = [f for f in full if f["asset"] == inc["asset"] and f["first_seen"] == inc["first_seen"]]
        if not match or match[0]["id"] != inc["id"]:
            stable = False
    ok = check("IDs stable between upto=2000 and upto=3000", stable, str(ids_full)) and ok

    try:
        fin = by_asset["FIN-DB-01"]
        text = template_summary(fin)
        prev = template_prevention(fin)
        wrapped = draft_prevention(fin)
        cmd_ok = any("FIN-DB-01" in a["command"] for a in prev) and any(
            "10.10.23.87" in a["command"] for a in prev
        )
        exact_edr = 'Invoke-FalconHostIsolation -Hostname "FIN-DB-01" -Severity "CRITICAL"'
        exact_fw = 'set rulebase security rules "Block-Brute-Force" source 10.10.23.87 action drop'
        cmds = [a["command"] for a in prev]
        ok = check("template summary (no API key required)", bool(text) and "FIN-DB-01" in text) and ok
        ok = check("template prevention (no API key required)", bool(prev) and cmd_ok) and ok
        ok = check("CRITICAL T1110 EDR command exact", exact_edr in cmds, cmds) and ok
        ok = check("CRITICAL T1110 firewall command exact", exact_fw in cmds, cmds) and ok
        ok = check("draft_prevention returns actions", bool(wrapped.get("actions"))) and ok
    except Exception:
        traceback.print_exc()
        ok = check("template summary and prevention work", False) and ok

    if not ok:
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
