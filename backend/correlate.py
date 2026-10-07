"""Correlation engine.

Ingestion is a synthetic replay of raw_alerts.csv (not a live SIEM).
Grouping by asset + 10-minute gap, scoring, and stable IDs are real code.

IDs: a full-dataset run at startup is sorted by first_seen and numbered
INC-015, INC-016, ... Partial replays match (asset, first_seen) so IDs
never change while the feed advances.
"""

from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd

from cmdb import lookup_asset
from scoring import score_incident, technique_name

GAP_MINUTES = 10
MIN_ALERTS = 5
ID_START = 15


def load_alerts(csv_path):
    # type: (str) -> pd.DataFrame
    """Load CSV, drop vendor criticality, sort, tag replay index i."""
    df = pd.read_csv(csv_path)
    # Firewalls/EDR do not know business value. Criticality comes from CMDB only.
    if "asset_criticality" in df.columns:
        df = df.drop(columns=["asset_criticality"])
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["mitre_technique_id"] = df["mitre_technique_id"].fillna("").astype(str)
    df.loc[df["mitre_technique_id"].isin(["nan", "None"]), "mitre_technique_id"] = ""
    df = df.sort_values("timestamp").reset_index(drop=True)
    df["i"] = df.index
    return df


def _iso(ts):
    # type: (Any) -> str
    stamp = pd.Timestamp(ts)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S")


def format_duration(first, last):
    # type: (pd.Timestamp, pd.Timestamp) -> str
    total_s = int((pd.Timestamp(last) - pd.Timestamp(first)).total_seconds())
    if total_s < 0:
        total_s = 0
    minutes, seconds = divmod(total_s, 60)
    if minutes and seconds:
        return "{} min {} s".format(minutes, seconds)
    if minutes:
        return "{} min".format(minutes)
    return "{} s".format(seconds)


def _alert_row(record):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    mitre = str(record.get("mitre_technique_id") or "").strip()
    return {
        "timestamp": _iso(record["timestamp"]),
        "source_ip": str(record["source_ip"]),
        "destination_ip": str(record["destination_ip"]),
        "description": str(record["event_description"]),
        "mitre_id": mitre,
        "raw_severity": str(record["raw_severity"]),
        "technique_name": technique_name(mitre) if mitre else "",
    }


def correlation_confidence(alert_count, mitre_share, distinct_techniques):
    # type: (int, float, int) -> int
    """Correlation confidence (deterministic, not from the LLM).

    100 * (0.5 * share_of_alerts_with_MITRE
           + 0.3 * min(1, distinct_techniques / 3)
           + 0.2 * min(1, alert_count / 10))
    """
    value = 100.0 * (
        0.5 * mitre_share
        + 0.3 * min(1.0, distinct_techniques / 3.0)
        + 0.2 * min(1.0, alert_count / 10.0)
    )
    return int(round(value))


def _build_incident(cluster, id_map):
    # type: (List[Dict[str, Any]], Optional[Dict[Tuple[str, str], str]]) -> Dict[str, Any]
    cluster = sorted(cluster, key=lambda r: r["timestamp"])
    asset = str(cluster[0]["asset_name"])
    inventory = lookup_asset(asset)
    first_seen = _iso(cluster[0]["timestamp"])
    last_seen = _iso(cluster[-1]["timestamp"])
    alert_count = len(cluster)

    techniques = []  # type: List[str]
    seen = set()
    mitre_hits = 0
    for record in cluster:
        tid = str(record.get("mitre_technique_id") or "").strip()
        if tid:
            mitre_hits += 1
            if tid not in seen:
                seen.add(tid)
                techniques.append(tid)

    sources = [str(r["source_ip"]) for r in cluster]
    counts = Counter(sources)
    likely = counts.most_common(1)[0][0] if counts else ""

    score, severity, breakdown = score_incident(
        inventory["criticality"], techniques, alert_count
    )
    mitre_share = mitre_hits / float(alert_count) if alert_count else 0.0
    confidence = correlation_confidence(alert_count, mitre_share, len(techniques))

    incident_id = None
    if id_map is not None:
        incident_id = id_map.get((asset, first_seen))

    return {
        "id": incident_id,
        "asset": asset,
        "owner": inventory["owner"],
        "criticality": inventory["criticality"],
        "alert_count": alert_count,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration": format_duration(cluster[0]["timestamp"], cluster[-1]["timestamp"]),
        "techniques": [{"id": tid, "name": technique_name(tid)} for tid in techniques],
        "source_ips": sorted(set(sources)),
        "likely_attacker": likely,
        "alerts": [_alert_row(r) for r in cluster],
        "score": score,
        "severity": severity,
        "score_breakdown": breakdown,
        "confidence": confidence,
    }


def correlate(df, upto, id_map=None):
    # type: (pd.DataFrame, int, Optional[Dict[Tuple[str, str], str]]) -> List[Dict[str, Any]]
    """Group the first `upto` replay rows into incidents."""
    n = max(0, int(upto))
    slice_df = df.iloc[:n]
    incidents = []  # type: List[Dict[str, Any]]
    if slice_df.empty:
        return incidents

    gap = pd.Timedelta(minutes=GAP_MINUTES)
    for asset, group in slice_df.groupby("asset_name", sort=False):
        records = group.sort_values("timestamp").to_dict("records")
        current = []  # type: List[Dict[str, Any]]
        prev_ts = None
        clusters = []  # type: List[List[Dict[str, Any]]]
        for record in records:
            ts = pd.Timestamp(record["timestamp"])
            if prev_ts is None or (ts - prev_ts) > gap:
                if current:
                    clusters.append(current)
                current = [record]
            else:
                current.append(record)
            prev_ts = ts
        if current:
            clusters.append(current)
        for cluster in clusters:
            if len(cluster) >= MIN_ALERTS:
                incidents.append(_build_incident(cluster, id_map))
    return incidents


def build_id_map(df):
    # type: (pd.DataFrame) -> Dict[Tuple[str, str], str]
    """Assign stable IDs from a full-dataset correlation, ordered by first_seen."""
    full = correlate(df, len(df), id_map=None)
    full.sort(key=lambda inc: inc["first_seen"])
    id_map = {}  # type: Dict[Tuple[str, str], str]
    for index, inc in enumerate(full):
        incident_id = "INC-{:03d}".format(ID_START + index)
        id_map[(inc["asset"], inc["first_seen"])] = incident_id
    return id_map
