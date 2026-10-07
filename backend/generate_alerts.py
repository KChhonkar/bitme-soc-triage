#!/usr/bin/env python3
"""
generate_alerts.py

Generates raw_alerts.csv: a deterministic, synthetic SOC alert dataset with
exactly 3,000 rows:

    2,930 background/noise alerts
       12 Incident 1 alerts  (FIN-DB-01 critical database compromise)
        8 Incident 2 alerts  (CEO-Laptop malicious download -> unusual process)
       50 Incident 3 alerts  (Guest-WiFi-04 network scan that goes nowhere)

Only pandas (third-party) and the standard-library modules random, datetime
and ipaddress are used.
"""

import random
import ipaddress
from datetime import datetime, timedelta

import pandas as pd

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------
SEED = 42
OUTPUT_FILE = "raw_alerts.csv"

COLUMNS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "asset_name",
    "asset_criticality",
    "event_description",
    "mitre_technique_id",
    "raw_severity",
]
REQUIRED_COLUMNS = [c for c in COLUMNS if c != "mitre_technique_id"]

BACKGROUND_COUNT = 2930
INCIDENT_1_COUNT = 12
INCIDENT_2_COUNT = 8
INCIDENT_3_COUNT = 50
TOTAL_COUNT = BACKGROUND_COUNT + INCIDENT_1_COUNT + INCIDENT_2_COUNT + INCIDENT_3_COUNT  # 3000

SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CRITICALITY_VALUES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

# Monitoring window for background telemetry: 7 days
BACKGROUND_START = datetime(2026, 9, 29, 0, 0, 0)
BACKGROUND_DAYS = 7
# Hour-of-day weights (index = hour): quiet at night, busy during office hours
HOUR_WEIGHTS = [1] * 6 + [3] * 2 + [10] * 10 + [4] * 4 + [1] * 2  # 24 entries

# Planted assets (background generator must never use these names)
FIN_DB_NAME = "FIN-DB-01"
CEO_NAME = "CEO-Laptop"
SCAN_ASSET_NAME = "Guest-WiFi-04"
PLANTED_ASSETS = {FIN_DB_NAME, CEO_NAME, SCAN_ASSET_NAME}


def ip_at(network_cidr, offset):
    """Return the address at `offset` inside a network, validated by ipaddress."""
    return str(ipaddress.ip_network(network_cidr)[offset])


# Shared infrastructure addresses
DNS_SERVER_IP = ip_at("10.0.0.0/24", 53)
DHCP_SERVER_IP = ip_at("10.0.0.0/24", 67)
SCANNER_IP = ip_at("10.0.9.0/24", 15)          # approved vulnerability scanner
MAIL_RELAY_IP = ip_at("10.0.2.0/24", 10)
PRINT_SERVER_IP = ip_at("172.16.40.0/24", 5)
BACKUP_SERVER_IP = ip_at("172.16.50.0/24", 5)
GUEST_GATEWAY_IP = ip_at("192.168.50.0/24", 1)

# Planted-incident addresses
FIN_DB_IP = ip_at("10.40.1.0/24", 21)
PIVOT_HOST_IP = ip_at("10.10.23.0/24", 87)     # foothold host used in Incident 1
CEO_LAPTOP_IP = ip_at("10.10.1.0/24", 5)
MALICIOUS_HOST_IP = "45.147.230.17"            # external host serving the payload
GUEST_04_IP = ip_at("192.168.50.0/24", 100 + 4)

PUBLIC_NETWORKS = [
    "142.250.74.0/24", "151.101.1.0/24", "104.18.32.0/24",
    "13.107.42.0/24", "52.96.0.0/24", "172.217.160.0/24",
]
USERS = ["asharma", "mpatel", "jlee", "rgupta", "kmehta", "tbrown", "svc_backup", "nkhan", "vsingh", "dcole"]
DOMAINS = ["office.com", "slack.com", "github.com", "zoom.us", "windowsupdate.com", "salesforce.com", "dropbox.com"]
PORTS = [22, 53, 80, 135, 139, 443, 445, 631, 8080, 9100]
SHARES = ["Finance-Share", "HR-Docs", "Marketing-Assets", "Shared-Templates", "Projects"]

# --------------------------------------------------------------------------
# Background event catalog (benign / low-value SOC telemetry only).
# MITRE field is blank, except T1046 for legitimate discovery/scanning.
# No offensive technique (T1566, T1059, T1110, ...) is used in background data.
# --------------------------------------------------------------------------
EVENT_CATALOG = {
    "Failed Login (Typo)": {
        "mitre": "",
        "severity": {"INFO": 30, "LOW": 60, "MEDIUM": 10},
        "texts": [
            "Failed Login (Typo): user {user} entered an incorrect password once, then logged in successfully",
            "Failed Login (Typo): single failed logon for {user}, followed by a successful logon within 30 seconds",
            "Failed Login (Typo): mistyped credentials for {user}, account not locked",
        ],
    },
    "Successful Login": {
        "mitre": "",
        "severity": {"INFO": 85, "LOW": 13, "MEDIUM": 2},
        "texts": [
            "Successful Login: user {user} authenticated from a known device",
            "Successful Login: interactive logon for {user} during normal working hours",
            "Successful Login: {user} signed in with MFA satisfied",
        ],
    },
    "Routine Port Scan": {
        "mitre": "T1046",
        "severity": {"LOW": 55, "MEDIUM": 41, "HIGH": 4},
        "texts": [
            "Routine Port Scan: scheduled vulnerability scan from approved scanner probing port {port}",
            "Routine Port Scan: authorized weekly scan of {asset_name} (ports 22, 80, 443, 445)",
            "Routine Port Scan: compliance scan from IT security scanner, port {port} checked",
        ],
    },
    "Ping Sweep": {
        "mitre": "T1046",
        "severity": {"LOW": 70, "MEDIUM": 30},
        "texts": [
            "Ping Sweep: ICMP echo sweep from approved network monitoring scanner",
            "Ping Sweep: asset inventory discovery sweep by IT operations",
        ],
    },
    "DNS Query": {
        "mitre": "",
        "severity": {"INFO": 90, "LOW": 10},
        "texts": [
            "DNS Query: standard A record lookup for {domain}",
            "DNS Query: recursive resolution of {domain} completed normally",
            "DNS Query: AAAA lookup for {domain}",
        ],
    },
    "DHCP Request": {
        "mitre": "",
        "severity": {"INFO": 92, "LOW": 8},
        "texts": [
            "DHCP Request: lease renewal for {asset_name}",
            "DHCP Request: new lease granted to {asset_name}",
            "DHCP Request: DHCPDISCOVER received from {asset_name}",
        ],
    },
    "Printer Discovery": {
        "mitre": "",
        "severity": {"INFO": 80, "LOW": 20},
        "texts": [
            "Printer Discovery: mDNS/SNMP discovery by print server located {asset_name}",
            "Printer Discovery: periodic printer status poll for {asset_name}",
        ],
    },
    "Internal Service Connection": {
        "mitre": "",
        "severity": {"INFO": 70, "LOW": 27, "MEDIUM": 3},
        "texts": [
            "Internal Service Connection: established session to internal service on port {port}",
            "Internal Service Connection: API call to internal application on port {port}",
            "Internal Service Connection: routine service-to-service connection on port {port}",
        ],
    },
    "Routine File Access": {
        "mitre": "",
        "severity": {"INFO": 80, "LOW": 18, "MEDIUM": 2},
        "texts": [
            "Routine File Access: {user} opened documents on {share}",
            "Routine File Access: normal read access to {share} by {user}",
            "Routine File Access: {user} saved a file to {share}",
        ],
    },
    "Web Request": {
        "mitre": "",
        "severity": {"INFO": 85, "LOW": 14, "MEDIUM": 1},
        "texts": [
            "Web Request: HTTPS request to {domain} allowed by proxy policy",
            "Web Request: browsing session to {domain} (category: business)",
            "Web Request: HTTP GET to {domain} permitted",
        ],
    },
    "Software Update Check": {
        "mitre": "",
        "severity": {"INFO": 95, "LOW": 5},
        "texts": [
            "Software Update Check: endpoint contacted update service at {domain}",
            "Software Update Check: antivirus signature update retrieved",
        ],
    },
    "Scheduled Backup Job": {
        "mitre": "",
        "severity": {"INFO": 90, "LOW": 10},
        "texts": [
            "Scheduled Backup Job: nightly backup of {asset_name} completed",
            "Scheduled Backup Job: incremental backup transferred to backup server",
        ],
    },
}

# Which events each kind of asset can produce, with relative weights
KIND_EVENTS = {
    "laptop": {
        "Failed Login (Typo)": 10, "Successful Login": 14, "DNS Query": 20,
        "DHCP Request": 8, "Internal Service Connection": 14, "Routine File Access": 12,
        "Web Request": 18, "Software Update Check": 4, "Ping Sweep": 2, "Routine Port Scan": 1,
    },
    "guest": {
        "DHCP Request": 18, "DNS Query": 30, "Web Request": 40,
        "Failed Login (Typo)": 6, "Successful Login": 8,
    },
    "printer": {
        "Printer Discovery": 35, "DHCP Request": 25,
        "Internal Service Connection": 30, "Ping Sweep": 5,
    },
    "server": {
        "Successful Login": 25, "Failed Login (Typo)": 8, "Internal Service Connection": 25,
        "Routine File Access": 15, "Routine Port Scan": 8, "Ping Sweep": 4,
        "Scheduled Backup Job": 5,
    },
}
# Share of background alerts per asset kind
KIND_WEIGHTS = {"laptop": 55, "guest": 20, "printer": 6, "server": 19}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
class DatasetValidationError(Exception):
    """Raised when the generated dataset violates any specification rule."""


def check(condition, message):
    if not condition:
        raise DatasetValidationError(message)


def weighted_choice(weight_map):
    keys = list(weight_map.keys())
    return random.choices(keys, weights=[weight_map[k] for k in keys], k=1)[0]


def random_public_ip():
    return ip_at(random.choice(PUBLIC_NETWORKS), random.randrange(1, 255))


def random_background_timestamp():
    """Random timestamp across 7 days, weighted toward office hours."""
    day = random.randrange(BACKGROUND_DAYS)
    hour = random.choices(range(24), weights=HOUR_WEIGHTS, k=1)[0]
    return BACKGROUND_START + timedelta(
        days=day, hours=hour, minutes=random.randrange(60), seconds=random.randrange(60)
    )


def build_asset_inventory():
    """Create background assets. Planted assets are deliberately excluded."""
    assets = []

    # Employee laptops: 10.10.20.0/24, mostly LOW criticality
    for n in range(1, 41):
        assets.append({
            "name": f"Employee-Laptop-{n:02d}",
            "ip": ip_at("10.10.20.0/24", 10 + n),
            "criticality": "MEDIUM" if n % 8 == 7 else "LOW",
            "kind": "laptop",
        })

    # Guest Wi-Fi devices: 192.168.50.0/24 (Guest-WiFi-04 is reserved for Incident 3)
    for n in range(1, 13):
        name = f"Guest-WiFi-{n:02d}"
        if name in PLANTED_ASSETS:
            continue
        assets.append({
            "name": name,
            "ip": ip_at("192.168.50.0/24", 100 + n),
            "criticality": "LOW",
            "kind": "guest",
        })

    # Printers: 10.20.5.0/24
    for n in range(1, 9):
        assets.append({
            "name": f"Printer-Network-{n:02d}",
            "ip": ip_at("10.20.5.0/24", 10 + n),
            "criticality": "LOW",
            "kind": "printer",
        })

    # Servers (no CRITICAL assets in background; FIN-DB-01 is planted only)
    for n in range(1, 6):
        assets.append({"name": f"App-Server-{n:02d}", "ip": ip_at("172.16.10.0/24", 10 + n),
                       "criticality": "MEDIUM", "kind": "server"})
    for n in range(1, 3):
        assets.append({"name": f"File-Server-{n:02d}", "ip": ip_at("172.16.20.0/24", 10 + n),
                       "criticality": "MEDIUM" if n == 1 else "HIGH", "kind": "server"})
    assets.append({"name": "HR-DB-01", "ip": ip_at("172.16.30.0/24", 11), "criticality": "HIGH", "kind": "server"})
    assets.append({"name": "CRM-DB-01", "ip": ip_at("172.16.30.0/24", 12), "criticality": "HIGH", "kind": "server"})
    assets.append({"name": "DNS-Server-01", "ip": DNS_SERVER_IP, "criticality": "MEDIUM", "kind": "server"})
    assets.append({"name": "DHCP-Server-01", "ip": DHCP_SERVER_IP, "criticality": "MEDIUM", "kind": "server"})
    assets.append({"name": "Web-Proxy-01", "ip": ip_at("10.0.1.0/24", 10), "criticality": "MEDIUM", "kind": "server"})
    assets.append({"name": "Mail-Server-01", "ip": MAIL_RELAY_IP, "criticality": "MEDIUM", "kind": "server"})

    return assets


def pick_endpoints(event, asset, laptop_ips, auth_target_ips, file_server_ips):
    """Choose source/destination IPs that make sense for the event and asset."""
    kind, ip = asset["kind"], asset["ip"]
    guest = kind == "guest"
    printer = kind == "printer"

    if event in ("Routine Port Scan", "Ping Sweep"):
        return SCANNER_IP, ip                              # approved scanner -> asset
    if event == "Printer Discovery":
        return PRINT_SERVER_IP, ip                         # print server -> printer
    if event == "Scheduled Backup Job":
        return ip, BACKUP_SERVER_IP                        # server -> backup server
    if kind == "server":
        return random.choice(laptop_ips), ip               # internal clients -> server

    # Remaining events originate from the asset itself (laptop / guest / printer)
    if event == "DNS Query":
        dst = GUEST_GATEWAY_IP if guest else DNS_SERVER_IP
    elif event == "DHCP Request":
        dst = GUEST_GATEWAY_IP if guest else DHCP_SERVER_IP
    elif event in ("Web Request", "Software Update Check"):
        dst = random_public_ip()                           # external/public destination
    elif event in ("Successful Login", "Failed Login (Typo)"):
        dst = GUEST_GATEWAY_IP if guest else random.choice(auth_target_ips)
    elif event == "Routine File Access":
        dst = random.choice(file_server_ips)
    elif event == "Internal Service Connection":
        dst = PRINT_SERVER_IP if printer else random.choice(auth_target_ips)
    else:
        dst = DNS_SERVER_IP
    return ip, dst


def make_row(timestamp, src, dst, asset, criticality, description, mitre, severity):
    return {
        "timestamp": timestamp,
        "source_ip": src,
        "destination_ip": dst,
        "asset_name": asset,
        "asset_criticality": criticality,
        "event_description": description,
        "mitre_technique_id": mitre,
        "raw_severity": severity,
    }


# --------------------------------------------------------------------------
# Background noise: exactly 2,930 rows
# --------------------------------------------------------------------------
def generate_background_alerts():
    assets = build_asset_inventory()
    by_kind = {kind: [a for a in assets if a["kind"] == kind] for kind in KIND_WEIGHTS}
    laptop_ips = [a["ip"] for a in by_kind["laptop"]]
    file_server_ips = [a["ip"] for a in by_kind["server"] if a["name"].startswith("File-Server")]
    auth_target_ips = [a["ip"] for a in by_kind["server"]
                       if a["name"].startswith(("App-Server", "File-Server"))]

    rows = []
    for _ in range(BACKGROUND_COUNT):
        kind = weighted_choice(KIND_WEIGHTS)
        asset = random.choice(by_kind[kind])
        event = weighted_choice(KIND_EVENTS[kind])
        spec = EVENT_CATALOG[event]

        description = random.choice(spec["texts"]).format(
            user=random.choice(USERS),
            port=random.choice(PORTS),
            domain=random.choice(DOMAINS),
            share=random.choice(SHARES),
            asset_name=asset["name"],
        )
        src, dst = pick_endpoints(event, asset, laptop_ips, auth_target_ips, file_server_ips)
        rows.append(make_row(
            random_background_timestamp(), src, dst, asset["name"], asset["criticality"],
            description, spec["mitre"], weighted_choice(spec["severity"]),
        ))
    return pd.DataFrame(rows, columns=COLUMNS)


# --------------------------------------------------------------------------
# Incident 1: FIN-DB-01 critical compromise (12 alerts inside 5 minutes)
# Phishing -> PowerShell -> Brute Force -> Database Access
# --------------------------------------------------------------------------
INCIDENT_1_START = datetime(2026, 10, 2, 14, 32, 17)

# (offset_seconds, source_ip, description, mitre, severity)
# Last offset is 281s, so the whole chain fits in a 5-minute (300s) window.
# MITRE: T1566 Phishing, T1059 Command and Scripting Interpreter,
#        T1110 Brute Force, T1078 Valid Accounts, T1213 Data from Information Repositories
INCIDENT_1_EVENTS = [
    (0,   MAIL_RELAY_IP, "Phishing email detected: credential-lure message with macro attachment delivered to FIN-DB-01 administrator mailbox", "T1566", "MEDIUM"),
    (12,  MAIL_RELAY_IP, "Suspicious attachment opened: Invoice_Q3_Reconciliation.xlsm launched by DBA session on FIN-DB-01", "T1566", "MEDIUM"),
    (31,  PIVOT_HOST_IP, "PowerShell process spawned by Office application on FIN-DB-01 administrator session", "T1059", "MEDIUM"),
    (48,  PIVOT_HOST_IP, "Encoded PowerShell command detected (-EncodedCommand, hidden window)", "T1059", "HIGH"),
    (67,  PIVOT_HOST_IP, "PowerShell child process observed: rundll32.exe launched with outbound network connection", "T1059", "HIGH"),
    (95,  PIVOT_HOST_IP, "Authentication attempts detected against FIN-DB-01 service accounts from non-standard host", "T1110", "HIGH"),
    (128, PIVOT_HOST_IP, "Multiple failed database logins for account svc_finreport (41 attempts in 30 seconds)", "T1110", "HIGH"),
    (156, PIVOT_HOST_IP, "Credential attack detected: password spraying pattern against database listener", "T1110", "HIGH"),
    (187, PIVOT_HOST_IP, "Successful authentication to FIN-DB-01 as svc_finreport after repeated failures", "T1078", "CRITICAL"),
    (214, PIVOT_HOST_IP, "Suspicious database connection: interactive session from workstation outside DBA allow-list", "T1078", "CRITICAL"),
    (243, PIVOT_HOST_IP, "Sensitive database query: bulk SELECT on general_ledger and payroll tables", "T1213", "CRITICAL"),
    (281, PIVOT_HOST_IP, "Database access anomaly: abnormal data volume returned to remote client", "T1213", "CRITICAL"),
]


def generate_incident_1():
    rows = [
        make_row(INCIDENT_1_START + timedelta(seconds=offset), src, FIN_DB_IP,
                 FIN_DB_NAME, "CRITICAL", description, mitre, severity)
        for offset, src, description, mitre, severity in INCIDENT_1_EVENTS
    ]
    return pd.DataFrame(rows, columns=COLUMNS)


# --------------------------------------------------------------------------
# Incident 2: CEO-Laptop (8 alerts) Malicious File Download -> Unusual Process Spawned
# MITRE: T1105 Ingress Tool Transfer, T1204.002 User Execution: Malicious File
# --------------------------------------------------------------------------
INCIDENT_2_START = datetime(2026, 10, 3, 9, 15, 42)

# (offset_seconds, source_ip, destination_ip, description, mitre, severity)
INCIDENT_2_EVENTS = [
    (0,   MALICIOUS_HOST_IP, CEO_LAPTOP_IP, "Malicious File Download: browser fetched invoice_viewer_setup.zip from newly registered domain", "T1105", "LOW"),
    (38,  MALICIOUS_HOST_IP, CEO_LAPTOP_IP, "Malicious File Download: archive Board_Pack_Q4.zip flagged by web proxy reputation service", "T1105", "MEDIUM"),
    (75,  MALICIOUS_HOST_IP, CEO_LAPTOP_IP, "Malicious File Download: executable payload written to Downloads folder", "T1105", "MEDIUM"),
    (130, MALICIOUS_HOST_IP, CEO_LAPTOP_IP, "Malicious File Download: saved file hash matches threat intelligence indicator", "T1105", "MEDIUM"),
    (260, CEO_LAPTOP_IP, CEO_LAPTOP_IP, "Unusual Process Spawned: invoice_viewer.exe executed from Downloads directory", "T1204.002", "HIGH"),
    (312, CEO_LAPTOP_IP, CEO_LAPTOP_IP, "Unusual Process Spawned: unsigned binary launched from user Temp directory by invoice_viewer.exe", "T1204.002", "HIGH"),
    (405, CEO_LAPTOP_IP, CEO_LAPTOP_IP, "Unusual Process Spawned: abnormal parent-child chain explorer.exe -> msiexec.exe -> unknown binary", "T1204.002", "HIGH"),
    (511, CEO_LAPTOP_IP, MALICIOUS_HOST_IP, "Unusual Process Spawned: new child process attempting outbound connection to external host", "T1204.002", "HIGH"),
]


def generate_incident_2():
    rows = [
        make_row(INCIDENT_2_START + timedelta(seconds=offset), src, dst,
                 CEO_NAME, "HIGH", description, mitre, severity)
        for offset, src, dst, description, mitre, severity in INCIDENT_2_EVENTS
    ]
    return pd.DataFrame(rows, columns=COLUMNS)


# --------------------------------------------------------------------------
# Incident 3: Guest-WiFi-04 network scan (50 alerts, T1046 only, goes nowhere)
# Stays INFO/LOW, targets only the guest subnet, never escalates.
# --------------------------------------------------------------------------
INCIDENT_3_START = datetime(2026, 10, 4, 2, 10, 5)
SCAN_TEXTS = [
    "Network Scan: TCP SYN sweep from Guest-WiFi-04 across guest subnet (port {port})",
    "Network Discovery: ICMP echo sweep detected from guest device",
    "Network Scan: sequential port probe against guest subnet host (port {port})",
    "Network Discovery: ARP scan activity detected on guest VLAN",
    "Network Scan: repeated connection attempts to port {port}, no session established",
]


def generate_incident_3():
    rows = []
    current_time = INCIDENT_3_START
    target_hosts = [n for n in range(2, 255) if n != 104]   # never target itself
    for i in range(INCIDENT_3_COUNT):
        if i > 0:
            current_time += timedelta(seconds=random.randint(4, 22))  # strictly increasing
        description = random.choice(SCAN_TEXTS).format(port=random.choice(PORTS))
        severity = random.choice(["INFO", "LOW", "LOW", "LOW"])
        rows.append(make_row(
            current_time, GUEST_04_IP, ip_at("192.168.50.0/24", random.choice(target_hosts)),
            SCAN_ASSET_NAME, "LOW", description, "T1046", severity,
        ))
    return pd.DataFrame(rows, columns=COLUMNS)


# --------------------------------------------------------------------------
# Validation (raises DatasetValidationError before any CSV is written)
# --------------------------------------------------------------------------
def validate_dataset(df, background, inc1, inc2, inc3):
    # Composition
    check(len(background) == BACKGROUND_COUNT, f"Background rows = {len(background)}, expected {BACKGROUND_COUNT}")
    check(len(inc1) == INCIDENT_1_COUNT, f"Incident 1 rows = {len(inc1)}, expected {INCIDENT_1_COUNT}")
    check(len(inc2) == INCIDENT_2_COUNT, f"Incident 2 rows = {len(inc2)}, expected {INCIDENT_2_COUNT}")
    check(len(inc3) == INCIDENT_3_COUNT, f"Incident 3 rows = {len(inc3)}, expected {INCIDENT_3_COUNT}")
    check(len(df) == TOTAL_COUNT, f"Total rows = {len(df)}, expected {TOTAL_COUNT}")

    # Schema
    check(list(df.columns) == COLUMNS, f"Columns {list(df.columns)} do not match required schema")

    # Missing values
    for col in REQUIRED_COLUMNS:
        check(not df[col].isnull().any(), f"Null values found in required column '{col}'")
        if col != "timestamp":
            check(not (df[col].astype(str).str.strip() == "").any(), f"Blank values found in required column '{col}'")
    check(not df["mitre_technique_id"].isnull().any(), "mitre_technique_id contains nulls (blank must be empty string)")

    # Timestamps
    check(pd.api.types.is_datetime64_any_dtype(df["timestamp"]), "timestamp column is not datetime typed")
    check(df["timestamp"].is_monotonic_increasing, "Final dataset is not sorted chronologically")

    # Allowed values
    check(set(df["raw_severity"]) <= set(SEVERITY_RANK), "Unexpected raw_severity value")
    check(set(df["asset_criticality"]) <= CRITICALITY_VALUES, "Unexpected asset_criticality value")

    # IP validity via ipaddress
    for col in ("source_ip", "destination_ip"):
        for value in df[col]:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                raise DatasetValidationError(f"Invalid IP address in {col}: {value!r}")

    # Background isolation: benign only
    check(not set(background["asset_name"]) & PLANTED_ASSETS, "Background data uses a planted asset name")
    check(set(background["mitre_technique_id"]) <= {"", "T1046"},
          f"Background contains unexpected MITRE IDs: {set(background['mitre_technique_id'])}")
    check(not (background["raw_severity"] == "CRITICAL").any(), "Background contains CRITICAL severity")
    check(not (background["asset_criticality"] == "CRITICAL").any(), "Background contains CRITICAL assets")
    high_count = int((background["raw_severity"] == "HIGH").sum())
    check(high_count <= int(0.03 * BACKGROUND_COUNT), f"Too many HIGH background alerts: {high_count}")

    # Incident counts in the final dataset (by asset name)
    counts = df["asset_name"].value_counts()
    check(counts.get(FIN_DB_NAME, 0) == INCIDENT_1_COUNT, f"{FIN_DB_NAME} count = {counts.get(FIN_DB_NAME, 0)}")
    check(counts.get(CEO_NAME, 0) == INCIDENT_2_COUNT, f"{CEO_NAME} count = {counts.get(CEO_NAME, 0)}")
    check(counts.get(SCAN_ASSET_NAME, 0) == INCIDENT_3_COUNT, f"{SCAN_ASSET_NAME} count = {counts.get(SCAN_ASSET_NAME, 0)}")

    # Incident 1 checks
    f = df[df["asset_name"] == FIN_DB_NAME]
    check((f["asset_criticality"] == "CRITICAL").all(), "Incident 1: not all alerts have CRITICAL criticality")
    check(f["timestamp"].is_monotonic_increasing and f["timestamp"].is_unique, "Incident 1: timestamps not strictly chronological")
    check((f["timestamp"].max() - f["timestamp"].min()).total_seconds() <= 300, "Incident 1: chain exceeds 5-minute window")
    check(f["event_description"].nunique() == INCIDENT_1_COUNT, "Incident 1: descriptions are not all distinct")
    check({"T1566", "T1059", "T1110"} <= set(f["mitre_technique_id"]), "Incident 1: missing T1566/T1059/T1110")
    stage_ids = list(f["mitre_technique_id"])
    check(stage_ids.index("T1566") < stage_ids.index("T1059") < stage_ids.index("T1110")
          < min(stage_ids.index(t) for t in ("T1078", "T1213") if t in stage_ids),
          "Incident 1: stages out of order (Phishing -> PowerShell -> Brute Force -> DB access)")
    ranks = [SEVERITY_RANK[s] for s in f["raw_severity"]]
    check(ranks == sorted(ranks) and ranks[-1] == SEVERITY_RANK["CRITICAL"], "Incident 1: severity does not escalate to CRITICAL")

    # Incident 2 checks
    c = df[df["asset_name"] == CEO_NAME]
    check((c["asset_criticality"] == "HIGH").all(), "Incident 2: not all alerts have HIGH criticality")
    check(c["timestamp"].is_monotonic_increasing and c["timestamp"].is_unique, "Incident 2: timestamps not strictly chronological")
    check((c["timestamp"].max() - c["timestamp"].min()).total_seconds() <= 900, "Incident 2: events too far apart")
    descriptions = list(c["event_description"])
    first_process = next(i for i, d in enumerate(descriptions) if d.startswith("Unusual Process Spawned"))
    check(first_process > 0 and all(d.startswith("Malicious File Download") for d in descriptions[:first_process]),
          "Incident 2: download stage must precede process stage")
    check(all(d.startswith("Unusual Process Spawned") for d in descriptions[first_process:]),
          "Incident 2: unexpected event after process stage began")
    ranks2 = [SEVERITY_RANK[s] for s in c["raw_severity"]]
    check(ranks2 == sorted(ranks2), "Incident 2: severity does not progress")

    # Incident 3 checks
    g = df[df["asset_name"] == SCAN_ASSET_NAME]
    check((g["asset_criticality"] == "LOW").all(), "Incident 3: criticality must be LOW")
    check((g["mitre_technique_id"] == "T1046").all(), "Incident 3: all alerts must be T1046")
    check(set(g["raw_severity"]) <= {"INFO", "LOW"}, "Incident 3: scan severity must stay INFO/LOW")
    check(g["timestamp"].is_monotonic_increasing, "Incident 3: timestamps not chronological")
    check((g["source_ip"] == GUEST_04_IP).all(), "Incident 3: unexpected source IP")


def main():
    random.seed(SEED)  # fixed seed -> identical output on every run

    background = generate_background_alerts()
    incident_1 = generate_incident_1()
    incident_2 = generate_incident_2()
    incident_3 = generate_incident_3()

    df = pd.concat([background, incident_1, incident_2, incident_3], ignore_index=True)
    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)  # stable: ties keep generation order

    validate_dataset(df, background, incident_1, incident_2, incident_3)

    output = df.copy()
    output["timestamp"] = output["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    output.to_csv(OUTPUT_FILE, index=False)

    # Re-read the file as a final check on what was actually written
    written = pd.read_csv(OUTPUT_FILE, keep_default_na=False)
    check(len(written) == TOTAL_COUNT, f"Written CSV has {len(written)} rows, expected {TOTAL_COUNT}")
    check(list(written.columns) == COLUMNS, "Written CSV columns do not match schema")

    print(f"✅ Successfully generated {OUTPUT_FILE} with {len(written)} rows")
    print(f"Rows: {len(written)}")
    print(f"Background alerts: {len(background)}")
    print(f"Incident 1 alerts: {len(incident_1)}")
    print(f"Incident 2 alerts: {len(incident_2)}")
    print(f"Incident 3 alerts: {len(incident_3)}")
    print("Validation: PASSED")


if __name__ == "__main__":
    try:
        main()
    except DatasetValidationError as error:
        raise SystemExit(f"❌ Validation FAILED: {error}")
