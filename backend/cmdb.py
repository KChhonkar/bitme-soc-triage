"""Mock company asset inventory (CMDB).

Firewalls and EDR tools emit asset names, not business value. The CSV
`asset_criticality` column is dropped on load; every score uses this lookup.
"""

from typing import Dict


MOCK_CMDB = {
    "FIN-DB-01": {
        "criticality": "CRITICAL",
        "owner": "Finance infrastructure",
        "description": "Finance production database",
    },
    "CEO-Laptop": {
        "criticality": "HIGH",
        "owner": "Executive IT",
        "description": "Executive endpoint",
    },
    "PAY-API-01": {"criticality": "CRITICAL", "owner": "Payments platform", "description": "Payments API"},
    "HR-DB-02": {"criticality": "HIGH", "owner": "People systems", "description": "HR database"},
}  # type: Dict[str, Dict[str, str]]


def lookup_asset(asset_name):
    # type: (str) -> Dict[str, str]
    """Return criticality, owner, and description for an asset name."""
    if asset_name in MOCK_CMDB:
        return MOCK_CMDB[asset_name]
    if asset_name.startswith("Guest-WiFi"):
        return {
            "criticality": "LOW",
            "owner": "Workplace network",
            "description": "Guest wireless client",
        }
    if asset_name.startswith("Employee-Laptop"):
        return {
            "criticality": "LOW",
            "owner": "Workplace endpoints",
            "description": "Employee laptop",
        }
    if asset_name.startswith("Mail-Server") or asset_name.startswith("App-Server"):
        return {
            "criticality": "MEDIUM",
            "owner": "Infrastructure",
            "description": "Application or mail server",
        }
    return {
        "criticality": "MEDIUM",
        "owner": "IT operations",
        "description": "Unclassified asset",
    }
