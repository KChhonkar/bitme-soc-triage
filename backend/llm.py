"""Gemini REST wrapper with a deterministic template fallback.

Calls POST .../v1beta/models/{MODEL}:generateContent with x-goog-api-key.
12 s timeout. On missing key, timeout, or parse failure, use the template.
Prevention commands are drafts and are NEVER executed against a real system.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional

import httpx
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

# verify the current model name in Google AI Studio before the demo
GEMINI_MODEL = os.getenv("GEMINI_MODEL") or "gemini-2.5-flash"
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or ""
GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent"
).format(GEMINI_MODEL)
TIMEOUT_S = 30.0

SYSTEM_BRIEF = (
    "You are a Tier-3 SOC analyst writing a brief for the next-shift Tier-1 analyst. "
    "Use ONLY the provided incident JSON. Do not invent IPs, hosts, accounts, counts or techniques. "
    "Cite MITRE ATT&CK technique IDs exactly as given. Mention the asset and its criticality. "
    "Write exactly 2 short sentences (under 60 words total), plain English, no markdown. Finish both sentences."
)

SYSTEM_PREVENTION = (
    "You draft containment commands for a SOC console. Return ONLY a JSON array of 2 to 3 objects. "
    'Each object must have keys tool, action, command, rationale. tool must be one of "EDR", '
    '"Firewall", "Identity". Use only the asset name and source IP in the incident JSON. '
    "Do not wrap the array in markdown. These are drafts, not live commands."
)

ALLOWED_TOOLS = ("EDR", "Firewall", "Identity")


def gemini_configured():
    # type: () -> bool
    return bool(GEMINI_API_KEY.strip()) or bool(os.getenv("LLM_BASE_URL"))


def _incident_payload(incident):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    alerts = incident.get("alerts") or []
    descriptions = [a.get("description", "") for a in alerts[:15]]
    techniques = incident.get("techniques") or []
    return {
        "asset": incident.get("asset"),
        "criticality": incident.get("criticality"),
        "owner": incident.get("owner"),
        "duration": incident.get("duration"),
        "alert_count": incident.get("alert_count"),
        "techniques": techniques,
        "likely_attacker": incident.get("likely_attacker"),
        "alert_descriptions": descriptions,
    }


LAST_ERROR = {"msg": ""}


def _models():
    # type: () -> List[str]
    out = []  # type: List[str]
    for m in [GEMINI_MODEL, "gemini-flash-latest"]:
        if m and m not in out:
            out.append(m)
    return out


LLM_BASE_URL = (os.getenv("LLM_BASE_URL") or "").rstrip("/")
LLM_API_KEY = os.getenv("LLM_API_KEY") or "none"
LLM_MODEL = os.getenv("LLM_MODEL") or ""


def _call_openai_compat(system_text, user_text):
    # type: (str, str) -> Optional[str]
    """Any OpenAI-compatible endpoint: OpenAI, Groq, Ollama (local), etc."""
    body = {
        "model": LLM_MODEL,
        "temperature": 0.2,
        "max_tokens": 2000,
        "messages": [
            {"role": "system", "content": system_text},
            {"role": "user", "content": user_text},
        ],
    }
    if "gpt-oss" in LLM_MODEL:
        body["reasoning_effort"] = "low"  # reasoning models otherwise burn the token budget thinking
    try:
        with httpx.Client(timeout=TIMEOUT_S) as client:
            r = client.post(
                LLM_BASE_URL + "/chat/completions",
                headers={"Authorization": "Bearer " + LLM_API_KEY, "Content-Type": "application/json"},
                json=body,
            )
        if r.status_code != 200:
            LAST_ERROR["msg"] = "{} -> HTTP {}: {}".format(LLM_MODEL, r.status_code, r.text[:160].replace("\n", " "))
            print("[llm]", LAST_ERROR["msg"])
            return None
        text = (r.json()["choices"][0]["message"].get("content") or "").strip()
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
        if text:
            LAST_ERROR["msg"] = ""
        else:
            LAST_ERROR["msg"] = "{} returned empty text".format(LLM_MODEL)
            print("[llm]", LAST_ERROR["msg"])
        return text or None
    except Exception as exc:
        LAST_ERROR["msg"] = "{} -> {}".format(LLM_MODEL, repr(exc)[:160])
        print("[llm]", LAST_ERROR["msg"])
        return None


def _call_gemini(system_text, user_text):
    # type: (str, str) -> Optional[str]
    if LLM_BASE_URL and LLM_MODEL:
        text = _call_openai_compat(system_text, user_text)
        if text:
            return text
    return _call_gemini_native(system_text, user_text)


def _call_gemini_native(system_text, user_text):
    # type: (str, str) -> Optional[str]
    if not gemini_configured():
        LAST_ERROR["msg"] = "GEMINI_API_KEY missing in backend/.env"
        return None
    errs = []  # type: List[str]
    for model in _models():
        cfg = {"temperature": 0.2, "maxOutputTokens": 4096}  # type: Dict[str, Any]
        if "2.5" in model:
            cfg["thinkingConfig"] = {"thinkingBudget": 0}  # thinking tokens ate the budget -> empty text
        body = {
            "systemInstruction": {"parts": [{"text": system_text}]},
            "contents": [{"role": "user", "parts": [{"text": user_text}]}],
            "generationConfig": cfg,
        }
        url = "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent".format(model)
        try:
            with httpx.Client(timeout=TIMEOUT_S) as client:
                response = client.post(
                    url,
                    headers={"x-goog-api-key": GEMINI_API_KEY, "Content-Type": "application/json"},
                    json=body,
                )
            if response.status_code in (429, 500, 503):
                import time
                time.sleep(2)
                with httpx.Client(timeout=TIMEOUT_S) as client:
                    response = client.post(
                        url,
                        headers={"x-goog-api-key": GEMINI_API_KEY, "Content-Type": "application/json"},
                        json=body,
                    )
            if response.status_code != 200:
                errs.append("{} -> HTTP {}: {}".format(model, response.status_code, response.text[:160].replace("\n", " ")))
                LAST_ERROR["msg"] = " || ".join(errs)
                print("[gemini]", LAST_ERROR["msg"])
                continue
            data = response.json()
            candidates = data.get("candidates") or []
            parts = ((candidates[0].get("content") or {}).get("parts") or []) if candidates else []
            text = "".join(p.get("text") or "" for p in parts if not p.get("thought")).strip()
            finish = (candidates[0].get("finishReason") if candidates else "") or ""
            if finish and finish != "STOP":
                print("[gemini] finishReason:", finish)
            if text:
                LAST_ERROR["msg"] = ""
                return text
            errs.append("{} returned empty text".format(model))
            LAST_ERROR["msg"] = " || ".join(errs)
            print("[gemini]", LAST_ERROR["msg"])
        except Exception as exc:
            errs.append("{} -> {}".format(model, repr(exc)[:160]))
            LAST_ERROR["msg"] = " || ".join(errs)
            print("[gemini]", LAST_ERROR["msg"])
    return None


def template_summary(incident):
    # type: (Dict[str, Any]) -> str
    payload = _incident_payload(incident)
    tech_bits = []
    for tech in payload["techniques"]:
        tid = tech.get("id") if isinstance(tech, dict) else str(tech)
        name = tech.get("name", "") if isinstance(tech, dict) else ""
        tech_bits.append("{} ({})".format(tid, name) if name else tid)
    tech_text = ", ".join(tech_bits) if tech_bits else "no mapped MITRE techniques"
    descriptions = [d for d in payload["alert_descriptions"] if d]
    activity = "; ".join(descriptions[:4]) if descriptions else "correlated telemetry"
    sentence1 = (
        "{asset} is a {crit} asset (owner {owner}) with {count} correlated alerts "
        "over {duration}, including {tech}."
    ).format(
        asset=payload["asset"],
        crit=payload["criticality"],
        owner=payload["owner"],
        count=payload["alert_count"],
        duration=payload["duration"],
        tech=tech_text,
    )
    sentence2 = (
        "The most frequent source IP {} appears across the sequence: {}."
    ).format(payload["likely_attacker"], activity)
    return sentence1 + " " + sentence2


def summarize(incident):
    # type: (Dict[str, Any]) -> Dict[str, str]
    payload = _incident_payload(incident)
    text = _call_gemini(SYSTEM_BRIEF, json.dumps(payload))
    if text:
        text = text.replace("\n", " ").strip()
        return {"text": text, "source": "gemini" if True else "template"}
    return {"text": template_summary(incident), "source": "template"}


def _strip_fences(text):
    # type: (str) -> str
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def _has_tech(incident, needles):
    # type: (Dict[str, Any], List[str]) -> bool
    ids = []
    for tech in incident.get("techniques") or []:
        if isinstance(tech, dict):
            ids.append(tech.get("id") or "")
        else:
            ids.append(str(tech))
    return any(n in ids for n in needles)


def template_prevention(incident):
    # type: (Dict[str, Any]) -> List[Dict[str, str]]
    # Illustrative drafts, not real vendor syntax; in production they would go
    # through the CrowdStrike Falcon and Palo Alto APIs.
    asset = incident.get("asset") or "UNKNOWN"
    source_ip = incident.get("likely_attacker") or "0.0.0.0"
    criticality = incident.get("criticality") or "MEDIUM"
    actions = [
        {
            "tool": "EDR",
            "action": "Isolate host",
            "command": 'Invoke-FalconHostIsolation -Hostname "{}" -Severity "{}"'.format(
                asset, criticality
            ),
            "rationale": "Contain the affected asset so the process tree cannot spread.",
        },
        {
            "tool": "Firewall",
            "action": "Block source IP",
            "command": 'set rulebase security rules "Block-Brute-Force" source {} action drop'.format(
                source_ip
            ),
            "rationale": "Drop further packets from the most frequent source IP on this incident.",
        },
    ]
    if _has_tech(incident, ["T1110", "T1078"]):
        actions.append(
            {
                "tool": "Identity",
                "action": "Reset credentials",
                "command": 'Reset-AdmPwd -Identity "{}" -Reason "Suspected credential compromise"'.format(
                    asset
                ),
                "rationale": "Brute force or valid-account activity means passwords may already be known.",
            }
        )
    return actions


def _validate_actions(raw):
    # type: (Any) -> Optional[List[Dict[str, str]]]
    if not isinstance(raw, list) or not (2 <= len(raw) <= 3):
        return None
    actions = []  # type: List[Dict[str, str]]
    for item in raw:
        if not isinstance(item, dict):
            return None
        tool = str(item.get("tool") or "")
        if tool not in ALLOWED_TOOLS:
            return None
        action = str(item.get("action") or "").strip()
        command = str(item.get("command") or "").strip()
        rationale = str(item.get("rationale") or "").strip()
        if not action or not command or not rationale:
            return None
        actions.append(
            {"tool": tool, "action": action, "command": command, "rationale": rationale}
        )
    return actions


def draft_prevention(incident):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    user = json.dumps(_incident_payload(incident))
    text = _call_gemini(SYSTEM_PREVENTION, user)
    if text:
        try:
            parsed = json.loads(_strip_fences(text))
            actions = _validate_actions(parsed)
            if actions:
                return {"actions": actions, "source": "gemini"}
        except Exception:
            pass
    return {"actions": template_prevention(incident), "source": "template"}
