export type Severity = "Critical" | "High" | "Low";
export type IncidentStatus = "New" | "Reviewed" | "Closed" | "Contained";
export type BriefSource = "gemini" | "template";

export type Technique = {
  id: string;
  name: string;
};

export type ScoreBreakdown = {
  criticality: number;
  technique: number;
  volume: number;
};

export type AlertRow = {
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  description: string;
  mitre_id: string;
  raw_severity: string;
  technique_name: string;
};

export type Incident = {
  id: string;
  asset: string;
  owner: string;
  criticality: string;
  alert_count: number;
  first_seen: string;
  last_seen: string;
  duration: string;
  techniques: Technique[];
  source_ips: string[];
  likely_attacker: string;
  score: number;
  severity: Severity;
  score_breakdown: ScoreBreakdown;
  confidence: number;
  status: IncidentStatus;
  alerts?: AlertRow[];
};

export type IncidentStats = {
  alerts_received: number;
  alerts_in_incidents: number;
  noise_suppressed_pct: number;
  incidents_open: number;
  awaiting_decision: number;
  handled?: number;
};

export type IncidentsResponse = {
  incidents: Incident[];
  stats: IncidentStats;
};

export type CompactAlert = {
  i: number;
  ts: string;
  asset: string;
  desc: string;
  mitre: string;
  sev: string;
};

export type AuditRow = {
  ts: string;
  analyst: string;
  incident: string;
  decision: string;
  action: string;
  note: string;
};

export type PreventionAction = {
  tool: string;
  action: string;
  command: string;
  rationale: string;
};

/** Relative /api URLs so Vite's proxy (dev) or same-origin (prod) hits FastAPI. */
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(body || `Request failed (${response.status})`);
  }
  return (await response.json()) as T;
}

export function getHealth() {
  return request<{ status: string; alerts_loaded: number; gemini_configured: boolean; ai_error?: string }>(
    "/api/health",
  );
}

export function getAlerts() {
  return request<CompactAlert[]>("/api/alerts");
}

export function getIncidents(upto: number) {
  return request<IncidentsResponse>(`/api/incidents?upto=${upto}`);
}

export function getIncident(id: string, upto: number) {
  return request<Incident>(`/api/incidents/${encodeURIComponent(id)}?upto=${upto}`);
}

export function postSummarize(id: string, upto: number) {
  return request<{ text: string; source: BriefSource }>(
    `/api/incidents/${encodeURIComponent(id)}/summarize?upto=${upto}`,
    { method: "POST" },
  );
}

export function postPrevention(id: string, upto: number) {
  return request<{ actions: PreventionAction[]; source: BriefSource }>(
    `/api/incidents/${encodeURIComponent(id)}/prevention?upto=${upto}`,
    { method: "POST" },
  );
}

export function postDecision(
  id: string,
  body: { decision: "Approved" | "Modified" | "Rejected"; note?: string; brief?: string },
) {
  return request<{ status: IncidentStatus }>(
    `/api/incidents/${encodeURIComponent(id)}/decision`,
    { method: "POST", body: JSON.stringify(body) },
  );
}

export function postExecute(id: string, upto: number) {
  return request<{ message: string; note: string }>(
    `/api/incidents/${encodeURIComponent(id)}/execute?upto=${upto}`,
    { method: "POST" },
  );
}

export function getAudit() {
  return request<AuditRow[]>("/api/audit");
}

export function postInject() {
  return request<{ asset: string; alerts_loaded: number }>("/api/inject", { method: "POST" });
}
