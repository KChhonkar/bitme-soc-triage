// BitMe console: replay N alerts, fetch correlated incidents, show briefs/prevention.
// Visual class names match the Figma export; numbers come from the FastAPI backend.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import {
  getAlerts,
  getAudit,
  getHealth,
  getIncident,
  getIncidents,
  postDecision,
  postExecute,
  postInject,
  postPrevention,
  postSummarize,
  type AuditRow,
  type BriefSource,
  type CompactAlert,
  type Incident,
  type IncidentStats,
  type PreventionAction,
  type Severity,
} from "./api";

const CONFIDENCE_FORMULA =
  "100 × (0.5 × share of alerts with a MITRE id + 0.3 × min(1, distinct techniques / 3) + 0.2 × min(1, alert count / 10))";

const EMPTY_STATS: IncidentStats = {
  alerts_received: 0,
  alerts_in_incidents: 0,
  noise_suppressed_pct: 0,
  incidents_open: 0,
  awaiting_decision: 0,
};

function Icon({
  name,
  size = 14,
}: {
  name: "sun" | "moon" | "play" | "pause" | "reset" | "chevron" | "check" | "edit" | "x";
  size?: number;
}) {
  const paths: Record<string, ReactNode> = {
    sun: (
      <>
        <circle cx="12" cy="12" r="3.5" />
        <path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.65 17.65l1.42 1.42M2 12h2M20 12h2M4.93 19.07l1.42-1.42M17.65 6.35l1.42-1.42" />
      </>
    ),
    moon: <path d="M20.2 15.2A8.4 8.4 0 0 1 8.8 3.8 8.5 8.5 0 1 0 20.2 15.2Z" />,
    play: <path d="m8 5 11 7-11 7V5Z" />,
    pause: (
      <>
        <path d="M8 5v14" />
        <path d="M16 5v14" />
      </>
    ),
    reset: (
      <>
        <path d="M4 4v6h6" />
        <path d="M5.6 18.4A8 8 0 1 0 4 10" />
      </>
    ),
    chevron: <path d="m7 10 5 5 5-5" />,
    check: <path d="m5 12 4 4L19 6" />,
    edit: (
      <>
        <path d="M12 20h9" />
        <path d="m16.5 3.5 4 4L9 19l-5 1 1-5 11.5-11.5Z" />
      </>
    ),
    x: (
      <>
        <path d="m6 6 12 12" />
        <path d="m18 6-12 12" />
      </>
    ),
  };
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name]}
    </svg>
  );
}

function Button({
  children,
  variant = "secondary",
  onClick,
  disabled,
  className = "",
  title,
}: {
  children: ReactNode;
  variant?: "primary" | "secondary" | "ghost" | "success";
  onClick?: () => void;
  disabled?: boolean;
  className?: string;
  title?: string;
}) {
  return (
    <button
      type="button"
      title={title}
      className={`btn btn-${variant} ${className}`}
      onClick={onClick}
      disabled={disabled}
    >
      {children}
    </button>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`severity severity-${severity.toLowerCase()}`}>{severity}</span>;
}

function Metric({
  label,
  children,
  className = "",
}: {
  label: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`metric ${className}`}>
      <span className="eyebrow">{label}</span>
      <div className="metric-value">{children}</div>
    </div>
  );
}

function formatClock(iso: string) {
  const d = new Date(iso.includes("T") ? iso : iso.replace(" ", "T"));
  if (Number.isNaN(d.getTime())) return iso.slice(11, 19) || iso;
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

function sourceLabel(source: BriefSource | undefined) {
  if (source === "gemini") return "Live AI";
  if (source === "template") return "Template fallback";
  return "";
}

function ActivityChart({
  running,
  alerts,
  received,
  incidents,
}: {
  running: boolean;
  alerts: CompactAlert[];
  received: number;
  incidents: Incident[];
}) {
  const { path, fill, markers, labels } = useMemo(() => {
    const slice = alerts.slice(0, received);
    if (slice.length === 0) {
      return {
        path: "M0 53 L1360 53",
        fill: "M0 58 L0 53 L1360 53 L1360 58Z",
        markers: [] as { x: number; y: number }[],
        labels: ["--:--", "--:--", "--:--"],
      };
    }
    const hourKey = (ts: string) => ts.slice(0, 13);
    const pad = (n: number) => String(n).padStart(2, "0");
    const stamp = (d: Date) =>
      `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}`;
    const counts = new Map<string, number>();
    for (const row of slice) {
      const key = hourKey(row.ts);
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const keys = Array.from(counts.keys()).sort();
    const first = new Date(keys[0] + ":00:00").getTime();
    const last = new Date(keys[keys.length - 1] + ":00:00").getTime();
    const hours: string[] = [];
    for (let t = first; t <= last; t += 60 * 60 * 1000) {
      hours.push(stamp(new Date(t)));
    }
    const values = hours.map((h) => counts.get(h) ?? 0);
    const max = Math.max(1, ...values);
    const width = 1360;
    const points = values.map((v, i) => {
      const x = hours.length === 1 ? 0 : (i / (hours.length - 1)) * width;
      const y = 58 - (v / max) * 40;
      return { x, y };
    });
    const line = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(" ");
    const fillPath = `M0 58 ${line} L${width} 58Z`;
    const xAt = (iso: string) => {
      const t = new Date(iso).getTime();
      if (last === first) return 0;
      return ((t - first) / (last - first)) * width;
    };
    const marks = incidents.map((inc) => {
      const x = xAt(inc.first_seen);
      const hour = hourKey(inc.first_seen);
      const idx = hours.indexOf(hour);
      const y = idx >= 0 ? points[idx].y : 33;
      return { x, y };
    });
    const labelAt = (t: number) =>
      new Date(t).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", hour12: false });
    return {
      path: line,
      fill: fillPath,
      markers: marks,
      labels: [labelAt(first), labelAt((first + last) / 2), labelAt(last)],
    };
  }, [alerts, received, incidents]);

  return (
    <div className="chart-wrap">
      <div className="chart-label">Alerts per hour (replay time)</div>
      <svg className={running ? "chart chart-running" : "chart"} viewBox="0 0 1360 70" preserveAspectRatio="none">
        <defs>
          <linearGradient id="chartFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="currentColor" stopOpacity=".16" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path className="gridline" d="M0 20H1360M0 45H1360" />
        <path className="chart-fill" d={fill} />
        <path className="chart-line" d={path} />
        {markers.map((m, i) => (
          <g key={`${m.x}-${i}`}>
            <path className="incident-marker" d={`M${m.x.toFixed(1)} 9V61`} />
            <circle className="marker-dot" cx={m.x} cy={m.y} r="3" />
          </g>
        ))}
      </svg>
      <div className="chart-times">
        {labels.map((label) => (
          <span key={label}>{label}</span>
        ))}
      </div>
    </div>
  );
}

export default function App() {
  const [dark, setDark] = useState(false);
  const [running, setRunning] = useState(false);
  const [received, setReceived] = useState(0);
  const [speed, setSpeed] = useState(1);
  const [backendDown, setBackendDown] = useState(false);
  const [total, setTotal] = useState(3000);
  const [aiError, setAiError] = useState("");
  const [handled, setHandled] = useState<Incident[]>([]);
  const [queue, setQueue] = useState<Incident[]>([]);
  const [stats, setStats] = useState<IncidentStats>(EMPTY_STATS);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<Incident | null>(null);
  const [allAlerts, setAllAlerts] = useState<CompactAlert[]>([]);
  const [generatingBrief, setGeneratingBrief] = useState(false);
  const [generatingRule, setGeneratingRule] = useState(false);
  const [ruleVisible, setRuleVisible] = useState(false);
  const [toast, setToast] = useState<{ message: string; note: string } | null>(null);
  const [editing, setEditing] = useState(false);
  const [briefs, setBriefs] = useState<Record<string, { text: string; source: BriefSource }>>({});
  const [rules, setRules] = useState<Record<string, { actions: PreventionAction[]; source: BriefSource }>>({});
  const [auditOpen, setAuditOpen] = useState(true);
  const [audit, setAudit] = useState<AuditRow[]>([]);
  const [actionError, setActionError] = useState("");
  const [draftText, setDraftText] = useState("");
  const [enteringIds, setEnteringIds] = useState<Set<string>>(() => new Set());

  const receivedRef = useRef(0);
  const lastFetchRef = useRef(-999);
  const selectedRef = useRef<string | null>(null);
  const speedRef = useRef(1);
  const totalRef = useRef(3000);
  const seenIdsRef = useRef<Set<string>>(new Set());

  receivedRef.current = received;
  selectedRef.current = selectedId;
  speedRef.current = speed;
  totalRef.current = total;

  const selected = detail && detail.id === selectedId ? detail : queue.find((i) => i.id === selectedId) ?? null;
  const briefRecord = selected ? briefs[selected.id] : undefined;
  const brief = editing ? draftText : (briefRecord?.text ?? "");
  const rule = selected ? rules[selected.id] : undefined;

  const loadAudit = useCallback(async () => {
    const rows = await getAudit();
    setAudit(rows);
  }, []);

  const fetchQueue = useCallback(async (n: number) => {
    lastFetchRef.current = n;
    const data = await getIncidents(n);
    const seen = seenIdsRef.current;
    const openList = data.incidents.filter((item) => item.status === "New");
    setHandled(data.incidents.filter((item) => item.status !== "New"));
    const newcomers = openList.filter((item) => !seen.has(item.id)).map((item) => item.id);
    data.incidents.forEach((item) => seen.add(item.id));
    setQueue(openList);
    setEnteringIds(new Set(newcomers));
    setStats(data.stats);
    const currentId = selectedRef.current;
    const stillThere = currentId ? openList.some((item) => item.id === currentId) : false;
    const nextId = stillThere ? currentId : openList[0]?.id ?? null;
    selectedRef.current = nextId;
    setSelectedId(nextId);
    if (!nextId) {
      setDetail(null);
      return;
    }
    try {
      const full = await getIncident(nextId, n);
      setDetail(full);
    } catch {
      setDetail(null);
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const health = await getHealth();
        setTotal(health.alerts_loaded);
        totalRef.current = health.alerts_loaded;
        setAiError(health.gemini_configured ? health.ai_error ?? "" : "No Gemini key in backend/.env");
        if (cancelled) return;
        setBackendDown(false);
        const [alerts, auditRows] = await Promise.all([getAlerts(), getAudit()]);
        if (cancelled) return;
        setAllAlerts(alerts);
        setAudit(auditRows);
        await fetchQueue(0);
      } catch {
        if (!cancelled) setBackendDown(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [fetchQueue]);

  useEffect(() => {
    if (!running || backendDown) return;
    const timer = window.setInterval(() => {
      const step = 2 * speedRef.current;
      const prev = receivedRef.current;
      const next = Math.min(totalRef.current, prev + step);
      setReceived(next);
      receivedRef.current = next;
      if (next - lastFetchRef.current >= 50 || next === totalRef.current) {
        fetchQueue(next).catch(() => setBackendDown(true));
      }
      if (next >= totalRef.current) setRunning(false);
    }, 100);
    return () => window.clearInterval(timer);
  }, [running, backendDown, fetchQueue]);

  useEffect(() => {
    if (!selectedId || backendDown) {
      if (!selectedId) setDetail(null);
      return;
    }
    getIncident(selectedId, receivedRef.current)
      .then(setDetail)
      .catch(() => setDetail(null));
  }, [selectedId, backendDown]);

  useEffect(() => {
    setRuleVisible(Boolean(selectedId && rules[selectedId]));
    setGeneratingRule(false);
    setEditing(false);
    setToast(null);
    setActionError("");
  }, [selectedId, rules]);

  useEffect(() => {
    if (!selectedId || backendDown) return;
    if (briefs[selectedId]) return;
    let cancelled = false;
    setGeneratingBrief(true);
    postSummarize(selectedId, receivedRef.current)
      .then((result) => {
        if (cancelled) return;
        setBriefs((all) => ({ ...all, [selectedId]: result }));
      })
      .catch((err: Error) => {
        if (!cancelled) setActionError(err.message || "Brief failed");
      })
      .finally(() => {
        if (!cancelled) setGeneratingBrief(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId, backendDown, briefs]);

  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 4500);
    return () => window.clearTimeout(timer);
  }, [toast]);

  function pauseFeed() {
    setRunning(false);
    fetchQueue(receivedRef.current).catch(() => setBackendDown(true));
  }

  function resetFeed() {
    setRunning(false);
    setReceived(0);
    receivedRef.current = 0;
    lastFetchRef.current = -999;
    setSelectedId(null);
    setDetail(null);
    setQueue([]);
    setHandled([]);
    seenIdsRef.current = new Set();
    setEnteringIds(new Set());
    setStats(EMPTY_STATS);
    setBriefs({});
    setRules({});
    setRuleVisible(false);
    fetchQueue(0).catch(() => setBackendDown(true));
  }

  function injectAttack() {
    postInject()
      .then(async (r) => {
        setTotal(r.alerts_loaded);
        totalRef.current = r.alerts_loaded;
        setAllAlerts(await getAlerts());
        setRunning(true);
      })
      .catch(() => setBackendDown(true));
  }

  function skipToEnd() {
    setReceived(totalRef.current);
    receivedRef.current = totalRef.current;
    setRunning(false);
    fetchQueue(totalRef.current).catch(() => setBackendDown(true));
  }

  function regenerateBrief() {
    if (!selected) return;
    setGeneratingBrief(true);
    setActionError("");
    postSummarize(selected.id, receivedRef.current)
      .then((result) => setBriefs((all) => ({ ...all, [selected.id]: result })))
      .catch((err: Error) => setActionError(err.message || "Brief failed"))
      .finally(() => setGeneratingBrief(false));
  }

  function generateRule() {
    if (!selected) return;
    setGeneratingRule(true);
    setActionError("");
    postPrevention(selected.id, receivedRef.current)
      .then((result) => {
        setRules((all) => ({ ...all, [selected.id]: result }));
        setRuleVisible(true);
      })
      .catch((err: Error) => setActionError(err.message || "Prevention draft failed"))
      .finally(() => setGeneratingRule(false));
  }

  function executeRule() {
    if (!selected) return;
    setActionError("");
    postExecute(selected.id, receivedRef.current)
      .then(async (result) => {
        setToast({ message: result.message, note: result.note });
        await loadAudit();
        await fetchQueue(receivedRef.current);
      })
      .catch((err: Error) => setActionError(err.message || "Execute failed"));
  }

  function decide(kind: "Approved" | "Modify" | "Rejected") {
    if (!selected) return;
    if (kind === "Modify") {
      setEditing(true);
      setDraftText(briefRecord?.text ?? "");
      return;
    }
    setActionError("");
    const note = kind === "Rejected" ? "Marked false positive" : "Incident confirmed";
    postDecision(selected.id, { decision: kind, note })
      .then(async () => {
        await loadAudit();
        await fetchQueue(receivedRef.current);
      })
      .catch((err: Error) => setActionError(err.message || "Decision failed"));
  }

  function saveBrief() {
    if (!selected) return;
    setActionError("");
    postDecision(selected.id, { decision: "Modified", note: "Analyst edited draft", brief: draftText })
      .then(async () => {
        setBriefs((all) => ({
          ...all,
          [selected.id]: { text: draftText, source: all[selected.id]?.source ?? "template" },
        }));
        setEditing(false);
        await loadAudit();
        await fetchQueue(receivedRef.current);
      })
      .catch((err: Error) => setActionError(err.message || "Save failed"));
  }

  const breakdown = selected?.score_breakdown ?? { criticality: 0, technique: 0, volume: 0 };
  const timeline = selected?.alerts ?? [];
  const feedDisabled = backendDown;

  return (
    <div className="app" data-theme={dark ? "dark" : "light"}>
      {backendDown && (
        <div className="error-banner" role="alert">
          Backend not reachable. Start it with: uvicorn main:app --port 8000
        </div>
      )}
      {aiError && !backendDown && (
        <div className="error-banner" role="alert">
          AI offline, using template fallback: {aiError}
        </div>
      )}
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">B</span>
          <span>BitMe</span>
        </div>
        <div className="topbar-actions">
          <div className="feed-status">
            <span className={running ? "live-dot live-dot-active" : "live-dot"} />
            Feed: {running ? "Live" : "Paused"}
          </div>
          <div className="control-group" aria-label="Feed controls">
            <Button variant="ghost" onClick={() => setRunning(true)} disabled={feedDisabled || running || received >= total}>
              <Icon name="play" /> Start
            </Button>
            <Button variant="ghost" onClick={pauseFeed} disabled={feedDisabled || !running}>
              <Icon name="pause" /> Pause
            </Button>
            <Button variant="ghost" onClick={resetFeed} disabled={feedDisabled}>
              <Icon name="reset" /> Reset
            </Button>
            <Button variant="ghost" onClick={injectAttack} disabled={feedDisabled}>
              + New attack
            </Button>
            <Button variant="ghost" onClick={skipToEnd} disabled={feedDisabled || received >= total}>
              Skip to end
            </Button>
          </div>
          <div className="control-group" aria-label="Replay speed">
            {[1, 2, 4].map((value) => (
              <Button
                key={value}
                variant="ghost"
                className={speed === value ? "speed-active" : ""}
                onClick={() => setSpeed(value)}
                disabled={feedDisabled}
              >
                {value}x
              </Button>
            ))}
          </div>
          <span className="top-divider" />
          <Button
            variant="ghost"
            className="icon-button"
            onClick={() => setDark((value) => !value)}
            title={dark ? "Switch to light theme" : "Switch to dark theme"}
          >
            <Icon name={dark ? "sun" : "moon"} size={16} />
          </Button>
          <div className="analyst">
            <span className="avatar">AS</span>
            <span>A. Sharma, Tier-1</span>
          </div>
        </div>
      </header>

      <section className="stats-section">
        <div className="metrics-grid">
          <Metric label="Alerts received">
            <span>{received.toLocaleString()}</span>
            <span className="metric-denom"> / {total.toLocaleString()}</span>
          </Metric>
          <Metric label="Noise suppressed">
            {stats.noise_suppressed_pct}
            <span className="metric-unit">%</span>
          </Metric>
          <Metric label="Incidents open">{stats.incidents_open}</Metric>
          <Metric label="Target (design estimate)">
            <span>42m</span>
            <span className="metric-arrow">→</span>
            <span>18m</span>
            <span className="reduction">-57%</span>
          </Metric>
          <Metric label="Awaiting decision">{stats.awaiting_decision}</Metric>
        </div>
        <ActivityChart running={running} alerts={allAlerts} received={received} incidents={queue} />
      </section>

      <main className="workspace">
        <aside className="queue-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">Incident queue</span>
              <span className="panel-count">{queue.length}</span>
            </div>
            <span className="sort-label">Risk score ↓</span>
          </div>
          <div className="queue-list">
            {queue.map((incident) => (
              <button
                type="button"
                className={`queue-row severity-edge-${incident.severity.toLowerCase()} ${
                  selected?.id === incident.id ? "queue-row-selected" : ""
                } ${enteringIds.has(incident.id) ? "queue-row-enter" : ""}`}
                key={incident.id}
                onClick={() => setSelectedId(incident.id)}
              >
                <div className="risk-score">{incident.score}</div>
                <div className="queue-main">
                  <div className="asset-line">
                    <span className="asset-name">{incident.asset}</span>
                    <SeverityBadge severity={incident.severity} />
                  </div>
                  <div className="queue-meta">
                    <span className="mono">{incident.id}</span>
                    <span>
                      {incident.alert_count} alerts · {incident.duration}
                    </span>
                  </div>
                </div>
                <span className={`status status-${incident.status.toLowerCase()}`}>{incident.status}</span>
              </button>
            ))}
            {queue.length === 0 && (
              <div className="queue-empty">
                <span>No incidents in queue</span>
                <span>Start the feed to receive alerts</span>
              </div>
            )}
          </div>
          {handled.length > 0 && (
            <div className="handled-list">
              <span className="eyebrow">Handled ({handled.length}), see audit log</span>
              {handled.map((h) => (
                <div className="handled-row" key={h.id}>
                  <span className="mono">{h.id}</span>
                  <span>{h.asset}</span>
                  <span className={`status status-${h.status.toLowerCase()}`}>{h.status}</span>
                </div>
              ))}
            </div>
          )}
          <div className="queue-caption">Ranked by asset criticality, not alert volume.</div>
        </aside>

        <section className="detail-panel">
          {!selected ? (
            <div className="detail-empty">
              <span>No incident selected</span>
              <span>Start the feed to receive alerts</span>
            </div>
          ) : (
            <>
              <div className="detail-scroll">
                <div className="incident-header">
                  <div>
                    <div className="incident-kicker">
                      <span className="mono">{selected.id}</span>
                      <span>·</span>
                      <span>First detected {formatClock(selected.first_seen)}</span>
                    </div>
                    <div className="incident-title-row">
                      <h1>{selected.asset}</h1>
                      <SeverityBadge severity={selected.severity} />
                    </div>
                  </div>
                  <div className="incident-owner">
                    <span className="eyebrow">Owner</span>
                    <span>{selected.owner}</span>
                  </div>
                </div>
                <div className="mitre-row">
                  <span className="eyebrow">MITRE ATT&amp;CK</span>
                  {selected.techniques.map((technique) => (
                    <span className="mitre-chip" key={technique.id} title={technique.name}>
                      {technique.id}
                    </span>
                  ))}
                </div>

                <section className="detail-section risk-section">
                  <div className="section-title-row">
                    <h2>Risk score breakdown</h2>
                    <span className="total-score">
                      <strong>{selected.score}</strong> / 100
                    </span>
                  </div>
                  <div className="stacked-bar" aria-label={`Risk score ${selected.score} out of 100`}>
                    <span className="bar-criticality" style={{ width: `${breakdown.criticality}%` }} />
                    <span className="bar-technique" style={{ width: `${breakdown.technique}%` }} />
                    <span className="bar-volume" style={{ width: `${breakdown.volume}%` }} />
                  </div>
                  <div className="risk-table">
                    {[
                      ["Asset criticality", "50%", breakdown.criticality],
                      ["Technique severity", "30%", breakdown.technique],
                      ["Alert volume", "20%", breakdown.volume],
                    ].map(([label, weight, points], index) => (
                      <div className="risk-cell" key={String(label)}>
                        <span className={`risk-key risk-key-${index}`} />
                        <span>{label}</span>
                        <span className="muted">{weight}</span>
                        <strong className="mono">{points} pts</strong>
                      </div>
                    ))}
                  </div>
                  <p className="section-note">
                    Asset criticality is looked up from the asset inventory, not from the raw log.
                  </p>
                </section>

                <section className="detail-section timeline-section">
                  <div className="section-title-row">
                    <h2>Attack timeline</h2>
                    <span className="section-meta">
                      {timeline.length} correlated alerts · {selected.duration}
                    </span>
                  </div>
                  <div className="timeline">
                    {timeline.map((item, index) => (
                      <div className="timeline-row" key={`${selected.id}-${index}`}>
                        <span className="timeline-dot" />
                        <time>{formatClock(item.timestamp)}</time>
                        <span className="mitre-chip" title={item.technique_name}>
                          {item.mitre_id || "—"}
                        </span>
                        <span className="timeline-event">{item.description}</span>
                        <span className="timeline-source">
                          {item.source_ip} → {item.destination_ip}
                        </span>
                      </div>
                    ))}
                  </div>
                </section>

                <section className="detail-section">
                  <div className="section-title-row">
                    <h2>
                      Draft brief <span className="unverified">(AI-generated, unverified)</span>
                    </h2>
                    <div className="ai-actions">
                      <span title={CONFIDENCE_FORMULA}>Correlation confidence {selected.confidence}%</span>
                      <button type="button" onClick={regenerateBrief} disabled={generatingBrief}>
                        Regenerate
                      </button>
                    </div>
                  </div>
                  <div className="ai-brief">
                    {generatingBrief && !editing ? (
                      <p className="muted">Generating...</p>
                    ) : editing ? (
                      <textarea
                        value={draftText}
                        autoFocus
                        onChange={(event) => setDraftText(event.target.value)}
                        aria-label="Edit incident brief"
                      />
                    ) : (
                      <p>{brief || "Select an incident to generate a brief."}</p>
                    )}
                    {briefRecord && !generatingBrief && (
                      <span className="source-label">{sourceLabel(briefRecord.source)}</span>
                    )}
                    {editing && (
                      <div className="edit-actions">
                        <Button variant="primary" onClick={saveBrief}>
                          Save brief
                        </Button>
                        <Button variant="ghost" onClick={() => setEditing(false)}>
                          Done
                        </Button>
                      </div>
                    )}
                  </div>
                </section>

                <section className="detail-section prevention-section">
                  <div className="section-title-row">
                    <div>
                      <h2>AI recommended prevention</h2>
                      <p className="section-subtitle">Review generated controls before execution.</p>
                    </div>
                    {!ruleVisible && (
                      <Button variant="secondary" onClick={generateRule} disabled={generatingRule}>
                        {generatingRule ? (
                          <>
                            <span className="spinner" /> Generating...
                          </>
                        ) : (
                          "Generate prevention rule"
                        )}
                      </Button>
                    )}
                  </div>
                  {ruleVisible && rule && (
                    <>
                      <div className="command-layout">
                        <div className="terminal">
                          <span className="terminal-label">COMMANDS · DRAFT</span>
                          {rule.actions.map((action) => (
                            <div className="terminal-action" key={`${action.tool}-${action.command}`}>
                              <span className="terminal-tool">
                                {action.tool} · {action.action}
                              </span>
                              <code>
                                <span>&gt;</span> {action.command}
                              </code>
                              <span className="terminal-rationale">{action.rationale}</span>
                            </div>
                          ))}
                          <span className="source-label source-label-on-dark">{sourceLabel(rule.source)}</span>
                        </div>
                        <Button variant="success" className="execute-button" onClick={executeRule}>
                          <Icon name="play" /> Execute rule
                        </Button>
                      </div>
                      <p className="section-note">
                        Commands are drafted by AI and run only when the analyst clicks Execute.
                      </p>
                    </>
                  )}
                </section>
                {actionError && <p className="action-error">{actionError}</p>}
              </div>

              <div className="decision-bar">
                <div className="decision-item">
                  <Button variant="primary" onClick={() => decide("Approved")}>
                    <Icon name="check" /> Approve
                  </Button>
                  <span>Confirms the incident is real and logs the decision</span>
                </div>
                <div className="decision-item">
                  <Button variant="secondary" onClick={() => decide("Modify")}>
                    <Icon name="edit" /> Modify
                  </Button>
                  <span>Edit the brief before deciding</span>
                </div>
                <div className="decision-item decision-item-wide">
                  <Button variant="secondary" onClick={() => decide("Rejected")}>
                    <Icon name="x" /> Reject as false positive
                  </Button>
                  <span>Closes the incident as a false positive and logs it</span>
                </div>
              </div>
            </>
          )}
        </section>
      </main>

      <section className={auditOpen ? "audit-drawer audit-open" : "audit-drawer"}>
        <button className="audit-handle" type="button" onClick={() => setAuditOpen((value) => !value)}>
          <span className="audit-handle-title">
            Audit log <span>{audit.length}</span>
          </span>
          <span className="audit-handle-right">
            Append-only activity record <Icon name="chevron" />
          </span>
        </button>
        <div className="audit-content">
          <div className="audit-grid audit-head">
            <span>Time</span>
            <span>Analyst</span>
            <span>Incident</span>
            <span>Decision</span>
            <span>Action</span>
            <span>Note</span>
          </div>
          <div className="audit-rows">
            {audit.length === 0 && <div className="audit-empty">No decisions yet</div>}
            {audit.map((row, index) => (
              <div className="audit-grid audit-row" key={`${row.ts}-${index}`}>
                <span className="mono">{formatClock(row.ts)}</span>
                <span>{row.analyst}</span>
                <span className="mono">{row.incident}</span>
                <span>{row.decision}</span>
                <span>{row.action}</span>
                <span className="muted">{row.note}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {toast && (
        <div className="toast" role="status">
          <span className="toast-icon">
            <Icon name="check" />
          </span>
          <div>
            <strong>{toast.message}</strong>
            <span>{toast.note}</span>
          </div>
        </div>
      )}
    </div>
  );
}
