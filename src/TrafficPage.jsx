import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Clock3,
  Filter,
  Globe2,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  XCircle,
  Zap,
} from "lucide-react";

const REQUEST_TIMEOUT = 6000;

function getApiCandidates() {
  if (typeof window === "undefined") {
    return ["http://127.0.0.1:8000", "http://localhost:8000"];
  }

  const host = window.location.hostname || "localhost";
  const protocol = window.location.protocol || "http:";

  return [
    `${protocol}//${host}:8000`,
    "http://127.0.0.1:8000",
    "http://localhost:8000",
  ].filter((value, index, array) => array.indexOf(value) === index);
}

async function apiFetch(path) {
  const candidates = getApiCandidates();
  let lastError = null;

  for (const baseUrl of candidates) {
    const controller = new AbortController();

    const timeout = setTimeout(() => {
      controller.abort();
    }, REQUEST_TIMEOUT);

    try {
      const response = await fetch(`${baseUrl}${path}`, {
        method: "GET",
        cache: "no-store",
        headers: {
          Accept: "application/json",
          "Cache-Control": "no-cache",
        },
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (!response.ok) {
        throw new Error(
          `Request failed with status ${response.status}`
        );
      }

      return await response.json();
    } catch (error) {
      clearTimeout(timeout);
      lastError = error;
    }
  }

  throw lastError || new Error("Unable to connect to A²FaaS backend");
}

function normalizeEvents(payload) {
  const source =
    payload?.events ??
    payload?.recent_events ??
    payload?.items ??
    payload?.results ??
    payload;

  if (!Array.isArray(source)) {
    return [];
  }

  return source.map((event, index) => ({
    id:
      event?.id ??
      event?.event_id ??
      event?.request_id ??
      `event-${index}`,

    requestId:
      event?.request_id ??
      event?.id ??
      `REQ-${index + 1}`,

    timestamp:
      event?.timestamp ??
      event?.created_at ??
      event?.time ??
      null,

    method:
      String(event?.method ?? "GET").toUpperCase(),

    path:
      event?.path ??
      event?.request_path ??
      "/",

    sourceIp:
      event?.source_ip ??
      event?.client_ip ??
      event?.ip ??
      "Unknown",

    decision:
      String(event?.decision ?? "UNKNOWN").toUpperCase(),

    riskScore: Number(
      event?.risk_score ??
      event?.risk ??
      0
    ),

    riskLevel:
      String(
        event?.risk_level ??
        event?.riskLevel ??
        "low"
      ).toLowerCase(),

    mlPrediction:
      event?.ml_prediction ??
      event?.prediction ??
      "Unknown",

    identityVerified:
      Boolean(
        event?.identity_verified ??
        event?.identityVerified ??
        false
      ),

    deviceTrusted:
      Boolean(
        event?.device_trusted ??
        event?.deviceTrusted ??
        false
      ),
  }));
}

function formatTimestamp(timestamp) {
  if (!timestamp) {
    return "Time unavailable";
  }

  const date = new Date(timestamp);

  if (Number.isNaN(date.getTime())) {
    return String(timestamp);
  }

  return date.toLocaleString([], {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function getRiskLabel(score) {
  if (score >= 0.75) return "High";
  if (score >= 0.4) return "Medium";
  return "Low";
}

function getDecisionIcon(decision) {
  if (decision === "ALLOW") return CheckCircle2;
  if (decision === "BLOCK") return XCircle;
  return AlertTriangle;
}

function getDecisionClass(decision) {
  if (decision === "ALLOW") return "allow";
  if (decision === "BLOCK") return "block";
  return "challenge";
}

function getRiskClass(score) {
  if (score >= 0.75) return "high";
  if (score >= 0.4) return "medium";
  return "low";
}

function StatCard({
  icon: Icon,
  label,
  value,
  description,
  tone,
}) {
  return (
    <div className="traffic-stat-card">
      <div className={`traffic-stat-icon ${tone}`}>
        <Icon size={19} />
      </div>

      <div className="traffic-stat-content">
        <span>{label}</span>

        <strong>{value}</strong>

        <small>{description}</small>
      </div>
    </div>
  );
}

function DecisionBadge({ decision }) {
  const Icon = getDecisionIcon(decision);

  return (
    <span
      className={`traffic-decision-badge ${getDecisionClass(
        decision
      )}`}
    >
      <Icon size={13} />
      {decision}
    </span>
  );
}

function RiskBadge({ score }) {
  const percentage = Math.max(
    0,
    Math.min(100, score * 100)
  );

  return (
    <div className="traffic-risk-cell">
      <div className="traffic-risk-top">
        <span className={getRiskClass(score)}>
          {getRiskLabel(score)}
        </span>

        <strong>
          {percentage.toFixed(1)}%
        </strong>
      </div>

      <div className="traffic-risk-track">
        <div
          className={`traffic-risk-fill ${getRiskClass(
            score
          )}`}
          style={{
            width: `${Math.max(2, percentage)}%`,
          }}
        />
      </div>
    </div>
  );
}

function EmptyTrafficState({ onRefresh, refreshing }) {
  return (
    <div className="traffic-empty-state">
      <div className="traffic-empty-icon">
        <Activity size={30} />
      </div>

      <h3>No traffic events yet</h3>

      <p>
        A²FaaS has not recorded any request
        telemetry yet. Analyze a request through
        the Firewall module and the event will
        appear here automatically.
      </p>

      <button
        type="button"
        className="traffic-refresh-button"
        onClick={onRefresh}
        disabled={refreshing}
      >
        <RefreshCw
          size={15}
          className={
            refreshing
              ? "traffic-spin"
              : ""
          }
        />
        {refreshing
          ? "Refreshing..."
          : "Refresh telemetry"}
      </button>
    </div>
  );
}

export default function TrafficPage() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [connectionError, setConnectionError] =
    useState(false);
  const [search, setSearch] = useState("");
  const [decisionFilter, setDecisionFilter] =
    useState("ALL");
  const [riskFilter, setRiskFilter] =
    useState("ALL");

  const refreshLock = useRef(false);

  const loadTraffic = useCallback(
    async (manual = false) => {
      if (refreshLock.current) {
        return;
      }

      refreshLock.current = true;

      if (manual) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      try {
        const data = await apiFetch(
          "/api/requests/recent?limit=100"
        );

        const normalized =
          normalizeEvents(data);

        setEvents(normalized);
        setConnectionError(false);
      } catch (error) {
        console.error(
          "Traffic telemetry error:",
          error
        );

        setConnectionError(true);
      } finally {
        setLoading(false);
        setRefreshing(false);
        refreshLock.current = false;
      }
    },
    []
  );

  useEffect(() => {
    loadTraffic();

    const interval = setInterval(() => {
      loadTraffic();
    }, 15000);

    return () => {
      clearInterval(interval);
    };
  }, [loadTraffic]);

  const filteredEvents = useMemo(() => {
    const query = search.trim().toLowerCase();

    return events.filter((event) => {
      const matchesSearch =
        !query ||
        event.path
          .toLowerCase()
          .includes(query) ||
        event.method
          .toLowerCase()
          .includes(query) ||
        event.sourceIp
          .toLowerCase()
          .includes(query) ||
        event.decision
          .toLowerCase()
          .includes(query);

      const matchesDecision =
        decisionFilter === "ALL" ||
        event.decision === decisionFilter;

      const riskLabel =
        event.riskScore >= 0.75
          ? "HIGH"
          : event.riskScore >= 0.4
            ? "MEDIUM"
            : "LOW";

      const matchesRisk =
        riskFilter === "ALL" ||
        riskLabel === riskFilter;

      return (
        matchesSearch &&
        matchesDecision &&
        matchesRisk
      );
    });
  }, [
    events,
    search,
    decisionFilter,
    riskFilter,
  ]);

  const trafficStats = useMemo(() => {
    const total = events.length;

    const allowed = events.filter(
      (event) =>
        event.decision === "ALLOW"
    ).length;

    const challenged = events.filter(
      (event) =>
        event.decision === "CHALLENGE"
    ).length;

    const blocked = events.filter(
      (event) =>
        event.decision === "BLOCK"
    ).length;

    const highRisk = events.filter(
      (event) =>
        event.riskScore >= 0.75
    ).length;

    const averageRisk =
      total > 0
        ? events.reduce(
            (sum, event) =>
              sum + event.riskScore,
            0
          ) / total
        : 0;

    return {
      total,
      allowed,
      challenged,
      blocked,
      highRisk,
      averageRisk,
    };
  }, [events]);

  return (
    <>
      <style>{`
        .traffic-page {
          padding: 28px 30px 34px;
          max-width: 1500px;
          margin: 0 auto;
        }

        .traffic-page-header {
          display: flex;
          justify-content: space-between;
          align-items: flex-end;
          gap: 20px;
          margin-bottom: 22px;
        }

        .traffic-eyebrow {
          display: flex;
          align-items: center;
          gap: 8px;
          color: #6474df;
          font-size: 10px;
          font-weight: 850;
          letter-spacing: 1.3px;
          margin-bottom: 8px;
        }

        .traffic-eyebrow-line {
          width: 18px;
          height: 2px;
          border-radius: 99px;
          background: #6474df;
        }

        .traffic-page-title {
          margin: 0;
          color: #172033;
          font-size: 30px;
          line-height: 1.15;
          font-weight: 850;
          letter-spacing: -0.7px;
        }

        .traffic-page-description {
          margin: 8px 0 0;
          color: #7c879a;
          font-size: 13px;
          line-height: 1.6;
          max-width: 650px;
        }

        .traffic-header-actions {
          display: flex;
          align-items: center;
          gap: 9px;
        }

        .traffic-live-indicator {
          display: inline-flex;
          align-items: center;
          gap: 7px;
          padding: 9px 12px;
          border: 1px solid #dfe7e2;
          border-radius: 9px;
          background: #f7fbf8;
          color: #28764f;
          font-size: 10px;
          font-weight: 800;
        }

        .traffic-live-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: #43a66d;
          box-shadow: 0 0 0 4px rgba(67,166,109,.10);
        }

        .traffic-header-refresh {
          width: 37px;
          height: 37px;
          display: flex;
          align-items: center;
          justify-content: center;
          border: 1px solid #dfe5ee;
          border-radius: 9px;
          background: #ffffff;
          color: #59677e;
          cursor: pointer;
          transition: .2s ease;
        }

        .traffic-header-refresh:hover {
          border-color: #cbd4e3;
          color: #4f62d4;
          transform: translateY(-1px);
        }

        .traffic-header-refresh:disabled {
          opacity: .6;
          cursor: wait;
        }

        .traffic-spin {
          animation: traffic-spin 0.9s linear infinite;
        }

        @keyframes traffic-spin {
          to {
            transform: rotate(360deg);
          }
        }

        .traffic-stat-grid {
          display: grid;
          grid-template-columns: repeat(5, minmax(0, 1fr));
          gap: 12px;
          margin-bottom: 16px;
        }

        .traffic-stat-card {
          min-height: 108px;
          display: flex;
          align-items: flex-start;
          gap: 12px;
          padding: 18px;
          border: 1px solid #e2e7ef;
          border-radius: 14px;
          background: #ffffff;
          box-shadow: 0 7px 24px rgba(30,45,80,.035);
        }

        .traffic-stat-icon {
          width: 38px;
          height: 38px;
          flex: 0 0 38px;
          display: flex;
          align-items: center;
          justify-content: center;
          border-radius: 10px;
        }

        .traffic-stat-icon.blue {
          background: #eef2ff;
          color: #5c6fe0;
        }

        .traffic-stat-icon.green {
          background: #edf8f2;
          color: #31805a;
        }

        .traffic-stat-icon.amber {
          background: #fff7e6;
          color: #aa7b24;
        }

        .traffic-stat-icon.red {
          background: #fff0f0;
          color: #c45757;
        }

        .traffic-stat-icon.purple {
          background: #f2efff;
          color: #745dcc;
        }

        .traffic-stat-content {
          min-width: 0;
        }

        .traffic-stat-content span {
          display: block;
          color: #7d899d;
          font-size: 9px;
          font-weight: 800;
          letter-spacing: .8px;
          text-transform: uppercase;
          margin-bottom: 5px;
        }

        .traffic-stat-content strong {
          display: block;
          color: #172033;
          font-size: 23px;
          line-height: 1;
          font-weight: 850;
          margin-bottom: 6px;
        }

        .traffic-stat-content small {
          display: block;
          color: #98a1b1;
          font-size: 9px;
          line-height: 1.4;
        }

        .traffic-toolbar {
          display: flex;
          align-items: center;
          gap: 10px;
          padding: 12px;
          margin-bottom: 12px;
          border: 1px solid #e2e7ef;
          border-radius: 13px;
          background: #ffffff;
        }

        .traffic-search {
          flex: 1;
          min-width: 220px;
          height: 38px;
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 0 12px;
          border: 1px solid #e1e6ee;
          border-radius: 9px;
          background: #fafbfd;
          color: #8b95a7;
        }

        .traffic-search:focus-within {
          border-color: #aeb8ee;
          background: #ffffff;
          box-shadow: 0 0 0 3px rgba(100,116,223,.08);
        }

        .traffic-search input {
          width: 100%;
          border: 0;
          outline: 0;
          background: transparent;
          color: #263148;
          font-size: 12px;
        }

        .traffic-filter {
          height: 38px;
          display: flex;
          align-items: center;
          gap: 7px;
          padding: 0 10px;
          border: 1px solid #e1e6ee;
          border-radius: 9px;
          background: #fafbfd;
          color: #67748a;
        }

        .traffic-filter select {
          border: 0;
          outline: 0;
          background: transparent;
          color: #435068;
          font-size: 11px;
          font-weight: 700;
          cursor: pointer;
        }

        .traffic-results-count {
          margin-left: auto;
          color: #8a94a6;
          font-size: 10px;
          font-weight: 700;
          white-space: nowrap;
        }

        .traffic-table-panel {
          overflow: hidden;
          border: 1px solid #e1e7f0;
          border-radius: 15px;
          background: #ffffff;
          box-shadow: 0 8px 30px rgba(30,45,80,.035);
        }

        .traffic-table-header {
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 17px 20px;
          border-bottom: 1px solid #edf0f4;
        }

        .traffic-table-heading {
          display: flex;
          align-items: center;
          gap: 9px;
        }

        .traffic-table-heading-icon {
          width: 31px;
          height: 31px;
          display: flex;
          align-items: center;
          justify-content: center;
          border-radius: 8px;
          background: #eef2ff;
          color: #6071dc;
        }

        .traffic-table-heading strong {
          display: block;
          color: #1b263b;
          font-size: 13px;
          font-weight: 800;
        }

        .traffic-table-heading span {
          display: block;
          margin-top: 2px;
          color: #97a0b0;
          font-size: 9px;
        }

        .traffic-table-wrapper {
          overflow-x: auto;
        }

        .traffic-table {
          width: 100%;
          min-width: 950px;
          border-collapse: collapse;
        }

        .traffic-table th {
          padding: 11px 16px;
          background: #fafbfd;
          border-bottom: 1px solid #e9edf3;
          color: #8993a5;
          font-size: 9px;
          font-weight: 850;
          letter-spacing: .7px;
          text-align: left;
          text-transform: uppercase;
          white-space: nowrap;
        }

        .traffic-table td {
          padding: 14px 16px;
          border-bottom: 1px solid #f0f2f6;
          color: #536178;
          font-size: 11px;
          vertical-align: middle;
        }

        .traffic-table tbody tr {
          transition: background .16s ease;
        }

        .traffic-table tbody tr:hover {
          background: #fafbfe;
        }

        .traffic-table tbody tr:last-child td {
          border-bottom: 0;
        }

        .traffic-request {
          display: flex;
          align-items: center;
          gap: 9px;
        }

        .traffic-method {
          min-width: 42px;
          padding: 4px 6px;
          border-radius: 5px;
          background: #f1f3f7;
          color: #536178;
          font-size: 8px;
          font-weight: 850;
          text-align: center;
        }

        .traffic-path {
          max-width: 250px;
          overflow: hidden;
          color: #243149;
          font-size: 11px;
          font-weight: 750;
          text-overflow: ellipsis;
          white-space: nowrap;
        }

        .traffic-ip {
          color: #5f6d83;
          font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
          font-size: 10px;
        }

        .traffic-time {
          display: flex;
          align-items: center;
          gap: 6px;
          color: #8993a4;
          font-size: 9px;
          white-space: nowrap;
        }

        .traffic-decision-badge {
          display: inline-flex;
          align-items: center;
          gap: 5px;
          padding: 5px 8px;
          border-radius: 6px;
          font-size: 8px;
          font-weight: 850;
          letter-spacing: .4px;
        }

        .traffic-decision-badge.allow {
          background: #edf8f2;
          color: #28764f;
        }

        .traffic-decision-badge.challenge {
          background: #fff7e5;
          color: #99711f;
        }

        .traffic-decision-badge.block {
          background: #fff0f0;
          color: #b64d4d;
        }

        .traffic-risk-cell {
          min-width: 115px;
        }

        .traffic-risk-top {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 5px;
        }

        .traffic-risk-top span {
          font-size: 8px;
          font-weight: 850;
        }

        .traffic-risk-top span.low {
          color: #39815b;
        }

        .traffic-risk-top span.medium {
          color: #9b7626;
        }

        .traffic-risk-top span.high {
          color: #b74f4f;
        }

        .traffic-risk-top strong {
          color: #56647a;
          font-size: 9px;
        }

        .traffic-risk-track {
          width: 100%;
          height: 4px;
          overflow: hidden;
          border-radius: 99px;
          background: #edf0f4;
        }

        .traffic-risk-fill {
          height: 100%;
          border-radius: 99px;
        }

        .traffic-risk-fill.low {
          background: #67ad84;
        }

        .traffic-risk-fill.medium {
          background: #d1ad52;
        }

        .traffic-risk-fill.high {
          background: #d16b6b;
        }

        .traffic-identity {
          display: flex;
          flex-direction: column;
          gap: 4px;
        }

        .traffic-identity-item {
          display: flex;
          align-items: center;
          gap: 5px;
          color: #6f7c91;
          font-size: 8px;
        }

        .traffic-identity-item.verified {
          color: #31805a;
        }

        .traffic-identity-item.unverified {
          color: #9aa3b2;
        }

        .traffic-empty-state {
          min-height: 360px;
          display: flex;
          align-items: center;
          justify-content: center;
          flex-direction: column;
          padding: 50px 25px;
          text-align: center;
        }

        .traffic-empty-icon {
          width: 64px;
          height: 64px;
          display: flex;
          align-items: center;
          justify-content: center;
          margin-bottom: 16px;
          border-radius: 18px;
          background: #eef2ff;
          color: #6374df;
        }

        .traffic-empty-state h3 {
          margin: 0 0 8px;
          color: #1b263b;
          font-size: 17px;
        }

        .traffic-empty-state p {
          max-width: 500px;
          margin: 0 0 18px;
          color: #8792a5;
          font-size: 11px;
          line-height: 1.7;
        }

        .traffic-refresh-button {
          display: inline-flex;
          align-items: center;
          gap: 7px;
          padding: 9px 13px;
          border: 1px solid #dbe2ec;
          border-radius: 8px;
          background: #ffffff;
          color: #536178;
          font-size: 10px;
          font-weight: 750;
          cursor: pointer;
        }

        .traffic-refresh-button:hover {
          border-color: #b9c3d5;
          color: #5266d8;
        }

        .traffic-refresh-button:disabled {
          opacity: .6;
          cursor: wait;
        }

        .traffic-error-banner {
          display: flex;
          align-items: center;
          gap: 10px;
          margin-bottom: 12px;
          padding: 11px 13px;
          border: 1px solid #f0dddd;
          border-radius: 10px;
          background: #fff8f8;
          color: #9d5757;
          font-size: 10px;
        }

        .traffic-error-banner strong {
          color: #8d4848;
        }

        .traffic-error-banner span {
          color: #aa7777;
        }

        @media (max-width: 1150px) {
          .traffic-stat-grid {
            grid-template-columns: repeat(3, minmax(0, 1fr));
          }
        }

        @media (max-width: 850px) {
          .traffic-page {
            padding: 20px 16px;
          }

          .traffic-page-header {
            align-items: flex-start;
            flex-direction: column;
          }

          .traffic-stat-grid {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .traffic-toolbar {
            flex-wrap: wrap;
          }

          .traffic-search {
            min-width: 100%;
          }

          .traffic-results-count {
            margin-left: 0;
          }
        }

        @media (max-width: 520px) {
          .traffic-stat-grid {
            grid-template-columns: 1fr;
          }

          .traffic-header-actions {
            width: 100%;
          }

          .traffic-live-indicator {
            flex: 1;
          }
        }
      `}</style>

      <div className="traffic-page">
        <section className="traffic-page-header">
          <div>
            <div className="traffic-eyebrow">
              <span className="traffic-eyebrow-line" />
              TRAFFIC INTELLIGENCE
            </div>

            <h1 className="traffic-page-title">
              Traffic Analytics
            </h1>

            <p className="traffic-page-description">
              Monitor incoming requests, ML risk
              scores, Zero Trust context, and
              adaptive firewall decisions in real
              time.
            </p>
          </div>

          <div className="traffic-header-actions">
            <div className="traffic-live-indicator">
              <span className="traffic-live-dot" />
              LIVE TELEMETRY
            </div>

            <button
              type="button"
              className="traffic-header-refresh"
              title="Refresh traffic telemetry"
              onClick={() => loadTraffic(true)}
              disabled={refreshing}
            >
              <RefreshCw
                size={16}
                className={
                  refreshing
                    ? "traffic-spin"
                    : ""
                }
              />
            </button>
          </div>
        </section>

        {connectionError && (
          <div className="traffic-error-banner">
            <ShieldAlert size={16} />

            <div>
              <strong>
                Telemetry connection issue
              </strong>

              <span>
                Unable to retrieve the latest
                traffic events. The page will retry
                automatically.
              </span>
            </div>
          </div>
        )}

        <section className="traffic-stat-grid">
          <StatCard
            icon={Activity}
            label="Total Requests"
            value={trafficStats.total}
            description="Recorded security events"
            tone="blue"
          />

          <StatCard
            icon={ShieldCheck}
            label="Allowed"
            value={trafficStats.allowed}
            description="Requests permitted"
            tone="green"
          />

          <StatCard
            icon={AlertTriangle}
            label="Challenged"
            value={trafficStats.challenged}
            description="Requests requiring verification"
            tone="amber"
          />

          <StatCard
            icon={XCircle}
            label="Blocked"
            value={trafficStats.blocked}
            description="Requests denied"
            tone="red"
          />

          <StatCard
            icon={ShieldAlert}
            label="High Risk"
            value={trafficStats.highRisk}
            description="Risk score ≥ 75%"
            tone="purple"
          />
        </section>

        <section className="traffic-toolbar">
          <div className="traffic-search">
            <Search size={15} />

            <input
              type="text"
              value={search}
              onChange={(event) =>
                setSearch(event.target.value)
              }
              placeholder="Search path, IP, method, or decision..."
            />
          </div>

          <div className="traffic-filter">
            <Filter size={14} />

            <select
              value={decisionFilter}
              onChange={(event) =>
                setDecisionFilter(
                  event.target.value
                )
              }
            >
              <option value="ALL">
                All decisions
              </option>

              <option value="ALLOW">
                Allowed
              </option>

              <option value="CHALLENGE">
                Challenged
              </option>

              <option value="BLOCK">
                Blocked
              </option>
            </select>
          </div>

          <div className="traffic-filter">
            <Shield size={14} />

            <select
              value={riskFilter}
              onChange={(event) =>
                setRiskFilter(
                  event.target.value
                )
              }
            >
              <option value="ALL">
                All risk levels
              </option>

              <option value="LOW">
                Low risk
              </option>

              <option value="MEDIUM">
                Medium risk
              </option>

              <option value="HIGH">
                High risk
              </option>
            </select>
          </div>

          <span className="traffic-results-count">
            {filteredEvents.length} of{" "}
            {events.length} events
          </span>
        </section>

        <section className="traffic-table-panel">
          <div className="traffic-table-header">
            <div className="traffic-table-heading">
              <div className="traffic-table-heading-icon">
                <Globe2 size={16} />
              </div>

              <div>
                <strong>
                  Request Telemetry
                </strong>

                <span>
                  Live events from the A²FaaS
                  security database
                </span>
              </div>
            </div>

            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "6px",
                color: "#8390a4",
                fontSize: "9px",
                fontWeight: 700,
              }}
            >
              <Clock3 size={13} />

              Auto-refresh: 15s
            </div>
          </div>

          {loading ? (
            <div className="traffic-empty-state">
              <div className="traffic-empty-icon">
                <RefreshCw
                  size={28}
                  className="traffic-spin"
                />
              </div>

              <h3>
                Loading traffic telemetry
              </h3>

              <p>
                Connecting to the A²FaaS security
                event stream...
              </p>
            </div>
          ) : filteredEvents.length === 0 ? (
            <EmptyTrafficState
              onRefresh={() =>
                loadTraffic(true)
              }
              refreshing={refreshing}
            />
          ) : (
            <div className="traffic-table-wrapper">
              <table className="traffic-table">
                <thead>
                  <tr>
                    <th>Request</th>
                    <th>Source</th>
                    <th>Risk Score</th>
                    <th>ML Prediction</th>
                    <th>Identity Context</th>
                    <th>Decision</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredEvents.map(
                    (event) => (
                      <tr key={event.id}>
                        <td>
                          <div className="traffic-request">
                            <span className="traffic-method">
                              {event.method}
                            </span>

                            <span
                              className="traffic-path"
                              title={event.path}
                            >
                              {event.path}
                            </span>
                          </div>
                        </td>

                        <td>
                          <span className="traffic-ip">
                            {event.sourceIp}
                          </span>
                        </td>

                        <td>
                          <RiskBadge
                            score={
                              event.riskScore
                            }
                          />
                        </td>

                        <td>
                          <span
                            style={{
                              color:
                                String(
                                  event.mlPrediction
                                ).toLowerCase() ===
                                "attack"
                                  ? "#b64d4d"
                                  : "#3d7859",
                              fontSize: "9px",
                              fontWeight: 800,
                            }}
                          >
                            {
                              event.mlPrediction
                            }
                          </span>
                        </td>

                        <td>
                          <div className="traffic-identity">
                            <span
                              className={`traffic-identity-item ${
                                event.identityVerified
                                  ? "verified"
                                  : "unverified"
                              }`}
                            >
                              {event.identityVerified ? (
                                <CheckCircle2
                                  size={11}
                                />
                              ) : (
                                <XCircle
                                  size={11}
                                />
                              )}

                              Identity{" "}
                              {event.identityVerified
                                ? "verified"
                                : "unverified"}
                            </span>

                            <span
                              className={`traffic-identity-item ${
                                event.deviceTrusted
                                  ? "verified"
                                  : "unverified"
                              }`}
                            >
                              {event.deviceTrusted ? (
                                <CheckCircle2
                                  size={11}
                                />
                              ) : (
                                <XCircle
                                  size={11}
                                />
                              )}

                              Device{" "}
                              {event.deviceTrusted
                                ? "trusted"
                                : "untrusted"}
                            </span>
                          </div>
                        </td>

                        <td>
                          <DecisionBadge
                            decision={
                              event.decision
                            }
                          />
                        </td>

                        <td>
                          <span className="traffic-time">
                            <Clock3 size={11} />

                            {formatTimestamp(
                              event.timestamp
                            )}
                          </span>
                        </td>
                      </tr>
                    )
                  )}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: "15px",
            marginTop: "13px",
            padding: "0 2px",
            color: "#98a1b1",
            fontSize: "9px",
          }}
        >
          <span>
            A²FaaS traffic telemetry • ML risk
            scoring • Zero Trust enforcement
          </span>

          <span
            style={{
              display: "flex",
              alignItems: "center",
              gap: "5px",
            }}
          >
            <Zap size={11} />

            Average risk:{" "}
            {(
              trafficStats.averageRisk * 100
            ).toFixed(2)}
            %
          </span>
        </div>
      </div>
    </>
  );
}