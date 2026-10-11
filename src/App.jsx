import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  BarChart3,
  Bell,
  CheckCircle2,
  ChevronDown,
  CircleDot,
  Cloud,
  Cpu,
  FileWarning,
  Fingerprint,
  Gauge,
  Globe2,
  Info,
  LockKeyhole,
  Menu,
  Network,
  Radar,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  UserRound,
  Zap,
} from "lucide-react";
import "./App.css";
import FirewallPage from "./FirewallPage";
import TrafficPage from "./TrafficPage";

const getApiBases = () => {
  const configuredApi = (import.meta.env.VITE_API_URL || "")
    .trim()
    .replace(/\/+$/, "");

  if (configuredApi) {
    return [configuredApi];
  }

  return [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
  ];
};

const apiFetch = async (path, options = {}) => {
  let lastError = null;

  for (const base of getApiBases()) {
    const controller = new AbortController();
    const timeoutId = window.setTimeout(
      () => controller.abort(),
      6000
    );

    try {
      const separator = path.includes("?") ? "&" : "?";
      const response = await fetch(
        `${base}${path}${separator}t=${Date.now()}`,
        {
          ...options,
          method: options.method || "GET",
          cache: "no-store",
          headers: {
            Accept: "application/json",
            ...(options.headers || {}),
          },
          signal: controller.signal,
        }
      );

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      lastError = error;
    } finally {
      window.clearTimeout(timeoutId);
    }
  }

  throw (
    lastError ||
    new Error("Backend connection unavailable")
  );
};

const navigation = [
  { label: "Overview", icon: Gauge },
  { label: "Firewall", icon: Shield },
  { label: "Traffic", icon: Activity },
  { label: "ML Engine", icon: Cpu },
  { label: "Zero Trust", icon: LockKeyhole },
];

const systemItems = [
  {
    label: "Cloud Application",
    status: "Protected",
    icon: Cloud,
  },
  {
    label: "Traffic Interceptor",
    status: "Online",
    icon: Network,
  },
  {
    label: "ML Risk Engine",
    status: "Ready",
    icon: Cpu,
  },
  {
    label: "Zero Trust Policy",
    status: "Enforced",
    icon: Fingerprint,
  },
];

const ML_METRICS = {
  model: "Logistic Regression",
  dataset: "UNSW-NB15",
  features: 42,
  accuracy: 93.23,
  precision: 95.0,
  recall: 95.06,
  f1: 95.03,
  averagePredictionLatencyMs: 0.0029583563826577302,
  trainingTime: 3.4093404000159353,
  normalSamples: 56000,
  attackSamples: 119341,
  trainingSamples: 140272,
  validationSamples: 35069,
};

function App() {
  const [activePage, setActivePage] = useState("Overview");
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const [systemHealth, setSystemHealth] = useState({
    status: "checking",
    message: "Checking backend connection...",
  });

  const [dashboardStats, setDashboardStats] = useState({
    total_requests: 0,
    allowed_requests: 0,
    challenged_requests: 0,
    blocked_requests: 0,
    high_risk_requests: 0,
  });

  const [statsLoading, setStatsLoading] = useState(true);

  const checkSystemHealth = async () => {
    try {
      const data = await apiFetch("/api/system/health");

      const status = String(
        data?.status || "healthy"
      ).toLowerCase();

      setSystemHealth({
        status,
        message: data?.message || "Backend is healthy",
      });

      return [
        "healthy",
        "operational",
        "ok",
        "online",
      ].includes(status);
    } catch (error) {
      console.error("Health check failed:", error);

      setSystemHealth({
        status: "offline",
        message:
          error?.name === "AbortError"
            ? "Backend health check timed out"
            : "Backend connection unavailable",
      });

      return false;
    }
  };

  const fetchDashboardStats = async () => {
    try {
      setStatsLoading(true);

      const data = await apiFetch("/api/dashboard/stats");

      setDashboardStats({
        total_requests: data?.total_requests ?? 0,
        allowed_requests: data?.allowed_requests ?? 0,
        challenged_requests: data?.challenged_requests ?? 0,
        blocked_requests: data?.blocked_requests ?? 0,
        high_risk_requests: data?.high_risk_requests ?? 0,
      });

      return true;
    } catch (error) {
      console.error(
        "Unable to fetch dashboard statistics:",
        error
      );

      return false;
    } finally {
      setStatsLoading(false);
    }
  };

  const refreshSystem = async () => {
    const results = await Promise.allSettled([
      checkSystemHealth(),
      fetchDashboardStats(),
    ]);

    const healthOk =
      results[0]?.status === "fulfilled" &&
      results[0]?.value === true;

    const statsOk =
      results[1]?.status === "fulfilled" &&
      results[1]?.value === true;

    if (!healthOk && statsOk) {
      setSystemHealth({
        status: "healthy",
        message: "Backend is responding",
      });
    }
  };

  useEffect(() => {
    refreshSystem();

    const interval = setInterval(refreshSystem, 30000);

    const handleFocus = () => refreshSystem();
    const handleOnline = () => refreshSystem();

    window.addEventListener("focus", handleFocus);
    window.addEventListener("online", handleOnline);

    return () => {
      clearInterval(interval);
      window.removeEventListener("focus", handleFocus);
      window.removeEventListener("online", handleOnline);
    };
  }, []);

  const isOperational =
    systemHealth.status === "healthy" ||
    systemHealth.status === "operational";

  const isChecking = systemHealth.status === "checking";

  const handleNavigation = (label) => {
    setActivePage(label);
    setSidebarOpen(false);
    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  };

  return (
    <div className="app-shell">
      {sidebarOpen && (
        <button
          className="sidebar-backdrop"
          type="button"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside
        className={`sidebar ${
          sidebarOpen ? "sidebar-open" : ""
        }`}
      >
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={23} strokeWidth={2.2} />
          </div>

          <div>
            <div className="brand-name">A²FaaS</div>
            <div className="brand-subtitle">
              Adaptive Cloud Security
            </div>
          </div>
        </div>

        <div className="workspace">
          <div className="workspace-label">
            SECURITY CONSOLE
          </div>

          <nav className="navigation">
            {navigation.map((item) => {
              const Icon = item.icon;
              const active = activePage === item.label;

              return (
                <button
                  key={item.label}
                  type="button"
                  onClick={() => handleNavigation(item.label)}
                  className={`nav-item ${
                    active ? "active" : ""
                  }`}
                >
                  <Icon size={18} />
                  <span>{item.label}</span>
                  {active && (
                    <span className="nav-indicator" />
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="sidebar-divider" />

        <div className="workspace">
          <div className="workspace-label">
            SYSTEM STATUS
          </div>

          <div className="system-list">
            {systemItems.map((item) => {
              const Icon = item.icon;

              return (
                <div
                  className="system-item"
                  key={item.label}
                >
                  <div className="system-icon">
                    <Icon size={16} />
                  </div>

                  <div className="system-copy">
                    <span>{item.label}</span>
                    <small>{item.status}</small>
                  </div>

                  <span className="system-dot" />
                </div>
              );
            })}
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="menu-button"
              type="button"
              aria-label={
                sidebarOpen ? "Close menu" : "Open menu"
              }
              aria-expanded={sidebarOpen}
              onClick={() =>
                setSidebarOpen((open) => !open)
              }
            >
              <Menu size={19} />
            </button>

            <div>
              <div className="topbar-title">
                A²FaaS Security Console
              </div>
              <div className="topbar-subtitle">
                Adaptive firewall · ML risk intelligence ·
                Zero Trust
              </div>
            </div>
          </div>

          <div className="topbar-right">
            <div
              className={`connection-status ${
                isOperational
                  ? "online"
                  : isChecking
                    ? "checking"
                    : "offline"
              }`}
            >
              <span className="connection-dot" />
              {isChecking
                ? "Checking systems"
                : isOperational
                  ? "All systems normal"
                  : "Service unavailable"}
            </div>

            <button
              className="icon-button"
              aria-label="Notifications"
              title="Notifications"
              type="button"
            >
              <Bell size={18} />
              <span className="notification-dot" />
            </button>

            <button
              className="icon-button"
              aria-label="Refresh system status"
              title="Refresh system status"
              type="button"
              onClick={() => {
                checkSystemHealth();
                fetchDashboardStats();
              }}
            >
              <RefreshCw size={17} />
            </button>
          </div>
        </header>

        {activePage === "Overview" && (
          <OverviewPage
            dashboardStats={dashboardStats}
            statsLoading={statsLoading}
            onAnalyze={() => handleNavigation("Firewall")}
          />
        )}

        {activePage === "ML Engine" && <MLEnginePage />}

        {activePage === "Firewall" && <FirewallPage />}

        {activePage === "Traffic" && <TrafficPage />}

        {activePage === "Zero Trust" && (
          <PlaceholderPage
            icon={LockKeyhole}
            eyebrow="ZERO TRUST SECURITY"
            title="Zero Trust Policy"
            description="Identity, device, and request-context verification for every access attempt."
            status="Zero Trust policy enforced"
          />
        )}
      </main>
    </div>
  );
}

function OverviewPage({
  dashboardStats,
  statsLoading,
  onAnalyze,
}) {
  const [activityData, setActivityData] = useState(() =>
    Array.from({ length: 8 }, (_, index) => ({
      time: `-${24 - index * 3}h`,
      value: 0,
    }))
  );

  const [activityTotal, setActivityTotal] = useState(0);
  const [activityLoading, setActivityLoading] = useState(true);
  const [activityError, setActivityError] = useState("");

  useEffect(() => {
    let cancelled = false;
    let requestInProgress = false;

    const parseEventTimestamp = (raw) => {
      if (raw === undefined || raw === null || raw === "") {
        return NaN;
      }

      // Epoch timestamps can arrive in seconds or milliseconds.
      if (
        typeof raw === "number" ||
        /^\d{10,13}$/.test(String(raw).trim())
      ) {
        const numeric = Number(raw);
        return numeric < 1e12 ? numeric * 1000 : numeric;
      }

      const value = String(raw).trim();

      // ISO timestamps with Z/offset are parsed as absolute instants.
      const parsed = Date.parse(value);
      if (Number.isFinite(parsed)) return parsed;

      // SQLite timestamps without a timezone are treated as local time.
      const sqliteMatch = value.match(
        /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:\s*(Z|[+-]\d{2}:?\d{2}))?$/i
      );

      if (!sqliteMatch) return NaN;

      const normalized =
        `${sqliteMatch[1]}T${sqliteMatch[2]}${sqliteMatch[3] || ""}`;

      const sqliteParsed = Date.parse(normalized);

      return Number.isFinite(sqliteParsed)
        ? sqliteParsed
        : NaN;
    };

    const loadActivity = async () => {
      if (requestInProgress) return;
      requestInProgress = true;

      try {
        const response = await apiFetch(
          "/api/requests/recent?limit=100"
        );

        const events = Array.isArray(response)
          ? response
          : [
              response?.events,
              response?.requests,
              response?.records,
              response?.items,
              response?.results,
              response?.data?.events,
              response?.data,
            ].find(Array.isArray) || [];

        const now = Date.now();
        const windowStart = now - 24 * 60 * 60 * 1000;
        const bucketDuration = 3 * 60 * 60 * 1000;
        const counts = Array(8).fill(0);
        let counted = 0;

        for (const event of events) {
          const timestamp = parseEventTimestamp(
            event?.timestamp ??
              event?.created_at ??
              event?.event_timestamp ??
              event?.request_timestamp ??
              event?.created ??
              event?.time ??
              event?.date
          );

          if (!Number.isFinite(timestamp)) continue;
          if (
            timestamp < windowStart ||
            timestamp > now + 60_000
          ) {
            continue;
          }

          const bucket = Math.min(
            counts.length - 1,
            Math.max(
              0,
              Math.floor(
                (timestamp - windowStart) / bucketDuration
              )
            )
          );

          counts[bucket] += 1;
          counted += 1;
        }

        const formattedBuckets = counts.map((value, index) => {
          const bucketStart = new Date(
            windowStart + index * bucketDuration
          );

          const label = bucketStart.toLocaleTimeString([], {
            hour: "2-digit",
            minute: "2-digit",
            hour12: false,
          });

          return { time: label, value };
        });

        if (!cancelled) {
          setActivityData(formattedBuckets);
          setActivityTotal(counted);
          setActivityError("");
        }
      } catch (error) {
        console.error(
          "Unable to load request activity:",
          error
        );

        if (!cancelled) {
          setActivityError(
            "Request activity could not be loaded. Check the backend connection."
          );
        }
      } finally {
        requestInProgress = false;
        if (!cancelled) setActivityLoading(false);
      }
    };

    loadActivity();

    const intervalId = window.setInterval(
      loadActivity,
      15000
    );

    const handleFocus = () => loadActivity();
    window.addEventListener("focus", handleFocus);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
      window.removeEventListener("focus", handleFocus);
    };
  }, []);

  const chartMax = Math.max(
    5,
    ...activityData.map((item) => item.value)
  );

  return (
    <div className="page-content">
      <section className="page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            CLOUD SECURITY INTELLIGENCE
          </div>

          <h1>Adaptive Firewall Overview</h1>

          <p>
            Real-time visibility into traffic risk, ML
            decisions, and Zero Trust enforcement.
          </p>
        </div>

        <div className="heading-actions">
          <button
            className="secondary-button"
            type="button"
            onClick={() => {
              const apiBase = getApiBases()[0];
              window.open(
                `${apiBase}/docs`,
                "_blank",
                "noopener,noreferrer"
              );
            }}
          >
            <TerminalSquare size={16} />
            API Console
          </button>

          <button
            className="primary-button"
            type="button"
            onClick={onAnalyze}
          >
            <Radar size={16} />
            Analyze Request
          </button>
        </div>
      </section>

      <section className="security-banner">
        <div className="banner-icon">
          <ShieldCheck size={22} />
        </div>

        <div className="banner-content">
          <strong>Adaptive protection is active</strong>
          <span>
            A²FaaS is continuously evaluating application
            traffic using ML risk scoring and Zero Trust
            verification.
          </span>
        </div>

        <div className="banner-status">
          <span />
          PROTECTED
        </div>
      </section>

      <section className="metrics-grid">
        <MetricCard
          icon={Globe2}
          label="TOTAL REQUESTS"
          value={
            statsLoading ? "..." : dashboardStats.total_requests
          }
          description="Requests evaluated by A²FaaS"
          tone="blue"
        />

        <MetricCard
          icon={ShieldCheck}
          label="ALLOWED"
          value={
            statsLoading
              ? "..."
              : dashboardStats.allowed_requests
          }
          description="Requests permitted after verification"
          tone="green"
        />

        <MetricCard
          icon={ShieldAlert}
          label="CHALLENGED"
          value={
            statsLoading
              ? "..."
              : dashboardStats.challenged_requests
          }
          description="Requests requiring additional verification"
          tone="orange"
        />

        <MetricCard
          icon={FileWarning}
          label="BLOCKED"
          value={
            statsLoading
              ? "..."
              : dashboardStats.blocked_requests
          }
          description="High-risk requests blocked"
          tone="red"
        />
      </section>

      <section className="dashboard-grid">
        <div className="dashboard-card">
          <div className="card-header">
            <div>
              <div className="card-eyebrow">
                TRAFFIC ACTIVITY
              </div>
              <h2>Request Activity</h2>
            </div>

            <div className="live-badge">
              <span />
              LIVE
            </div>
          </div>

          <div className="activity-chart">
            <div className="chart-y-axis">
              <span>{chartMax}</span>
              <span>{Math.round(chartMax * 0.75)}</span>
              <span>{Math.round(chartMax * 0.5)}</span>
              <span>{Math.round(chartMax * 0.25)}</span>
              <span>0</span>
            </div>

            <div className="chart-area">
              <div className="chart-grid-lines">
                <span />
                <span />
                <span />
                <span />
                <span />
              </div>

              <div
                className="chart-bars"
                role="img"
                aria-label={`Request activity over the last 24 hours: ${activityTotal} recorded requests in the latest 100 events`}
              >
                {activityData.map((item) => (
                  <div
                    className="chart-bar-column"
                    key={item.time}
                  >
                    <span className="chart-bar-value">
                      {item.value}
                    </span>

                    <div className="chart-bar-track">
                      <div
                        className="chart-bar"
                        style={{
                          height: `${
                            item.value === 0
                              ? 0
                              : Math.max(
                                  8,
                                  (item.value / chartMax) * 100
                                )
                          }%`,
                        }}
                        title={`${item.value} requests ${item.time}`}
                      />
                    </div>

                    <span className="chart-bar-label">
                      {item.time}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div
            className={`activity-footnote ${
              activityError ? "error" : ""
            }`}
            aria-live="polite"
          >
            {activityError ||
              (activityLoading
                ? "Loading request activity…"
                : `${activityTotal} requests recorded in the last 24 hours · refreshed every 15 seconds`)}
          </div>
        </div>

        <div className="dashboard-card">
          <div className="card-header">
            <div>
              <div className="card-eyebrow">
                DECISION DISTRIBUTION
              </div>
              <h2>Security Decisions</h2>
            </div>

            <BarChart3 size={19} />
          </div>

          <div className="decision-content">
            <div className="decision-total">
              <strong>{dashboardStats.total_requests}</strong>
              <span>Requests evaluated</span>
            </div>

            <div className="legend-list">
              <LegendItem
                label="Allowed"
                value={dashboardStats.allowed_requests}
                type="allowed"
              />

              <LegendItem
                label="Challenge"
                value={dashboardStats.challenged_requests}
                type="challenge"
              />

              <LegendItem
                label="Blocked"
                value={dashboardStats.blocked_requests}
                type="blocked"
              />
            </div>
          </div>
        </div>
      </section>

      <section className="dashboard-card">
        <div className="card-header">
          <div>
            <div className="card-eyebrow">
              PROTECTION PIPELINE
            </div>
            <h2>Adaptive Security Architecture</h2>
          </div>

          <span className="card-link">
            A²FaaS
            <ArrowUpRight size={15} />
          </span>
        </div>

        <div className="pipeline">
          <PipelineStep
            number="01"
            icon={Network}
            title="Traffic Interceptor"
            description="Captures incoming application requests."
          />

          <PipelineStep
            number="02"
            icon={Zap}
            title="Feature Extraction"
            description="Converts request context into ML features."
          />

          <PipelineStep
            number="03"
            icon={Cpu}
            title="ML Risk Engine"
            description="Computes adaptive traffic risk."
          />

          <PipelineStep
            number="04"
            icon={Fingerprint}
            title="Zero Trust"
            description="Validates identity and device context."
          />

          <PipelineStep
            number="05"
            icon={ShieldCheck}
            title="Decision"
            description="Allow, challenge, or block."
          />
        </div>
      </section>

      <section className="dashboard-card">
        <div className="card-header">
          <div>
            <div className="card-eyebrow">
              SECURITY POSTURE
            </div>
            <h2>Current Protection Status</h2>
          </div>

          <span className="protected-badge">
            <CheckCircle2 size={14} />
            Protected
          </span>
        </div>

        <div className="posture-grid">
          <PostureItem
            icon={Cloud}
            title="Cloud Application"
            status="Protected"
            description="Application traffic is routed through the adaptive firewall."
          />

          <PostureItem
            icon={Cpu}
            title="ML Risk Engine"
            status="Ready"
            description="Logistic regression model is available for risk scoring."
          />

          <PostureItem
            icon={Fingerprint}
            title="Zero Trust"
            status="Enforced"
            description="Identity and device verification is applied independently."
          />

          <PostureItem
            icon={Shield}
            title="Adaptive Firewall"
            status="Active"
            description="Risk-based decisions are enforced at the request layer."
          />
        </div>
      </section>
    </div>
  );
}

function MLEnginePage() {
  return (
    <div className="page-content">
      <section className="page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            MACHINE LEARNING SECURITY
          </div>

          <h1>ML Risk Engine</h1>

          <p>
            Lightweight machine learning model for adaptive
            network threat detection.
          </p>
        </div>

        <div className="heading-actions">
          <div className="model-status">
            <span />
            MODEL READY
          </div>
        </div>
      </section>

      <section className="security-banner">
        <div className="banner-icon">
          <Cpu size={22} />
        </div>

        <div className="banner-content">
          <strong>{ML_METRICS.model}</strong>
          <span>
            Trained on {ML_METRICS.dataset} with{" "}
            {ML_METRICS.features} extracted traffic features.
          </span>
        </div>

        <div className="banner-status">
          <span />
          ONLINE
        </div>
      </section>

      <section className="metric-grid">
        <MetricCard
          icon={Gauge}
          label="ACCURACY"
          value={`${ML_METRICS.accuracy}%`}
          description="Validation classification accuracy"
          tone="blue"
        />

        <MetricCard
          icon={ShieldCheck}
          label="PRECISION"
          value={`${ML_METRICS.precision}%`}
          description="Attack prediction precision"
          tone="green"
        />

        <MetricCard
          icon={Radar}
          label="RECALL"
          value={`${ML_METRICS.recall}%`}
          description="Attack detection recall"
          tone="orange"
        />

        <MetricCard
          icon={BarChart3}
          label="F1 SCORE"
          value={`${ML_METRICS.f1}%`}
          description="Balanced classification metric"
          tone="purple"
        />
      </section>

      <section className="dashboard-grid">
        <div className="dashboard-card">
          <div className="card-header">
            <div>
              <div className="card-eyebrow">
                MODEL INFORMATION
              </div>
              <h2>Risk Scoring Model</h2>
            </div>

            <Cpu size={19} />
          </div>

          <div className="info-grid">
            <MLInfoBox
              label="Algorithm"
              value={ML_METRICS.model}
            />

            <MLInfoBox
              label="Dataset"
              value={ML_METRICS.dataset}
            />

            <MLInfoBox
              label="Features"
              value={ML_METRICS.features}
            />

            <MLInfoBox
              label="Prediction Time"
              value={`${ML_METRICS.averagePredictionLatencyMs.toFixed(3)} ms`}
            />
          </div>
        </div>

        <div className="dashboard-card">
          <div className="card-header">
            <div>
              <div className="card-eyebrow">DATASET</div>
              <h2>Training Distribution</h2>
            </div>

            <Server size={19} />
          </div>

          <div className="dataset-bars">
            <div className="dataset-row">
              <div className="dataset-label">
                Normal Traffic
              </div>

              <div className="dataset-bar">
                <span style={{ width: "32%" }} />
              </div>

              <strong>
                {ML_METRICS.normalSamples.toLocaleString()}
              </strong>
            </div>

            <div className="dataset-row">
              <div className="dataset-label">
                Attack Traffic
              </div>

              <div className="dataset-bar">
                <span style={{ width: "68%" }} />
              </div>

              <strong>
                {ML_METRICS.attackSamples.toLocaleString()}
              </strong>
            </div>
          </div>
        </div>
      </section>

      <section className="dashboard-card">
        <div className="card-header">
          <div>
            <div className="card-eyebrow">MODEL PIPELINE</div>
            <h2>ML Processing Flow</h2>
          </div>
        </div>

        <div className="pipeline">
          <PipelineStep
            number="01"
            icon={Network}
            title="Request Capture"
            description="Incoming traffic is intercepted."
          />

          <PipelineStep
            number="02"
            icon={BarChart3}
            title="Feature Extraction"
            description="42 request-level features are generated."
          />

          <PipelineStep
            number="03"
            icon={Cpu}
            title="Risk Prediction"
            description="The classifier generates a risk score."
          />

          <PipelineStep
            number="04"
            icon={ShieldAlert}
            title="Risk Classification"
            description="Traffic is categorized by severity."
          />

          <PipelineStep
            number="05"
            icon={ShieldCheck}
            title="Policy Decision"
            description="Zero Trust determines final access."
          />
        </div>
      </section>

      <section className="dashboard-card">
        <div className="card-header">
          <div>
            <div className="card-eyebrow">PERFORMANCE</div>
            <h2>Model Evaluation</h2>
          </div>
        </div>

        <div className="performance-table">
          <PerformanceRow
            metric="Accuracy"
            value={ML_METRICS.accuracy}
          />

          <PerformanceRow
            metric="Precision"
            value={ML_METRICS.precision}
          />

          <PerformanceRow
            metric="Recall"
            value={ML_METRICS.recall}
          />

          <PerformanceRow
            metric="F1 Score"
            value={ML_METRICS.f1}
          />
        </div>
      </section>
    </div>
  );
}

function MLInfoBox({ label, value }) {
  return (
    <div className="info-box">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function PipelineStep({
  number,
  icon: Icon,
  title,
  description,
}) {
  return (
    <div className="pipeline-step">
      <div className="pipeline-number">{number}</div>

      <div className="pipeline-icon">
        <Icon size={18} />
      </div>

      <div className="pipeline-copy">
        <strong>{title}</strong>
        <span>{description}</span>
      </div>
    </div>
  );
}

function PerformanceRow({ metric, value }) {
  return (
    <div className="performance-row">
      <span>{metric}</span>

      <div className="performance-bar">
        <span style={{ width: `${value}%` }} />
      </div>

      <strong>{value}%</strong>
    </div>
  );
}

function PlaceholderPage({
  icon: Icon,
  eyebrow,
  title,
  description,
  status,
}) {
  return (
    <div className="page-content">
      <section className="page-heading">
        <div>
          <div className="eyebrow">
            <span className="eyebrow-line" />
            {eyebrow}
          </div>

          <h1>{title}</h1>
          <p>{description}</p>
        </div>
      </section>

      <section
        style={{
          minHeight: "420px",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "#ffffff",
          border: "1px solid #e1e7f0",
          borderRadius: "16px",
        }}
      >
        <div
          style={{
            textAlign: "center",
            maxWidth: "500px",
            padding: "40px",
          }}
        >
          <div
            style={{
              width: "72px",
              height: "72px",
              margin: "0 auto 20px",
              borderRadius: "20px",
              background: "#eef1ff",
              color: "#5d6fe5",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <Icon size={34} />
          </div>

          <h2
            style={{
              margin: "0 0 10px",
              color: "#172033",
            }}
          >
            Module Connected
          </h2>

          <p
            style={{
              margin: "0 0 20px",
              color: "#7b879d",
              fontSize: "13px",
              lineHeight: 1.7,
            }}
          >
            {description}
          </p>

          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "7px",
              padding: "8px 12px",
              borderRadius: "8px",
              background: "#edf8f2",
              color: "#26784f",
              fontSize: "11px",
              fontWeight: 800,
            }}
          >
            <CheckCircle2 size={14} />
            {status}
          </div>
        </div>
      </section>
    </div>
  );
}

function MetricCard({
  icon: Icon,
  label,
  value,
  description,
  tone,
}) {
  return (
    <div className={`metric-card ${tone}`}>
      <div className="metric-top">
        <div className="metric-icon">
          <Icon size={18} />
        </div>

        <span className="metric-live">
          <span />
          LIVE
        </span>
      </div>

      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-description">{description}</div>
    </div>
  );
}

function LegendItem({ label, value, type }) {
  return (
    <div className="legend-item">
      <div className={`legend-dot ${type}`} />
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function PostureItem({
  icon: Icon,
  title,
  status,
  description,
}) {
  return (
    <div className="posture-item">
      <div className="posture-icon">
        <Icon size={17} />
      </div>

      <div className="posture-copy">
        <strong>{title}</strong>
        <span>{description}</span>
      </div>

      <div className="posture-status">
        <span className="posture-check">
          <CheckCircle2 size={13} />
        </span>
        {status}
      </div>
    </div>
  );
}

export default App;