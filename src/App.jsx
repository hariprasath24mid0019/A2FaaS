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
  if (typeof window === "undefined") {
    return ["http://127.0.0.1:8000", "http://localhost:8000"];
  }
  const protocol = window.location.protocol || "http:";
  const hostname = window.location.hostname || "localhost";
  return [
    `${protocol}//${hostname}:8000`,
    "http://127.0.0.1:8000",
    "http://localhost:8000",
  ].filter((value, index, array) => array.indexOf(value) === index);
};

const apiFetch = async (path, options = {}) => {
  let lastError = null;
  for (const base of getApiBases()) {
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), 6000);
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
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } catch (error) {
      lastError = error;
    } finally {
      window.clearTimeout(timeoutId);
    }
  }
  throw lastError || new Error("Backend connection unavailable");
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



const activityData = [

  { time: "00:00", value: 0 },

  { time: "04:00", value: 0 },

  { time: "08:00", value: 0 },

  { time: "12:00", value: 0 },

  { time: "16:00", value: 0 },

  { time: "20:00", value: 0 },

  { time: "24:00", value: 0 },

];



const ML_METRICS = {

  model: "Logistic Regression",

  dataset: "UNSW-NB15",

  features: 42,

  accuracy: 93.23,

  precision: 95.0,

  recall: 95.06,

  f1: 95.03,

  predictionTime: 103.7,

  trainingTime: 4.42,

  normalSamples: 56000,

  attackSamples: 119341,

  trainingSamples: 140272,

  validationSamples: 35069,

};



function App() {

  const [activePage, setActivePage] = useState("Overview");



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
      const status = String(data?.status || "healthy").toLowerCase();
      setSystemHealth({
        status,
        message: data?.message || "Backend is healthy",
      });
      return ["healthy", "operational", "ok", "online"].includes(status);
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
      console.error("Unable to fetch dashboard statistics:", error);
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
      results[0]?.status === "fulfilled" && results[0]?.value === true;
    const statsOk =
      results[1]?.status === "fulfilled" && results[1]?.value === true;
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



  const isChecking =

    systemHealth.status === "checking";



  const handleNavigation = (label) => {

    setActivePage(label);

    window.scrollTo({

      top: 0,

      behavior: "smooth",

    });

  };



  return (

    <div className="app-shell">

      <aside className="sidebar">

        <div className="brand">

          <div className="brand-mark">

            <ShieldCheck

              size={23}

              strokeWidth={2.2}

            />

          </div>



          <div>

            <div className="brand-name">

              A²FaaS

            </div>



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

              const active =

                activePage === item.label;



              return (

                <button

                  key={item.label}

                  type="button"

                  onClick={() =>

                    handleNavigation(item.label)

                  }

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

                    <Icon size={15} />

                  </div>



                  <div className="system-copy">

                    <span>{item.label}</span>

                    <small>{item.status}</small>

                  </div>



                  <span className="online-dot" />

                </div>

              );

            })}

          </div>

        </div>



        <div className="sidebar-bottom">

          <div className="environment-card">

            <div className="environment-top">

              <span className="status-pulse" />

              <span>DEVELOPMENT</span>

            </div>



            <div className="environment-description">

              Local security environment

            </div>

          </div>



          <div className="user-card">

            <div className="avatar">

              <UserRound size={17} />

            </div>



            <div className="user-details">

              <strong>Security Admin</strong>

              <span>Administrator</span>

            </div>



            <ChevronDown

              size={16}

              className="muted-icon"

            />

          </div>

        </div>

      </aside>



      <main className="main-content">

        <header className="topbar">

          <div className="mobile-brand">

            <Menu size={20} />

            <span>A²FaaS</span>

          </div>



          <div className="breadcrumb">

            <span>Security Console</span>



            <span className="breadcrumb-separator">

              /

            </span>



            <strong>{activePage}</strong>

          </div>



          <div className="topbar-actions">

            <div

              className="live-status"

              title={systemHealth.message}

            >

              <span

                className={`live-dot ${

                  isOperational

                    ? ""

                    : "status-offline"

                }`}

              />



              <span>

                {isChecking

                  ? "Checking System"

                  : isOperational

                    ? "System Operational"

                    : "System Offline"}

              </span>

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

          />

        )}



        {activePage === "ML Engine" && (

          <MLEnginePage />

        )}



        {activePage === "Firewall" && <FirewallPage />}



        {activePage === "Traffic" && (
          <TrafficPage />
        )}



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

}) {

  return (

    <div className="page-content">

      <section className="page-heading">

        <div>

          <div className="eyebrow">

            <span className="eyebrow-line" />

            CLOUD SECURITY INTELLIGENCE

          </div>



          <h1>

            Adaptive Firewall Overview

          </h1>



          <p>

            Real-time visibility into traffic risk,

            ML decisions, and Zero Trust enforcement.

          </p>

        </div>



        <div className="heading-actions">

          <button

            className="secondary-button"

            type="button"

          >

            <TerminalSquare size={16} />

            API Console

          </button>



          <button

            className="primary-button"

            type="button"

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

          <strong>

            Adaptive protection is ready

          </strong>



          <span>

            Every request will be evaluated through

            ML risk scoring and Zero Trust policy

            verification.

          </span>

        </div>



        <div className="banner-status">

          <span className="status-check">

            <CheckCircle2 size={15} />

          </span>



          <span>Protected</span>

        </div>

      </section>



      <section className="metrics-grid">

        <MetricCard

          icon={Activity}

          label="Requests Analyzed"

          value={

            statsLoading

              ? "..."

              : dashboardStats.total_requests.toLocaleString()

          }

          description={

            statsLoading

              ? "Loading live telemetry"

              : "Requests processed by A²FaaS"

          }

          tone="blue"

        />



        <MetricCard

          icon={ShieldAlert}

          label="Threats Detected"

          value={

            statsLoading

              ? "..."

              : dashboardStats.high_risk_requests.toLocaleString()

          }

          description={

            statsLoading

              ? "Loading threat telemetry"

              : "High-risk requests detected"

          }

          tone="red"

        />



        <MetricCard

          icon={Gauge}

          label="Average Risk Score"

          value="0.00%"

          description="Calculated from recent events"

          tone="purple"

        />



        <MetricCard

          icon={Zap}

          label="Decision Latency"

          value="—"

          description="Measured after analysis"

          tone="green"

        />

      </section>



      <section className="dashboard-grid">

        <div className="panel traffic-panel">

          <div className="panel-header">

            <div>

              <div className="panel-kicker">

                <Activity size={14} />

                TRAFFIC TELEMETRY

              </div>



              <h2>Request Activity</h2>

            </div>



            <button

              className="panel-menu"

              type="button"

            >

              Last 24 hours

              <ChevronDown size={14} />

            </button>

          </div>



          <div className="chart-area">

            <div className="chart-y-axis">

              <span>100</span>

              <span>75</span>

              <span>50</span>

              <span>25</span>

              <span>0</span>

            </div>



            <div className="chart">

              <div className="chart-grid-lines">

                <span />

                <span />

                <span />

                <span />

                <span />

              </div>



              <div className="live-chart-bars">

                {dashboardStats.total_requests > 0 ? (

                  <>

                    <div

                      className="live-bar allowed-bar"

                      style={{

                        height: `${Math.max(

                          8,

                          Math.min(

                            100,

                            dashboardStats.allowed_requests * 10

                          )

                        )}%`,

                      }}

                    />



                    <div

                      className="live-bar challenged-bar"

                      style={{

                        height: `${Math.max(

                          8,

                          Math.min(

                            100,

                            dashboardStats.challenged_requests * 10

                          )

                        )}%`,

                      }}

                    />



                    <div

                      className="live-bar blocked-bar"

                      style={{

                        height: `${Math.max(

                          8,

                          Math.min(

                            100,

                            dashboardStats.blocked_requests * 10

                          )

                        )}%`,

                      }}

                    />

                  </>

                ) : (

                  <div className="empty-chart">

                    <div className="empty-chart-icon">

                      <BarChart3 size={21} />

                    </div>



                    <strong>

                      Awaiting traffic data

                    </strong>



                    <span>

                      Request telemetry will appear

                      here when the firewall begins

                      analyzing traffic.

                    </span>

                  </div>

                )}



                <div className="chart-x-axis">

                  {activityData.map((item) => (

                    <span key={item.time}>

                      {item.time}

                    </span>

                  ))}

                </div>

              </div>

            </div>

          </div>

        </div>



        <div className="panel decision-panel">

          <div className="panel-header">

            <div>

              <div className="panel-kicker">

                <Shield size={14} />

                FIREWALL DECISIONS

              </div>



              <h2>Decision Distribution</h2>

            </div>



            <button

              className="panel-menu icon-only"

              type="button"

            >

              <ArrowUpRight size={15} />

            </button>

          </div>



          <div className="decision-empty">

            <div className="decision-ring">

              <Shield size={28} />

            </div>



            <strong>

              {dashboardStats.total_requests > 0

                ? `${dashboardStats.total_requests} decisions`

                : "No decisions yet"}

            </strong>



            <span>

              Allow, challenge, and block decisions

              are tracked from the security database.

            </span>

          </div>



          <div className="decision-legend">

            <LegendItem

              label="Allowed"

              value={dashboardStats.allowed_requests}

              type="allowed"

            />



            <LegendItem

              label="Challenged"

              value={dashboardStats.challenged_requests}

              type="challenged"

            />



            <LegendItem

              label="Blocked"

              value={dashboardStats.blocked_requests}

              type="blocked"

            />

          </div>

        </div>

      </section>



      <section className="lower-grid">

        <div className="panel events-panel">

          <div className="panel-header">

            <div>

              <div className="panel-kicker">

                <FileWarning size={14} />

                SECURITY EVENTS

              </div>



              <h2>Recent Activity</h2>

            </div>



            <button

              className="view-all"

              type="button"

            >

              View all

              <ArrowUpRight size={14} />

            </button>

          </div>



          <div className="empty-events">

            <div className="empty-events-icon">

              <CircleDot size={21} />

            </div>



            <div>

              <strong>

                Security telemetry connected

              </strong>



              <span>

                Live request events are being recorded

                by the firewall analysis engine.

              </span>

            </div>

          </div>

        </div>



        <div className="panel posture-panel">

          <div className="panel-header">

            <div>

              <div className="panel-kicker">

                <LockKeyhole size={14} />

                SECURITY POSTURE

              </div>



              <h2>Protection Status</h2>

            </div>

          </div>



          <div className="posture-list">

            <PostureItem

              icon={ShieldCheck}

              title="Adaptive Firewall"

              status="Ready"

              description="ML risk scoring engine"

            />



            <PostureItem

              icon={Fingerprint}

              title="Zero Trust"

              status="Enforced"

              description="Identity and context verification"

            />



            <PostureItem

              icon={Server}

              title="Cloud Application"

              status="Protected"

              description="Application gateway"

            />



            <PostureItem

              icon={Globe2}

              title="Network Layer"

              status="Monitoring"

              description="Incoming request traffic"

            />

          </div>

        </div>

      </section>



      <footer className="footer">

        <div>

          <span className="footer-brand">

            A²FaaS

          </span>



          <span>

            AI-Assisted Adaptive Firewall-as-a-Service

          </span>

        </div>



        <div className="footer-right">

          <span>v1.0.0</span>



          <span className="footer-separator">

            •

          </span>



          <span>

            Development Environment

          </span>

        </div>

      </footer>

    </div>

  );

}



function MLEnginePage() {

  const [selectedMetric, setSelectedMetric] =

    useState("accuracy");



  const metricCards = useMemo(

    () => [

      {

        key: "accuracy",

        label: "Accuracy",

        value: `${ML_METRICS.accuracy}%`,

        description: "Overall validation accuracy",

      },

      {

        key: "precision",

        label: "Precision",

        value: `${ML_METRICS.precision}%`,

        description: "Attack prediction precision",

      },

      {

        key: "recall",

        label: "Recall",

        value: `${ML_METRICS.recall}%`,

        description: "Attack detection recall",

      },

      {

        key: "f1",

        label: "F1 Score",

        value: `${ML_METRICS.f1}%`,

        description: "Balanced classification score",

      },

    ],

    []

  );



  return (

    <div className="page-content">

      <section className="page-heading">

        <div>

          <div className="eyebrow">

            <span className="eyebrow-line" />

            MACHINE LEARNING INTELLIGENCE

          </div>



          <h1>

            ML Risk Engine

          </h1>



          <p>

            Transparent view of the trained A²FaaS

            traffic-risk classification model.

          </p>

        </div>



        <div className="heading-actions">

          <div

            style={{

              display: "flex",

              alignItems: "center",

              gap: "8px",

              padding: "10px 14px",

              borderRadius: "10px",

              border: "1px solid #dce4ef",

              background: "#ffffff",

              color: "#16794f",

              fontSize: "12px",

              fontWeight: 700,

            }}

          >

            <CheckCircle2 size={15} />

            MODEL READY

          </div>

        </div>

      </section>



      <section

        style={{

          display: "grid",

          gridTemplateColumns:

            "minmax(0, 1.5fr) minmax(300px, 0.9fr)",

          gap: "16px",

          marginBottom: "16px",

        }}

      >

        <div

          style={{

            background: "#ffffff",

            border: "1px solid #e1e7f0",

            borderRadius: "16px",

            padding: "24px",

            boxShadow:

              "0 8px 30px rgba(30, 45, 80, 0.04)",

          }}

        >

          <div

            style={{

              display: "flex",

              justifyContent: "space-between",

              alignItems: "flex-start",

              marginBottom: "24px",

            }}

          >

            <div>

              <div

                style={{

                  fontSize: "11px",

                  fontWeight: 800,

                  letterSpacing: "1.2px",

                  color: "#667eea",

                  marginBottom: "8px",

                }}

              >

                MODEL PROFILE

              </div>



              <h2

                style={{

                  margin: 0,

                  color: "#172033",

                  fontSize: "24px",

                  fontWeight: 800,

                }}

              >

                Logistic Regression

              </h2>



              <p

                style={{

                  margin:

                    "7px 0 0",

                  color: "#7b879d",

                  fontSize: "13px",

                }}

              >

                Lightweight binary classifier for

                adaptive cloud traffic risk scoring.

              </p>

            </div>



            <div

              style={{

                width: "46px",

                height: "46px",

                borderRadius: "12px",

                display: "flex",

                alignItems: "center",

                justifyContent: "center",

                background: "#eef1ff",

                color: "#5d6fe5",

              }}

            >

              <Cpu size={23} />

            </div>

          </div>



          <div

            style={{

              display: "grid",

              gridTemplateColumns:

                "repeat(3, minmax(0, 1fr))",

              gap: "12px",

            }}

          >

            <MLInfoBox

              label="Dataset"

              value="UNSW-NB15"

            />



            <MLInfoBox

              label="Features"

              value="42"

            />



            <MLInfoBox

              label="Task"

              value="Binary Classification"

            />

          </div>

        </div>



        <div

          style={{

            background:

              "linear-gradient(145deg, #17233d, #24365c)",

            borderRadius: "16px",

            padding: "24px",

            color: "#ffffff",

            boxShadow:

              "0 12px 35px rgba(31, 48, 86, 0.16)",

          }}

        >

          <div

            style={{

              display: "flex",

              alignItems: "center",

              gap: "9px",

              color: "#b8c7ff",

              fontSize: "11px",

              fontWeight: 800,

              letterSpacing: "1.2px",

              marginBottom: "20px",

            }}

          >

            <Radar size={15} />

            RISK PIPELINE

          </div>



          <div

            style={{

              display: "flex",

              flexDirection: "column",

              gap: "11px",

            }}

          >

            <PipelineStep

              number="01"

              title="Traffic Features"

              text="42 normalized inputs"

            />



            <PipelineStep

              number="02"

              title="ML Prediction"

              text="Normal / Attack"

            />



            <PipelineStep

              number="03"

              title="Risk Score"

              text="Attack probability"

            />



            <PipelineStep

              number="04"

              title="Firewall Decision"

              text="Allow / Challenge / Block"

            />

          </div>

        </div>

      </section>



      <section

        style={{

          display: "grid",

          gridTemplateColumns:

            "repeat(4, minmax(0, 1fr))",

          gap: "14px",

          marginBottom: "16px",

        }}

      >

        {metricCards.map((metric) => {

          const active =

            selectedMetric === metric.key;



          return (

            <button

              key={metric.key}

              type="button"

              onClick={() =>

                setSelectedMetric(metric.key)

              }

              style={{

                textAlign: "left",

                cursor: "pointer",

                border:

                  active

                    ? "1px solid #6a76df"

                    : "1px solid #e1e7f0",

                background:

                  active

                    ? "#f5f6ff"

                    : "#ffffff",

                borderRadius: "14px",

                padding: "20px",

                boxShadow:

                  active

                    ? "0 8px 24px rgba(93,111,229,0.10)"

                    : "0 6px 20px rgba(30,45,80,0.035)",

              }}

            >

              <div

                style={{

                  display: "flex",

                  justifyContent: "space-between",

                  alignItems: "center",

                  marginBottom: "13px",

                }}

              >

                <span

                  style={{

                    fontSize: "10px",

                    fontWeight: 800,

                    letterSpacing: "1px",

                    color: "#71809a",

                  }}

                >

                  {metric.label.toUpperCase()}

                </span>



                <CheckCircle2

                  size={15}

                  color="#5d6fe5"

                />

              </div>



              <div

                style={{

                  fontSize: "28px",

                  lineHeight: 1,

                  fontWeight: 850,

                  color: "#172033",

                  marginBottom: "8px",

                }}

              >

                {metric.value}

              </div>



              <div

                style={{

                  fontSize: "11px",

                  color: "#8994a8",

                }}

              >

                {metric.description}

              </div>

            </button>

          );

        })}

      </section>



      <section

        style={{

          display: "grid",

          gridTemplateColumns:

            "minmax(0, 1.35fr) minmax(330px, 0.85fr)",

          gap: "16px",

          marginBottom: "16px",

        }}

      >

        <div

          style={{

            background: "#ffffff",

            border: "1px solid #e1e7f0",

            borderRadius: "16px",

            padding: "24px",

          }}

        >

          <div

            style={{

              display: "flex",

              justifyContent: "space-between",

              alignItems: "center",

              marginBottom: "20px",

            }}

          >

            <div>

              <div

                style={{

                  fontSize: "10px",

                  fontWeight: 800,

                  letterSpacing: "1.1px",

                  color: "#667eea",

                  marginBottom: "7px",

                }}

              >

                VALIDATION RESULTS

              </div>



              <h2

                style={{

                  margin: 0,

                  fontSize: "19px",

                  color: "#172033",

                }}

              >

                Classification Performance

              </h2>

            </div>



            <span

              style={{

                padding: "7px 10px",

                borderRadius: "8px",

                background: "#edf8f2",

                color: "#247a50",

                fontSize: "10px",

                fontWeight: 800,

              }}

            >

              VERIFIED RUN

            </span>

          </div>



          <PerformanceRow

            label="Accuracy"

            value={ML_METRICS.accuracy}

          />



          <PerformanceRow

            label="Precision"

            value={ML_METRICS.precision}

          />



          <PerformanceRow

            label="Recall"

            value={ML_METRICS.recall}

          />



          <PerformanceRow

            label="F1 Score"

            value={ML_METRICS.f1}

          />

        </div>



        <div

          style={{

            background: "#ffffff",

            border: "1px solid #e1e7f0",

            borderRadius: "16px",

            padding: "24px",

          }}

        >

          <div

            style={{

              fontSize: "10px",

              fontWeight: 800,

              letterSpacing: "1.1px",

              color: "#667eea",

              marginBottom: "7px",

            }}

          >

            CONFUSION MATRIX

          </div>



          <h2

            style={{

              margin:

                "0 0 18px",

              fontSize: "19px",

              color: "#172033",

            }}

          >

            Validation Predictions

          </h2>



          <div

            style={{

              display: "grid",

              gridTemplateColumns:

                "80px 1fr 1fr",

              border:

                "1px solid #e2e7ef",

              borderRadius: "10px",

              overflow: "hidden",

            }}

          >

            <div

              style={{

                background: "#f6f8fb",

                padding: "12px",

              }}

            />



            <MatrixHeader text="Predicted Normal" />



            <MatrixHeader text="Predicted Attack" />



            <MatrixHeader text="Actual Normal" />



            <MatrixCell

              value="10,007"

              tone="normal"

              label="True Negative"

            />



            <MatrixCell

              value="1,193"

              tone="warning"

              label="False Positive"

            />



            <MatrixHeader text="Actual Attack" />



            <MatrixCell

              value="1,180"

              tone="warning"

              label="False Negative"

            />



            <MatrixCell

              value="22,689"

              tone="danger"

              label="True Positive"

            />

          </div>

        </div>

      </section>



      <section

        style={{

          display: "grid",

          gridTemplateColumns:

            "repeat(3, minmax(0, 1fr))",

          gap: "14px",

          marginBottom: "16px",

        }}

      >

        <RuntimeCard

          icon={Zap}

          label="Prediction Latency"

          value={`${ML_METRICS.predictionTime} ms`}

          description="Measured during model evaluation"

        />



        <RuntimeCard

          icon={BarChart3}

          label="Training Time"

          value={`${ML_METRICS.trainingTime} s`}

          description="End-to-end training run"

        />



        <RuntimeCard

          icon={Activity}

          label="Validation Set"

          value={ML_METRICS.validationSamples.toLocaleString()}

          description="Stratified validation records"

        />

      </section>



      <section

        style={{

          background: "#ffffff",

          border: "1px solid #e1e7f0",

          borderRadius: "16px",

          padding: "22px 24px",

          marginBottom: "16px",

          display: "flex",

          alignItems: "flex-start",

          gap: "14px",

        }}

      >

        <div

          style={{

            width: "38px",

            height: "38px",

            borderRadius: "10px",

            background: "#eef1ff",

            color: "#5d6fe5",

            display: "flex",

            alignItems: "center",

            justifyContent: "center",

            flexShrink: 0,

          }}

        >

          <Info size={19} />

        </div>



        <div>

          <strong

            style={{

              display: "block",

              color: "#172033",

              fontSize: "14px",

              marginBottom: "5px",

            }}

          >

            How A²FaaS uses the model

          </strong>



          <span

            style={{

              color: "#707d93",

              fontSize: "12px",

              lineHeight: 1.7,

            }}

          >

            The firewall converts observable request

            properties into the 42-feature schema

            expected by the trained UNSW-NB15 model.

            Logistic Regression produces an attack

            probability, which becomes the ML risk

            score. The result is then passed to the

            Zero Trust policy engine before the final

            Allow, Challenge, or Block decision.

          </span>

        </div>

      </section>



      <footer className="footer">

        <div>

          <span className="footer-brand">

            A²FaaS

          </span>



          <span>

            AI-Assisted Adaptive Firewall-as-a-Service

          </span>

        </div>



        <div className="footer-right">

          <span>ML Engine</span>



          <span className="footer-separator">

            •

          </span>



          <span>

            UNSW-NB15 / Logistic Regression

          </span>

        </div>

      </footer>

    </div>

  );

}



function MLInfoBox({ label, value }) {

  return (

    <div

      style={{

        padding: "14px",

        borderRadius: "10px",

        background: "#f7f9fc",

        border: "1px solid #e8edf4",

      }}

    >

      <div

        style={{

          color: "#8490a4",

          fontSize: "10px",

          fontWeight: 800,

          letterSpacing: "0.8px",

          marginBottom: "6px",

        }}

      >

        {label.toUpperCase()}

      </div>



      <div

        style={{

          color: "#1b263b",

          fontSize: "13px",

          fontWeight: 750,

        }}

      >

        {value}

      </div>

    </div>

  );

}



function PipelineStep({

  number,

  title,

  text,

}) {

  return (

    <div

      style={{

        display: "flex",

        alignItems: "center",

        gap: "12px",

        padding: "10px 0",

        borderBottom:

          "1px solid rgba(255,255,255,0.09)",

      }}

    >

      <span

        style={{

          fontSize: "10px",

          fontWeight: 800,

          color: "#aab9e9",

          width: "22px",

        }}

      >

        {number}

      </span>



      <div>

        <strong

          style={{

            display: "block",

            fontSize: "12px",

            color: "#ffffff",

            marginBottom: "2px",

          }}

        >

          {title}

        </strong>



        <span

          style={{

            fontSize: "10px",

            color: "#aebbd8",

          }}

        >

          {text}

        </span>

      </div>

    </div>

  );

}



function PerformanceRow({

  label,

  value,

}) {

  return (

    <div

      style={{

        marginBottom: "18px",

      }}

    >

      <div

        style={{

          display: "flex",

          justifyContent: "space-between",

          alignItems: "center",

          marginBottom: "7px",

        }}

      >

        <span

          style={{

            color: "#536178",

            fontSize: "12px",

            fontWeight: 700,

          }}

        >

          {label}

        </span>



        <strong

          style={{

            color: "#172033",

            fontSize: "12px",

          }}

        >

          {value.toFixed(2)}%

        </strong>

      </div>



      <div

        style={{

          height: "8px",

          borderRadius: "20px",

          background: "#edf0f5",

          overflow: "hidden",

        }}

      >

        <div

          style={{

            height: "100%",

            width: `${value}%`,

            borderRadius: "20px",

            background:

              "linear-gradient(90deg, #6474df, #7b86e8)",

          }}

        />

      </div>

    </div>

  );

}



function MatrixHeader({ text }) {

  return (

    <div

      style={{

        padding: "11px",

        background: "#f6f8fb",

        borderLeft:

          "1px solid #e2e7ef",

        borderBottom:

          "1px solid #e2e7ef",

        color: "#718097",

        fontSize: "9px",

        fontWeight: 800,

        textAlign: "center",

      }}

    >

      {text}

    </div>

  );

}



function MatrixCell({

  value,

  tone,

  label,

}) {

  const background =

    tone === "danger"

      ? "#edf8f2"

      : tone === "warning"

        ? "#fff8e9"

        : "#f4f7ff";



  const color =

    tone === "danger"

      ? "#26784f"

      : tone === "warning"

        ? "#98711e"

        : "#5669c9";



  return (

    <div

      title={label}

      style={{

        padding: "18px 10px",

        background,

        borderLeft:

          "1px solid #e2e7ef",

        borderBottom:

          "1px solid #e2e7ef",

        textAlign: "center",

        color,

        fontSize: "16px",

        fontWeight: 800,

      }}

    >

      {value}

    </div>

  );

}



function RuntimeCard({

  icon: Icon,

  label,

  value,

  description,

}) {

  return (

    <div

      style={{

        background: "#ffffff",

        border: "1px solid #e1e7f0",

        borderRadius: "14px",

        padding: "20px",

        display: "flex",

        alignItems: "flex-start",

        gap: "13px",

      }}

    >

      <div

        style={{

          width: "38px",

          height: "38px",

          borderRadius: "10px",

          background: "#f0f2ff",

          color: "#5d6fe5",

          display: "flex",

          alignItems: "center",

          justifyContent: "center",

          flexShrink: 0,

        }}

      >

        <Icon size={18} />

      </div>



      <div>

        <div

          style={{

            color: "#7b879d",

            fontSize: "10px",

            fontWeight: 800,

            letterSpacing: "0.8px",

            marginBottom: "5px",

          }}

        >

          {label.toUpperCase()}

        </div>



        <div

          style={{

            color: "#172033",

            fontSize: "21px",

            fontWeight: 850,

            marginBottom: "4px",

          }}

        >

          {value}

        </div>



        <div

          style={{

            color: "#8994a8",

            fontSize: "10px",

          }}

        >

          {description}

        </div>

      </div>

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

              margin:

                "0 0 10px",

              color: "#172033",

            }}

          >

            Module Connected

          </h2>



          <p

            style={{

              margin:

                "0 0 20px",

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



      <div className="metric-label">

        {label}

      </div>



      <div className="metric-value">

        {value}

      </div>



      <div className="metric-description">

        {description}

      </div>

    </div>

  );

}



function LegendItem({

  label,

  value,

  type,

}) {

  return (

    <div className="legend-item">

      <div

        className={`legend-dot ${type}`}

      />



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
