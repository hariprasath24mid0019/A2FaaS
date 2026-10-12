import React, { useState } from "react";

import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Fingerprint,
  Gauge,
  Globe2,
  LockKeyhole,
  Radar,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  XCircle,
  Zap,
} from "lucide-react";

const API_BASE = (
  import.meta.env.VITE_API_URL || "http://127.0.0.1:8000"
)
  .trim()
  .replace(/\/+$/, "");

const INITIAL_FORM = {
  source_ip: "192.168.1.25",
  method: "GET",
  path: "/api/profile",
  user_agent:
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/154.0.0.0",
  request_size: 512,
  request_rate: 2,
  identity_verified: true,
  device_trusted: true,
};

export default function FirewallPage() {
  const [form, setForm] = useState(INITIAL_FORM);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [gatewayResult, setGatewayResult] = useState(null);
  const [gatewayLoading, setGatewayLoading] = useState(false);
  const [gatewayError, setGatewayError] = useState("");

  const updateField = (field, value) => {
    setForm((current) => ({
      ...current,
      [field]: value,
    }));
  };

  const analyzeRequest = async () => {
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const payload = {
        source_ip: form.source_ip.trim(),
        method: form.method,
        path: form.path.trim(),
        user_agent: form.user_agent.trim(),
        request_size: Number(form.request_size),
        request_rate: Number(form.request_rate),
        identity_verified: Boolean(form.identity_verified),
        device_trusted: Boolean(form.device_trusted),
      };

      const response = await fetch(
        `${API_BASE}/api/firewall/analyze`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        }
      );

      let data;

      try {
        data = await response.json();
      } catch {
        throw new Error(
          "The A²FaaS backend returned an invalid response."
        );
      }

      if (!response.ok) {
        const detail =
          typeof data?.detail === "string"
            ? data.detail
            : "Firewall analysis request failed.";

        throw new Error(detail);
      }

      setResult(data);
    } catch (err) {
      console.error("A²FaaS firewall analysis error:", err);

      if (err instanceof TypeError) {
        setError(
          "Unable to connect to the A²FaaS backend. Make sure FastAPI is running on port 8000."
        );
      } else {
        setError(
          err?.message ||
            "Unable to connect to the A²FaaS firewall analysis engine."
        );
      }
    } finally {
      setLoading(false);
    }
  };

  const accessProtectedDashboard = async () => {
    setGatewayLoading(true);
    setGatewayError("");
    setGatewayResult(null);

    try {
      const payload = {
        source_ip: form.source_ip.trim(),
        method: form.method,
        path: form.path.trim(),
        user_agent: form.user_agent.trim(),
        request_size: Number(form.request_size),
        request_rate: Number(form.request_rate),
        identity_verified: Boolean(form.identity_verified),
        device_trusted: Boolean(form.device_trusted),
      };

      const response = await fetch(
        `${API_BASE}/api/gateway/protected-dashboard`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }
      );

      let data;
      try {
        data = await response.json();
      } catch {
        throw new Error("The A²FaaS gateway returned an invalid response.");
      }

      // The API intentionally uses HTTP 403 for CHALLENGE and BLOCK.
      // Keep those decisions visible as results instead of treating them as
      // connectivity errors.
      if (response.ok) {
        setGatewayResult(data);
      } else if (response.status === 403 && data?.detail) {
        setGatewayResult(data.detail);
      } else {
        const detail =
          typeof data?.detail === "string"
            ? data.detail
            : data?.detail?.message || "Protected dashboard request failed.";
        throw new Error(detail);
      }
    } catch (err) {
      console.error("A²FaaS protected gateway error:", err);
      setGatewayError(
        err instanceof TypeError
          ? "Unable to connect to the A²FaaS gateway. Check the backend URL and network connection."
          : err?.message || "Unable to access the protected dashboard."
      );
    } finally {
      setGatewayLoading(false);
    }
  };

  const resetAnalyzer = () => {
    setForm(INITIAL_FORM);
    setResult(null);
    setError("");
    setGatewayResult(null);
    setGatewayError("");
  };

  const getDecisionClass = (decision) => {
    if (decision === "ALLOW") return "allow";
    if (decision === "CHALLENGE") return "challenge";
    return "block";
  };

  const getRiskClass = (riskLevel) => {
    if (riskLevel === "LOW") return "low";
    if (riskLevel === "MEDIUM") return "medium";
    return "high";
  };

  /*
   * The backend normally returns the number of extracted features.
   * This helper is deliberately defensive because an older response
   * may contain the complete feature object instead.
   */
  const getFeatureCount = (features) => {
    if (typeof features === "number") {
      return features;
    }

    if (
      features &&
      typeof features === "object" &&
      !Array.isArray(features)
    ) {
      return Object.keys(features).length;
    }

    if (Array.isArray(features)) {
      return features.length;
    }

    return 0;
  };

  const featureCount = result
    ? getFeatureCount(result.extracted_features)
    : 0;

  const riskScore = result
    ? Number(result.risk_score || 0)
    : 0;

  const riskPercentage = Math.min(
    100,
    Math.max(0, riskScore * 100)
  );

  return (
    <div className="firewall-page">
      <style>{`
        .firewall-page {
          padding: 32px;
          max-width: 1600px;
          margin: 0 auto;
        }

        .firewall-heading {
          display: flex;
          align-items: flex-end;
          justify-content: space-between;
          gap: 24px;
          margin-bottom: 22px;
        }

        .firewall-eyebrow {
          display: flex;
          align-items: center;
          gap: 7px;
          color: #5967d9;
          font-size: 9px;
          font-weight: 800;
          letter-spacing: 1.25px;
        }

        .firewall-eyebrow-line {
          width: 18px;
          height: 2px;
          background: #5967d9;
        }

        .firewall-heading h1 {
          margin: 9px 0 7px;
          color: #172033;
          font-size: 35px;
          line-height: 1.08;
          letter-spacing: -1.2px;
        }

        .firewall-heading p {
          margin: 0;
          color: #697586;
          font-size: 12px;
        }

        .firewall-status {
          display: flex;
          align-items: center;
          gap: 7px;
          padding: 9px 12px;
          border: 1px solid #dcefe2;
          border-radius: 9px;
          background: #f2fbf5;
          color: #4d8b67;
          font-size: 9px;
          font-weight: 800;
          white-space: nowrap;
        }

        .firewall-status-dot {
          width: 7px;
          height: 7px;
          border-radius: 50%;
          background: #69b381;
          box-shadow: 0 0 0 3px #e8f6ec;
        }

        .firewall-layout {
          display: grid;
          grid-template-columns: minmax(0, 1.4fr) minmax(340px, 0.8fr);
          gap: 15px;
          align-items: start;
        }

        .firewall-card {
          background: #ffffff;
          border: 1px solid #e5e9f2;
          border-radius: 13px;
          overflow: hidden;
        }

        .firewall-card-header {
          min-height: 72px;
          padding: 15px 17px;
          border-bottom: 1px solid #edf0f5;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 15px;
        }

        .firewall-card-title {
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .firewall-card-icon {
          width: 35px;
          height: 35px;
          border-radius: 9px;
          background: #eef0ff;
          color: #5967d9;
          display: flex;
          align-items: center;
          justify-content: center;
        }

        .firewall-card-header h2 {
          margin: 0 0 4px;
          font-size: 13px;
          color: #172033;
        }

        .firewall-card-header p {
          margin: 0;
          font-size: 8px;
          color: #98a2b3;
        }

        .firewall-form {
          padding: 19px;
        }

        .firewall-section-label {
          display: flex;
          align-items: center;
          gap: 6px;
          margin-bottom: 12px;
          color: #5967d9;
          font-size: 8px;
          font-weight: 800;
          letter-spacing: 1px;
        }

        .firewall-form-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 14px;
        }

        .firewall-field {
          display: flex;
          flex-direction: column;
          gap: 6px;
        }

        .firewall-field.full {
          grid-column: 1 / -1;
        }

        .firewall-field label {
          color: #667085;
          font-size: 9px;
          font-weight: 700;
        }

        .firewall-field input,
        .firewall-field select {
          width: 100%;
          height: 40px;
          padding: 0 11px;
          border: 1px solid #dce2eb;
          border-radius: 8px;
          outline: none;
          background: #ffffff;
          color: #172033;
          font-size: 10px;
          transition: 0.18s ease;
          box-sizing: border-box;
        }

        .firewall-field input:focus,
        .firewall-field select:focus {
          border-color: #5967d9;
          box-shadow: 0 0 0 3px rgba(89, 103, 217, 0.08);
        }

        .firewall-field textarea {
          width: 100%;
          min-height: 72px;
          padding: 10px 11px;
          border: 1px solid #dce2eb;
          border-radius: 8px;
          outline: none;
          background: #ffffff;
          color: #172033;
          font-size: 10px;
          line-height: 1.45;
          resize: vertical;
          font-family: inherit;
          box-sizing: border-box;
        }

        .firewall-field textarea:focus {
          border-color: #5967d9;
          box-shadow: 0 0 0 3px rgba(89, 103, 217, 0.08);
        }

        .firewall-security {
          margin-top: 18px;
          padding: 14px;
          border: 1px solid #e4e8f1;
          border-radius: 10px;
          background: #f8faff;
        }

        .firewall-security-title {
          display: flex;
          align-items: center;
          gap: 7px;
          margin-bottom: 11px;
          color: #344054;
          font-size: 9px;
          font-weight: 800;
        }

        .firewall-security-options {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 9px;
        }

        .firewall-toggle {
          min-height: 43px;
          padding: 0 11px;
          border: 1px solid #e0e5ee;
          border-radius: 8px;
          background: #ffffff;
          display: flex;
          align-items: center;
          gap: 8px;
          cursor: pointer;
        }

        .firewall-toggle.active {
          border-color: #bfc7f7;
          background: #f3f4ff;
        }

        .firewall-toggle input {
          accent-color: #5967d9;
        }

        .firewall-toggle-content {
          display: flex;
          flex-direction: column;
          gap: 2px;
        }

        .firewall-toggle-content strong {
          color: #344054;
          font-size: 9px;
        }

        .firewall-toggle-content span {
          color: #98a2b3;
          font-size: 7px;
        }

        .firewall-actions {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 12px;
          margin-top: 19px;
        }

        .firewall-reset {
          height: 38px;
          padding: 0 13px;
          border: 1px solid #e0e5ed;
          border-radius: 8px;
          background: #ffffff;
          color: #667085;
          display: inline-flex;
          align-items: center;
          gap: 7px;
          font-size: 9px;
          font-weight: 700;
          cursor: pointer;
        }

        .firewall-reset:hover {
          background: #f8f9fc;
        }

        .firewall-analyze {
          min-width: 160px;
          height: 38px;
          padding: 0 15px;
          border: 0;
          border-radius: 8px;
          background: #5967d9;
          color: #ffffff;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          font-size: 9px;
          font-weight: 800;
          box-shadow: 0 6px 15px rgba(89, 103, 217, 0.17);
          cursor: pointer;
        }

        .firewall-analyze:hover {
          background: #4654c5;
        }

        .firewall-analyze:disabled {
          opacity: 0.65;
          cursor: wait;
        }

        .firewall-error {
          margin-top: 14px;
          padding: 11px 12px;
          border: 1px solid #f1d3d3;
          border-radius: 8px;
          background: #fff3f3;
          color: #a65353;
          display: flex;
          align-items: flex-start;
          gap: 8px;
          font-size: 9px;
          line-height: 1.45;
        }

        .firewall-pipeline {
          padding: 18px;
        }

        .pipeline-intro {
          margin-bottom: 16px;
          padding: 13px;
          border-radius: 10px;
          background: #252e50;
          color: #ffffff;
        }

        .pipeline-intro-label {
          color: #aeb7ec;
          font-size: 7px;
          letter-spacing: 1px;
          font-weight: 800;
          margin-bottom: 6px;
        }

        .pipeline-intro strong {
          display: block;
          font-size: 13px;
          margin-bottom: 4px;
        }

        .pipeline-intro span {
          color: #cbd1e8;
          font-size: 8px;
          line-height: 1.5;
        }

        .pipeline-step {
          position: relative;
          display: flex;
          gap: 11px;
          padding: 11px 0;
          border-bottom: 1px solid #edf0f5;
        }

        .pipeline-step:last-child {
          border-bottom: 0;
        }

        .pipeline-number {
          width: 27px;
          height: 27px;
          flex-shrink: 0;
          border-radius: 8px;
          background: #f1f3ff;
          color: #5967d9;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 8px;
          font-weight: 800;
        }

        .pipeline-step-content {
          display: flex;
          flex-direction: column;
          gap: 3px;
        }

        .pipeline-step-content strong {
          font-size: 9px;
          color: #344054;
        }

        .pipeline-step-content span {
          font-size: 7px;
          color: #98a2b3;
          line-height: 1.4;
        }

        .firewall-result {
          margin-top: 15px;
        }

        .result-empty {
          min-height: 250px;
          padding: 25px;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          text-align: center;
          color: #98a2b3;
        }

        .result-empty-icon {
          width: 48px;
          height: 48px;
          border-radius: 13px;
          background: #f1f3ff;
          color: #7180e4;
          display: flex;
          align-items: center;
          justify-content: center;
          margin-bottom: 11px;
        }

        .result-empty strong {
          color: #667085;
          font-size: 11px;
          margin-bottom: 5px;
        }

        .result-empty span {
          max-width: 235px;
          font-size: 8px;
          line-height: 1.5;
        }

        .result-live {
          padding: 17px;
        }

        .result-decision {
          padding: 15px;
          border-radius: 11px;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 15px;
          margin-bottom: 14px;
        }

        .result-decision.allow {
          background: #eef9f2;
          border: 1px solid #d8efdf;
        }

        .result-decision.challenge {
          background: #fff8e8;
          border: 1px solid #f1e4c2;
        }

        .result-decision.block {
          background: #fff1f1;
          border: 1px solid #f0d3d3;
        }

        .result-decision-left {
          display: flex;
          align-items: center;
          gap: 10px;
        }

        .result-decision-icon {
          width: 36px;
          height: 36px;
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          background: rgba(255, 255, 255, 0.65);
        }

        .result-decision.allow .result-decision-icon {
          color: #4f9669;
        }

        .result-decision.challenge .result-decision-icon {
          color: #a8791f;
        }

        .result-decision.block .result-decision-icon {
          color: #b65e5e;
        }

        .result-decision-copy {
          display: flex;
          flex-direction: column;
          gap: 3px;
        }

        .result-decision-copy small {
          color: #8c96a8;
          font-size: 7px;
          font-weight: 800;
          letter-spacing: 0.8px;
        }

        .result-decision-copy strong {
          font-size: 18px;
          letter-spacing: -0.3px;
        }

        .result-decision.allow .result-decision-copy strong {
          color: #4f9669;
        }

        .result-decision.challenge .result-decision-copy strong {
          color: #a8791f;
        }

        .result-decision.block .result-decision-copy strong {
          color: #b65e5e;
        }

        .result-risk {
          text-align: right;
        }

        .result-risk small {
          display: block;
          color: #8c96a8;
          font-size: 7px;
          margin-bottom: 3px;
        }

        .result-risk strong {
          font-size: 17px;
        }

        .result-risk strong.low {
          color: #4f9669;
        }

        .result-risk strong.medium {
          color: #a8791f;
        }

        .result-risk strong.high {
          color: #b65e5e;
        }

        .result-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          border: 1px solid #e7eaf1;
          border-radius: 9px;
          overflow: hidden;
        }

        .result-cell {
          min-height: 65px;
          padding: 11px;
          border-right: 1px solid #e7eaf1;
          border-bottom: 1px solid #e7eaf1;
        }

        .result-cell:nth-child(2n) {
          border-right: 0;
        }

        .result-cell:nth-last-child(-n + 2) {
          border-bottom: 0;
        }

        .result-cell span {
          display: block;
          color: #98a2b3;
          font-size: 7px;
          margin-bottom: 5px;
          font-weight: 700;
        }

        .result-cell strong {
          color: #344054;
          font-size: 10px;
        }

        .result-reason {
          margin-top: 12px;
          padding: 11px 12px;
          border-radius: 8px;
          background: #f8faff;
          border: 1px solid #e5e9f2;
          display: flex;
          gap: 8px;
        }

        .result-reason svg {
          color: #6575df;
          flex-shrink: 0;
          margin-top: 1px;
        }

        .result-reason-copy {
          display: flex;
          flex-direction: column;
          gap: 3px;
        }

        .result-reason-copy strong {
          color: #344054;
          font-size: 8px;
        }

        .result-reason-copy span {
          color: #8c96a8;
          font-size: 7px;
          line-height: 1.45;
        }

        .result-request-id {
          margin-top: 10px;
          color: #a0a9b8;
          font-size: 7px;
          word-break: break-all;
        }

        .result-request-id strong {
          color: #7b8495;
        }

        .firewall-mini-status {
          margin-top: 15px;
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 9px;
        }

        .mini-status {
          padding: 11px;
          border: 1px solid #e5e9f2;
          border-radius: 9px;
          background: #ffffff;
        }

        .mini-status-top {
          display: flex;
          align-items: center;
          gap: 6px;
          margin-bottom: 5px;
        }

        .mini-status-top svg {
          color: #5967d9;
        }

        .mini-status strong {
          color: #344054;
          font-size: 8px;
        }

        .mini-status span {
          color: #8f99aa;
          font-size: 7px;
        }

        .firewall-spin {
          animation: firewallSpin 0.8s linear infinite;
        }

        @keyframes firewallSpin {
          from {
            transform: rotate(0deg);
          }

          to {
            transform: rotate(360deg);
          }
        }

        .firewall-gateway-button {
          min-width: 170px;
          min-height: 38px;
          padding: 0 14px;
          border: 1px solid #cbd2ff;
          border-radius: 8px;
          background: #f2f4ff;
          color: #4654c5;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          font-size: 9px;
          font-weight: 800;
          cursor: pointer;
        }

        .firewall-gateway-button:hover { background: #e8ebff; }
        .firewall-gateway-button:disabled { opacity: 0.65; cursor: wait; }

        .gateway-outcome {
          margin: 16px;
          padding: 16px;
          border: 1px solid #e5e9f2;
          border-radius: 10px;
          background: #fff;
        }

        .gateway-outcome.allow { border-color: #d8efdf; background: #f5fcf7; }
        .gateway-outcome.challenge { border-color: #f1e4c2; background: #fffbf1; }
        .gateway-outcome.block { border-color: #f0d3d3; background: #fff7f7; }
        .gateway-outcome h3 { margin: 0 0 7px; font-size: 14px; color: #172033; }
        .gateway-outcome p { margin: 0 0 10px; color: #667085; font-size: 10px; line-height: 1.5; }
        .gateway-outcome pre { white-space: pre-wrap; overflow-wrap: anywhere; margin: 10px 0 0; padding: 11px; border-radius: 7px; background: rgba(255,255,255,.8); color: #344054; font-size: 9px; }
        .gateway-label { display: inline-block; margin-bottom: 8px; font-size: 9px; font-weight: 800; letter-spacing: .6px; }

        @media (max-width: 1050px) {
          .firewall-layout {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 650px) {
          .firewall-page {
            padding: 20px 14px;
          }

          .firewall-heading {
            flex-direction: column;
            align-items: flex-start;
          }

          .firewall-form-grid {
            grid-template-columns: 1fr;
          }

          .firewall-field.full {
            grid-column: auto;
          }

          .firewall-security-options {
            grid-template-columns: 1fr;
          }

          .firewall-actions {
            flex-direction: column;
            align-items: stretch;
          }

          .firewall-reset,
          .firewall-analyze {
            width: 100%;
          }

          .firewall-mini-status {
            grid-template-columns: 1fr;
          }
        }
      `}</style>

      <section className="firewall-heading">
        <div>
          <div className="firewall-eyebrow">
            <span className="firewall-eyebrow-line" />
            ADAPTIVE FIREWALL
          </div>

          <h1>Firewall Control Center</h1>

          <p>
            Inspect requests, calculate ML risk, verify identity context,
            and enforce adaptive security decisions.
          </p>
        </div>

        <div className="firewall-status">
          <span className="firewall-status-dot" />
          Firewall Engine Online
        </div>
      </section>

      <div className="firewall-layout">
        <section className="firewall-card">
          <div className="firewall-card-header">
            <div className="firewall-card-title">
              <div className="firewall-card-icon">
                <Radar size={18} />
              </div>

              <div>
                <h2>Request Inspection</h2>
                <p>
                  Submit traffic directly to the A²FaaS security pipeline.
                </p>
              </div>
            </div>
          </div>

          <div className="firewall-form">
            <div className="firewall-section-label">
              <Globe2 size={13} />
              REQUEST CONTEXT
            </div>

            <div className="firewall-form-grid">
              <div className="firewall-field">
                <label>Source IP Address</label>

                <input
                  value={form.source_ip}
                  onChange={(event) =>
                    updateField("source_ip", event.target.value)
                  }
                  placeholder="192.168.1.25"
                />
              </div>

              <div className="firewall-field">
                <label>HTTP Method</label>

                <select
                  value={form.method}
                  onChange={(event) =>
                    updateField("method", event.target.value)
                  }
                >
                  <option value="GET">GET</option>
                  <option value="POST">POST</option>
                  <option value="PUT">PUT</option>
                  <option value="PATCH">PATCH</option>
                  <option value="DELETE">DELETE</option>
                </select>
              </div>

              <div className="firewall-field full">
                <label>Request Path</label>

                <input
                  value={form.path}
                  onChange={(event) =>
                    updateField("path", event.target.value)
                  }
                  placeholder="/api/profile"
                />
              </div>

              <div className="firewall-field full">
                <label>User-Agent</label>

                <textarea
                  value={form.user_agent}
                  onChange={(event) =>
                    updateField("user_agent", event.target.value)
                  }
                />
              </div>

              <div className="firewall-field">
                <label>Request Size (bytes)</label>

                <input
                  type="number"
                  min="0"
                  value={form.request_size}
                  onChange={(event) =>
                    updateField("request_size", event.target.value)
                  }
                />
              </div>

              <div className="firewall-field">
                <label>Request Rate / second</label>

                <input
                  type="number"
                  min="0"
                  step="0.1"
                  value={form.request_rate}
                  onChange={(event) =>
                    updateField("request_rate", event.target.value)
                  }
                />
              </div>
            </div>

            <div className="firewall-security">
              <div className="firewall-security-title">
                <LockKeyhole size={13} />
                ZERO TRUST CONTEXT
              </div>

              <div className="firewall-security-options">
                <label
                  className={`firewall-toggle ${
                    form.identity_verified ? "active" : ""
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={form.identity_verified}
                    onChange={(event) =>
                      updateField(
                        "identity_verified",
                        event.target.checked
                      )
                    }
                  />

                  <span className="firewall-toggle-content">
                    <strong>Identity Verified</strong>
                    <span>User identity has been verified</span>
                  </span>
                </label>

                <label
                  className={`firewall-toggle ${
                    form.device_trusted ? "active" : ""
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={form.device_trusted}
                    onChange={(event) =>
                      updateField(
                        "device_trusted",
                        event.target.checked
                      )
                    }
                  />

                  <span className="firewall-toggle-content">
                    <strong>Trusted Device</strong>
                    <span>Device passed trust verification</span>
                  </span>
                </label>
              </div>
            </div>

            {error && (
              <div className="firewall-error">
                <AlertTriangle size={15} />

                <span>{error}</span>
              </div>
            )}

            <div className="firewall-actions">
              <button
                className="firewall-reset"
                type="button"
                onClick={resetAnalyzer}
                disabled={loading}
              >
                <RefreshCw size={13} />
                Reset
              </button>

              <button
                className="firewall-analyze"
                type="button"
                onClick={analyzeRequest}
                disabled={loading}
              >
                {loading ? (
                  <>
                    <RefreshCw
                      size={14}
                      className="firewall-spin"
                    />
                    Analyzing Request...
                  </>
                ) : (
                  <>
                    <Zap size={14} />
                    Analyze Request
                  </>
                )}
              </button>

              <button
                className="firewall-gateway-button"
                type="button"
                onClick={accessProtectedDashboard}
                disabled={gatewayLoading || loading}
              >
                {gatewayLoading ? (
                  <>
                    <RefreshCw size={13} className="firewall-spin" />
                    Checking Access...
                  </>
                ) : (
                  <>
                    <LockKeyhole size={13} />
                    Test Protected Access
                  </>
                )}
              </button>
            </div>
          </div>
        </section>

        <section className="firewall-card">
          <div className="firewall-card-header">
            <div className="firewall-card-title">
              <div className="firewall-card-icon">
                <ShieldCheck size={18} />
              </div>

              <div>
                <h2>Security Pipeline</h2>
                <p>
                  Every request passes through adaptive controls.
                </p>
              </div>
            </div>
          </div>

          <div className="firewall-pipeline">
            <div className="pipeline-intro">
              <div className="pipeline-intro-label">
                A²FaaS DECISION ENGINE
              </div>

              <strong>Adaptive request protection</strong>

              <span>
                ML classification and Zero Trust verification work
                together before the application receives traffic.
              </span>
            </div>

            <PipelineStep
              number="01"
              title="Traffic Features"
              description="HTTP request properties are normalized into the ML feature vector."
            />

            <PipelineStep
              number="02"
              title="ML Risk Scoring"
              description="The trained Logistic Regression model calculates attack probability."
            />

            <PipelineStep
              number="03"
              title="Zero Trust Verification"
              description="Identity, device trust, path, and request context are evaluated."
            />

            <PipelineStep
              number="04"
              title="Firewall Decision"
              description="The request is allowed, challenged, or blocked."
            />
          </div>
        </section>
      </div>

      <div className="firewall-result firewall-card">
        <div className="firewall-card-header">
          <div className="firewall-card-title">
            <div className="firewall-card-icon">
              <Activity size={18} />
            </div>

            <div>
              <h2>Live Analysis Result</h2>
              <p>
                Real response returned by the A²FaaS backend.
              </p>
            </div>
          </div>

          {result && (
            <div className="firewall-status">
              <CheckCircle2 size={12} />
              Verified Backend Response
            </div>
          )}
        </div>

        {!result ? (
          <div className="result-empty">
            <div className="result-empty-icon">
              <Shield size={22} />
            </div>

            <strong>No request analyzed yet</strong>

            <span>
              Configure the request context above and run the analyzer
              to receive a real ML risk score and Zero Trust decision.
            </span>
          </div>
        ) : (
          <div className="result-live">
            <div
              className={`result-decision ${getDecisionClass(
                result.decision
              )}`}
            >
              <div className="result-decision-left">
                <div className="result-decision-icon">
                  {result.decision === "ALLOW" && (
                    <CheckCircle2 size={21} />
                  )}

                  {result.decision === "CHALLENGE" && (
                    <AlertTriangle size={21} />
                  )}

                  {result.decision === "BLOCK" && (
                    <XCircle size={21} />
                  )}
                </div>

                <div className="result-decision-copy">
                  <small>FIREWALL DECISION</small>
                  <strong>{result.decision}</strong>
                </div>
              </div>

              <div className="result-risk">
                <small>RISK SCORE</small>

                <strong
                  className={getRiskClass(result.risk_level)}
                >
                  {riskPercentage.toFixed(2)}%
                </strong>
              </div>
            </div>

            <div className="result-grid">
              <ResultCell
                label="ML Prediction"
                value={
                  Number(result.ml_prediction) === 1
                    ? "ATTACK"
                    : "NORMAL"
                }
              />

              <ResultCell
                label="Risk Level"
                value={result.risk_level || "UNKNOWN"}
              />

              <ResultCell
                label="Zero Trust"
                value={result.zero_trust_status || "UNKNOWN"}
              />

              <ResultCell
                label="Identity"
                value={
                  result.identity_verified
                    ? "VERIFIED"
                    : "UNVERIFIED"
                }
              />

              <ResultCell
                label="Device"
                value={
                  result.device_trusted
                    ? "TRUSTED"
                    : "UNTRUSTED"
                }
              />

              <ResultCell
                label="Features Extracted"
                value={featureCount}
              />
            </div>

            <div className="result-reason">
              <ShieldAlert size={15} />

              <div className="result-reason-copy">
                <strong>Decision Explanation</strong>

                <span>
                  {result.reason ||
                    result.message ||
                    "The A²FaaS security engine completed request evaluation."}
                </span>
              </div>
            </div>

            <div className="result-request-id">
              <strong>Request ID:</strong>{" "}
              {result.request_id || "N/A"}
            </div>

            <div className="firewall-mini-status">
              <MiniStatus
                icon={Fingerprint}
                title="Identity"
                value={
                  result.identity_verified
                    ? "Verified"
                    : "Not verified"
                }
              />

              <MiniStatus
                icon={Smartphone}
                title="Device"
                value={
                  result.device_trusted
                    ? "Trusted"
                    : "Untrusted"
                }
              />

              <MiniStatus
                icon={Gauge}
                title="ML Engine"
                value="Prediction complete"
              />
            </div>
          </div>
        )}
      </div>

      <section className="firewall-card" style={{ marginTop: 15 }}>
        <div className="firewall-card-header">
          <div className="firewall-card-title">
            <div className="firewall-card-icon">
              <LockKeyhole size={18} />
            </div>
            <div>
              <h2>Protected Dashboard Gateway</h2>
              <p>Live enforcement test against the deployed protected resource.</p>
            </div>
          </div>
          {gatewayResult && (
            <div className="firewall-status" style={{
              borderColor: gatewayResult.firewall_decision === "ALLOW" ? "#d8efdf" : "#f0d3d3",
              background: gatewayResult.firewall_decision === "ALLOW" ? "#f2fbf5" : "#fff3f3",
              color: gatewayResult.firewall_decision === "ALLOW" ? "#4d8b67" : "#a65353"
            }}>
              {gatewayResult.firewall_decision || gatewayResult.access || "RESULT"}
            </div>
          )}
        </div>

        {gatewayError && (
          <div className="firewall-error" style={{ margin: 16 }}>
            <AlertTriangle size={15} />
            <span>{gatewayError}</span>
          </div>
        )}

        {!gatewayResult ? (
          <div className="result-empty" style={{ minHeight: 140 }}>
            <div className="result-empty-icon"><LockKeyhole size={21} /></div>
            <strong>No protected access test yet</strong>
            <span>Use “Test Protected Access” to submit the current request context to the live gateway.</span>
          </div>
        ) : (
          <div className={`gateway-outcome ${
            gatewayResult.firewall_decision === "ALLOW" ? "allow" :
            gatewayResult.firewall_decision === "CHALLENGE" ? "challenge" : "block"
          }`}>
            <span className="gateway-label">
              {gatewayResult.firewall_decision === "ALLOW" || gatewayResult.access === "GRANTED"
                ? "ACCESS GRANTED"
                : gatewayResult.firewall_decision === "CHALLENGE" || gatewayResult.access === "CHALLENGE"
                  ? "VERIFICATION REQUIRED"
                  : "ACCESS DENIED"}
            </span>
            <h3>{gatewayResult.message || "Gateway decision received"}</h3>
            <p>
              Decision: <strong>{gatewayResult.firewall_decision || gatewayResult.access || "UNKNOWN"}</strong>
              {gatewayResult.risk_level ? <> · Risk: <strong>{gatewayResult.risk_level}</strong></> : null}
              {gatewayResult.risk_score !== undefined ? <> · Score: <strong>{gatewayResult.risk_score}</strong></> : null}
            </p>

            {gatewayResult.protected_resource && (
              <div>
                <h3>{gatewayResult.protected_resource.name}</h3>
                <p>
                  Classification: <strong>{gatewayResult.protected_resource.classification}</strong>
                </p>
                <pre>{JSON.stringify(gatewayResult.protected_resource.data, null, 2)}</pre>
              </div>
            )}

            {Array.isArray(gatewayResult.reasons) && gatewayResult.reasons.length > 0 && (
              <div>
                <p><strong>Decision reasons</strong></p>
                <ul style={{ margin: 0, paddingLeft: 18, color: "#667085", fontSize: 10, lineHeight: 1.6 }}>
                  {gatewayResult.reasons.map((reason, index) => <li key={`${index}-${reason}`}>{reason}</li>)}
                </ul>
              </div>
            )}

            {gatewayResult.zero_trust_reason && <p style={{ marginTop: 10 }}>{gatewayResult.zero_trust_reason}</p>}
            <div className="result-request-id">
              <strong>Request ID:</strong> {gatewayResult.request_id || "N/A"}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

function PipelineStep({
  number,
  title,
  description,
}) {
  return (
    <div className="pipeline-step">
      <div className="pipeline-number">
        {number}
      </div>

      <div className="pipeline-step-content">
        <strong>{title}</strong>
        <span>{description}</span>
      </div>
    </div>
  );
}

function ResultCell({ label, value }) {
  return (
    <div className="result-cell">
      <span>{label}</span>
      <strong>{String(value ?? "N/A")}</strong>
    </div>
  );
}

function MiniStatus({
  icon: Icon,
  title,
  value,
}) {
  return (
    <div className="mini-status">
      <div className="mini-status-top">
        <Icon size={12} />
        <strong>{title}</strong>
      </div>

      <span>{value}</span>
    </div>
  );
}