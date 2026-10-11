
import os
import time
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel, Field

from database.database import (
    initialize_database,
    save_security_event,
    get_security_statistics,
    get_recent_events,
    _USE_POSTGRES,
)
from ml.predict import predict_risk
from security.feature_extractor import extract_features
from security.zero_trust import verify_request


# ============================================================
# A²FaaS — AI-Assisted Adaptive Firewall-as-a-Service
# ============================================================

APP_NAME = "A²FaaS"
APP_VERSION = "1.0.0"


app = FastAPI(
    title=APP_NAME,
    description=(
        "AI-Assisted Adaptive Firewall-as-a-Service "
        "for Cloud Applications"
    ),
    version=APP_VERSION,
)


# ============================================================
# CORS CONFIGURATION
# ============================================================

allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

frontend_origin = os.getenv("FRONTEND_ORIGIN", "").strip()

if frontend_origin and frontend_origin not in allowed_origins:
    allowed_origins.append(frontend_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Response-Time-ms"],
)


# ============================================================
# REQUEST ID AND SECURITY HEADERS
# ============================================================

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    request_id = request.headers.get(
        "X-Request-ID",
        str(uuid.uuid4()),
    )

    request.state.request_id = request_id
    start_time = time.perf_counter()

    response = await call_next(request)

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )
    response.headers["Referrer-Policy"] = (
        "strict-origin-when-cross-origin"
    )
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    elapsed_ms = (time.perf_counter() - start_time) * 1000
    response.headers["X-Response-Time-ms"] = f"{elapsed_ms:.2f}"

    return response


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event():
    initialize_database()

    print("=" * 60)
    print("A²FaaS BACKEND STARTED")
    print(f"Service     : {APP_NAME}")
    print(f"Version     : {APP_VERSION}")
    print(f"Database    : {'PostgreSQL' if _USE_POSTGRES else 'SQLite'}")
    print("ML Engine   : READY")
    print("Zero Trust  : READY")
    print("=" * 60)


# ============================================================
# FIREWALL REQUEST MODEL
# ============================================================

class FirewallRequest(BaseModel):
    source_ip: str = Field(default="127.0.0.1")
    method: str = Field(default="GET")
    path: str = Field(default="/")
    user_agent: str = Field(default="Mozilla/5.0")
    request_size: int = Field(default=0, ge=0)
    request_rate: float = Field(default=1.0, ge=0)
    identity_verified: bool = False
    device_trusted: bool = False


# ============================================================
# ROOT AND HEALTH ENDPOINTS
# ============================================================

@app.get("/")
async def root():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "status": "running",
        "message": "A²FaaS Adaptive Firewall API is operational",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": APP_NAME,
        "version": APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================
# SYSTEM INFORMATION
# ============================================================

@app.get("/api/system")
async def system_info():
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "environment": os.getenv("ENVIRONMENT", "development"),
        "database": "ready",
        "ml_engine": "ready",
        "zero_trust": "ready",
        "adaptive_firewall": "active",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/system/health")
async def system_health():
    return {
        "status": "healthy",
        "service": APP_NAME,
        "database": "ready",
        "ml_engine": "ready",
        "zero_trust": "ready",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

@app.get("/api/dashboard/stats")
async def dashboard_stats():
    """Return actual statistics from the SQLite database."""
    try:
        return get_security_statistics()
    except Exception as exc:
        print(f"[DASHBOARD STATS ERROR] {exc}")
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve dashboard statistics",
        )


# ============================================================
# RECENT SECURITY REQUESTS
# ============================================================

@app.get("/api/requests/recent")
async def recent_requests(
    limit: int = Query(default=20, ge=1, le=100),
):
    """Return recent firewall events stored in SQLite."""
    try:
        events = get_recent_events(limit=limit)
        return {
            "count": len(events),
            "events": events,
        }
    except Exception as exc:
        print(f"[RECENT REQUESTS ERROR] {exc}")
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve recent requests",
        )


# ============================================================
# BEHAVIORAL RISK CALCULATION
# ============================================================

def calculate_behavioral_risk(
    payload: FirewallRequest,
) -> float:
    """
    Calculate additional deterministic risk from request behavior.
    """

    risk = 0.0

    method = payload.method.upper()
    path = payload.path.lower()
    user_agent = payload.user_agent.lower()

    # Request rate
    if payload.request_rate >= 100:
        risk += 0.35
    elif payload.request_rate >= 50:
        risk += 0.20
    elif payload.request_rate >= 20:
        risk += 0.10

    # Request size
    if payload.request_size >= 100000:
        risk += 0.30
    elif payload.request_size >= 25000:
        risk += 0.20
    elif payload.request_size >= 10000:
        risk += 0.10

    # Administrative endpoint
    if "/admin" in path:
        risk += 0.15

    # Authentication-related endpoint
    auth_keywords = [
        "login",
        "signin",
        "sign-in",
        "auth",
        "token",
        "password",
    ]

    if any(keyword in path for keyword in auth_keywords):
        risk += 0.10

    # State-changing HTTP methods
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        risk += 0.05

    # Recognized security tool signatures
    suspicious_tools = [
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "burp",
        "hydra",
        "wpscan",
    ]

    if any(tool in user_agent for tool in suspicious_tools):
        risk += 0.25

    # Combined high-risk pattern
    if (
        "/admin" in path
        and any(keyword in path for keyword in auth_keywords)
        and method in {"POST", "PUT", "PATCH", "DELETE"}
        and payload.request_rate >= 50
    ):
        risk += 0.20

    return min(max(risk, 0.0), 1.0)


# ============================================================
# FIREWALL ANALYSIS
# ============================================================

@app.post("/api/firewall/analyze")
async def analyze_firewall_request(
    payload: FirewallRequest,
    request: Request,
):
    request_id = getattr(
        request.state,
        "request_id",
        str(uuid.uuid4()),
    )

    try:
        # ----------------------------------------------------
        # 1. Feature extraction
        # ----------------------------------------------------

        extracted_features = extract_features(
            source_ip=payload.source_ip,
            method=payload.method,
            path=payload.path,
            user_agent=payload.user_agent,
            request_size=payload.request_size,
            request_rate=payload.request_rate,
        )

        # ----------------------------------------------------
        # 2. ML risk prediction
        # ----------------------------------------------------

        ml_result = predict_risk(extracted_features)

        raw_ml_score = float(
            ml_result.get(
                "risk_score",
                ml_result.get("probability", 0.0),
            )
        )

        raw_ml_score = min(max(raw_ml_score, 0.0), 1.0)

        ml_prediction = int(
            ml_result.get(
                "prediction",
                1 if raw_ml_score >= 0.75 else 0,
            )
        )

        # ----------------------------------------------------
        # 3. Behavioral risk
        # ----------------------------------------------------

        behavioral_risk = calculate_behavioral_risk(payload)

        # ----------------------------------------------------
        # 4. Final adaptive risk score
        # ----------------------------------------------------

        risk_score = max(raw_ml_score, behavioral_risk)

        # ----------------------------------------------------
        # 5. Risk classification
        # ----------------------------------------------------

        if risk_score >= 0.75:
            risk_level = "HIGH"
            ml_prediction = 1
        elif risk_score >= 0.40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # ----------------------------------------------------
        # 6. Zero Trust verification
        # ----------------------------------------------------

        zero_trust_result = verify_request(
            source_ip=payload.source_ip,
            method=payload.method,
            path=payload.path,
            user_agent=payload.user_agent,
            risk_score=risk_score,
            ml_prediction=ml_prediction,
            identity_verified=payload.identity_verified,
            device_trusted=payload.device_trusted,
        )

        zero_trust_status = zero_trust_result.get(
            "status",
            "CHALLENGE",
        )

        zero_trust_decision = zero_trust_result.get(
            "decision",
            "CHALLENGE",
        )

        zero_trust_reason = zero_trust_result.get(
            "reason",
            "Zero Trust verification required",
        )

        # ----------------------------------------------------
        # 7. Decision reasons
        # ----------------------------------------------------

        reasons = []

        if behavioral_risk > raw_ml_score:
            reasons.append(
                "Behavioral security signals increased the risk score"
            )

        if payload.request_rate >= 50:
            reasons.append("High request rate detected")

        if payload.request_size >= 25000:
            reasons.append("Large request payload detected")

        if "/admin" in payload.path.lower():
            reasons.append("Administrative endpoint accessed")

        auth_keywords = [
            "login",
            "signin",
            "sign-in",
            "auth",
            "token",
            "password",
        ]

        if any(
            keyword in payload.path.lower()
            for keyword in auth_keywords
        ):
            reasons.append(
                "Authentication-sensitive endpoint detected"
            )

        if payload.method.upper() in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            reasons.append("State-changing HTTP method detected")

        suspicious_tools = [
            "sqlmap",
            "nikto",
            "nmap",
            "masscan",
            "burp",
            "hydra",
            "wpscan",
        ]

        if any(
            tool in payload.user_agent.lower()
            for tool in suspicious_tools
        ):
            reasons.append(
                "Known security scanning tool signature detected"
            )

        # ----------------------------------------------------
        # 8. Final firewall policy
        # ----------------------------------------------------

        if risk_level == "HIGH":
            decision = "BLOCK"
            zero_trust_status = "FAILED"

            reasons.append(
                "High adaptive risk score exceeded blocking threshold"
            )

        elif risk_level == "MEDIUM":
            if (
                zero_trust_decision == "ALLOW"
                and payload.identity_verified
                and payload.device_trusted
            ):
                decision = "ALLOW"
            else:
                decision = "CHALLENGE"
                zero_trust_status = "CHALLENGE"

                reasons.append(
                    "Medium-risk request requires additional verification"
                )

        else:
            if (
                payload.identity_verified
                and payload.device_trusted
                and zero_trust_decision == "ALLOW"
            ):
                decision = "ALLOW"
                zero_trust_status = "VERIFIED"
            else:
                decision = "CHALLENGE"
                zero_trust_status = "CHALLENGE"

                reasons.append(
                    "Zero Trust verification is required before access"
                )

        # ----------------------------------------------------
        # 9. Response message
        # ----------------------------------------------------

        if decision == "ALLOW":
            message = "Request allowed"
        elif decision == "CHALLENGE":
            message = "Request requires additional verification"
        else:
            message = "Request blocked by adaptive firewall"

        if not reasons:
            reasons.append(
                "Request passed adaptive risk and Zero Trust verification"
                if decision == "ALLOW"
                else "Request evaluated by adaptive security policy"
            )

        timestamp = datetime.now(timezone.utc).isoformat()

        # ----------------------------------------------------
        # 10. Persist security event
        # ----------------------------------------------------

        try:
            save_security_event(
                request_id=request_id,
                timestamp=timestamp,
                source_ip=payload.source_ip,
                method=payload.method,
                path=payload.path,
                user_agent=payload.user_agent,
                request_size=payload.request_size,
                request_rate=payload.request_rate,
                ml_prediction=ml_prediction,
                risk_score=risk_score,
                risk_level=risk_level,
                zero_trust_status=zero_trust_status,
                identity_verified=payload.identity_verified,
                device_trusted=payload.device_trusted,
                decision=decision,
                reason="; ".join(reasons),

                # database.py requires the feature dictionary.
                extracted_features=extracted_features,
            )

        except Exception as db_error:
            # Log the failure without hiding the firewall decision.
            print(f"[DATABASE WARNING] {db_error}")

        # ----------------------------------------------------
        # 11. API response
        # ----------------------------------------------------

        return {
            "request_id": request_id,
            "decision": decision,
            "message": message,
            "ml_prediction": ml_prediction,
            "risk_score": round(risk_score, 4),
            "risk_level": risk_level,
            "ml_risk_score": round(raw_ml_score, 4),
            "behavioral_risk_score": round(behavioral_risk, 4),
            "extracted_features": len(extracted_features),
            "zero_trust_status": zero_trust_status,
            "zero_trust_decision": zero_trust_decision,
            "zero_trust_reason": zero_trust_reason,
            "identity_verified": payload.identity_verified,
            "device_trusted": payload.device_trusted,
            "reasons": reasons,
            "timestamp": timestamp,
        }

    except Exception as exc:
        print(f"[FIREWALL ERROR] Request {request_id}: {exc}")

        raise HTTPException(
            status_code=500,
            detail={
                "request_id": request_id,
                "message": "Firewall analysis failed",
                "error": str(exc),
            },
        )


# ============================================================
# LOCAL APPLICATION ENTRY POINT
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )
