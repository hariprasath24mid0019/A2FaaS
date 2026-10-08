"""
======================================================================
A²FaaS
AI-Assisted Adaptive Firewall-as-a-Service
======================================================================

FastAPI Backend

Security Pipeline
-----------------

Incoming Request
       ↓
Traffic Interceptor
       ↓
42-Feature Extraction
       ↓
Trained ML Risk Scoring
       ↓
Application Behaviour Risk Calibration
       ↓
Zero Trust Verification
       ↓
ALLOW / CHALLENGE / BLOCK
       ↓
Security Event Database

The ML model remains the primary risk-scoring engine.

The application behaviour calibration layer supplements the
network-flow model with observable HTTP-level security signals
such as:

    • request rate
    • request size
    • administrative endpoint access
    • authentication endpoint access
    • write operations

This is necessary because UNSW-NB15 is a network-flow dataset,
while the A²FaaS firewall API operates at the application-request
boundary.
======================================================================
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Literal
import logging
import time
import uuid


from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field


from ml.predict import predict_risk
from security.feature_extractor import extract_features
from security.zero_trust import verify_request as verify_zero_trust


from database.database import (
    initialize_database,
    save_security_event,
    get_security_statistics,
    get_recent_events,
)


# ======================================================================
# APPLICATION CONFIGURATION
# ======================================================================

APPLICATION_NAME = "A²FaaS"

APPLICATION_VERSION = "1.0.0"

APPLICATION_DESCRIPTION = (
    "AI-Assisted Adaptive Firewall-as-a-Service "
    "for Cloud Applications"
)

ENVIRONMENT = "development"


# ======================================================================
# LOGGING
# ======================================================================

logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(name)s | "
        "%(message)s"
    ),
)

logger = logging.getLogger("a2faas")


# ======================================================================
# RESPONSE MODELS
# ======================================================================


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    environment: str
    timestamp: str


class RootResponse(BaseModel):
    service: str
    version: str
    description: str
    status: str
    documentation: str


class SystemStatusResponse(BaseModel):
    service: str
    version: str
    environment: str
    status: str
    components: dict
    timestamp: str


class SecurityStatisticsResponse(BaseModel):
    total_requests: int
    allowed_requests: int
    challenged_requests: int
    blocked_requests: int
    high_risk_requests: int


class FirewallAnalysisRequest(BaseModel):

    source_ip: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Source IP address",
    )

    method: Literal[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    ]

    path: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Requested application path",
    )

    user_agent: str = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="HTTP User-Agent",
    )

    request_size: int = Field(
        default=512,
        ge=0,
        le=10_000_000,
        description="Request payload size in bytes",
    )

    request_rate: float = Field(
        default=1.0,
        ge=0,
        le=1_000_000,
        description="Observed request rate",
    )

    identity_verified: bool = False

    device_trusted: bool = False


class FirewallAnalysisResponse(BaseModel):

    request_id: str

    decision: str

    ml_prediction: int

    risk_score: float

    risk_level: str

    extracted_features: dict

    zero_trust_status: str

    identity_verified: bool

    device_trusted: bool

    reason: str

    message: str


class SecurityEventResponse(BaseModel):

    id: int

    request_id: str

    timestamp: str

    source_ip: str

    method: str

    path: str

    user_agent: str | None

    request_size: int

    request_rate: float

    ml_prediction: int

    risk_score: float

    risk_level: str

    zero_trust_status: str

    identity_verified: bool

    device_trusted: bool

    decision: str

    reason: str

    extracted_features: dict


# ======================================================================
# APPLICATION LIFESPAN
# ======================================================================


@asynccontextmanager
async def lifespan(app: FastAPI):

    logger.info("=" * 72)

    logger.info("A²FaaS application starting")

    logger.info(
        "Version: %s",
        APPLICATION_VERSION,
    )

    logger.info(
        "Environment: %s",
        ENVIRONMENT,
    )

    try:

        initialize_database()

        logger.info(
            "Database: READY"
        )

        logger.info(
            "ML risk engine: READY"
        )

        logger.info(
            "Zero Trust engine: READY"
        )

        logger.info(
            "Adaptive firewall engine: READY"
        )

    except Exception as exc:

        logger.exception(
            "Startup initialization failed: %s",
            exc,
        )

        raise

    logger.info("=" * 72)

    yield

    logger.info(
        "A²FaaS application shutting down"
    )


# ======================================================================
# FASTAPI APPLICATION
# ======================================================================


app = FastAPI(
    title="A²FaaS — Adaptive Firewall-as-a-Service",
    version=APPLICATION_VERSION,
    description=(
        "AI-Assisted Adaptive Firewall-as-a-Service "
        "combining ML risk scoring and Zero Trust verification."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# ======================================================================
# CORS
# ======================================================================

app.add_middleware(
    CORSMiddleware,

    allow_origin_regex=(
        r"^https?://"
        r"(localhost|127\.0\.0\.1)"
        r"(:\d+)?$"
    ),

    allow_credentials=True,

    allow_methods=["*"],

    allow_headers=["*"],

    expose_headers=[
        "X-Request-ID",
        "X-Process-Time",
    ],
)


# ======================================================================
# REQUEST SECURITY MIDDLEWARE
# ======================================================================


@app.middleware("http")
async def request_middleware(
    request: Request,
    call_next,
):

    request_id = (
        f"REQ-{uuid.uuid4().hex[:10].upper()}"
    )

    start_time = time.perf_counter()

    try:

        response = await call_next(request)

        elapsed_ms = (
            time.perf_counter() - start_time
        ) * 1000

        response.headers[
            "X-Request-ID"
        ] = request_id

        response.headers[
            "X-Process-Time"
        ] = f"{elapsed_ms:.3f}ms"

        response.headers[
            "X-Content-Type-Options"
        ] = "nosniff"

        response.headers[
            "X-Frame-Options"
        ] = "DENY"

        response.headers[
            "Referrer-Policy"
        ] = "strict-origin-when-cross-origin"

        response.headers[
            "Permissions-Policy"
        ] = (
            "camera=(), "
            "microphone=(), "
            "geolocation=()"
        )

        response.headers[
            "Cache-Control"
        ] = "no-store"

        logger.info(
            "%s | %s | %s | %.3f ms",
            request.method,
            request.url.path,
            request_id,
            elapsed_ms,
        )

        return response

    except Exception:

        logger.exception(
            "Unhandled request error | request_id=%s",
            request_id,
        )

        raise


# ======================================================================
# VALIDATION ERROR HANDLER
# ======================================================================


@app.exception_handler(
    RequestValidationError
)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
):

    return JSONResponse(
        status_code=422,
        content={
            "status": "validation_error",
            "message": "Request validation failed.",
            "errors": exc.errors(),
        },
    )


# ======================================================================
# GLOBAL ERROR HANDLER
# ======================================================================


@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):

    logger.exception(
        "Unhandled application exception: %s",
        exc,
    )

    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": (
                "A²FaaS encountered an internal "
                "processing error."
            ),
        },
    )


# ======================================================================
# ROOT ENDPOINT
# ======================================================================


@app.get(
    "/",
    response_model=RootResponse,
    tags=["System"],
)
async def root():

    return RootResponse(
        service=APPLICATION_NAME,
        version=APPLICATION_VERSION,
        description=APPLICATION_DESCRIPTION,
        status="operational",
        documentation="/docs",
    )


# ======================================================================
# HEALTH ENDPOINT
# ======================================================================


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
)
async def health():

    return HealthResponse(
        status="healthy",
        service=APPLICATION_NAME,
        version=APPLICATION_VERSION,
        environment=ENVIRONMENT,
        timestamp=datetime.now(
            timezone.utc
        ).isoformat(),
    )


# ======================================================================
# SYSTEM HEALTH
# ======================================================================


@app.get(
    "/api/system/health",
    response_model=HealthResponse,
    tags=["System"],
)
async def system_health():

    return HealthResponse(
        status="healthy",
        service=APPLICATION_NAME,
        version=APPLICATION_VERSION,
        environment=ENVIRONMENT,
        timestamp=datetime.now(
            timezone.utc
        ).isoformat(),
    )


# ======================================================================
# SYSTEM INFORMATION
# ======================================================================


@app.get(
    "/api/system/info",
    response_model=SystemStatusResponse,
    tags=["System"],
)
async def system_info():

    return SystemStatusResponse(

        service=APPLICATION_NAME,

        version=APPLICATION_VERSION,

        environment=ENVIRONMENT,

        status="operational",

        components={

            "traffic_interceptor":
                "online",

            "feature_extraction":
                "online",

            "ml_risk_engine":
                "online",

            "zero_trust_policy":
                "enforced",

            "firewall_engine":
                "online",

            "cloud_application":
                "protected",
        },

        timestamp=datetime.now(
            timezone.utc
        ).isoformat(),
    )


# ======================================================================
# DASHBOARD STATISTICS
# ======================================================================


@app.get(
    "/api/dashboard/stats",
    response_model=SecurityStatisticsResponse,
    tags=["Dashboard"],
)
async def dashboard_statistics():

    try:

        statistics = (
            get_security_statistics()
        )

        return SecurityStatisticsResponse(

            total_requests=int(
                statistics.get(
                    "total_requests",
                    0,
                )
            ),

            allowed_requests=int(
                statistics.get(
                    "allowed_requests",
                    0,
                )
            ),

            challenged_requests=int(
                statistics.get(
                    "challenged_requests",
                    0,
                )
            ),

            blocked_requests=int(
                statistics.get(
                    "blocked_requests",
                    0,
                )
            ),

            high_risk_requests=int(
                statistics.get(
                    "high_risk_requests",
                    0,
                )
            ),
        )

    except Exception as exc:

        logger.exception(
            "Dashboard statistics failed: %s",
            exc,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to retrieve "
                "dashboard statistics."
            ),
        )


# ======================================================================
# RECENT SECURITY EVENTS
# ======================================================================


@app.get(
    "/api/requests/recent",
    response_model=list[
        SecurityEventResponse
    ],
    tags=["Dashboard"],
)
async def recent_security_events(
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
):

    try:

        events = get_recent_events(
            limit
        )

        response = []

        for event in events:

            response.append(
                SecurityEventResponse(

                    id=int(
                        event["id"]
                    ),

                    request_id=str(
                        event["request_id"]
                    ),

                    timestamp=str(
                        event["timestamp"]
                    ),

                    source_ip=str(
                        event["source_ip"]
                    ),

                    method=str(
                        event["method"]
                    ),

                    path=str(
                        event["path"]
                    ),

                    user_agent=event.get(
                        "user_agent"
                    ),

                    request_size=int(
                        event["request_size"]
                    ),

                    request_rate=float(
                        event["request_rate"]
                    ),

                    ml_prediction=int(
                        event["ml_prediction"]
                    ),

                    risk_score=float(
                        event["risk_score"]
                    ),

                    risk_level=str(
                        event["risk_level"]
                    ),

                    zero_trust_status=str(
                        event[
                            "zero_trust_status"
                        ]
                    ),

                    identity_verified=bool(
                        event[
                            "identity_verified"
                        ]
                    ),

                    device_trusted=bool(
                        event[
                            "device_trusted"
                        ]
                    ),

                    decision=str(
                        event["decision"]
                    ),

                    reason=str(
                        event["reason"]
                    ),

                    extracted_features=event[
                        "extracted_features"
                    ],
                )
            )

        return response

    except Exception as exc:

        logger.exception(
            "Recent event retrieval failed: %s",
            exc,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to retrieve "
                "recent security events."
            ),
        )


# ======================================================================
# APPLICATION BEHAVIOUR RISK CALIBRATION
# ======================================================================


def calculate_behavioral_risk(
    payload: FirewallAnalysisRequest,
) -> tuple[float, list[str]]:
    """
    Calculate an application-level behavioural risk score.

    This does NOT replace the trained ML model.

    It supplements the network-flow model with signals that are
    directly observable at the HTTP firewall boundary.

    Score range:
        0.0 -> 1.0

    The signals are intentionally interpretable so the final
    firewall decision can be explained during project evaluation.
    """

    path = (
        payload.path or "/"
    ).lower()

    method = (
        payload.method or "GET"
    ).upper()

    request_size = float(
        payload.request_size
    )

    request_rate = float(
        payload.request_rate
    )

    score = 0.0

    signals = []


    # --------------------------------------------------------------
    # HIGH REQUEST RATE
    # --------------------------------------------------------------

    if request_rate >= 100:

        score += 0.35

        signals.append(
            "very high request rate"
        )

    elif request_rate >= 50:

        score += 0.20

        signals.append(
            "elevated request rate"
        )

    elif request_rate >= 20:

        score += 0.10

        signals.append(
            "increased request rate"
        )


    # --------------------------------------------------------------
    # LARGE REQUEST PAYLOAD
    # --------------------------------------------------------------

    if request_size >= 100_000:

        score += 0.30

        signals.append(
            "very large request payload"
        )

    elif request_size >= 25_000:

        score += 0.20

        signals.append(
            "large request payload"
        )

    elif request_size >= 10_000:

        score += 0.10

        signals.append(
            "elevated request payload"
        )


    # --------------------------------------------------------------
    # ADMINISTRATIVE ENDPOINT
    # --------------------------------------------------------------

    if (
        "/admin" in path
        or path.startswith(
            "/administrator"
        )
    ):

        score += 0.15

        signals.append(
            "administrative endpoint"
        )


    # --------------------------------------------------------------
    # AUTHENTICATION ENDPOINT
    # --------------------------------------------------------------

    authentication_keywords = (
        "login",
        "signin",
        "sign-in",
        "auth",
        "token",
        "password",
    )

    if any(
        keyword in path
        for keyword in authentication_keywords
    ):

        score += 0.10

        signals.append(
            "authentication-related endpoint"
        )


    # --------------------------------------------------------------
    # WRITE OPERATION
    # --------------------------------------------------------------

    if method in {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }:

        score += 0.05

        signals.append(
            f"{method} write operation"
        )


    # --------------------------------------------------------------
    # COMBINATION SIGNAL
    # --------------------------------------------------------------
    #
    # Administrative authentication endpoint +
    # POST/PUT/PATCH + high request rate is considerably
    # more suspicious than any individual signal.
    # --------------------------------------------------------------

    is_admin = (
        "/admin" in path
        or path.startswith(
            "/administrator"
        )
    )

    is_auth = any(
        keyword in path
        for keyword in authentication_keywords
    )

    is_write = method in {
        "POST",
        "PUT",
        "PATCH",
    }

    if (
        is_admin
        and is_auth
        and is_write
        and request_rate >= 50
    ):

        score += 0.20

        signals.append(
            "high-rate administrative authentication attempt"
        )


    # --------------------------------------------------------------
    # FINAL NORMALIZATION
    # --------------------------------------------------------------

    score = min(
        max(score, 0.0),
        1.0,
    )

    return score, signals


# ======================================================================
# FIREWALL ANALYSIS ENGINE
# ======================================================================


@app.post(
    "/api/firewall/analyze",
    response_model=FirewallAnalysisResponse,
    tags=["Firewall"],
    summary="Analyze an incoming request",
    description=(
        "Processes an incoming request through "
        "42-feature extraction, trained ML risk scoring, "
        "application behaviour calibration, and Zero Trust."
    ),
)
async def analyze_firewall_request(
    payload: FirewallAnalysisRequest,
):

    request_id = (
        f"REQ-{uuid.uuid4().hex[:12].upper()}"
    )

    started_at = time.perf_counter()

    logger.info("=" * 72)

    logger.info(
        "Firewall analysis started | request_id=%s",
        request_id,
    )

    logger.info(
        "Source IP: %s",
        payload.source_ip,
    )

    logger.info(
        "Method: %s",
        payload.method,
    )

    logger.info(
        "Path: %s",
        payload.path,
    )

    logger.info(
        "Request size: %d bytes",
        payload.request_size,
    )

    logger.info(
        "Request rate: %.2f",
        payload.request_rate,
    )

    try:

        # ==========================================================
        # STEP 1 — TRAFFIC FEATURE EXTRACTION
        # ==========================================================

        features = extract_features(

            source_ip=payload.source_ip,

            method=payload.method,

            path=payload.path,

            user_agent=payload.user_agent,

            request_size=payload.request_size,

            request_rate=payload.request_rate,
        )

        feature_count = len(features)

        logger.info(
            "Feature extraction completed | features=%d",
            feature_count,
        )


        # ==========================================================
        # STEP 2 — TRAINED ML RISK PREDICTION
        # ==========================================================

        prediction_result = predict_risk(
            features
        )

        model_risk_score = float(
            prediction_result[
                "risk_score"
            ]
        )

        model_risk_level = str(
            prediction_result[
                "risk_level"
            ]
        )

        model_prediction = int(
            prediction_result[
                "prediction"
            ]
        )

        logger.info(
            (
                "ML prediction | "
                "prediction=%d | "
                "score=%.6f | "
                "level=%s"
            ),
            model_prediction,
            model_risk_score,
            model_risk_level,
        )


        # ==========================================================
        # STEP 3 — APPLICATION BEHAVIOUR CALIBRATION
        # ==========================================================

        behavioral_score, behavioral_signals = (
            calculate_behavioral_risk(
                payload
            )
        )

        logger.info(
            (
                "Behaviour calibration | "
                "score=%.4f | "
                "signals=%s"
            ),
            behavioral_score,
            behavioral_signals,
        )


        # ==========================================================
        # STEP 4 — COMBINED ADAPTIVE RISK SCORE
        # ==========================================================
        #
        # The trained ML score remains intact.
        #
        # For application-boundary traffic, the final adaptive
        # score uses the stronger of:
        #
        #     trained ML probability
        #     behavioural security score
        #
        # This prevents a network-flow model from masking an
        # obviously dangerous HTTP request.
        # ==========================================================

        risk_score = max(
            model_risk_score,
            behavioral_score,
        )

        risk_score = min(
            max(risk_score, 0.0),
            1.0,
        )


        # ==========================================================
        # STEP 5 — FINAL RISK CLASSIFICATION
        # ==========================================================

        if risk_score >= 0.75:

            risk_level = "HIGH"

        elif risk_score >= 0.40:

            risk_level = "MEDIUM"

        else:

            risk_level = "LOW"


        # Adaptive prediction used by the firewall.

        if risk_score >= 0.75:

            ml_prediction = 1

        else:

            ml_prediction = 0


        logger.info(
            (
                "Adaptive risk result | "
                "score=%.4f | "
                "level=%s | "
                "prediction=%d"
            ),
            risk_score,
            risk_level,
            ml_prediction,
        )


        # ==========================================================
        # STEP 6 — ZERO TRUST VERIFICATION
        # ==========================================================

        zero_trust_result = verify_zero_trust(

            source_ip=payload.source_ip,

            method=payload.method,

            path=payload.path,

            user_agent=payload.user_agent,

            risk_score=risk_score,

            ml_prediction=ml_prediction,

            identity_verified=(
                payload.identity_verified
            ),

            device_trusted=(
                payload.device_trusted
            ),
        )


        zero_trust_status = str(
            zero_trust_result[
                "status"
            ]
        )

        decision = str(
            zero_trust_result[
                "decision"
            ]
        )

        reason = str(
            zero_trust_result[
                "reason"
            ]
        )


        # ==========================================================
        # STEP 7 — HIGH-RISK OVERRIDE
        # ==========================================================
        #
        # A high-risk request must never be allowed merely because
        # identity/device verification succeeds.
        #
        # This is the adaptive firewall's fail-closed rule.
        # ==========================================================

        if (
            risk_level == "HIGH"
            or ml_prediction == 1
        ):

            decision = "BLOCK"

            zero_trust_status = "FAILED"

            if behavioral_signals:

                reason = (
                    "High-risk request blocked by the "
                    "adaptive firewall. Security signals: "
                    + ", ".join(
                        behavioral_signals
                    )
                )

            else:

                reason = (
                    "High-risk request blocked by "
                    "the adaptive firewall."
                )


        # ==========================================================
        # STEP 8 — NORMAL-RISK ZERO TRUST DECISION
        # ==========================================================

        elif risk_level == "MEDIUM":

            if decision == "ALLOW":

                decision = "CHALLENGE"

                zero_trust_status = (
                    "CHALLENGE"
                )

                reason = (
                    "Medium-risk request requires "
                    "additional verification."
                )


        # ==========================================================
        # STEP 9 — SECURITY EVENT PERSISTENCE
        # ==========================================================

        save_security_event(

            request_id=request_id,

            timestamp=datetime.now(
                timezone.utc
            ).isoformat(),

            source_ip=payload.source_ip,

            method=payload.method,

            path=payload.path,

            user_agent=payload.user_agent,

            request_size=payload.request_size,

            request_rate=payload.request_rate,

            ml_prediction=ml_prediction,

            risk_score=risk_score,

            risk_level=risk_level,

            zero_trust_status=(
                zero_trust_status
            ),

            identity_verified=(
                payload.identity_verified
            ),

            device_trusted=(
                payload.device_trusted
            ),

            decision=decision,

            reason=reason,

            extracted_features=features,
        )


        # ==========================================================
        # STEP 10 — RESPONSE MESSAGE
        # ==========================================================

        if decision == "ALLOW":

            message = (
                "Request allowed after ML risk "
                "scoring and Zero Trust verification."
            )

        elif decision == "CHALLENGE":

            message = (
                "Request requires additional "
                "Zero Trust verification."
            )

        else:

            message = (
                "Request blocked by the adaptive "
                "security engine."
            )


        elapsed_ms = (
            time.perf_counter()
            - started_at
        ) * 1000


        logger.info(
            (
                "Firewall analysis completed | "
                "request_id=%s | "
                "decision=%s | "
                "risk=%.4f | "
                "level=%s | "
                "latency=%.3f ms"
            ),
            request_id,
            decision,
            risk_score,
            risk_level,
            elapsed_ms,
        )

        logger.info("=" * 72)


        # ==========================================================
        # FINAL API RESPONSE
        # ==========================================================

        return FirewallAnalysisResponse(

            request_id=request_id,

            decision=decision,

            ml_prediction=ml_prediction,

            risk_score=risk_score,

            risk_level=risk_level,

            extracted_features=features,

            zero_trust_status=(
                zero_trust_status
            ),

            identity_verified=(
                payload.identity_verified
            ),

            device_trusted=(
                payload.device_trusted
            ),

            reason=reason,

            message=message,
        )


    except HTTPException:

        raise


    except Exception as exc:

        logger.exception(
            (
                "Firewall analysis failed | "
                "request_id=%s | "
                "error=%s"
            ),
            request_id,
            exc,
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Firewall analysis failed. "
                "Check the backend terminal for details."
            ),
        )


# ======================================================================
# APPLICATION ENTRY POINT
# ======================================================================


if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )