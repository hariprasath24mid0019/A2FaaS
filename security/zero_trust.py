"""
============================================================
A²FaaS
Zero Trust Policy Engine
============================================================

Implements request-level Zero Trust verification.

Core principles:
    1. Never trust a request based only on network location.
    2. Every request must pass policy verification.
    3. Identity and request context are evaluated.
    4. ML risk is incorporated into the final decision.
    5. High-risk traffic is blocked.
    6. Unauthenticated requests can be challenged.
    7. Verified low-risk requests can be allowed.

This module is intentionally independent from FastAPI so that
the policy engine can later be reused by:
    - API routes
    - reverse proxy
    - cloud deployment
    - protected application
    - automated tests
============================================================
"""

from dataclasses import dataclass
from typing import Literal


# ============================================================
# TYPES
# ============================================================

ZeroTrustStatus = Literal[
    "VERIFIED",
    "CHALLENGE",
    "FAILED",
]

ZeroTrustDecision = Literal[
    "ALLOW",
    "CHALLENGE",
    "BLOCK",
]


# ============================================================
# POLICY RESULT
# ============================================================

@dataclass
class ZeroTrustResult:
    """
    Result produced by the Zero Trust policy engine.
    """

    status: ZeroTrustStatus
    decision: ZeroTrustDecision
    identity_verified: bool
    device_trusted: bool
    context_valid: bool
    reason: str


# ============================================================
# ZERO TRUST POLICY ENGINE
# ============================================================

class ZeroTrustPolicyEngine:
    """
    Request-level Zero Trust verification engine.

    The engine does not trust a request merely because its
    source IP belongs to a private or familiar network.

    Instead, it evaluates:
        - identity
        - device trust
        - request context
        - ML risk
    """

    # --------------------------------------------------------
    # Risk thresholds
    # --------------------------------------------------------

    HIGH_RISK_THRESHOLD = 0.90
    MEDIUM_RISK_THRESHOLD = 0.50

    # --------------------------------------------------------
    # Allowed HTTP methods
    # --------------------------------------------------------

    ALLOWED_METHODS = {
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    }

    # --------------------------------------------------------
    # Protected authentication paths
    # --------------------------------------------------------

    PROTECTED_PATHS = {
        "/admin",
        "/admin/",
        "/dashboard/admin",
        "/api/admin",
    }

    # --------------------------------------------------------
    # Verification
    # --------------------------------------------------------

    def verify_request(
        self,
        *,
        source_ip: str,
        method: str,
        path: str,
        user_agent: str,
        risk_score: float,
        ml_prediction: int,
        identity_verified: bool = False,
        device_trusted: bool = False,
    ) -> ZeroTrustResult:
        """
        Verify an incoming request using Zero Trust principles.

        Parameters
        ----------
        source_ip:
            Source IP address.

        method:
            HTTP method.

        path:
            Requested application path.

        user_agent:
            Client user-agent.

        risk_score:
            ML-generated probability of attack.

        ml_prediction:
            ML classification:
                0 = Normal
                1 = Attack

        identity_verified:
            Whether the requester's identity has been verified.

        device_trusted:
            Whether the requesting device has passed trust
            verification.

        Returns
        -------
        ZeroTrustResult
            Final Zero Trust verification result.
        """

        # ----------------------------------------------------
        # Normalize values
        # ----------------------------------------------------

        normalized_method = method.upper().strip()
        normalized_path = path.strip()

        risk_score = max(
            0.0,
            min(
                1.0,
                float(risk_score),
            ),
        )

        # ----------------------------------------------------
        # Rule 1 — High-risk traffic is never trusted
        # ----------------------------------------------------

        if (
            ml_prediction == 1
            and risk_score >= self.HIGH_RISK_THRESHOLD
        ):
            return ZeroTrustResult(
                status="FAILED",
                decision="BLOCK",
                identity_verified=identity_verified,
                device_trusted=device_trusted,
                context_valid=False,
                reason=(
                    "Request blocked because the ML risk engine "
                    "identified high-probability attack traffic."
                ),
            )

        # ----------------------------------------------------
        # Rule 2 — Invalid HTTP method
        # ----------------------------------------------------

        if normalized_method not in self.ALLOWED_METHODS:
            return ZeroTrustResult(
                status="FAILED",
                decision="BLOCK",
                identity_verified=identity_verified,
                device_trusted=device_trusted,
                context_valid=False,
                reason=(
                    "Request blocked because the HTTP method "
                    "is not permitted by the Zero Trust policy."
                ),
            )

        # ----------------------------------------------------
        # Rule 3 — Missing request context
        # ----------------------------------------------------

        if not source_ip.strip():
            return ZeroTrustResult(
                status="FAILED",
                decision="BLOCK",
                identity_verified=identity_verified,
                device_trusted=device_trusted,
                context_valid=False,
                reason=(
                    "Request blocked because source identity "
                    "information is missing."
                ),
            )

        if not user_agent.strip():
            return ZeroTrustResult(
                status="FAILED",
                decision="BLOCK",
                identity_verified=identity_verified,
                device_trusted=device_trusted,
                context_valid=False,
                reason=(
                    "Request blocked because client context "
                    "information is missing."
                ),
            )

        # ----------------------------------------------------
        # Rule 4 — Protected resources require identity
        # ----------------------------------------------------

        if normalized_path in self.PROTECTED_PATHS:

            if not identity_verified:
                return ZeroTrustResult(
                    status="CHALLENGE",
                    decision="CHALLENGE",
                    identity_verified=False,
                    device_trusted=device_trusted,
                    context_valid=True,
                    reason=(
                        "Authentication is required before "
                        "accessing the protected resource."
                    ),
                )

        # ----------------------------------------------------
        # Rule 5 — Medium-risk requests require verification
        # ----------------------------------------------------

        if (
            ml_prediction == 1
            or risk_score >= self.MEDIUM_RISK_THRESHOLD
        ):
            if not identity_verified:
                return ZeroTrustResult(
                    status="CHALLENGE",
                    decision="CHALLENGE",
                    identity_verified=False,
                    device_trusted=device_trusted,
                    context_valid=True,
                    reason=(
                        "Request requires additional identity "
                        "verification because its risk level "
                        "requires stronger assurance."
                    ),
                )

            if not device_trusted:
                return ZeroTrustResult(
                    status="CHALLENGE",
                    decision="CHALLENGE",
                    identity_verified=True,
                    device_trusted=False,
                    context_valid=True,
                    reason=(
                        "Request requires device verification "
                        "before access can be granted."
                    ),
                )

        # ----------------------------------------------------
        # Rule 6 — Low-risk but unauthenticated request
        # ----------------------------------------------------

        if not identity_verified:
            return ZeroTrustResult(
                status="CHALLENGE",
                decision="CHALLENGE",
                identity_verified=False,
                device_trusted=device_trusted,
                context_valid=True,
                reason=(
                    "Request appears low risk, but Zero Trust "
                    "requires identity verification before "
                    "granting access."
                ),
            )

        # ----------------------------------------------------
        # Rule 7 — Verified identity + trusted device
        # ----------------------------------------------------

        if identity_verified and device_trusted:

            return ZeroTrustResult(
                status="VERIFIED",
                decision="ALLOW",
                identity_verified=True,
                device_trusted=True,
                context_valid=True,
                reason=(
                    "Request passed Zero Trust identity, "
                    "device, context, and ML risk checks."
                ),
            )

        # ----------------------------------------------------
        # Default deny
        # ----------------------------------------------------

        return ZeroTrustResult(
            status="FAILED",
            decision="BLOCK",
            identity_verified=identity_verified,
            device_trusted=device_trusted,
            context_valid=False,
            reason=(
                "Request did not satisfy the Zero Trust "
                "verification policy."
            ),
        )


# ============================================================
# SINGLETON POLICY ENGINE
# ============================================================

zero_trust_engine = ZeroTrustPolicyEngine()


# ============================================================
# CONVENIENCE FUNCTION
# ============================================================

def verify_request(
    *,
    source_ip: str,
    method: str,
    path: str,
    user_agent: str,
    risk_score: float,
    ml_prediction: int,
    identity_verified: bool = False,
    device_trusted: bool = False,
) -> dict:
    """
    Convenience wrapper around the Zero Trust policy engine.

    Returns a serializable dictionary suitable for FastAPI
    responses and logging.
    """

    result = zero_trust_engine.verify_request(
        source_ip=source_ip,
        method=method,
        path=path,
        user_agent=user_agent,
        risk_score=risk_score,
        ml_prediction=ml_prediction,
        identity_verified=identity_verified,
        device_trusted=device_trusted,
    )

    return {
        "status": result.status,
        "decision": result.decision,
        "identity_verified": result.identity_verified,
        "device_trusted": result.device_trusted,
        "context_valid": result.context_valid,
        "reason": result.reason,
    }


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 68)
    print("A²FaaS ZERO TRUST POLICY ENGINE")
    print("=" * 68)

    print()
    print("Test 1: Low-risk unauthenticated request")

    result = verify_request(
        source_ip="192.168.1.100",
        method="GET",
        path="/login",
        user_agent="Mozilla/5.0",
        risk_score=0.01,
        ml_prediction=0,
        identity_verified=False,
        device_trusted=False,
    )

    print(result)

    print()
    print("Test 2: Verified low-risk request")

    result = verify_request(
        source_ip="192.168.1.100",
        method="GET",
        path="/dashboard",
        user_agent="Mozilla/5.0",
        risk_score=0.01,
        ml_prediction=0,
        identity_verified=True,
        device_trusted=True,
    )

    print(result)

    print()
    print("Test 3: High-risk attack request")

    result = verify_request(
        source_ip="10.0.0.55",
        method="POST",
        path="/login",
        user_agent="SuspiciousClient/1.0",
        risk_score=0.9977,
        ml_prediction=1,
        identity_verified=True,
        device_trusted=True,
    )

    print(result)

    print()
    print("=" * 68)
    print("ZERO TRUST POLICY ENGINE TEST COMPLETED")
    print("=" * 68)