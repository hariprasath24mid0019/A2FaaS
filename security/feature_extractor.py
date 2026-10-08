"""
============================================================
A²FaaS
Traffic Feature Extraction Layer
============================================================

Converts incoming firewall request information into the
42-feature schema expected by the trained UNSW-NB15 ML model.

The firewall API operates at the HTTP/application boundary,
while UNSW-NB15 contains network-flow features.

Therefore, this module uses a NORMAL-flow baseline from the
training dataset for features that cannot be directly observed
at the HTTP boundary.

Observable HTTP characteristics are then applied on top of
that baseline.

This prevents unavailable network-flow fields from being
incorrectly replaced with zeros.
============================================================
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import pandas as pd


# ============================================================
# Configuration
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = (
    PROJECT_ROOT
    / "ml"
    / "UNSW_NB15_training-set.csv"
)


MODEL_FEATURES = [
    "dur",
    "proto",
    "service",
    "state",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_srv_src",
    "ct_state_ttl",
    "ct_dst_ltm",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "ct_dst_src_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "ct_src_ltm",
    "ct_srv_dst",
    "is_sm_ips_ports",
]


CATEGORICAL_FEATURES = {
    "proto",
    "service",
    "state",
}


# ============================================================
# Helper functions
# ============================================================

def _safe_float(
    value: Any,
    default: float = 0.0,
) -> float:
    """Safely convert a value to float."""

    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(
    value: Any,
    default: int = 0,
) -> int:
    """Safely convert a value to integer."""

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalise_method(method: str) -> str:
    """Normalize HTTP method."""

    return str(method or "GET").upper()


def _extract_path(path: str) -> str:
    """Extract path from a URL-like value."""

    value = str(path or "/")

    if value.startswith("http://") or value.startswith("https://"):
        parsed = urlparse(value)
        return parsed.path or "/"

    return value.split("?")[0] or "/"


def _infer_service(path: str) -> str:
    """Map the HTTP request to the UNSW service category."""

    path_lower = path.lower()

    if (
        path_lower.startswith("/api")
        or "login" in path_lower
        or "signin" in path_lower
        or "auth" in path_lower
        or "token" in path_lower
        or "upload" in path_lower
        or "admin" in path_lower
    ):
        return "http"

    return "http"


def _infer_state(method: str) -> str:
    """Map HTTP behavior to a simplified UNSW connection state."""

    method = _normalise_method(method)

    if method in {"POST", "PUT", "PATCH"}:
        return "REQ"

    if method == "DELETE":
        return "FIN"

    return "CON"


def _infer_protocol(user_agent: str) -> str:
    """
    Infer application protocol.

    The firewall currently receives HTTP traffic, therefore
    TCP/HTTP-compatible UNSW categorical values are used.
    """

    return "tcp"


# ============================================================
# NORMAL DATASET BASELINE
# ============================================================

@lru_cache(maxsize=1)
def _load_normal_baseline() -> dict[str, Any]:
    """
    Load representative NORMAL-flow feature values.

    Numeric features use the median of NORMAL traffic.

    Categorical features use the most frequent NORMAL value.

    This creates a realistic baseline for network-flow
    information that is not directly visible at the HTTP
    firewall boundary.
    """

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"UNSW-NB15 dataset not found at: {DATASET_PATH}"
        )

    df = pd.read_csv(DATASET_PATH)

    if "label" not in df.columns:
        raise ValueError(
            "UNSW-NB15 dataset must contain the 'label' column."
        )

    normal_df = df[df["label"] == 0].copy()

    if normal_df.empty:
        raise ValueError(
            "No NORMAL records were found in the UNSW-NB15 dataset."
        )

    baseline: dict[str, Any] = {}

    for feature in MODEL_FEATURES:

        if feature not in normal_df.columns:
            raise ValueError(
                f"Required model feature missing from dataset: {feature}"
            )

        series = normal_df[feature]

        if feature in CATEGORICAL_FEATURES:

            mode_values = series.mode(dropna=True)

            if mode_values.empty:
                baseline[feature] = "tcp"
            else:
                baseline[feature] = str(mode_values.iloc[0])

        else:

            numeric_series = pd.to_numeric(
                series,
                errors="coerce",
            )

            median_value = numeric_series.median()

            if pd.isna(median_value):
                baseline[feature] = 0.0
            else:
                baseline[feature] = float(median_value)

    return baseline


# ============================================================
# Main feature extraction
# ============================================================

def extract_features(
    source_ip: str,
    method: str,
    path: str,
    user_agent: str,
    request_size: int,
    request_rate: float,
) -> dict[str, Any]:
    """
    Convert an HTTP request into the 42 features expected by
    the trained UNSW-NB15 ML model.
    """

    method = _normalise_method(method)
    path = _extract_path(path)

    request_size = max(
        0,
        _safe_int(request_size),
    )

    request_rate = max(
        0.0,
        _safe_float(request_rate),
    )

    user_agent = str(
        user_agent or "A2FaaS-Client"
    )

    # --------------------------------------------------------
    # Load representative NORMAL network-flow baseline
    # --------------------------------------------------------

    baseline = _load_normal_baseline()

    # Start with a realistic normal-flow vector.
    features = dict(baseline)

    # --------------------------------------------------------
    # Application-level behavioral signals
    # --------------------------------------------------------

    is_write_request = int(
        method in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }
    )

    is_login_request = int(
        any(
            keyword in path.lower()
            for keyword in (
                "login",
                "signin",
                "auth",
                "token",
            )
        )
    )

    is_admin_request = int(
        "admin" in path.lower()
    )

    # --------------------------------------------------------
    # Categorical HTTP information
    # --------------------------------------------------------

    features["proto"] = _infer_protocol(user_agent)
    features["service"] = _infer_service(path)
    features["state"] = _infer_state(method)

    # --------------------------------------------------------
    # Directly observable request properties
    # --------------------------------------------------------

    features["sbytes"] = max(
        1,
        request_size,
    )

    features["rate"] = request_rate

    # Request packet estimate.
    features["spkts"] = max(
        1,
        min(
            20,
            1 + request_size // 1500,
        ),
    )

    # We do not know the actual response packet count yet.
    # Keep the NORMAL baseline rather than inventing zero.
    features["dpkts"] = max(
        1,
        int(round(_safe_float(features["dpkts"], 1))),
    )

    # --------------------------------------------------------
    # Derived HTTP traffic measurements
    # --------------------------------------------------------

    # Preserve normal baseline for network measurements that
    # cannot currently be observed at this API boundary.

    # Mean source packet size should reflect the HTTP request.
    features["smean"] = max(
        1,
        request_size,
    )

    # A response body is unknown before the protected
    # application executes, so retain the normal baseline.
    features["dmean"] = max(
        1,
        _safe_int(features["dmean"], 1),
    )

    # Login/authentication requests represent an HTTP
    # transaction depth.
    if is_login_request:
        features["trans_depth"] = max(
            1,
            _safe_int(features["trans_depth"], 1),
        )

    # Common HTTP method observation.
    features["ct_flw_http_mthd"] = max(
        1,
        _safe_int(features["ct_flw_http_mthd"], 1),
    )

    # --------------------------------------------------------
    # Controlled behavioral adjustments
    # --------------------------------------------------------

    # Very large requests are suspicious.
    if request_size > 100_000:

        features["sbytes"] = request_size

        features["spkts"] = max(
            features["spkts"],
            10,
        )

        features["sload"] = max(
            _safe_float(features["sload"], 0.0),
            request_size * max(request_rate, 1.0),
        )

    # Very high request rates are suspicious.
    if request_rate > 100:

        features["ct_src_dport_ltm"] = max(
            _safe_int(features["ct_src_dport_ltm"], 1),
            int(request_rate),
        )

        features["ct_dst_src_ltm"] = max(
            _safe_int(features["ct_dst_src_ltm"], 1),
            int(request_rate),
        )

        features["ct_srv_src"] = max(
            _safe_int(features["ct_srv_src"], 1),
            int(request_rate),
        )

    # Administrative access gets a small behavioral signal.
    if is_admin_request:

        features["ct_srv_src"] = max(
            _safe_int(features["ct_srv_src"], 1),
            2,
        )

    # --------------------------------------------------------
    # Final type normalization
    # --------------------------------------------------------

    for feature in MODEL_FEATURES:

        if feature in CATEGORICAL_FEATURES:
            features[feature] = str(
                features[feature]
            )

        else:
            features[feature] = _safe_float(
                features[feature]
            )

    # Ensure exact model schema.
    features = {
        feature: features[feature]
        for feature in MODEL_FEATURES
    }

    return features


# ============================================================
# Feature validation
# ============================================================

EXPECTED_FEATURES = set(MODEL_FEATURES)


def validate_features(
    features: dict[str, Any],
) -> bool:
    """
    Verify that the generated feature dictionary contains
    exactly the expected model features.
    """

    return set(features.keys()) == EXPECTED_FEATURES


# ============================================================
# Local test
# ============================================================

if __name__ == "__main__":

    print("=" * 68)
    print("A²FaaS TRAFFIC FEATURE EXTRACTION TEST")
    print("=" * 68)

    print()
    print("Dataset:", DATASET_PATH)
    print("Loading NORMAL baseline...")

    baseline = _load_normal_baseline()

    print(
        "NORMAL baseline features:",
        len(baseline),
    )

    test_features = extract_features(
        source_ip="192.168.1.100",
        method="GET",
        path="/login",
        user_agent="Mozilla/5.0",
        request_size=512,
        request_rate=5,
    )

    print()
    print(
        "Features generated:",
        len(test_features),
    )

    print(
        "Feature validation:",
        validate_features(test_features),
    )

    print()
    print("Sample extracted features:")

    for key in (
        "proto",
        "service",
        "state",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "rate",
        "smean",
        "dmean",
        "trans_depth",
        "ct_srv_src",
        "ct_src_ltm",
    ):
        print(
            f"  {key:<20} : "
            f"{test_features[key]}"
        )

    print()
    print(
        "Traffic feature extraction "
        "completed successfully."
    )

    print("=" * 68)