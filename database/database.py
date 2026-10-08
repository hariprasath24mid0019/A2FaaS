"""
A²FaaS Database Layer

SQLite persistence for security events,
dashboard statistics, and recent activity.
"""

from pathlib import Path
from typing import Any
import json
import sqlite3


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "a2faas.db"


# ============================================================
# CONNECTION
# ============================================================

def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10,
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_database() -> None:
    DATABASE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                request_id TEXT NOT NULL UNIQUE,

                timestamp TEXT NOT NULL,

                source_ip TEXT NOT NULL,

                method TEXT NOT NULL,

                path TEXT NOT NULL,

                user_agent TEXT,

                request_size INTEGER NOT NULL,

                request_rate REAL NOT NULL,

                ml_prediction INTEGER NOT NULL,

                risk_score REAL NOT NULL,

                risk_level TEXT NOT NULL,

                zero_trust_status TEXT NOT NULL,

                identity_verified INTEGER NOT NULL,

                device_trusted INTEGER NOT NULL,

                decision TEXT NOT NULL,

                reason TEXT NOT NULL,

                extracted_features TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_security_events_timestamp
            ON security_events(timestamp)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_security_events_decision
            ON security_events(decision)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_security_events_risk_level
            ON security_events(risk_level)
            """
        )

        connection.commit()

    finally:
        connection.close()


# ============================================================
# JSON SERIALIZATION HELPERS
# ============================================================

def _serialize_features(
    extracted_features: Any,
) -> str:
    """
    Convert extracted feature data into JSON text.

    New records store the complete feature dictionary.
    """

    if isinstance(extracted_features, dict):
        return json.dumps(
            extracted_features,
            ensure_ascii=False,
        )

    if isinstance(extracted_features, int):
        return json.dumps(
            {
                "feature_count": extracted_features,
                "legacy_record": True,
            }
        )

    return json.dumps({})


def _deserialize_features(
    value: Any,
) -> dict:
    """
    Convert database feature data back into a dictionary.

    Handles old records where only the number 42
    was stored.
    """

    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    # SQLite normally returns TEXT here.
    if isinstance(value, bytes):
        value = value.decode(
            "utf-8",
            errors="replace",
        )

    # Legacy database record:
    # extracted_features = 42
    if isinstance(value, int):
        return {
            "feature_count": value,
            "legacy_record": True,
        }

    if isinstance(value, float):
        return {
            "feature_count": int(value),
            "legacy_record": True,
        }

    if isinstance(value, str):

        value = value.strip()

        if not value:
            return {}

        try:
            parsed = json.loads(value)

            if isinstance(parsed, dict):
                return parsed

            if isinstance(parsed, int):
                return {
                    "feature_count": parsed,
                    "legacy_record": True,
                }

            return {}

        except json.JSONDecodeError:

            # If an old record contains plain "42"
            try:
                count = int(value)

                return {
                    "feature_count": count,
                    "legacy_record": True,
                }

            except ValueError:
                return {}

    return {}


# ============================================================
# SAVE SECURITY EVENT
# ============================================================

def save_security_event(
    *,
    request_id: str,
    timestamp: str,
    source_ip: str,
    method: str,
    path: str,
    user_agent: str | None,
    request_size: int,
    request_rate: float,
    ml_prediction: int,
    risk_score: float,
    risk_level: str,
    zero_trust_status: str,
    identity_verified: bool,
    device_trusted: bool,
    decision: str,
    reason: str,
    extracted_features: dict,
) -> None:

    initialize_database()

    connection = get_connection()

    try:
        cursor = connection.cursor()

        features_json = _serialize_features(
            extracted_features
        )

        cursor.execute(
            """
            INSERT INTO security_events (
                request_id,
                timestamp,
                source_ip,
                method,
                path,
                user_agent,
                request_size,
                request_rate,
                ml_prediction,
                risk_score,
                risk_level,
                zero_trust_status,
                identity_verified,
                device_trusted,
                decision,
                reason,
                extracted_features
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?
            )
            """,
            (
                request_id,
                timestamp,
                source_ip,
                method,
                path,
                user_agent,
                int(request_size),
                float(request_rate),
                int(ml_prediction),
                float(risk_score),
                risk_level,
                zero_trust_status,
                int(identity_verified),
                int(device_trusted),
                decision,
                reason,
                features_json,
            ),
        )

        connection.commit()

    finally:
        connection.close()


# ============================================================
# RECENT EVENTS
# ============================================================

def get_recent_events(
    limit: int = 20,
) -> list[dict]:

    initialize_database()

    safe_limit = max(
        1,
        min(int(limit), 100),
    )

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                request_id,
                timestamp,
                source_ip,
                method,
                path,
                user_agent,
                request_size,
                request_rate,
                ml_prediction,
                risk_score,
                risk_level,
                zero_trust_status,
                identity_verified,
                device_trusted,
                decision,
                reason,
                extracted_features
            FROM security_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        )

        rows = cursor.fetchall()

        events = []

        for row in rows:
            event = dict(row)

            event["identity_verified"] = bool(
                event["identity_verified"]
            )

            event["device_trusted"] = bool(
                event["device_trusted"]
            )

            event["extracted_features"] = (
                _deserialize_features(
                    event["extracted_features"]
                )
            )

            events.append(event)

        return events

    finally:
        connection.close()


# ============================================================
# SECURITY STATISTICS
# ============================================================

def get_security_statistics() -> dict:

    initialize_database()

    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            SELECT
                COUNT(*) AS total_requests,

                COALESCE(
                    SUM(
                        CASE
                            WHEN decision = 'ALLOW'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS allowed_requests,

                COALESCE(
                    SUM(
                        CASE
                            WHEN decision = 'CHALLENGE'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS challenged_requests,

                COALESCE(
                    SUM(
                        CASE
                            WHEN decision = 'BLOCK'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS blocked_requests,

                COALESCE(
                    SUM(
                        CASE
                            WHEN risk_level = 'HIGH'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS high_risk_requests

            FROM security_events
            """
        )

        row = cursor.fetchone()

        if row is None:
            return {
                "total_requests": 0,
                "allowed_requests": 0,
                "challenged_requests": 0,
                "blocked_requests": 0,
                "high_risk_requests": 0,
            }

        return {
            "total_requests": int(
                row["total_requests"] or 0
            ),
            "allowed_requests": int(
                row["allowed_requests"] or 0
            ),
            "challenged_requests": int(
                row["challenged_requests"] or 0
            ),
            "blocked_requests": int(
                row["blocked_requests"] or 0
            ),
            "high_risk_requests": int(
                row["high_risk_requests"] or 0
            ),
        }

    finally:
        connection.close()


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":
    initialize_database()

    print(
        "A²FaaS database initialized successfully."
    )

    print(
        f"Database path: {DATABASE_PATH}"
    )

    print(
        f"Recent events: {len(get_recent_events(10))}"
    )

    print(
        "Statistics:",
        get_security_statistics(),
    )