"""
A²FaaS Database Layer

SQLite is used by default for local development.
Set DATABASE_URL (or NEON_DATABASE_URL) to use PostgreSQL.
The local SQLite database is not modified when PostgreSQL is selected.
"""
from pathlib import Path
from typing import Any
import json
import os
import sqlite3

BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = Path(
    os.getenv("A2FAAS_DATABASE_PATH", str(BASE_DIR / "a2faas.db"))
).expanduser()
DATABASE_URL = os.getenv("DATABASE_URL", "").strip() or os.getenv("NEON_DATABASE_URL", "").strip()
_USE_POSTGRES = bool(DATABASE_URL)

if _USE_POSTGRES and not DATABASE_URL.startswith(("postgres://", "postgresql://")):
    raise RuntimeError("DATABASE_URL/NEON_DATABASE_URL must be a PostgreSQL connection URL.")


def get_connection():
    """Return a connection to the configured database."""
    if _USE_POSTGRES:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError(
                "PostgreSQL is configured but psycopg is missing. Install requirements.txt."
            ) from exc
        return psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=15)

    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def _placeholder() -> str:
    return "%s" if _USE_POSTGRES else "?"


def initialize_database() -> None:
    """Create the table and indexes if they do not exist."""
    if not _USE_POSTGRES:
        DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = get_connection()
    try:
        cursor = connection.cursor()
        id_definition = "BIGSERIAL PRIMARY KEY" if _USE_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS security_events (
                id {id_definition},
                request_id TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                user_agent TEXT,
                request_size INTEGER NOT NULL,
                request_rate DOUBLE PRECISION NOT NULL,
                ml_prediction INTEGER NOT NULL,
                risk_score DOUBLE PRECISION NOT NULL,
                risk_level TEXT NOT NULL,
                zero_trust_status TEXT NOT NULL,
                identity_verified INTEGER NOT NULL,
                device_trusted INTEGER NOT NULL,
                decision TEXT NOT NULL,
                reason TEXT NOT NULL,
                extracted_features TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
            ON security_events(timestamp)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_decision
            ON security_events(decision)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_security_events_risk_level
            ON security_events(risk_level)
        """)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _serialize_features(extracted_features: Any) -> str:
    if isinstance(extracted_features, dict):
        return json.dumps(extracted_features, ensure_ascii=False)
    if isinstance(extracted_features, int):
        return json.dumps({"feature_count": extracted_features, "legacy_record": True})
    return json.dumps({})


def _deserialize_features(value: Any) -> dict:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, (int, float)):
        return {"feature_count": int(value), "legacy_record": True}
    if isinstance(value, str):
        value = value.strip()
        if not value:
            return {}
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
            if isinstance(parsed, int):
                return {"feature_count": parsed, "legacy_record": True}
            return {}
        except json.JSONDecodeError:
            try:
                return {"feature_count": int(value), "legacy_record": True}
            except ValueError:
                return {}
    return {}


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
    """Save a security event; raise errors so callers can detect failed persistence."""
    initialize_database()
    connection = get_connection()
    try:
        p = _placeholder()
        connection.cursor().execute(f"""
            INSERT INTO security_events (
                request_id, timestamp, source_ip, method, path, user_agent,
                request_size, request_rate, ml_prediction, risk_score,
                risk_level, zero_trust_status, identity_verified,
                device_trusted, decision, reason, extracted_features
            ) VALUES (
                {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p},
                {p}, {p}, {p}, {p}, {p}, {p}, {p}, {p}
            )
        """, (
            request_id, timestamp, source_ip, method, path, user_agent,
            int(request_size), float(request_rate), int(ml_prediction),
            float(risk_score), risk_level, zero_trust_status,
            int(identity_verified), int(device_trusted), decision, reason,
            _serialize_features(extracted_features),
        ))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_recent_events(limit: int = 20) -> list[dict]:
    initialize_database()
    safe_limit = max(1, min(int(limit), 100))
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(f"""
            SELECT id, request_id, timestamp, source_ip, method, path, user_agent,
                   request_size, request_rate, ml_prediction, risk_score, risk_level,
                   zero_trust_status, identity_verified, device_trusted, decision,
                   reason, extracted_features
            FROM security_events
            ORDER BY id DESC
            LIMIT {_placeholder()}
        """, (safe_limit,))
        events = []
        for row in cursor.fetchall():
            event = dict(row)
            event["identity_verified"] = bool(event["identity_verified"])
            event["device_trusted"] = bool(event["device_trusted"])
            event["extracted_features"] = _deserialize_features(event["extracted_features"])
            events.append(event)
        return events
    finally:
        connection.close()


def get_security_statistics() -> dict:
    initialize_database()
    connection = get_connection()
    try:
        cursor = connection.cursor()
        cursor.execute("""
            SELECT COUNT(*) AS total_requests,
                   COALESCE(SUM(CASE WHEN decision = 'ALLOW' THEN 1 ELSE 0 END), 0) AS allowed_requests,
                   COALESCE(SUM(CASE WHEN decision = 'CHALLENGE' THEN 1 ELSE 0 END), 0) AS challenged_requests,
                   COALESCE(SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END), 0) AS blocked_requests,
                   COALESCE(SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END), 0) AS high_risk_requests
            FROM security_events
        """)
        fetched = cursor.fetchone()
        row = dict(fetched) if fetched is not None else {}
        return {
            "total_requests": int(row.get("total_requests", 0) or 0),
            "allowed_requests": int(row.get("allowed_requests", 0) or 0),
            "challenged_requests": int(row.get("challenged_requests", 0) or 0),
            "blocked_requests": int(row.get("blocked_requests", 0) or 0),
            "high_risk_requests": int(row.get("high_risk_requests", 0) or 0),
        }
    finally:
        connection.close()


if __name__ == "__main__":
    initialize_database()
    print("A²FaaS database initialized successfully.")
    print(f"Database mode: {'PostgreSQL' if _USE_POSTGRES else 'SQLite'}")
    if not _USE_POSTGRES:
        print(f"Database path: {DATABASE_PATH}")
    print(f"Recent events: {len(get_recent_events(10))}")
    print("Statistics:", get_security_statistics())
