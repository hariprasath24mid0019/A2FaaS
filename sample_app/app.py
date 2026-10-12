
import os
import hmac
import secrets
from functools import wraps

import requests
from flask import (
    Flask,
    jsonify,
    request,
    redirect,
    render_template_string,
    session,
    url_for,
    make_response,
)
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Required deployment configuration.
app.config.update(
    SECRET_KEY=os.environ.get("A2FAAS_SECRET_KEY", ""),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get(
        "A2FAAS_COOKIE_SECURE", "true"
    ).lower() == "true",
    PERMANENT_SESSION_LIFETIME=__import__("datetime").timedelta(minutes=30),
)

FIREWALL_API = os.environ.get(
    "A2FAAS_FIREWALL_API",
    "https://a2faas.onrender.com/api/firewall/analyze",
)
AUTH_USERNAME = os.environ.get("A2FAAS_USERNAME", "")
AUTH_PASSWORD_HASH = os.environ.get("A2FAAS_PASSWORD_HASH", "")
TIMEOUT_SECONDS = 15


def configuration_valid():
    return bool(
        app.config["SECRET_KEY"]
        and AUTH_USERNAME
        and AUTH_PASSWORD_HASH
    )


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def valid_csrf():
    supplied = request.form.get("csrf_token", "")
    expected = session.get("_csrf_token", "")
    return bool(expected and supplied and
                hmac.compare_digest(expected, supplied))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login", next="/"))
        return view(*args, **kwargs)
    return wrapped


LOGIN_HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>A²FaaS — Sign in</title>
<style>
body{font-family:Arial,sans-serif;background:#f0f4f8;display:grid;
place-items:center;min-height:100vh;margin:0;color:#172033}
.card{background:white;padding:32px;border-radius:14px;width:min(360px,85vw);
box-shadow:0 8px 28px #0001}
h1{font-size:23px;color:#173b70}
label{display:block;margin:16px 0 6px}
input{box-sizing:border-box;width:100%;padding:11px;border:1px solid #ccd4e0;
border-radius:7px}
button{width:100%;padding:12px;margin-top:20px;border:0;border-radius:7px;
background:#5967d9;color:white;font-weight:bold;cursor:pointer}
.error{color:#b42318}
</style>
</head>
<body><main class="card">
<h1>A²FaaS Protected Application</h1>
<p>Sign in to request access to the protected resource.</p>
{% if error %}<p class="error">{{ error }}</p>{% endif %}
<form method="post" action="{{ url_for('login') }}">
<input type="hidden" name="csrf_token" value="{{ token }}">
<label for="username">Username</label>
<input id="username" name="username" autocomplete="username" required>
<label for="password">Password</label>
<input id="password" name="password" type="password"
autocomplete="current-password" required>
<button type="submit">Sign in</button>
</form>
</main></body></html>
"""

PROTECTED_HTML = """
<!doctype html>
<html lang="en">
<head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>A²FaaS Protected Application</title>
<style>
body{font-family:Arial,sans-serif;text-align:center;margin:90px 15px;
background:#f0f4f8;color:#172033}
.card{display:inline-block;max-width:600px;background:white;padding:35px;
border-radius:12px;box-shadow:0 4px 15px #0002}
.status{color:#16803c;font-weight:bold}
button{padding:10px 16px;border:0;border-radius:7px;background:#5967d9;
color:white;cursor:pointer}
</style></head>
<body><main class="card">
<h1>A²FaaS Protected Sample Application</h1>
<p>Authentication succeeded and A²FaaS authorized this request.</p>
<p class="status">Firewall decision: ALLOW</p>
<p>Session: authenticated</p>
<form method="post" action="{{ url_for('logout') }}">
<input type="hidden" name="csrf_token" value="{{ token }}">
<button type="submit">Sign out</button>
</form>
</main></body></html>
"""


@app.before_request
def enforce_firewall():
    # Health checks and login must be reachable before authentication.
    # The protected route itself is always checked by the firewall.
    if request.endpoint in {
        "health", "login", "static"
    }:
        return None

    if not configuration_valid():
        return jsonify({
            "error": "Server authentication is not configured"
        }), 503

    authenticated = bool(session.get("authenticated"))
    device_enrolled = bool(session.get("device_enrolled"))

    payload = {
        "source_ip": request.remote_addr or "unknown",
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", "Unknown"),
        "request_size": request.content_length or 0,
        "request_rate": 1,
        "identity_verified": authenticated,
        # This is an enrolled-browser session marker, not proof of
        # hardware/device posture. Do not treat it as endpoint attestation.
        "device_trusted": authenticated and device_enrolled,
    }

    try:
        response = requests.post(
            FIREWALL_API,
            json=payload,
            timeout=TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        result = response.json()
    except (requests.RequestException, ValueError):
        app.logger.exception("A²FaaS firewall request failed")
        return jsonify({
            "error": "Firewall unavailable",
            "message": "A²FaaS could not verify this request.",
        }), 503

    decision = str(result.get("decision", "")).upper()

    if decision != "ALLOW":
        status_code = {
            "CHALLENGE": 401,
            "BLOCK": 403,
        }.get(decision, 502)

        return make_response(jsonify({
            "message": "Request not allowed by A²FaaS",
            "firewall_decision": decision or "UNKNOWN",
            "risk_level": result.get("risk_level"),
            "zero_trust_status": result.get("zero_trust_status"),
            "request_id": result.get("request_id"),
        }), status_code)

    return None


@app.route("/login", methods=["GET", "POST"])
def login():
    if not configuration_valid():
        return jsonify({
            "error": "Server authentication is not configured"
        }), 503

    if request.method == "GET":
        return render_template_string(
            LOGIN_HTML, token=csrf_token(), error=None
        )

    if not valid_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 400

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    username_ok = hmac.compare_digest(username, AUTH_USERNAME)
    try:
        password_ok = check_password_hash(
            AUTH_PASSWORD_HASH, password
        )
    except (ValueError, TypeError):
        password_ok = False

    if not (username_ok and password_ok):
        return render_template_string(
            LOGIN_HTML,
            token=csrf_token(),
            error="Invalid username or password.",
        ), 401

    # Rotate the session identifier/state after successful login.
    session.clear()
    session.permanent = True
    session["authenticated"] = True
    session["device_enrolled"] = True
    session["_csrf_token"] = secrets.token_urlsafe(32)

    return redirect(url_for("home"), code=303)


@app.route("/")
@login_required
def home():
    return render_template_string(
        PROTECTED_HTML, token=csrf_token()
    )


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    if not valid_csrf():
        return jsonify({"error": "Invalid CSRF token"}), 400

    session.clear()
    return redirect(url_for("login"), code=303)


@app.route("/health")
def health():
    return jsonify({
        "application": "A2FaaS Sample App",
        "status": "running",
    })


if __name__ == "__main__":
    if not configuration_valid():
        raise RuntimeError(
            "Set A2FAAS_SECRET_KEY, A2FAAS_USERNAME, "
            "and A2FAAS_PASSWORD_HASH before starting the app."
        )

    # Local HTTP testing only: set A2FAAS_COOKIE_SECURE=false locally.
    app.run(
    host="0.0.0.0",
    port=int(os.environ.get("PORT", 5000)),
    debug=False,
)
