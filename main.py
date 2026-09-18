"""
Kiya backend -- Flask + Didit identity verification (KYC).

Endpoints:
  GET  /                              -> health check (existing)
  GET  /health                        -> health check (existing)
  POST /create-session                -> app calls this to start verification
                                          for a user, gets back a session_token
  POST /webhooks/didit                -> Didit calls this on verification events
  GET  /users/<user_id>/verification  -> app polls this to check status

Env vars (set these in Render's dashboard under your service -> Environment):
  DIDIT_API_KEY        -- from Business Console (rotate the one you pasted earlier!)
  DIDIT_WORKFLOW_ID     -- from your workflow's detail page
  DIDIT_WEBHOOK_SECRET  -- secret_shared_key from your webhook destination

Local run:
  pip install flask flask-cors requests
  export DIDIT_API_KEY="..." DIDIT_WORKFLOW_ID="..." DIDIT_WEBHOOK_SECRET="..."
  python main.py
"""

import hashlib
import hmac
import json
import os
import threading
import time

import requests
from flask import Flask, jsonify, request

# Load variables from a local .env file (KEY=value, one per line) into the
# environment. Only needed for local dev -- Render injects its own
# Environment tab variables automatically, no dotenv needed there.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)

# CORS is optional here -- only add flask_cors back if your RN app calls
# this API directly from a web build. Native iOS/Android don't need it.
try:
    from flask_cors import CORS
    CORS(app)
except ImportError:
    pass

# --- Config -------------------------------------------------------------------
DIDIT_API_KEY = os.environ.get("DIDIT_API_KEY", "")
DIDIT_WORKFLOW_ID = os.environ.get("DIDIT_WORKFLOW_ID", "")
DIDIT_WEBHOOK_SECRET = os.environ.get("DIDIT_WEBHOOK_SECRET", "")
DIDIT_API_BASE = "https://verification.didit.me"  # confirm against current Didit docs
WEBHOOK_MAX_SKEW_SECONDS = 300  # 5 minutes

if not DIDIT_API_KEY:
    print("WARNING: DIDIT_API_KEY not set -- /create-session will fail")
if not DIDIT_WEBHOOK_SECRET:
    print("WARNING: DIDIT_WEBHOOK_SECRET not set -- webhook verification will always fail")

# --- Fake "database" for demo purposes -----------------------------------------
# Replace with a real DB (Postgres, etc). Render's filesystem is ephemeral and
# this dict resets on every deploy/restart -- fine for a demo, not for real users.
fake_users_db: dict[str, dict] = {}
processed_event_ids: set[str] = set()


def get_or_create_user(user_id: str) -> dict:
    if user_id not in fake_users_db:
        fake_users_db[user_id] = {"id": user_id, "verification_status": "unverified"}
    return fake_users_db[user_id]


# --- Existing health routes -----------------------------------------------------
@app.route("/")
def home():
    return jsonify({"status": "ok", "message": "Kiya backend running"})


@app.route("/health")
def health():
    return jsonify({"healthy": True})


# --- 1. Create a verification session --------------------------------------------
@app.route("/create-session", methods=["POST"])
def create_session():
    if not DIDIT_API_KEY:
        return jsonify({"error": "Server missing DIDIT_API_KEY"}), 500

    body = request.get_json(silent=True) or {}
    user_id = body.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    get_or_create_user(user_id)

    resp = requests.post(
        f"{DIDIT_API_BASE}/v3/sessions/",
        headers={"x-api-key": DIDIT_API_KEY},
        json={
            "workflow_id": DIDIT_WORKFLOW_ID,
            "vendor_data": user_id,  # ties the webhook back to this user
            "callback": "https://k1-2-zz4n.onrender.com/verification/callback",
        },
        timeout=15,
    )

    if resp.status_code not in (200, 201):
        return jsonify({
            "error": "Didit session creation failed",
            "status_code": resp.status_code,
            "detail": resp.text,
        }), 502

    data = resp.json()
    fake_users_db[user_id]["verification_status"] = "pending"

    # Send this to the RN app. Never send DIDIT_API_KEY to the client.
    return jsonify({
        "session_token": data.get("session_token") or data.get("token"),
        "session_id": data.get("session_id") or data.get("id"),
    })


# --- 2. Webhook: Didit sends real-time verification events -----------------------
def _canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def verify_signature_v2(parsed_body: dict, signature_header: str) -> bool:
    if not DIDIT_WEBHOOK_SECRET or not signature_header:
        return False
    canonical = _canonical_json(parsed_body)
    expected = hmac.new(
        DIDIT_WEBHOOK_SECRET.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def verify_signature_raw(raw_body: bytes, signature_header: str) -> bool:
    if not DIDIT_WEBHOOK_SECRET or not signature_header:
        return False
    expected = hmac.new(
        DIDIT_WEBHOOK_SECRET.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def verify_signature_simple(timestamp, session_id, status, webhook_type, signature_header) -> bool:
    if not DIDIT_WEBHOOK_SECRET or not signature_header:
        return False
    message = f"{timestamp}:{session_id}:{status}:{webhook_type}"
    expected = hmac.new(
        DIDIT_WEBHOOK_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def process_webhook_event(event: dict) -> None:
    """Runs in a background thread, after we've already returned 2xx."""
    webhook_type = event.get("webhook_type")
    session_id = event.get("session_id")
    vendor_data = event.get("vendor_data")
    status = event.get("status")
    decision = event.get("decision")

    print(f"Processing webhook: type={webhook_type} session={session_id} status={status}")

    if webhook_type in ("status.updated", "data.updated"):
        if not vendor_data:
            print("No vendor_data on session event -- can't map to a user, skipping")
            return
        user = get_or_create_user(vendor_data)

        if status == "Approved":
            user["verification_status"] = "verified"
            user["decision"] = decision
        elif status == "Declined":
            user["verification_status"] = "declined"
        elif status == "In Review":
            user["verification_status"] = "pending_review"
        elif status == "In Progress":
            user["verification_status"] = "in_progress"
        elif status == "Resubmitted":
            user["verification_status"] = "in_progress"
        elif status == "Abandoned":
            user["verification_status"] = "abandoned"
        elif status in ("Expired", "KYC Expired"):
            user["verification_status"] = "expired"

        print(f"  user={vendor_data} -> verification_status={user['verification_status']}")

    elif webhook_type in ("user.status.updated", "user.data.updated"):
        print(f"  entity event: {event}")
    elif webhook_type in ("business.status.updated", "business.data.updated"):
        print(f"  KYB event: business_session_id={event.get('business_session_id')}")
    elif webhook_type == "activity.created":
        print(f"  activity event: {event}")
    elif webhook_type in ("transaction.created", "transaction.status.updated"):
        print(f"  transaction event: {event}")
    else:
        print(f"  Unhandled webhook_type: {webhook_type}")


@app.route("/webhooks/didit", methods=["POST"])
def didit_webhook():
    raw_body = request.get_data()  # raw bytes, read before any JSON parsing

    x_signature_v2 = request.headers.get("X-Signature-V2", "")
    x_signature = request.headers.get("X-Signature", "")
    x_signature_simple = request.headers.get("X-Signature-Simple", "")
    x_timestamp = request.headers.get("X-Timestamp", "")

    if not x_timestamp:
        return jsonify({"error": "Missing X-Timestamp header"}), 401
    try:
        skew = abs(time.time() - int(x_timestamp))
    except ValueError:
        return jsonify({"error": "Malformed X-Timestamp header"}), 401
    if skew > WEBHOOK_MAX_SKEW_SECONDS:
        return jsonify({"error": "Webhook timestamp outside allowed window"}), 401

    try:
        parsed = json.loads(raw_body)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON body"}), 400

    verified = False
    if x_signature_v2:
        verified = verify_signature_v2(parsed, x_signature_v2)
    elif x_signature:
        verified = verify_signature_raw(raw_body, x_signature)
    elif x_signature_simple:
        verified = verify_signature_simple(
            x_timestamp,
            parsed.get("session_id", ""),
            parsed.get("status", ""),
            parsed.get("webhook_type", ""),
            x_signature_simple,
        )

    if not verified:
        print(f"Webhook signature verification FAILED. Raw body: {raw_body[:500]!r}")
        return jsonify({"error": "Invalid webhook signature"}), 401

    event_id = parsed.get("event_id") or (
        f"{parsed.get('session_id')}:{parsed.get('status')}:{parsed.get('webhook_type')}"
    )
    if event_id in processed_event_ids:
        print(f"Duplicate webhook delivery for event_id={event_id}, skipping")
        return jsonify({"received": True, "duplicate": True})
    processed_event_ids.add(event_id)

    # Return 2xx fast; process in a background thread.
    # (For real production traffic, swap this for a task queue like Celery/RQ.)
    threading.Thread(target=process_webhook_event, args=(parsed,), daemon=True).start()

    return jsonify({"received": True})


# --- 3. Let your app poll verification status -------------------------------------
@app.route("/users/<user_id>/verification-status")
def get_verification_status(user_id):
    user = get_or_create_user(user_id)
    return jsonify({"user_id": user_id, "verification_status": user["verification_status"]})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)