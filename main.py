"""
Demo backend for Didit identity verification (KYC).

Two endpoints:
  POST /create-session    -> app calls this to start verification for a user,
                              gets back a session_token to hand to the RN SDK
  POST /webhooks/didit     -> Didit calls this on verification events,
                              we verify + process them here

Run:
  pip install fastapi uvicorn httpx --break-system-packages
  export DIDIT_API_KEY="your-key-here"          # never hardcode this
  export DIDIT_WORKFLOW_ID="your-workflow-id"
  export DIDIT_WEBHOOK_SECRET="your-webhook-secret"   # per-destination secret_shared_key from Business Console
  uvicorn main:app --reload
"""

import hashlib
import hmac
import json
import os
import time

import httpx
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request

app = FastAPI()

# --- Config (read from environment, never hardcode) -------------------------
DIDIT_API_KEY = os.environ.get("DIDIT_API_KEY", "")
DIDIT_WORKFLOW_ID = os.environ.get("DIDIT_WORKFLOW_ID", "")
DIDIT_WEBHOOK_SECRET = os.environ.get("DIDIT_WEBHOOK_SECRET", "")
DIDIT_API_BASE = "https://verification.didit.me"  # confirm against Didit's current docs

if not DIDIT_API_KEY:
    print("WARNING: DIDIT_API_KEY is not set. /create-session will fail.")

# --- Fake "database" for demo purposes ---------------------------------------
# Replace this with your real DB (Postgres, etc). Keyed by user_id.
fake_users_db: dict[str, dict] = {}


def get_or_create_user(user_id: str) -> dict:
    if user_id not in fake_users_db:
        fake_users_db[user_id] = {"id": user_id, "verification_status": "unverified"}
    return fake_users_db[user_id]


# --- 1. Create a verification session ----------------------------------------
@app.post("/create-session")
async def create_session(user_id: str):
    """
    Called by your app (or your app's backend call, triggered from the
    RN app) when a user starts the "become a host" verification flow.
    Returns a session_token the RN SDK uses to launch the native flow.
    """
    if not DIDIT_API_KEY:
        raise HTTPException(status_code=500, detail="Server missing DIDIT_API_KEY")

    get_or_create_user(user_id)  # ensure user exists in our demo db

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{DIDIT_API_BASE}/v3/sessions/",
            headers={"x-api-key": DIDIT_API_KEY},
            json={
                "workflow_id": DIDIT_WORKFLOW_ID,
                "vendor_data": user_id,  # this is how we match the webhook back to a user
                "callback": "https://yourapp.com/verification/callback",
            },
        )

    if response.status_code != 200 and response.status_code != 201:
        raise HTTPException(
            status_code=502,
            detail=f"Didit session creation failed: {response.status_code} {response.text}",
        )

    data = response.json()
    fake_users_db[user_id]["verification_status"] = "pending"

    # Send this down to the RN app. Never send DIDIT_API_KEY to the client.
    return {
        "session_token": data.get("session_token") or data.get("token"),
        "session_id": data.get("session_id") or data.get("id"),
    }


# --- 2. Webhook: Didit sends real-time verification events --------------------

WEBHOOK_MAX_SKEW_SECONDS = 300  # 5 minutes

# Idempotency: remember event_ids we've already processed.
# Demo only -- use a real DB table (or Redis with TTL) in production, since
# this in-memory set resets on restart and won't be shared across workers.
processed_event_ids: set[str] = set()


def _canonical_json(data: dict) -> str:
    """
    Sorted, Unicode-preserving canonical JSON -- must match how Didit
    serializes the payload before signing for X-Signature-V2.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def verify_signature_v2(parsed_body: dict, signature_header: str) -> bool:
    if not DIDIT_WEBHOOK_SECRET or not signature_header:
        return False
    canonical = _canonical_json(parsed_body)
    expected = hmac.new(
        DIDIT_WEBHOOK_SECRET.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def verify_signature_raw(raw_body: bytes, signature_header: str) -> bool:
    """Fallback: HMAC over the exact raw bytes (X-Signature)."""
    if not DIDIT_WEBHOOK_SECRET or not signature_header:
        return False
    expected = hmac.new(
        DIDIT_WEBHOOK_SECRET.encode("utf-8"), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def verify_signature_simple(
    timestamp: str, session_id: str, status: str, webhook_type: str, signature_header: str
) -> bool:
    """Fallback only -- does not authenticate the decision body itself."""
    if not DIDIT_WEBHOOK_SECRET or not signature_header:
        return False
    message = f"{timestamp}:{session_id}:{status}:{webhook_type}"
    expected = hmac.new(
        DIDIT_WEBHOOK_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def process_webhook_event(event: dict) -> None:
    """
    Heavy/state-update work, run after we've already returned 2xx.
    Handles both session events and entity/transaction events.
    """
    webhook_type = event.get("webhook_type")
    session_id = event.get("session_id")
    vendor_data = event.get("vendor_data")  # your internal user_id, for session events
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
            user["decision"] = decision  # store id_verifications[], face_matches[], etc.
        elif status == "Declined":
            user["verification_status"] = "declined"
            if decision:
                for key in ("id_verifications", "face_matches", "liveness_checks", "aml_screenings"):
                    for item in decision.get(key, []) or []:
                        warnings = item.get("warnings")
                        if warnings:
                            print(f"  {key} warnings: {warnings}")
        elif status == "In Review":
            user["verification_status"] = "pending_review"
        elif status == "In Progress":
            user["verification_status"] = "in_progress"
        elif status == "Resubmitted":
            # decision.resubmit_info lists which feature nodes need to be redone
            user["verification_status"] = "in_progress"
        elif status == "Abandoned":
            user["verification_status"] = "abandoned"
            # optionally: queue a reminder notification here
        elif status in ("Expired", "KYC Expired"):
            user["verification_status"] = "expired"
            # optionally: create a fresh session for the user here

        print(f"  user={vendor_data} -> verification_status={user['verification_status']}")

    elif webhook_type in ("user.status.updated", "user.data.updated"):
        print(f"  entity event for user_id={event.get('user_id', session_id)}: {event}")
        # handle per your entity model if you use Didit's Entity APIs

    elif webhook_type in ("business.status.updated", "business.data.updated"):
        print(f"  business/KYB event: business_session_id={event.get('business_session_id')}")
        # handle per your KYB model if applicable

    elif webhook_type == "activity.created":
        print(f"  activity timeline event: {event}")

    elif webhook_type in ("transaction.created", "transaction.status.updated"):
        print(f"  transaction event: {event}")
        # handle per your transaction-monitoring logic if applicable

    else:
        print(f"  Unhandled webhook_type: {webhook_type}")


@app.post("/webhooks/didit")
async def didit_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_signature_v2: str = Header(default="", alias="X-Signature-V2"),
    x_signature: str = Header(default="", alias="X-Signature"),
    x_signature_simple: str = Header(default="", alias="X-Signature-Simple"),
    x_timestamp: str = Header(default="", alias="X-Timestamp"),
):
    # 1. Read raw body BEFORE any JSON parsing -- required for signature verification
    raw_body = await request.body()

    # 2. Timestamp freshness check
    if not x_timestamp:
        raise HTTPException(status_code=401, detail="Missing X-Timestamp header")
    try:
        skew = abs(time.time() - int(x_timestamp))
    except ValueError:
        raise HTTPException(status_code=401, detail="Malformed X-Timestamp header")
    if skew > WEBHOOK_MAX_SKEW_SECONDS:
        raise HTTPException(status_code=401, detail="Webhook timestamp outside allowed window")

    # 3. Parse JSON (only for use in signature check / processing -- the raw
    #    bytes above are what actually get HMAC'd for X-Signature)
    try:
        parsed = json.loads(raw_body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # 4. Verify signature -- prefer V2, fall back in order per Didit's docs
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
        # Log the raw body for debugging signature failures (don't log secrets)
        print(f"Webhook signature verification FAILED. Raw body: {raw_body[:500]!r}")
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # 5. Idempotency -- dedupe on event_id (fallback to session_id+status+type)
    event_id = parsed.get("event_id") or (
        f"{parsed.get('session_id')}:{parsed.get('status')}:{parsed.get('webhook_type')}"
    )
    if event_id in processed_event_ids:
        print(f"Duplicate webhook delivery for event_id={event_id}, skipping reprocess")
        return {"received": True, "duplicate": True}
    processed_event_ids.add(event_id)

    # 6. Return 2xx fast; do the actual state update asynchronously
    background_tasks.add_task(process_webhook_event, parsed)

    return {"received": True}


# --- 3. Helper: let your app check status -------------------------------------
@app.get("/users/{user_id}/verification-status")
async def get_verification_status(user_id: str):
    user = get_or_create_user(user_id)
    return {"user_id": user_id, "verification_status": user["verification_status"]}