"""
Kiya backend -- Flask + Didit KYC + SMS OTP + Google Sign-In.

Flow:
  1. POST /create_user        -> creates PENDING user + sends OTP
  2. POST /verify_otp         -> activates user (or wipes pending on failure)
  3. POST /resend_otp         -> resend OTP for a pending user
  4. POST /become_landlord    -> upgrade a verified user to landlord
  5. POST /create_landlord    -> standalone landlord (own OTP flow)
  6. POST /login_user         -> request OTP for a verified user
  7. POST /verify_login_otp   -> verify OTP, return JWT
  8. POST /google_signin      -> verify Google ID token; login OR request phone
  9. POST /google_create_user -> create pending user with google_sub + OTP
 10. GET  /me                 -> current user (Bearer JWT)

Other:
  GET  /                                   -> health
  GET  /health                             -> health
  POST /create-session                     -> Didit KYC session
  POST /webhooks/didit                     -> Didit webhook receiver
  GET  /users/<user_id>/verification-status -> Didit status poll
  GET  /uploads/images/<filename>          -> serve avatars

Required env vars (set these in Render's dashboard -> Environment tab,
never hardcode them in this file):
  DIDIT_API_KEY, DIDIT_WORKFLOW_ID, DIDIT_WEBHOOK_SECRET
  AT_USERNAME, AT_API_KEY            (Africa's Talking -- "sandbox" username
                                       while testing, your real username in
                                       production)
  AT_SENDER_ID                       (optional -- approved Sender ID for
                                       Kenya; leave unset to use the default)
  GOOGLE_CLIENT_ID
  SECRET_KEY                         (for JWT signing)
"""

import hashlib
import hmac
import json
import os
import random
import secrets
import threading
import time
import uuid
import jwt
from datetime import datetime, timedelta, timezone

import phonenumbers
from phonenumbers import NumberParseException
import requests
from flask import jsonify, request, send_from_directory
from werkzeug.utils import secure_filename

from config import (
    app, db,
    UPLOAD_FOLDER, PDF_FOLDER, VIDEO_FOLDER, IMAGE_UPLOAD_FOLDER,
    ALLOWED_PDF, ALLOWED_VIDEO, ALLOWED_IMAGE,
)

from models import UsersDetails, Landlords, OTPVerification

# --- Google sign-in -----------------------------------------------------------
try:
    from google.oauth2 import id_token as google_id_token
    from google.auth.transport import requests as google_requests
    GOOGLE_LIB_OK = True
except ImportError:
    google_id_token = None
    google_requests = None
    GOOGLE_LIB_OK = False
    print("FATAL: google-auth not installed -- Google sign-in disabled")


def utcnow():
    """UTC now, tz-naive. Safe for SQLite AND Postgres DateTime columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ===========================================================================
# Africa's Talking -- REQUIRED in production
# ===========================================================================
try:
    import africastalking

    # Always read from environment -- never hardcode credentials here.
    # Set these in Render's dashboard under your service's Environment tab.
    AT_USERNAME = "sandbox"
    AT_API_KEY = "atsk_ebcc23d72e5daf311e388cc8d92fb1419e56dc27ec51d80183c64b5db879970f8dc6fcf6"
   

    if not AT_USERNAME or not AT_API_KEY:
        raise RuntimeError(
            "Africa's Talking credentials are required. "
            "Set AT_USERNAME and AT_API_KEY in your environment "
            "(Render dashboard -> Environment tab)."
        )

    africastalking.initialize(AT_USERNAME, AT_API_KEY)
    sms = africastalking.SMS
    print(f"Africa's Talking initialized (username={AT_USERNAME})")

except ImportError:
    sms = None
    raise RuntimeError(
        "africastalking SDK is required. Install with: pip install africastalking"
    )


# --- Backblaze B2 (optional) --------------------------------------------------
B2_KEY_ID = os.getenv("B2_KEY_ID")
B2_APP_KEY = os.getenv("B2_APP_KEY")
B2_BUCKET_NAME = os.getenv("B2_BUCKET_NAME")

# --- Didit config -------------------------------------------------------------
DIDIT_API_KEY = os.environ.get("DIDIT_API_KEY", "")
DIDIT_WORKFLOW_ID = os.environ.get("DIDIT_WORKFLOW_ID", "")
DIDIT_WEBHOOK_SECRET = os.environ.get("DIDIT_WEBHOOK_SECRET", "")
DIDIT_API_BASE = "https://verification.didit.me"
WEBHOOK_MAX_SKEW_SECONDS = 300

if not DIDIT_API_KEY:
    raise RuntimeError("DIDIT_API_KEY is required.")
if not DIDIT_WORKFLOW_ID:
    raise RuntimeError("DIDIT_WORKFLOW_ID is required.")
if not DIDIT_WEBHOOK_SECRET:
    raise RuntimeError("DIDIT_WEBHOOK_SECRET is required.")

# --- Google config ------------------------------------------------------------
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
if not GOOGLE_CLIENT_ID:
    raise RuntimeError("GOOGLE_CLIENT_ID is required.")
if not GOOGLE_LIB_OK:
    raise RuntimeError("google-auth library is required.")

# --- Phone config -------------------------------------------------------------
DEFAULT_REGION = "KE"
ALLOWED_REGIONS = {"KE", "UG", "TZ", "ET", "SO"}

# --- OTP config ---------------------------------------------------------------
OTP_TTL_SECONDS = 300
OTP_MAX_ATTEMPTS = 5
OTP_LENGTH = 6
OTP_RESEND_COOLDOWN = 60

# --- In-memory webhook dedupe (single-process only; use Redis for multi-worker)
processed_event_ids: set[str] = set()

# --- Avatar palette -----------------------------------------------------------
AVATAR_COLORS = [
    "#F87171", "#FB923C", "#FBBF24", "#A3E635", "#34D399",
    "#22D3EE", "#60A5FA", "#A78BFA", "#F472B6", "#F43F5E",
    "#10B981", "#8B5CF6", "#0EA5E9", "#EAB308", "#EC4899",
]


def random_avatar_color() -> str:
    return random.choice(AVATAR_COLORS)


def first_initial(name: str) -> str:
    if not name:
        return "?"
    stripped = name.strip()
    return stripped[:1].upper() if stripped else "?"


# ===========================================================================
# Phone normalization
# ===========================================================================
def normalize_phone(raw: str, default_region: str = DEFAULT_REGION) -> str:
    if not raw or not str(raw).strip():
        raise ValueError("Phone number is required")

    cleaned = (
        str(raw).strip()
        .replace(" ", "").replace("-", "")
        .replace("(", "").replace(")", "")
    )

    if default_region == "KE" and cleaned.isdigit() and len(cleaned) == 9:
        cleaned = "0" + cleaned

    try:
        num = phonenumbers.parse(cleaned, default_region)
    except NumberParseException as e:
        raise ValueError(f"Could not parse phone number: {e}")

    if not phonenumbers.is_valid_number(num):
        raise ValueError("Invalid phone number")

    if ALLOWED_REGIONS:
        region = phonenumbers.region_code_for_number(num)
        if region not in ALLOWED_REGIONS:
            raise ValueError("Country not supported yet")

    return phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)


def split_phone(canonical_e164: str):
    n = phonenumbers.parse(canonical_e164, None)
    return f"+{n.country_code}", str(n.national_number)


# ===========================================================================
# OTP helpers
# ===========================================================================
def _hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def _generate_otp() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(OTP_LENGTH))


def _cleanup_expired_otps():
    cutoff = utcnow() - timedelta(hours=24)
    try:
        OTPVerification.query.filter(
            OTPVerification.created_at < cutoff
        ).delete(synchronize_session=False)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"OTP cleanup failed: {e}")


def _send_otp_sms(canonical: str, otp: str):
    """
    Send OTP via Africa's Talking.
    Returns (ok: bool, error_message or None).
    No local fallback: if SMS fails, we fail the request.
    """
    try:
        message = (
            f"Your Kiya verification code is {otp}. "
            f"Valid for {OTP_TTL_SECONDS // 60} minutes. Do not share it."
        )
        response = sms.send(message, [canonical], sender_id=AT_SENDER_ID)
        # Africa's Talking returns a dict; check for per-recipient failures.
        recipients = (response or {}).get("SMSMessageData", {}).get("Recipients", [])
        if recipients and recipients[0].get("status") != "Success":
            err = recipients[0].get("status", "Unknown SMS error")
            print(f"SMS delivery failed for {canonical}: {err}")
            return False, f"SMS delivery failed: {err}"
        print(f"SMS sent to {canonical}: {response}")
        return True, None
    except Exception as e:
        print(f"SMS send error for {canonical}: {e}")
        return False, "Failed to send SMS. Try again shortly."


def _store_otp(canonical: str, otp: str, user_id: int):
    OTPVerification.query.filter_by(
        phone_number=canonical, consumed=False
    ).update({"consumed": True})
    db.session.commit()

    rec = OTPVerification(
        phone_number=canonical,
        otp_hash=_hash_otp(otp),
        expires_at=utcnow() + timedelta(seconds=OTP_TTL_SECONDS),
        user_id=user_id,
    )
    db.session.add(rec)
    db.session.commit()
    return rec


def _issue_jwt(user: UsersDetails) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "phone": user.users_phone_number,
        "is_landlord": user.is_landlord,
        "is_tenant": user.is_tenant,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(days=30)).timestamp()),
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def _current_user_from_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except Exception:
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    return UsersDetails.query.get(int(user_id))


def _verify_google_token(token: str):
    """Return the decoded Google ID token payload, or raise ValueError."""
    if not GOOGLE_LIB_OK:
        raise ValueError("Server missing google-auth library")
    if not GOOGLE_CLIENT_ID:
        raise ValueError("Server missing GOOGLE_CLIENT_ID")
    return google_id_token.verify_oauth2_token(
        token, google_requests.Request(), GOOGLE_CLIENT_ID
    )


# ===========================================================================
# File helpers
# ===========================================================================
def allowed_file(filename: str, allowed: set) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed


def save_profile_photo(file_storage) -> str:
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename, ALLOWED_IMAGE):
        raise ValueError("Unsupported image type. Allowed: png, jpg, jpeg, webp")
    ext = file_storage.filename.rsplit(".", 1)[1].lower()
    unique_name = secure_filename(f"{uuid.uuid4().hex}.{ext}")
    filepath = os.path.join(IMAGE_UPLOAD_FOLDER, unique_name)
    file_storage.save(filepath)
    return f"uploads/images/{unique_name}"


def resolve_profile_photo(field_names):
    file = None
    for name in field_names:
        f = request.files.get(name)
        if f and f.filename:
            file = f
            break
    if file:
        return save_profile_photo(file), True

    body = request.get_json(silent=True) or request.form
    for name in field_names:
        val = body.get(name)
        if val:
            return val, True
    return None, False


def _get_body():
    return request.get_json(silent=True) or request.form


# ===========================================================================
# Health routes
# ===========================================================================
@app.route("/")
def home():
    return jsonify({"status": "ok", "message": "Kiya backend running"})


@app.route("/health")
def health():
    return jsonify({
        "healthy": True,
        "google_configured": bool(GOOGLE_CLIENT_ID),
        "sms_configured": sms is not None,
    })


# ===========================================================================
# Didit KYC endpoints
# ===========================================================================
@app.route("/create-session", methods=["POST"])
def create_session():
    body = request.get_json(silent=True) or {}
    user_id = body.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    resp = requests.post(
        f"{DIDIT_API_BASE}/v3/session/",
        headers={"x-api-key": DIDIT_API_KEY},
        json={
            "workflow_id": DIDIT_WORKFLOW_ID,
            "vendor_data": user_id,
            "callback": "https://k1-6.onrender.com/verification/callback",
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
    return jsonify({
        "session_token": data.get("session_token"),
        "session_id": data.get("session_id"),
        "url": data.get("url"),
    })


def _canonical_json(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def verify_signature_v2(parsed_body: dict, signature_header: str) -> bool:
    if not DIDIT_WEBHOOK_SECRET or not signature_header:
        return False
    expected = hmac.new(
        DIDIT_WEBHOOK_SECRET.encode("utf-8"),
        _canonical_json(parsed_body).encode("utf-8"),
        hashlib.sha256,
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
    webhook_type = event.get("webhook_type")
    session_id = event.get("session_id")
    vendor_data = event.get("vendor_data")
    status = event.get("status")
    decision = event.get("decision")
    print(f"Processing webhook: type={webhook_type} session={session_id} status={status}")

    if webhook_type in ("status.updated", "data.updated"):
        if not vendor_data:
            print("No vendor_data on session event -- skipping")
            return
        print(f"  user={vendor_data} status={status} decision={decision}")
    else:
        print(f"  Unhandled webhook_type: {webhook_type}")


@app.route("/webhooks/didit", methods=["POST"])
def didit_webhook():
    raw_body = request.get_data()
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
        print(f"Webhook signature FAILED: {raw_body[:500]!r}")
        return jsonify({"error": "Invalid webhook signature"}), 401

    event_id = parsed.get("event_id") or (
        f"{parsed.get('session_id')}:{parsed.get('status')}:{parsed.get('webhook_type')}"
    )
    if event_id in processed_event_ids:
        return jsonify({"received": True, "duplicate": True})
    processed_event_ids.add(event_id)

    threading.Thread(target=process_webhook_event, args=(parsed,), daemon=True).start()
    return jsonify({"received": True})


@app.route("/users/<user_id>/verification-status")
def get_verification_status(user_id):
    return jsonify({"user_id": user_id, "verification_status": "unverified"})


# ===========================================================================
# 1. CREATE USER (pending) + SEND OTP
# ===========================================================================
@app.route("/create_user", methods=["POST"])
def create_user():
    body = _get_body()

    users_fn = body.get("users_fn")
    users_ln = body.get("user_ln") or body.get("users_ln")
    country_iso2 = (body.get("country_iso2") or DEFAULT_REGION).upper()
    phone_national = body.get("phone_national")
    raw_phone = phone_national or body.get("users_phone_number")

    if not users_fn or not users_ln or not raw_phone:
        return jsonify({
            "message": "users_fn, user_ln and users_phone_number "
                       "(or country_iso2 + phone_national) are required"
        }), 400

    try:
        canonical = normalize_phone(raw_phone, default_region=country_iso2)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    cc, nn = split_phone(canonical)

    existing_verified = UsersDetails.query.filter_by(
        users_phone_number=canonical, is_verified=True
    ).first()
    if existing_verified:
        return jsonify({
            "message": "An account with this phone number already exists"
        }), 409

    if Landlords.query.filter_by(landloards_phone_number=canonical).first():
        return jsonify({
            "message": "This phone number is already registered as a landlord."
        }), 409

    UsersDetails.query.filter_by(
        users_phone_number=canonical, is_verified=False
    ).delete(synchronize_session=False)
    db.session.commit()

    try:
        profile_photou, had_photo = resolve_profile_photo(
            ["profile_photou", "profile_photo"]
        )
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    avatar_color = None if had_photo else random_avatar_color()

    new_user = UsersDetails(
        user_fn=users_fn,
        user_ln=users_ln,
        users_phone_number=canonical,
        country_code=cc,
        national_number=nn,
        profile_photou=profile_photou,
        avatar_color=avatar_color,
        is_tenant=True,
        is_landlord=False,
        is_verified=False,
    )
    db.session.add(new_user)
    db.session.commit()

    otp = _generate_otp()
    _store_otp(canonical, otp, user_id=new_user.id)

    ok, err = _send_otp_sms(canonical, otp)
    if not ok:
        db.session.delete(new_user)
        db.session.commit()
        return jsonify({"message": err or "Failed to send SMS"}), 502

    masked = canonical[:6] + "****" + canonical[-2:]
    return jsonify({
        "message": f"Account created (pending). Verification code sent to {masked}.",
        "user_id": new_user.id,
        "phone_display": new_user.pretty_phone(),
        "expires_in": OTP_TTL_SECONDS,
        "resend_cooldown": OTP_RESEND_COOLDOWN,
        "is_verified": False,
    }), 201


# ===========================================================================
# 2. VERIFY OTP
# ===========================================================================
@app.route("/verify_otp", methods=["POST"])
def verify_otp():
    body = _get_body()
    country_iso2 = (body.get("country_iso2") or DEFAULT_REGION).upper()
    raw_phone = body.get("phone_national") or body.get("users_phone_number")
    otp_entered = (body.get("otp_code") or "").strip()

    if not raw_phone or not otp_entered:
        return jsonify({"message": "Phone number and OTP are required"}), 400

    try:
        canonical = normalize_phone(raw_phone, default_region=country_iso2)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    pending_user = UsersDetails.query.filter_by(
        users_phone_number=canonical, is_verified=False
    ).first()

    def _wipe_pending(user, reason_msg, status):
        if user:
            OTPVerification.query.filter_by(
                phone_number=canonical
            ).delete(synchronize_session=False)
            db.session.delete(user)
            db.session.commit()
        return jsonify({"message": reason_msg}), status

    if not pending_user:
        verified = UsersDetails.query.filter_by(
            users_phone_number=canonical, is_verified=True
        ).first()
        if verified:
            return jsonify({
                "message": "This phone number is already verified",
                "user": verified.to_json(),
            }), 200
        return jsonify({
            "message": "No pending account. Please call /create_user first."
        }), 404

    record = (
        OTPVerification.query
        .filter_by(phone_number=canonical, consumed=False)
        .order_by(OTPVerification.created_at.desc())
        .first()
    )

    if not record:
        return _wipe_pending(
            pending_user,
            "No active code. Pending account removed. Please register again.",
            400,
        )

    if record.expires_at <= utcnow():
        return _wipe_pending(
            pending_user,
            "Code expired. Pending account removed. Please register again.",
            400,
        )

    if record.attempts >= OTP_MAX_ATTEMPTS:
        return _wipe_pending(
            pending_user,
            "Too many attempts. Pending account removed. Please register again.",
            429,
        )

    if not hmac.compare_digest(record.otp_hash, _hash_otp(otp_entered)):
        record.attempts += 1
        db.session.commit()
        remaining = OTP_MAX_ATTEMPTS - record.attempts
        if remaining <= 0:
            return _wipe_pending(
                pending_user,
                "Too many wrong attempts. Pending account removed. Please register again.",
                429,
            )
        return jsonify({
            "message": f"Invalid code. {remaining} attempt(s) remaining."
        }), 401

    record.consumed = True
    record.verified_at = utcnow()
    pending_user.is_verified = True
    pending_user.verified_at = utcnow()
    db.session.commit()

    return jsonify({
        "message": "Phone verified successfully. Account activated.",
        "user": pending_user.to_json(),
    }), 200


# ===========================================================================
# 3. RESEND OTP
# ===========================================================================
@app.route("/resend_otp", methods=["POST"])
def resend_otp():
    body = _get_body()
    country_iso2 = (body.get("country_iso2") or DEFAULT_REGION).upper()
    raw_phone = body.get("phone_national") or body.get("users_phone_number")

    if not raw_phone:
        return jsonify({"message": "Phone number is required"}), 400

    try:
        canonical = normalize_phone(raw_phone, default_region=country_iso2)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    user = UsersDetails.query.filter_by(
        users_phone_number=canonical, is_verified=False
    ).first()
    if not user:
        return jsonify({
            "message": "No pending account. Please call /create_user first."
        }), 404

    recent = (
        OTPVerification.query
        .filter_by(phone_number=canonical, consumed=False)
        .order_by(OTPVerification.created_at.desc())
        .first()
    )
    if recent and (utcnow() - recent.created_at).total_seconds() < OTP_RESEND_COOLDOWN:
        wait = OTP_RESEND_COOLDOWN - int(
            (utcnow() - recent.created_at).total_seconds()
        )
        return jsonify({
            "message": f"Please wait {wait}s before requesting another code"
        }), 429

    otp = _generate_otp()
    _store_otp(canonical, otp, user_id=user.id)

    ok, err = _send_otp_sms(canonical, otp)
    if not ok:
        return jsonify({"message": err or "Failed to send SMS"}), 502

    masked = canonical[:6] + "****" + canonical[-2:]
    return jsonify({
        "message": f"New verification code sent to {masked}",
        "expires_in": OTP_TTL_SECONDS,
    }), 200


# ===========================================================================
# 4. BECOME LANDLORD
# ===========================================================================
@app.route("/become_landlord", methods=["POST"])
def become_landlord():
    body = _get_body()
    country_iso2 = (body.get("country_iso2") or DEFAULT_REGION).upper()
    raw_phone = body.get("phone_national") or body.get("users_phone_number")

    if not raw_phone:
        return jsonify({"message": "users_phone_number or phone_national is required"}), 400

    try:
        canonical = normalize_phone(raw_phone, default_region=country_iso2)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    user = UsersDetails.query.filter_by(
        users_phone_number=canonical, is_verified=True
    ).first()
    if not user:
        return jsonify({
            "message": "No verified user with this phone number."
        }), 404

    if user.landlord_profile:
        return jsonify({
            "message": "This user is already a landlord",
            "landlord": user.landlord_profile.to_json(),
        }), 409

    try:
        profile_photol, had_photo = resolve_profile_photo(
            ["profile_photol", "profile_photo"]
        )
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    cc, nn = split_phone(canonical)

    landlord = Landlords(
        user_id=user.id,
        user_fn=body.get("user_fn") or user.user_fn,
        user_ln=body.get("user_ln") or user.user_ln,
        landloards_phone_number=canonical,
        country_code=cc,
        national_number=nn,
        profile_photol=profile_photol or user.profile_photou,
        avatar_color=(
            None if (had_photo or user.profile_photou)
            else (user.avatar_color or random_avatar_color())
        ),
        is_verified=True,
        verified_at=utcnow(),
    )
    user.is_landlord = True

    try:
        db.session.add(landlord)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "an error occurred", "detail": str(e)}), 500

    return jsonify({
        "message": "user is now a landlord",
        "user": user.to_json(),
        "landlord": landlord.to_json(),
    }), 201


# ===========================================================================
# 5. STANDALONE LANDLORD
# ===========================================================================
@app.route("/create_landlord", methods=["POST"])
def create_landlord():
    body = _get_body()
    users_fn = body.get("users_fn")
    users_ln = body.get("user_ln") or body.get("users_ln")
    country_iso2 = (body.get("country_iso2") or DEFAULT_REGION).upper()
    raw_phone = (
        body.get("phone_national")
        or body.get("users_phone_number")
        or body.get("landloards_phone_number")
    )

    if not users_fn or not users_ln or not raw_phone:
        return jsonify({
            "message": "users_fn, user_ln and users_phone_number are required"
        }), 400

    try:
        canonical = normalize_phone(raw_phone, default_region=country_iso2)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    cc, nn = split_phone(canonical)

    if UsersDetails.query.filter_by(
        users_phone_number=canonical, is_verified=True
    ).first():
        return jsonify({
            "message": "This phone already has a user account. Use /become_landlord instead."
        }), 409
    if Landlords.query.filter_by(landloards_phone_number=canonical).first():
        return jsonify({
            "message": "A landlord with this phone number already exists"
        }), 409

    try:
        profile_photol, had_photo = resolve_profile_photo(
            ["profile_photol", "profile_photo"]
        )
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    avatar_color = None if had_photo else random_avatar_color()

    landlord = Landlords(
        user_id=None,
        user_fn=users_fn,
        user_ln=users_ln,
        landloards_phone_number=canonical,
        country_code=cc,
        national_number=nn,
        profile_photol=profile_photol,
        avatar_color=avatar_color,
        is_verified=False,
    )

    try:
        db.session.add(landlord)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "an error occurred", "detail": str(e)}), 500

    return jsonify({
        "message": "successfully created a landlord account (verify OTP to activate)",
        "landlord": landlord.to_json(),
    }), 201


# ===========================================================================
# 6. Serve uploaded avatars
# ===========================================================================
@app.route("/uploads/images/<path:filename>")
def serve_uploaded_image(filename):
    return send_from_directory(IMAGE_UPLOAD_FOLDER, filename)


# ===========================================================================
# 7. LOGIN — Step 1: request OTP for an existing verified user
# ===========================================================================
@app.route("/login_user", methods=["POST"])
def login_user():
    body = _get_body()
    country_iso2 = (body.get("country_iso2") or DEFAULT_REGION).upper()
    raw_phone = body.get("phone_national") or body.get("users_phone_number")

    if not raw_phone:
        return jsonify({"message": "Phone number is required"}), 400

    try:
        canonical = normalize_phone(raw_phone, default_region=country_iso2)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    user = UsersDetails.query.filter_by(
        users_phone_number=canonical, is_verified=True
    ).first()

    if not user:
        landlord = Landlords.query.filter_by(
            landloards_phone_number=canonical
        ).first()
        if landlord:
            return jsonify({
                "message": "This phone is registered as a landlord. "
                           "Use the landlord login flow.",
                "action": "landlord_login",
            }), 409

        return jsonify({
            "message": "No account found with this phone number. Please sign up.",
            "action": "signup",
        }), 404

    recent = (
        OTPVerification.query
        .filter_by(phone_number=canonical, consumed=False)
        .order_by(OTPVerification.created_at.desc())
        .first()
    )
    if recent and (utcnow() - recent.created_at).total_seconds() < OTP_RESEND_COOLDOWN:
        wait = OTP_RESEND_COOLDOWN - int(
            (utcnow() - recent.created_at).total_seconds()
        )
        return jsonify({
            "message": f"Please wait {wait}s before requesting another code"
        }), 429

    otp = _generate_otp()
    _store_otp(canonical, otp, user_id=user.id)

    ok, err = _send_otp_sms(canonical, otp)
    if not ok:
        return jsonify({"message": err or "Failed to send SMS"}), 502

    masked = canonical[:6] + "****" + canonical[-2:]
    return jsonify({
        "message": f"Login code sent to {masked}",
        "user_id": user.id,
        "phone_display": user.pretty_phone(),
        "expires_in": OTP_TTL_SECONDS,
        "resend_cooldown": OTP_RESEND_COOLDOWN,
        "has_google": bool(user.google_sub),
    }), 200


# ===========================================================================
# 8. LOGIN — Step 2: verify OTP, return JWT
# ===========================================================================
@app.route("/verify_login_otp", methods=["POST"])
def verify_login_otp():
    body = _get_body()
    country_iso2 = (body.get("country_iso2") or DEFAULT_REGION).upper()
    raw_phone = body.get("phone_national") or body.get("users_phone_number")
    otp_entered = (body.get("otp_code") or "").strip()

    if not raw_phone or not otp_entered:
        return jsonify({"message": "Phone number and OTP are required"}), 400

    try:
        canonical = normalize_phone(raw_phone, default_region=country_iso2)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    user = UsersDetails.query.filter_by(
        users_phone_number=canonical, is_verified=True
    ).first()
    if not user:
        return jsonify({
            "message": "No verified account with this phone number."
        }), 404

    record = (
        OTPVerification.query
        .filter_by(phone_number=canonical, consumed=False)
        .order_by(OTPVerification.created_at.desc())
        .first()
    )

    if not record:
        return jsonify({
            "message": "No active code. Please request a new one."
        }), 400

    if record.expires_at <= utcnow():
        record.consumed = True
        db.session.commit()
        return jsonify({
            "message": "Code expired. Please request a new one."
        }), 400

    if record.attempts >= OTP_MAX_ATTEMPTS:
        record.consumed = True
        db.session.commit()
        return jsonify({
            "message": "Too many attempts. Please request a new code."
        }), 429

    if not hmac.compare_digest(record.otp_hash, _hash_otp(otp_entered)):
        record.attempts += 1
        db.session.commit()
        remaining = OTP_MAX_ATTEMPTS - record.attempts
        return jsonify({
            "message": f"Invalid code. {remaining} attempt(s) remaining."
        }), 401

    record.consumed = True
    record.verified_at = utcnow()
    db.session.commit()

    access_token = _issue_jwt(user)

    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in_days": 30,
        "user": user.to_json(),
    }), 200


# ===========================================================================
# 9. GOOGLE — Step 1: verify ID token; login or ask for phone
# ===========================================================================
@app.route("/google_signin", methods=["POST"])
def google_signin():
    body = _get_body()
    token = body.get("id_token") or body.get("google_id_token")
    if not token:
        return jsonify({"message": "id_token is required"}), 400

    try:
        info = _verify_google_token(token)
    except Exception as e:
        return jsonify({"message": f"Invalid Google token: {e}"}), 401

    google_sub = info.get("sub")
    if not google_sub:
        return jsonify({"message": "Google token missing 'sub'"}), 400

    email = info.get("email")
    name = info.get("name", "")
    given = info.get("given_name") or (name.split(" ")[0] if name else "")
    family = info.get("family_name") or (
        " ".join(name.split(" ")[1:]) if " " in name else ""
    )
    picture = info.get("picture")

    existing = UsersDetails.query.filter_by(
        google_sub=google_sub, is_verified=True
    ).first()

    if existing:
        access_token = _issue_jwt(existing)
        return jsonify({
            "message": "Login successful",
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in_days": 30,
            "user": existing.to_json(),
            "next_step": None,
        }), 200

    return jsonify({
        "message": "Google verified. Please provide your phone number.",
        "google": {
            "sub": google_sub,
            "email": email,
            "name": name,
            "given_name": given,
            "family_name": family,
            "picture": picture,
        },
        "next_step": "provide_phone",
    }), 200


# ===========================================================================
# 10. GOOGLE — Step 2: create PENDING user with google_sub + send OTP
# ===========================================================================
@app.route("/google_create_user", methods=["POST"])
def google_create_user():
    body = _get_body()
    token = body.get("google_id_token") or body.get("id_token")
    country_iso2 = (body.get("country_iso2") or DEFAULT_REGION).upper()
    raw_phone = body.get("phone_national") or body.get("users_phone_number")

    if not token or not raw_phone:
        return jsonify({"message": "google_id_token and phone are required"}), 400

    try:
        info = _verify_google_token(token)
    except Exception as e:
        return jsonify({"message": f"Invalid Google token: {e}"}), 401

    google_sub = info.get("sub")
    if not google_sub:
        return jsonify({"message": "Google token missing 'sub'"}), 400

    email = info.get("email")
    name = info.get("name", "")
    users_fn = body.get("users_fn") or info.get("given_name") or (
        name.split(" ")[0] if name else ""
    )
    users_ln = body.get("user_ln") or body.get("users_ln") or info.get("family_name") or (
        " ".join(name.split(" ")[1:]) if " " in name else ""
    )

    if not users_fn or not users_ln:
        return jsonify({
            "message": "Could not determine name. Please provide users_fn and user_ln."
        }), 400

    try:
        canonical = normalize_phone(raw_phone, default_region=country_iso2)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    cc, nn = split_phone(canonical)

    if UsersDetails.query.filter_by(
        users_phone_number=canonical, is_verified=True
    ).first():
        return jsonify({"message": "An account with this phone already exists"}), 409

    if Landlords.query.filter_by(landloards_phone_number=canonical).first():
        return jsonify({"message": "This phone is registered as a landlord"}), 409

    linked = UsersDetails.query.filter_by(
        google_sub=google_sub, is_verified=True
    ).first()
    if linked:
        return jsonify({
            "message": "This Google account is already linked to another user."
        }), 409

    UsersDetails.query.filter(
        (UsersDetails.users_phone_number == canonical) & (UsersDetails.is_verified == False)
    ).delete(synchronize_session=False)
    UsersDetails.query.filter(
        (UsersDetails.google_sub == google_sub) & (UsersDetails.is_verified == False)
    ).delete(synchronize_session=False)
    db.session.commit()

    try:
        profile_photou, had_photo = resolve_profile_photo(
            ["profile_photou", "profile_photo"]
        )
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    if not profile_photou and info.get("picture"):
        profile_photou = info.get("picture")
        had_photo = True

    avatar_color = None if had_photo else random_avatar_color()

    new_user = UsersDetails(
        user_fn=users_fn,
        user_ln=users_ln,
        users_phone_number=canonical,
        country_code=cc,
        national_number=nn,
        profile_photou=profile_photou,
        avatar_color=avatar_color,
        is_tenant=True,
        is_landlord=False,
        is_verified=False,
        google_sub=google_sub,
        email=email,
    )
    db.session.add(new_user)
    db.session.commit()

    otp = _generate_otp()
    _store_otp(canonical, otp, user_id=new_user.id)

    ok, err = _send_otp_sms(canonical, otp)
    if not ok:
        db.session.delete(new_user)
        db.session.commit()
        return jsonify({"message": err or "Failed to send SMS"}), 502

    masked = canonical[:6] + "****" + canonical[-2:]
    return jsonify({
        "message": f"Pending account created. Verify code sent to {masked}.",
        "user_id": new_user.id,
        "phone_display": new_user.pretty_phone(),
        "expires_in": OTP_TTL_SECONDS,
        "resend_cooldown": OTP_RESEND_COOLDOWN,
        "is_verified": False,
    }), 201


# ===========================================================================
# 11. Current user (protected)
# ===========================================================================
@app.route("/me", methods=["GET"])
def me():
    user = _current_user_from_token()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401
    return jsonify({"user": user.to_json()}), 200


# ===========================================================================
# Run (production uses gunicorn; this block is for local "just run it" only)
# ===========================================================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=10000, debug=False)