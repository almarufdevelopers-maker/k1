"""
Kiya backend -- Flask + Didit KYC + SMS OTP + Google Sign-In + Listings.

Flow:
  * Users sign up with first + last name only (phone optional).
  * Login by first + last name returns a JWT.
  * Landlords create listings. Everyone else can browse them.

Endpoints:
  1.  POST /create_user           -> creates user (name only, phone optional)
  2.  POST /login_user            -> login by first + last name
  3.  POST /update_phone          -> add phone later (optional)
  4.  POST /request_verification  -> send OTP to verify a phone
  5.  POST /verify_otp            -> verify OTP -> is_verified = True
  6.  POST /resend_otp            -> resend OTP
  7.  POST /create_landlord       -> standalone landlord (name only)
  8.  POST /become_landlord       -> upgrade a user to landlord
  9.  POST /verify_login_otp      -> login via OTP (kept for later)
  10. POST /google_signin         -> verify Google ID token
  11. POST /google_create_user    -> create user via Google
  12. GET  /me                    -> current user
  13. GET  /profile               -> view own profile
  14. PUT  /profile               -> edit ONLY the profile photo
  15. GET  /users/<id>            -> public profile
  16. GET  /get_users             -> list users
  17. GET  /get_landlords         -> list landlords

Listings (landlord-only write, any-auth read):
  18. POST   /listings                    -> create (landlord only)
  19. GET    /listings                    -> browse (any logged-in user)
  20. GET    /listings/mine               -> list my listings (landlord only)
  21. GET    /listings/<id>               -> view one (any logged-in user)
  22. PUT    /listings/<id>               -> update (owner only)
  23. DELETE /listings/<id>               -> delete (owner only)
  24. POST   /listings/<id>/publish       -> toggle published (owner only)

Other:
  GET  /                                   -> health
  GET  /health                             -> health
  POST /create-session                     -> Didit KYC session
  POST /webhooks/didit                     -> Didit webhook receiver
  GET  /uploads/images/<filename>          -> serve avatars
  GET  /uploads/listings/<filename>        -> serve listing photos
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

from models import UsersDetails, Landlords, OTPVerification, Listings

# --- Load .env ---------------------------------------------------------------
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("WARNING: python-dotenv not installed; .env will not be loaded")

# --- Google sign-in ----------------------------------------------------------
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
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ===========================================================================
# Africa's Talking (kept for later)
# ===========================================================================
try:
    import africastalking
    AT_USERNAME = os.environ.get("AT_USERNAME", "").strip()
    AT_API_KEY = os.environ.get("AT_API_KEY", "").strip()
    AT_SENDER_ID = os.environ.get("AT_SENDER_ID", "").strip() or None

    if AT_USERNAME and AT_API_KEY:
        africastalking.initialize(AT_USERNAME, AT_API_KEY)
        sms = africastalking.SMS
        print(f"Africa's Talking initialized (username={AT_USERNAME}, sender_id={AT_SENDER_ID})")
    else:
        sms = None
        print("WARNING: Africa's Talking not configured -- OTP SMS disabled.")
except ImportError:
    sms = None
    print("WARNING: africastalking SDK missing -- OTP SMS disabled.")

# --- Backblaze B2 ------------------------------------------------------------
B2_KEY_ID = os.getenv("B2_KEY_ID")
B2_APP_KEY = os.getenv("B2_APP_KEY")
B2_BUCKET_NAME = os.getenv("B2_BUCKET_NAME")

# --- Didit -------------------------------------------------------------------
DIDIT_API_KEY = os.environ.get("DIDIT_API_KEY", "")
DIDIT_WORKFLOW_ID = os.environ.get("DIDIT_WORKFLOW_ID", "")
DIDIT_WEBHOOK_SECRET = os.environ.get("DIDIT_WEBHOOK_SECRET", "")
DIDIT_API_BASE = "https://verification.didit.me"
WEBHOOK_MAX_SKEW_SECONDS = 300

# --- Google ------------------------------------------------------------------
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "").strip()

# --- Phone config ------------------------------------------------------------
DEFAULT_REGION = "KE"
ALLOWED_REGIONS = {"KE", "UG", "TZ", "ET", "SO"}

# --- OTP config --------------------------------------------------------------
OTP_TTL_SECONDS = 300
OTP_MAX_ATTEMPTS = 5
OTP_LENGTH = 6
OTP_RESEND_COOLDOWN = 60

processed_event_ids: set[str] = set()

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


def _send_otp_sms(canonical: str, otp: str):
    if sms is None:
        return False, "SMS service not configured"
    try:
        message = (
            f"Your Kiya verification code is {otp}. "
            f"Valid for {OTP_TTL_SECONDS // 60} minutes. Do not share it."
        )
        kwargs = {"sender_id": AT_SENDER_ID} if AT_SENDER_ID else {}
        response = sms.send(message, [canonical], **kwargs)
        recipients = (response or {}).get("SMSMessageData", {}).get("Recipients", [])
        if recipients and recipients[0].get("status") != "Success":
            return False, recipients[0].get("status", "Unknown SMS error")
        print(f"SMS sent to {canonical}: {response}")
        return True, None
    except Exception as e:
        print(f"SMS send error for {canonical}: {e}")
        return False, "Failed to send SMS."


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
        "is_verified": user.is_verified,
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


def _current_landlord_from_token():
    """
    Return (user, landlord).
    - user: UsersDetails or None if not authenticated
    - landlord: Landlords or None if user has no landlord profile
    """
    user = _current_user_from_token()
    if not user:
        return None, None
    return user, user.landlord_profile


def _verify_google_token(token: str):
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
# Listing photo helpers
# ===========================================================================
LISTING_PHOTO_DIR = os.path.join(UPLOAD_FOLDER, "listings")
os.makedirs(LISTING_PHOTO_DIR, exist_ok=True)

MIN_EXTRA_PHOTOS = 3
MAX_EXTRA_PHOTOS = 20


def _save_listing_photo(file_storage) -> str:
    if not file_storage or not file_storage.filename:
        return None
    if not allowed_file(file_storage.filename, ALLOWED_IMAGE):
        raise ValueError("Unsupported image type. Allowed: png, jpg, jpeg, webp")
    ext = file_storage.filename.rsplit(".", 1)[1].lower()
    unique_name = secure_filename(f"{uuid.uuid4().hex}.{ext}")
    filepath = os.path.join(LISTING_PHOTO_DIR, unique_name)
    file_storage.save(filepath)
    return f"uploads/listings/{unique_name}"


def _collect_listing_photos(field_names, min_count=MIN_EXTRA_PHOTOS):
    paths = []

    # Uploaded files
    for name in field_names:
        files = request.files.getlist(name)
        for f in files:
            if f and f.filename:
                try:
                    paths.append(_save_listing_photo(f))
                except ValueError as e:
                    return [], str(e)

    # JSON array of URLs
    if not paths:
        body = request.get_json(silent=True) or {}
        for name in field_names:
            urls = body.get(name)
            if isinstance(urls, list):
                paths.extend([u for u in urls if isinstance(u, str) and u.strip()])
                break

    if len(paths) < min_count:
        return [], f"At least {min_count} photos are required"

    if len(paths) > MAX_EXTRA_PHOTOS:
        return [], f"Too many photos (max {MAX_EXTRA_PHOTOS})"

    return paths, None


def _collect_single_photo(field_name):
    f = request.files.get(field_name)
    if f and f.filename:
        try:
            return _save_listing_photo(f), None
        except ValueError as e:
            return None, str(e)

    body = request.get_json(silent=True) or request.form
    val = body.get(field_name)
    if val and isinstance(val, str) and val.strip():
        return val.strip(), None

    return None, None


# ===========================================================================
# Health
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
# Didit KYC
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
    print(f"Webhook: {event.get('webhook_type')} session={event.get('session_id')} "
          f"status={event.get('status')}")


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
# 1. CREATE USER
# ===========================================================================
@app.route("/create_user", methods=["POST"])
def create_user():
    body = _get_body()

    users_fn = (body.get("users_fn") or "").strip()
    users_ln = (body.get("user_ln") or body.get("users_ln") or "").strip()

    if not users_fn or not users_ln:
        return jsonify({"message": "users_fn and user_ln are required"}), 400

    if len(users_fn) > 120 or len(users_ln) > 120:
        return jsonify({"message": "Name too long"}), 400

    existing = UsersDetails.query.filter(
        db.func.lower(UsersDetails.user_fn) == users_fn.lower(),
        db.func.lower(UsersDetails.user_ln) == users_ln.lower(),
    ).first()
    if existing:
        return jsonify({
            "message": "An account with this name already exists. Please log in."
        }), 409

    country_iso2 = (body.get("country_iso2") or DEFAULT_REGION).upper()
    raw_phone = body.get("phone_national") or body.get("users_phone_number")
    canonical = None
    cc = nn = None

    if raw_phone:
        try:
            canonical = normalize_phone(raw_phone, default_region=country_iso2)
            cc, nn = split_phone(canonical)
        except ValueError as e:
            return jsonify({"message": str(e)}), 400

        if UsersDetails.query.filter_by(users_phone_number=canonical).first():
            return jsonify({"message": "This phone number is already registered"}), 409

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

    access_token = _issue_jwt(new_user)

    return jsonify({
        "message": "Account created",
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in_days": 30,
        "user": new_user.to_json(),
        "is_verified": False,
        "next_step": "add_phone_later",
    }), 201


# ===========================================================================
# 2. LOGIN
# ===========================================================================
@app.route("/login_user", methods=["POST"])
def login_user():
    body = _get_body()

    users_fn = (body.get("users_fn") or "").strip()
    users_ln = (body.get("user_ln") or body.get("users_ln") or "").strip()

    if not users_fn or not users_ln:
        return jsonify({"message": "users_fn and user_ln are required"}), 400

    user = UsersDetails.query.filter(
        db.func.lower(UsersDetails.user_fn) == users_fn.lower(),
        db.func.lower(UsersDetails.user_ln) == users_ln.lower(),
    ).first()

    if not user:
        return jsonify({
            "message": "No account with this name. Please sign up.",
            "action": "signup",
        }), 404

    access_token = _issue_jwt(user)

    return jsonify({
        "message": "Login successful",
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in_days": 30,
        "user": user.to_json(),
    }), 200


# ===========================================================================
# 3. UPDATE PHONE
# ===========================================================================
@app.route("/update_phone", methods=["POST"])
def update_phone():
    user = _current_user_from_token()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    body = _get_body()
    country_iso2 = (body.get("country_iso2") or DEFAULT_REGION).upper()
    raw_phone = body.get("phone_national") or body.get("users_phone_number")

    if not raw_phone:
        return jsonify({"message": "Phone number is required"}), 400

    try:
        canonical = normalize_phone(raw_phone, default_region=country_iso2)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    cc, nn = split_phone(canonical)

    other = UsersDetails.query.filter(
        UsersDetails.users_phone_number == canonical,
        UsersDetails.id != user.id,
    ).first()
    if other:
        return jsonify({"message": "This phone number is already registered"}), 409

    if Landlords.query.filter_by(landloards_phone_number=canonical).first():
        return jsonify({"message": "This phone is registered as a landlord"}), 409

    user.users_phone_number = canonical
    user.country_code = cc
    user.national_number = nn
    user.is_verified = False
    user.verified_at = None
    db.session.commit()

    return jsonify({
        "message": "Phone updated. Please verify it.",
        "user": user.to_json(),
        "next_step": "request_verification",
    }), 200


# ===========================================================================
# 4. VERIFY LOGIN OTP
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

    user = UsersDetails.query.filter_by(users_phone_number=canonical).first()
    if not user:
        return jsonify({"message": "No account with this phone number."}), 404

    record = (
        OTPVerification.query
        .filter_by(phone_number=canonical, consumed=False)
        .order_by(OTPVerification.created_at.desc())
        .first()
    )
    if not record:
        return jsonify({"message": "No active code."}), 400
    if record.expires_at <= utcnow():
        record.consumed = True
        db.session.commit()
        return jsonify({"message": "Code expired."}), 400
    if record.attempts >= OTP_MAX_ATTEMPTS:
        record.consumed = True
        db.session.commit()
        return jsonify({"message": "Too many attempts."}), 429
    if not hmac.compare_digest(record.otp_hash, _hash_otp(otp_entered)):
        record.attempts += 1
        db.session.commit()
        remaining = OTP_MAX_ATTEMPTS - record.attempts
        return jsonify({"message": f"Invalid code. {remaining} attempt(s) remaining."}), 401

    record.consumed = True
    record.verified_at = utcnow()
    if not user.is_verified:
        user.is_verified = True
        user.verified_at = utcnow()
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
# 5. REQUEST VERIFICATION
# ===========================================================================
@app.route("/request_verification", methods=["POST"])
def request_verification():
    body = _get_body()
    country_iso2 = (body.get("country_iso2") or DEFAULT_REGION).upper()
    raw_phone = body.get("phone_national") or body.get("users_phone_number")

    if not raw_phone:
        return jsonify({"message": "Phone number is required"}), 400

    try:
        canonical = normalize_phone(raw_phone, default_region=country_iso2)
    except ValueError as e:
        return jsonify({"message": str(e)}), 400

    user = UsersDetails.query.filter_by(users_phone_number=canonical).first()
    landlord = Landlords.query.filter_by(landloards_phone_number=canonical).first()

    if not user and not landlord:
        return jsonify({"message": "No account found with this phone number."}), 404

    account = user or landlord
    account_kind = "user" if user else "landlord"

    if account.is_verified:
        return jsonify({"message": "This account is already verified"}), 409

    recent = (
        OTPVerification.query
        .filter_by(phone_number=canonical, consumed=False)
        .order_by(OTPVerification.created_at.desc())
        .first()
    )
    if recent and (utcnow() - recent.created_at).total_seconds() < OTP_RESEND_COOLDOWN:
        wait = OTP_RESEND_COOLDOWN - int((utcnow() - recent.created_at).total_seconds())
        return jsonify({"message": f"Please wait {wait}s before requesting again"}), 429

    otp = _generate_otp()
    _store_otp(canonical, otp, user_id=user.id if user else None)

    ok, err = _send_otp_sms(canonical, otp)
    if not ok:
        return jsonify({"message": err or "Failed to send SMS"}), 502

    masked = canonical[:6] + "****" + canonical[-2:]
    return jsonify({
        "message": f"Verification code sent to {masked}",
        "account_type": account_kind,
        "expires_in": OTP_TTL_SECONDS,
    }), 200


# ===========================================================================
# 6. VERIFY OTP
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

    record = (
        OTPVerification.query
        .filter_by(phone_number=canonical, consumed=False)
        .order_by(OTPVerification.created_at.desc())
        .first()
    )
    if not record:
        return jsonify({"message": "No active code."}), 400
    if record.expires_at <= utcnow():
        record.consumed = True
        db.session.commit()
        return jsonify({"message": "Code expired."}), 400
    if record.attempts >= OTP_MAX_ATTEMPTS:
        record.consumed = True
        db.session.commit()
        return jsonify({"message": "Too many attempts."}), 429
    if not hmac.compare_digest(record.otp_hash, _hash_otp(otp_entered)):
        record.attempts += 1
        db.session.commit()
        return jsonify({"message": f"Invalid code. {OTP_MAX_ATTEMPTS - record.attempts} left."}), 401

    record.consumed = True
    record.verified_at = utcnow()

    user = UsersDetails.query.filter_by(users_phone_number=canonical).first()
    landlord = Landlords.query.filter_by(landloards_phone_number=canonical).first()

    if user and not user.is_verified:
        user.is_verified = True
        user.verified_at = utcnow()
    if landlord and not landlord.is_verified:
        landlord.is_verified = True
        landlord.verified_at = utcnow()
    db.session.commit()

    return jsonify({
        "message": "Phone verified successfully.",
        "user": user.to_json() if user else None,
        "landlord": landlord.to_json() if landlord else None,
    }), 200


# ===========================================================================
# 7. RESEND OTP
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

    user = UsersDetails.query.filter_by(users_phone_number=canonical).first()
    landlord = Landlords.query.filter_by(landloards_phone_number=canonical).first()
    if not user and not landlord:
        return jsonify({"message": "No account found."}), 404

    recent = (
        OTPVerification.query
        .filter_by(phone_number=canonical, consumed=False)
        .order_by(OTPVerification.created_at.desc())
        .first()
    )
    if recent and (utcnow() - recent.created_at).total_seconds() < OTP_RESEND_COOLDOWN:
        wait = OTP_RESEND_COOLDOWN - int((utcnow() - recent.created_at).total_seconds())
        return jsonify({"message": f"Please wait {wait}s"}), 429

    otp = _generate_otp()
    _store_otp(canonical, otp, user_id=user.id if user else None)

    ok, err = _send_otp_sms(canonical, otp)
    if not ok:
        return jsonify({"message": err or "Failed to send SMS"}), 502

    masked = canonical[:6] + "****" + canonical[-2:]
    return jsonify({
        "message": f"New code sent to {masked}",
        "expires_in": OTP_TTL_SECONDS,
    }), 200


# ===========================================================================
# 8. CREATE LANDLORD
# ===========================================================================
@app.route("/create_landlord", methods=["POST"])
def create_landlord():
    body = _get_body()

    users_fn = (body.get("users_fn") or "").strip()
    users_ln = (body.get("user_ln") or body.get("users_ln") or "").strip()

    if not users_fn or not users_ln:
        return jsonify({"message": "users_fn and user_ln are required"}), 400

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
        landloards_phone_number=None,
        country_code=None,
        national_number=None,
        profile_photol=profile_photol,
        avatar_color=avatar_color,
        is_verified=False,
    )
    db.session.add(landlord)
    db.session.commit()

    return jsonify({
        "message": "Landlord account created",
        "landlord": landlord.to_json(),
        "is_verified": False,
    }), 201


# ===========================================================================
# 9. BECOME LANDLORD
# ===========================================================================
@app.route("/become_landlord", methods=["POST"])
def become_landlord():
    user = _current_user_from_token()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

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

    landlord = Landlords(
        user_id=user.id,
        user_fn=user.user_fn,
        user_ln=user.user_ln,
        landloards_phone_number=user.users_phone_number,
        country_code=user.country_code,
        national_number=user.national_number,
        profile_photol=profile_photol or user.profile_photou,
        avatar_color=(
            None if (had_photo or user.profile_photou)
            else (user.avatar_color or random_avatar_color())
        ),
        is_verified=user.is_verified,
        verified_at=user.verified_at,
    )
    user.is_landlord = True
    db.session.add(landlord)
    db.session.commit()

    return jsonify({
        "message": "user is now a landlord",
        "user": user.to_json(),
        "landlord": landlord.to_json(),
    }), 201


# ===========================================================================
# 10. Serve uploaded avatars
# ===========================================================================
@app.route("/uploads/images/<path:filename>")
def serve_uploaded_image(filename):
    return send_from_directory(IMAGE_UPLOAD_FOLDER, filename)


@app.route("/uploads/listings/<path:filename>")
def serve_listing_photo(filename):
    return send_from_directory(LISTING_PHOTO_DIR, filename)


# ===========================================================================
# 11. GOOGLE -- Step 1
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

    existing = UsersDetails.query.filter_by(google_sub=google_sub).first()
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

    name = info.get("name", "")
    given = info.get("given_name") or (name.split(" ")[0] if name else "")
    family = info.get("family_name") or (" ".join(name.split(" ")[1:]) if " " in name else "")

    return jsonify({
        "message": "Google verified. Please provide your phone number.",
        "google": {
            "sub": google_sub,
            "email": info.get("email"),
            "name": name,
            "given_name": given,
            "family_name": family,
            "picture": info.get("picture"),
        },
        "next_step": "provide_phone",
    }), 200


# ===========================================================================
# 12. GOOGLE -- Step 2
# ===========================================================================
@app.route("/google_create_user", methods=["POST"])
def google_create_user():
    body = _get_body()
    token = body.get("google_id_token") or body.get("id_token")
    if not token:
        return jsonify({"message": "google_id_token is required"}), 400

    try:
        info = _verify_google_token(token)
    except Exception as e:
        return jsonify({"message": f"Invalid Google token: {e}"}), 401

    google_sub = info.get("sub")
    if not google_sub:
        return jsonify({"message": "Google token missing 'sub'"}), 400

    if UsersDetails.query.filter_by(google_sub=google_sub).first():
        return jsonify({"message": "This Google account is already registered"}), 409

    name = info.get("name", "")
    users_fn = (body.get("users_fn") or info.get("given_name") or (name.split(" ")[0] if name else "")).strip()
    users_ln = (body.get("user_ln") or body.get("users_ln") or info.get("family_name") or (" ".join(name.split(" ")[1:]) if " " in name else "")).strip()

    if not users_fn or not users_ln:
        return jsonify({"message": "users_fn and user_ln are required"}), 400

    country_iso2 = (body.get("country_iso2") or DEFAULT_REGION).upper()
    raw_phone = body.get("phone_national") or body.get("users_phone_number")
    canonical = cc = nn = None

    if raw_phone:
        try:
            canonical = normalize_phone(raw_phone, default_region=country_iso2)
            cc, nn = split_phone(canonical)
        except ValueError as e:
            return jsonify({"message": str(e)}), 400

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
        email=info.get("email"),
    )
    db.session.add(new_user)
    db.session.commit()

    access_token = _issue_jwt(new_user)

    return jsonify({
        "message": "Account created via Google",
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in_days": 30,
        "user": new_user.to_json(),
    }), 201


# ===========================================================================
# 13. GET PROFILE
# ===========================================================================
@app.route("/profile", methods=["GET"])
def get_profile():
    user = _current_user_from_token()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401
    return jsonify({"user": user.to_json()}), 200


# ===========================================================================
# 14. UPDATE PROFILE -- photo only
# ===========================================================================
@app.route("/profile", methods=["PUT", "POST"])
def update_profile():
    user = _current_user_from_token()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401

    locked_fields = {
        "users_fn", "user_fn", "users_ln", "user_ln",
        "users_phone_number", "phone_national",
        "country_iso2", "country_code", "national_number",
        "email", "google_sub",
    }
    body = _get_body()
    attempted = [k for k in locked_fields if k in body]
    if attempted:
        return jsonify({
            "message": "Only the profile photo can be changed.",
            "locked_fields": attempted,
        }), 403

    remove_photo = str(body.get("remove_photo", "")).lower() in ("1", "true", "yes")
    if remove_photo:
        user.profile_photou = None
        if not user.avatar_color:
            user.avatar_color = random_avatar_color()
    else:
        try:
            new_photo, had_photo = resolve_profile_photo(
                ["profile_photou", "profile_photo"]
            )
        except ValueError as e:
            return jsonify({"message": str(e)}), 400

        if had_photo:
            user.profile_photou = new_photo
            user.avatar_color = None

    db.session.commit()
    return jsonify({
        "message": "Profile photo updated",
        "user": user.to_json(),
    }), 200


# ===========================================================================
# 15. PUBLIC PROFILE
# ===========================================================================
@app.route("/users/<int:user_id>", methods=["GET"])
def get_public_profile(user_id):
    caller = _current_user_from_token()
    if not caller:
        return jsonify({"message": "Unauthorized"}), 401

    user = UsersDetails.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "user_fn": user.user_fn,
        "user_ln": user.user_ln,
        "initial": (user.user_fn or "?").strip()[:1].upper(),
        "profile_photo": user.profile_photou,
        "avatar_color": user.avatar_color,
        "is_verified": user.is_verified,
        "is_landlord": user.is_landlord,
        "is_tenant": user.is_tenant,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }), 200


# ===========================================================================
# 16 & 17. Lists
# ===========================================================================
@app.route("/get_users", methods=["GET"])
def get_users():
    users = UsersDetails.query.all()
    return jsonify({"count": len(users), "users": [u.to_json() for u in users]}), 200


@app.route("/get_landlords", methods=["GET"])
def get_landlords():
    landlords = Landlords.query.all()
    return jsonify({"count": len(landlords), "landlords": [l.to_json() for l in landlords]}), 200


# ===========================================================================
# LISTINGS -- Landlords write, everyone reads
# ===========================================================================

# ---------------------------------------------------------------------------
# CREATE LISTING (landlord only)
# ---------------------------------------------------------------------------
@app.route("/listings", methods=["POST"])
def create_listing():
    """
    multipart/form-data OR application/json.

    Required:
      title, short_description, long_description,
      location, price, deposit_amount,
      cover_photo (file OR URL),
      photos      (3+ files OR JSON array of URL strings)

    Optional:
      county, latitude, longitude, currency, is_published
    """
    user, landlord = _current_landlord_from_token()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401
    if not landlord:
        return jsonify({
            "message": "Only landlords can create listings. "
                       "Call /become_landlord first."
        }), 403

    body = _get_body()

    title = (body.get("title") or "").strip()
    short_description = (body.get("short_description") or "").strip()
    long_description = (body.get("long_description") or "").strip()
    location = (body.get("location") or "").strip()
    county = (body.get("county") or "").strip() or None
    currency = (body.get("currency") or "KES").strip().upper()

    if not title or not short_description or not long_description or not location:
        return jsonify({
            "message": "title, short_description, long_description and location are required"
        }), 400
    if len(title) > 150:
        return jsonify({"message": "Title too long (max 150)"}), 400
    if len(short_description) > 255:
        return jsonify({"message": "short_description too long (max 255)"}), 400
    if len(currency) != 3:
        return jsonify({"message": "currency must be a 3-letter code"}), 400

    try:
        price = float(body.get("price"))
        deposit_amount = float(body.get("deposit_amount"))
    except (TypeError, ValueError):
        return jsonify({"message": "price and deposit_amount must be numbers"}), 400
    if price <= 0 or deposit_amount < 0:
        return jsonify({
            "message": "price must be positive and deposit_amount >= 0"
        }), 400

    latitude = body.get("latitude")
    longitude = body.get("longitude")
    try:
        latitude = float(latitude) if latitude is not None else None
        longitude = float(longitude) if longitude is not None else None
    except (TypeError, ValueError):
        return jsonify({"message": "latitude and longitude must be numbers"}), 400

    cover_photo, err = _collect_single_photo("cover_photo")
    if err:
        return jsonify({"message": err}), 400
    if not cover_photo:
        return jsonify({"message": "cover_photo is required"}), 400

    photos, err = _collect_listing_photos(
        ["photos", "additional_photos"], min_count=MIN_EXTRA_PHOTOS
    )
    if err:
        return jsonify({"message": err}), 400

    is_published = str(body.get("is_published", "")).lower() in ("1", "true", "yes")

    listing = Listings(
        landlord_id=landlord.id,
        title=title,
        short_description=short_description,
        long_description=long_description,
        location=location,
        county=county,
        latitude=latitude,
        longitude=longitude,
        price=price,
        deposit_amount=deposit_amount,
        currency=currency,
        cover_photo=cover_photo,
        photos=photos,
        is_available=True,
        is_published=is_published,
    )

    try:
        db.session.add(listing)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "an error occurred", "detail": str(e)}), 500

    return jsonify({
        "message": "Listing created",
        "listing": listing.to_json(),
    }), 201


# ---------------------------------------------------------------------------
# BROWSE LISTINGS (any logged-in user)
# ---------------------------------------------------------------------------
@app.route("/listings", methods=["GET"])
def browse_listings():
    """
    Read-only. Any authenticated user can call this.

    Query params (all optional):
      ?county=Nairobi
      ?min_price=10000&max_price=50000
      ?search=kilimani
      ?available=true|false|any
      ?limit=20&offset=0
    """
    caller = _current_user_from_token()
    if not caller:
        return jsonify({"message": "Unauthorized"}), 401

    query = Listings.query.filter_by(is_published=True)

    available = request.args.get("available", "true").lower()
    if available != "any":
        query = query.filter_by(is_available=available == "true")

    county = request.args.get("county")
    if county:
        query = query.filter(Listings.county.ilike(f"%{county}%"))

    search = request.args.get("search")
    if search:
        like = f"%{search.strip()}%"
        query = query.filter(
            (Listings.title.ilike(like)) |
            (Listings.location.ilike(like)) |
            (Listings.short_description.ilike(like))
        )

    try:
        min_price = request.args.get("min_price")
        max_price = request.args.get("max_price")
        if min_price is not None:
            query = query.filter(Listings.price >= float(min_price))
        if max_price is not None:
            query = query.filter(Listings.price <= float(max_price))
    except ValueError:
        return jsonify({"message": "min_price / max_price must be numbers"}), 400

    try:
        limit = min(int(request.args.get("limit", 20)), 100)
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return jsonify({"message": "limit / offset must be integers"}), 400

    total = query.count()
    listings = (
        query.order_by(Listings.created_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )

    return jsonify({
        "count": len(listings),
        "total": total,
        "limit": limit,
        "offset": offset,
        "listings": [l.to_json() for l in listings],
    }), 200


# ---------------------------------------------------------------------------
# MY LISTINGS (landlord only)
# ---------------------------------------------------------------------------
@app.route("/listings/mine", methods=["GET"])
def my_listings():
    user, landlord = _current_landlord_from_token()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401
    if not landlord:
        return jsonify({"message": "You are not a landlord"}), 403

    listings = (
        Listings.query
        .filter_by(landlord_id=landlord.id)
        .order_by(Listings.created_at.desc())
        .all()
    )
    return jsonify({
        "count": len(listings),
        "listings": [l.to_json() for l in listings],
    }), 200


# ---------------------------------------------------------------------------
# GET ONE LISTING (any logged-in user)
# ---------------------------------------------------------------------------
@app.route("/listings/<int:listing_id>", methods=["GET"])
def get_listing(listing_id):
    caller = _current_user_from_token()
    if not caller:
        return jsonify({"message": "Unauthorized"}), 401

    listing = Listings.query.get(listing_id)
    if not listing:
        return jsonify({"message": "Listing not found"}), 404

    try:
        listing.views_count = (listing.views_count or 0) + 1
        db.session.commit()
    except Exception:
        db.session.rollback()

    return jsonify({"listing": listing.to_json()}), 200


# ---------------------------------------------------------------------------
# UPDATE LISTING (owner only)
# ---------------------------------------------------------------------------
@app.route("/listings/<int:listing_id>", methods=["PUT", "POST"])
def update_listing(listing_id):
    user, landlord = _current_landlord_from_token()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401
    if not landlord:
        return jsonify({"message": "You are not a landlord"}), 403

    listing = Listings.query.get(listing_id)
    if not listing:
        return jsonify({"message": "Listing not found"}), 404
    if listing.landlord_id != landlord.id:
        return jsonify({"message": "You do not own this listing"}), 403

    body = _get_body()

    if "title" in body:
        title = (body.get("title") or "").strip()
        if not title or len(title) > 150:
            return jsonify({"message": "Invalid title"}), 400
        listing.title = title

    if "short_description" in body:
        sd = (body.get("short_description") or "").strip()
        if not sd or len(sd) > 255:
            return jsonify({"message": "Invalid short_description"}), 400
        listing.short_description = sd

    if "long_description" in body:
        ld = (body.get("long_description") or "").strip()
        if not ld:
            return jsonify({"message": "Invalid long_description"}), 400
        listing.long_description = ld

    if "location" in body:
        loc = (body.get("location") or "").strip()
        if not loc:
            return jsonify({"message": "Invalid location"}), 400
        listing.location = loc

    if "county" in body:
        listing.county = (body.get("county") or "").strip() or None

    if "latitude" in body:
        try:
            listing.latitude = float(body.get("latitude")) if body.get("latitude") is not None else None
        except (TypeError, ValueError):
            return jsonify({"message": "Invalid latitude"}), 400

    if "longitude" in body:
        try:
            listing.longitude = float(body.get("longitude")) if body.get("longitude") is not None else None
        except (TypeError, ValueError):
            return jsonify({"message": "Invalid longitude"}), 400

    if "price" in body:
        try:
            price = float(body.get("price"))
            if price <= 0:
                raise ValueError
            listing.price = price
        except (TypeError, ValueError):
            return jsonify({"message": "Invalid price"}), 400

    if "deposit_amount" in body:
        try:
            dep = float(body.get("deposit_amount"))
            if dep < 0:
                raise ValueError
            listing.deposit_amount = dep
        except (TypeError, ValueError):
            return jsonify({"message": "Invalid deposit_amount"}), 400

    if "is_available" in body:
        listing.is_available = str(body.get("is_available", "")).lower() in ("1", "true", "yes")

    if "is_published" in body:
        listing.is_published = str(body.get("is_published", "")).lower() in ("1", "true", "yes")

    # Cover photo — replace if a new one is sent
    if request.files.get("cover_photo") or "cover_photo" in body:
        new_cover, err = _collect_single_photo("cover_photo")
        if err:
            return jsonify({"message": err}), 400
        if new_cover:
            listing.cover_photo = new_cover

    # Photos — replace the entire array if new files/URLs are sent
    sent_photos = False
    for fld in ("photos", "additional_photos"):
        if request.files.getlist(fld) or fld in body:
            sent_photos = True
            break
    if sent_photos:
        new_photos, err = _collect_listing_photos(
            ["photos", "additional_photos"], min_count=MIN_EXTRA_PHOTOS
        )
        if err:
            return jsonify({"message": err}), 400
        listing.photos = new_photos

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "an error occurred", "detail": str(e)}), 500

    return jsonify({
        "message": "Listing updated",
        "listing": listing.to_json(),
    }), 200


# ---------------------------------------------------------------------------
# DELETE LISTING (owner only)
# ---------------------------------------------------------------------------
@app.route("/listings/<int:listing_id>", methods=["DELETE"])
def delete_listing(listing_id):
    user, landlord = _current_landlord_from_token()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401
    if not landlord:
        return jsonify({"message": "You are not a landlord"}), 403

    listing = Listings.query.get(listing_id)
    if not listing:
        return jsonify({"message": "Listing not found"}), 404
    if listing.landlord_id != landlord.id:
        return jsonify({"message": "You do not own this listing"}), 403

    try:
        db.session.delete(listing)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "an error occurred", "detail": str(e)}), 500

    return jsonify({"message": "Listing deleted"}), 200


# ---------------------------------------------------------------------------
# TOGGLE PUBLISH (owner only)
# ---------------------------------------------------------------------------
@app.route("/listings/<int:listing_id>/publish", methods=["POST"])
def toggle_publish(listing_id):
    user, landlord = _current_landlord_from_token()
    if not user or not landlord:
        return jsonify({"message": "Unauthorized"}), 401

    listing = Listings.query.get(listing_id)
    if not listing or listing.landlord_id != landlord.id:
        return jsonify({"message": "Listing not found"}), 404

    listing.is_published = not listing.is_published
    db.session.commit()
    return jsonify({
        "message": "Published" if listing.is_published else "Unpublished",
        "listing": listing.to_json(),
    }), 200


# ===========================================================================
# 18. Current user
# ===========================================================================
@app.route("/me", methods=["GET"])
def me():
    user = _current_user_from_token()
    if not user:
        return jsonify({"message": "Unauthorized"}), 401
    return jsonify({"user": user.to_json()}), 200


# ===========================================================================
# Run
# ===========================================================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=10000, debug=False)