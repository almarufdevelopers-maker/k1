# models.py
from config import db
from datetime import datetime, timezone


def utcnow():
    """Return a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class UsersDetails(db.Model):
    __tablename__ = "usersdetails"
    id = db.Column(db.Integer, primary_key=True)

    user_fn = db.Column(db.String(120))
    user_ln = db.Column(db.String(120))

    users_phone_number = db.Column(db.String(20), unique=True, nullable=False)

    country_code = db.Column(db.String(5))
    national_number = db.Column(db.String(20))

    # Google identity (optional — set when the user signs in with Google)
    google_sub = db.Column(db.String(64), unique=True, nullable=True, index=True)
    email = db.Column(db.String(255), nullable=True, index=True)

    profile_photou = db.Column(db.String(255))
    avatar_color = db.Column(db.String(10))

    is_landlord = db.Column(db.Boolean, default=False, nullable=False)
    is_tenant = db.Column(db.Boolean, default=True, nullable=False)

    is_verified = db.Column(db.Boolean, default=False, nullable=False, index=True)
    verified_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )

    landlord_profile = db.relationship(
        "Landlords",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )

    def pretty_phone(self):
        try:
            import phonenumbers
            n = phonenumbers.parse(self.users_phone_number, None)
            return phonenumbers.format_number(
                n, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
        except Exception:
            return self.users_phone_number

    def to_json(self):
        return {
            "id": self.id,
            "user_fn": self.user_fn,
            "user_ln": self.user_ln,
            "users_phone_number": self.users_phone_number,
            "phone_display": self.pretty_phone(),
            "country_code": self.country_code,
            "national_number": self.national_number,
            "email": self.email,
            "has_google": bool(self.google_sub),
            "profile_photo": self.profile_photou,
            "avatar_color": self.avatar_color,
            "initial": (self.user_fn or "?").strip()[:1].upper(),
            "is_landlord": self.is_landlord,
            "is_tenant": self.is_tenant,
            "is_verified": self.is_verified,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "landlord_id": self.landlord_profile.id if self.landlord_profile else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Landlords(db.Model):
    __tablename__ = "landlordsdetails"
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("usersdetails.id", ondelete="CASCADE"),
        unique=True,
        nullable=True,
    )

    user_fn = db.Column(db.String(120))
    user_ln = db.Column(db.String(120))

    landloards_phone_number = db.Column(db.String(20), unique=True, nullable=False)

    country_code = db.Column(db.String(5))
    national_number = db.Column(db.String(20))

    profile_photol = db.Column(db.String(255))
    avatar_color = db.Column(db.String(10))

    is_verified = db.Column(db.Boolean, default=False, nullable=False, index=True)
    verified_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=utcnow,
        onupdate=utcnow,
        nullable=False,
    )

    user = db.relationship("UsersDetails", back_populates="landlord_profile")

    def pretty_phone(self):
        try:
            import phonenumbers
            n = phonenumbers.parse(self.landloards_phone_number, None)
            return phonenumbers.format_number(
                n, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
        except Exception:
            return self.landloards_phone_number

    def to_json(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "user_fn": self.user_fn,
            "user_ln": self.user_ln,
            "landlords_phone_number": self.landloards_phone_number,
            "phone_display": self.pretty_phone(),
            "country_code": self.country_code,
            "national_number": self.national_number,
            "profile_photo": self.profile_photol,
            "avatar_color": self.avatar_color,
            "initial": (self.user_fn or "?").strip()[:1].upper(),
            "is_verified": self.is_verified,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class OTPVerification(db.Model):
    __tablename__ = "otp_verifications"
    id = db.Column(db.Integer, primary_key=True)

    phone_number = db.Column(db.String(20), nullable=False, index=True)
    otp_hash = db.Column(db.String(128), nullable=False)
    attempts = db.Column(db.Integer, default=0, nullable=False)
    consumed = db.Column(db.Boolean, default=False, nullable=False)

    verified_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("usersdetails.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    def is_valid(self) -> bool:
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return (
            not self.consumed
            and expires > now
            and self.attempts < 5
        )

    def to_json(self):
        return {
            "id": self.id,
            "phone_number": self.phone_number,
            "user_id": self.user_id,
            "attempts": self.attempts,
            "consumed": self.consumed,
            "is_valid": self.is_valid(),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }