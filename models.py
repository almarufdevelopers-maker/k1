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

    users_phone_number = db.Column(db.String(20), unique=True, nullable=True)

    country_code = db.Column(db.String(5))
    national_number = db.Column(db.String(20))

    # Google identity (optional)
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

    landloards_phone_number = db.Column(db.String(20), unique=True, nullable=True)

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
    listings = db.relationship(
        "Listings",
        backref="landlord",
        cascade="all, delete-orphan",
        lazy="select",
    )

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


class Listings(db.Model):
    __tablename__ = "listings"
    id = db.Column(db.Integer, primary_key=True)

    # Owner — landlord only
    landlord_id = db.Column(
        db.Integer,
        db.ForeignKey("landlordsdetails.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Basic info
    title = db.Column(db.String(150), nullable=False)
    short_description = db.Column(db.String(255), nullable=False)
    long_description = db.Column(db.Text, nullable=False)

    # Location
    location = db.Column(db.String(255), nullable=False, index=True)
    county = db.Column(db.String(50), index=True)
    latitude = db.Column(db.Float, nullable=True)
    longitude = db.Column(db.Float, nullable=True)

    # Pricing
    price = db.Column(db.Numeric(10, 2), nullable=False)
    deposit_amount = db.Column(db.Numeric(10, 2), nullable=False)
    currency = db.Column(db.String(3), default="KES", nullable=False)

    # Media — cover photo + at least 3 extra photos
    cover_photo = db.Column(db.String(255), nullable=False)
    photos = db.Column(db.JSON, default=list, nullable=False)

    # Status
    is_available = db.Column(db.Boolean, default=True, nullable=False, index=True)
    is_published = db.Column(db.Boolean, default=False, nullable=False, index=True)

    # Analytics
    views_count = db.Column(db.Integer, default=0, nullable=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=utcnow, onupdate=utcnow, nullable=False,
    )

    __table_args__ = (
        db.Index("ix_listings_county_price", "county", "price"),
        db.Index("ix_listings_published_available", "is_published", "is_available"),
    )

    def to_json(self):
        return {
            "id": self.id,
            "landlord_id": self.landlord_id,
            "title": self.title,
            "short_description": self.short_description,
            "long_description": self.long_description,
            "location": self.location,
            "county": self.county,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "price": float(self.price) if self.price is not None else None,
            "deposit_amount": float(self.deposit_amount) if self.deposit_amount is not None else None,
            "currency": self.currency,
            "cover_photo": self.cover_photo,
            "photos": self.photos or [],
            "is_available": self.is_available,
            "is_published": self.is_published,
            "views_count": self.views_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }