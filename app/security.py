"""Password hashing, JWT issuing/verification and output escaping."""

import datetime as dt
import re

import bcrypt
import jwt
from flask import current_app
from markupsafe import escape

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def hash_password(password: str) -> str:
    """bcrypt with a per-password salt and a work factor of 12."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def password_policy_error(password: str) -> str | None:
    """Return an error message when the password is too weak, else None."""
    minimum = int(current_app.config["PASSWORD_MIN_LENGTH"])
    if len(password) < minimum:
        return f"password must be at least {minimum} characters long"
    if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password):
        return "password must mix lower and upper case letters"
    if not re.search(r"\d", password):
        return "password must contain at least one digit"
    return None


def sanitize(value: str) -> str:
    """HTML-escape user controlled text before it leaves the API (anti-XSS)."""
    return str(escape(value))


def create_token(user) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "role": user["role"],
        "iat": now,
        "exp": now + dt.timedelta(minutes=int(current_app.config["JWT_EXPIRES_MINUTES"])),
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")


def decode_token(token: str) -> dict:
    """Verify signature, expiry and algorithm; raises jwt.InvalidTokenError."""
    return jwt.decode(
        token,
        current_app.config["SECRET_KEY"],
        algorithms=["HS256"],
        options={"require": ["exp", "sub"]},
    )
