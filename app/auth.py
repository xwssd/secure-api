"""JWT authentication middleware and a small login rate limiter."""

import time
from collections import deque
from functools import wraps
from threading import Lock

import jwt
from flask import g, jsonify, request

from .security import decode_token

_WINDOW_SECONDS = 60
_MAX_ATTEMPTS = 5
_attempts: dict[str, deque] = {}
_lock = Lock()


def rate_limited(key: str) -> bool:
    """Return True when ``key`` exceeded 5 requests inside 60 seconds."""
    now = time.monotonic()
    with _lock:
        bucket = _attempts.setdefault(key, deque())
        while bucket and now - bucket[0] > _WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= _MAX_ATTEMPTS:
            return True
        bucket.append(now)
        return False


def reset_limits() -> None:
    with _lock:
        _attempts.clear()


def _bearer_token() -> str | None:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    token = header[7:].strip()
    return token or None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        token = _bearer_token()
        if token is None:
            return jsonify(error="authorization header with a bearer token is required"), 401
        try:
            g.current_user = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify(error="token expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="invalid token"), 401
        return view(*args, **kwargs)

    return wrapped
